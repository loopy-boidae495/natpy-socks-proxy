#!/usr/bin/env python3
"""
VPN SOCKS5 Proxy Server with UDP Support
=========================================
Lightweight SOCKS5 proxy for sharing a VPN connection on a local network.
Supports both TCP (CONNECT) and UDP (UDP ASSOCIATE) — required for Xbox NAT Type.
"""

import re
import select
import socket
import struct
import subprocess
import threading
import hmac
import argparse
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple


# ── Global constants ──────────────────────────────────────────────────────────

_TCP_BUF        = 65536     # TCP relay buffer (64 KB)
_UDP_BUF        = 65536     # UDP relay buffer (64 KB)
_SELECT_TIMEOUT = 60.0      # select() idle timeout for TCP relay (seconds)
_UDP_IDLE       = 120.0     # UDP session idle timeout (seconds) — keeps STUN alive for Xbox
_DNS_TTL        = 300       # Successful DNS cache TTL (seconds)
_DNS_NEG_TTL    = 30        # Negative DNS cache TTL (seconds)
_BACKLOG        = 128       # TCP accept backlog


# ── DNS cache with per-entry TTL ─────────────────────────────────────────────

class _DnsCache:
    """Thread-safe DNS cache with separate TTLs for hits and misses."""

    def __init__(self):
        self._store: dict[str, Tuple[Optional[str], float]] = {}
        self._lock  = threading.Lock()

    def resolve(self, host: str) -> Optional[str]:
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(host)
            if entry is not None:
                ip, exp = entry
                if now < exp:
                    return ip   # None means known-bad; avoids redundant lookups
                del self._store[host]

        # Perform the DNS lookup outside the lock so other threads aren't blocked
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            ip = None

        ttl = _DNS_TTL if ip else _DNS_NEG_TTL
        with self._lock:
            self._store[host] = (ip, time.monotonic() + ttl)
        return ip


# ── Main proxy class ──────────────────────────────────────────────────────────

class VPNSocks5Proxy:
    def __init__(
        self,
        host: str        = None,
        port: int        = 9898,
        username: str    = None,
        password: str    = None,
        max_workers: int = 256,
    ):
        self.host         = host or self._detect_listen_address()
        self.port         = port
        self.require_auth = bool(username and password)
        self.running      = True
        self._max_workers = max_workers
        self._dns         = _DnsCache()

        # Encode credentials once at startup; avoids per-connection allocation
        self._user_b = username.encode() if username else b""
        self._pwd_b  = password.encode() if password else b""

        # Simple counters (GIL makes int ops atomic enough for stats)
        self._total     = 0
        self._active    = 0
        self._auth_ok   = 0
        self._auth_fail = 0
        self._udp_sess  = 0   # currently open UDP sessions

    # ── Listen address detection ──────────────────────────────────────────────

    @staticmethod
    def _detect_listen_address() -> str:
        """
        Scans ipconfig output for a Realtek/USB adapter with a private IP.
        Falls back to 0.0.0.0 (all interfaces) if nothing is found.
        """
        _IP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
        try:
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, shell=True, timeout=5
            )
            adapter = None
            for line in result.stdout.splitlines():
                s = line.strip()
                if "Ethernet adapter" in s or "Wireless LAN adapter" in s:
                    adapter = s
                elif "IPv4 Address" in s and adapter:
                    if "Realtek" in adapter or "USB" in adapter:
                        m = _IP_RE.search(s)
                        if m:
                            ip = m.group(1)
                            if ip.startswith(("192.168.", "10.")):
                                return ip
        except Exception:
            pass
        return "0.0.0.0"

    # ── Credential verification (constant-time to prevent timing attacks) ─────

    def _verify_credentials(self, user: bytes, pwd: bytes) -> bool:
        if not self.require_auth:
            return True
        return (
            hmac.compare_digest(user, self._user_b)
            and hmac.compare_digest(pwd, self._pwd_b)
        )

    # ── Low-level socket helpers ──────────────────────────────────────────────

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        """Read exactly n bytes; returns None on short read or socket error."""
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    # ── SOCKS5 handshake ──────────────────────────────────────────────────────

    def _do_handshake(self, sock: socket.socket) -> bool:
        """
        Performs the SOCKS5 greeting and optional username/password auth (RFC 1929).
        Returns True on success.
        """
        hdr = self._recv_exact(sock, 2)
        if not hdr or hdr[0] != 0x05:
            return False

        methods = self._recv_exact(sock, hdr[1])
        if methods is None:
            return False

        if self.require_auth:
            if 0x02 not in methods:
                sock.sendall(b"\x05\xFF")   # no acceptable auth method
                return False
            sock.sendall(b"\x05\x02")       # select username/password method

            # RFC 1929 sub-negotiation
            if not self._recv_exact(sock, 1):   # VER must be 0x01
                return False
            ulen = self._recv_exact(sock, 1)
            if not ulen:
                return False
            user = self._recv_exact(sock, ulen[0]) or b""
            plen = self._recv_exact(sock, 1)
            if not plen:
                return False
            pwd = self._recv_exact(sock, plen[0]) or b""

            if self._verify_credentials(user, pwd):
                sock.sendall(b"\x01\x00")   # auth success
                self._auth_ok += 1
                return True
            sock.sendall(b"\x01\x01")       # auth failure
            self._auth_fail += 1
            return False

        sock.sendall(b"\x05\x00")   # no authentication required
        return True

    # ── SOCKS5 request parser ─────────────────────────────────────────────────

    def _parse_request(self, sock: socket.socket) -> Optional[Tuple[int, str, int]]:
        """
        Reads the SOCKS5 request header.
        Returns (cmd, dest_ip, dest_port) or None on error.
        cmd: 0x01 = CONNECT (TCP)  |  0x03 = UDP ASSOCIATE
        """
        hdr = self._recv_exact(sock, 4)
        if not hdr or hdr[0] != 0x05:
            return None

        cmd  = hdr[1]
        atyp = hdr[3]

        if cmd not in (0x01, 0x03):
            sock.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)   # command not supported
            return None

        if atyp == 0x01:        # IPv4
            raw = self._recv_exact(sock, 6)
            if not raw:
                return None
            dest_ip   = socket.inet_ntoa(raw[:4])
            dest_port = struct.unpack_from(">H", raw, 4)[0]

        elif atyp == 0x03:      # domain name
            dlen_b = self._recv_exact(sock, 1)
            if not dlen_b:
                return None
            raw = self._recv_exact(sock, dlen_b[0] + 2)
            if not raw:
                return None
            domain    = raw[: dlen_b[0]].decode("utf-8", errors="replace")
            dest_port = struct.unpack_from(">H", raw, dlen_b[0])[0]
            dest_ip   = self._dns.resolve(domain)
            if dest_ip is None:
                sock.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6)   # host unreachable
                return None

        elif atyp == 0x04:      # IPv6 — not supported
            sock.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return None

        else:
            return None

        return cmd, dest_ip, dest_port

    # ── TCP relay (select-based, single thread for both directions) ───────────

    @staticmethod
    def _relay_tcp(client: socket.socket, remote: socket.socket) -> None:
        """
        Bidirectional TCP relay using select().
        One thread handles both directions — half the thread count vs. a
        two-thread approach, with no join() overhead.
        """
        peer = {client: remote, remote: client}
        client.setblocking(False)
        remote.setblocking(False)

        try:
            while True:
                try:
                    r, _, e = select.select(
                        [client, remote], [], [client, remote], _SELECT_TIMEOUT
                    )
                except OSError:
                    break

                if e or not r:  # socket error or idle timeout
                    break

                for s in r:
                    try:
                        data = s.recv(_TCP_BUF)
                    except OSError:
                        return
                    if not data:
                        return
                    try:
                        peer[s].sendall(data)
                    except OSError:
                        return
        finally:
            for s in (client, remote):
                try:
                    s.close()
                except OSError:
                    pass

    # ── UDP relay — fixes NAT Type ──────────────────────────────────────

    def _relay_udp(
        self,
        ctrl_sock: socket.socket,       # TCP control socket (detects client disconnect)
        client_addr: Tuple[str, int],
    ) -> None:
        """
        Opens a local UDP socket and relays packets between the client and
        their destination.

        Why this matters for Xbox:
        Xbox uses STUN (UDP port 3478) to determine NAT Type.  If the proxy
        only relays TCP, STUN requests get no response and NAT shows as
        "Unavailable".  This relay forwards UDP datagrams through the VPN
        tunnel so STUN succeeds and NAT Type is resolved correctly.
        """
        self._udp_sess += 1
        relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            relay_sock.bind(("0.0.0.0", 0))   # bind to an ephemeral port
            relay_sock.setblocking(False)
            ctrl_sock.setblocking(False)

            # Send the relay's bound address back to the client (RFC 1928 reply)
            _, local_port = relay_sock.getsockname()
            bound_ip = socket.inet_aton(
                self.host if self.host != "0.0.0.0" else "127.0.0.1"
            )
            reply = b"\x05\x00\x00\x01" + bound_ip + struct.pack(">H", local_port)
            try:
                ctrl_sock.sendall(reply)
            except OSError:
                return

            # Track the last client-side UDP source address for return traffic
            last_src: Optional[Tuple[str, int]] = None
            deadline = time.monotonic() + _UDP_IDLE

            while time.monotonic() < deadline:
                try:
                    r, _, _ = select.select([relay_sock, ctrl_sock], [], [], 5.0)
                except OSError:
                    break

                if not r:
                    continue

                # If the TCP control socket closes, end the UDP session
                if ctrl_sock in r:
                    try:
                        if not ctrl_sock.recv(1):
                            break
                    except OSError:
                        break

                if relay_sock in r:
                    try:
                        data, addr = relay_sock.recvfrom(_UDP_BUF)
                    except OSError:
                        continue

                    deadline = time.monotonic() + _UDP_IDLE  # reset idle timer

                    if last_src is None or addr == last_src:
                        # Packet from client — strip SOCKS5 UDP header and forward
                        parsed = self._parse_udp_header(data)
                        if parsed:
                            payload, dest = parsed
                            last_src = addr
                            try:
                                relay_sock.sendto(payload, dest)
                            except OSError:
                                pass
                    else:
                        # Packet from remote — wrap with SOCKS5 UDP header and return
                        if last_src:
                            wrapped = self._build_udp_header(addr) + data
                            try:
                                relay_sock.sendto(wrapped, last_src)
                            except OSError:
                                pass

        finally:
            relay_sock.close()
            self._udp_sess -= 1

    @staticmethod
    def _parse_udp_header(data: bytes) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        """
        Strips the SOCKS5 UDP request header from a datagram.
        Format: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA
        """
        if len(data) < 10:
            return None

        if data[2] != 0:
            return None     # fragmented datagrams are not supported

        atyp = data[3]

        if atyp == 0x01:    # IPv4
            dest_ip   = socket.inet_ntoa(data[4:8])
            dest_port = struct.unpack_from(">H", data, 8)[0]
            payload   = data[10:]
        elif atyp == 0x03:  # domain name
            dlen = data[4]
            if len(data) < 5 + dlen + 2:
                return None
            dest_ip   = socket.gethostbyname(
                data[5 : 5 + dlen].decode("utf-8", errors="replace")
            )
            dest_port = struct.unpack_from(">H", data, 5 + dlen)[0]
            payload   = data[5 + dlen + 2 :]
        else:
            return None

        return payload, (dest_ip, dest_port)

    @staticmethod
    def _build_udp_header(src_addr: Tuple[str, int]) -> bytes:
        """Builds a SOCKS5 UDP response header for wrapping inbound datagrams."""
        return (
            b"\x00\x00"                         # RSV
            + b"\x00"                           # FRAG
            + b"\x01"                           # ATYP = IPv4
            + socket.inet_aton(src_addr[0])     # source address
            + struct.pack(">H", src_addr[1])    # source port
        )

    # ── Per-connection handler ────────────────────────────────────────────────

    def handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        self._total  += 1
        self._active += 1
        try:
            client_sock.settimeout(15)

            if not self._do_handshake(client_sock):
                return

            result = self._parse_request(client_sock)
            if result is None:
                return

            cmd, dest_ip, dest_port = result

            if cmd == 0x03:
                # UDP ASSOCIATE — required for Xbox NAT Type / STUN
                self._relay_udp(client_sock, (dest_ip, dest_port))
                return

            # cmd == 0x01 → standard TCP CONNECT
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(15)
                remote.connect((dest_ip, dest_port))

                # TCP_NODELAY disables Nagle buffering — reduces latency in games
                for s in (client_sock, remote):
                    try:
                        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except OSError:
                        pass

                reply = (
                    b"\x05\x00\x00\x01"
                    + socket.inet_aton(dest_ip)
                    + struct.pack(">H", dest_port)
                )
                client_sock.sendall(reply)

                # _relay_tcp takes ownership of both sockets
                self._relay_tcp(client_sock, remote)
                client_sock = None  # prevent double-close in finally block

            except OSError:
                try:
                    client_sock.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
                except OSError:
                    pass

        except Exception:
            pass
        finally:
            if client_sock is not None:
                try:
                    client_sock.close()
                except OSError:
                    pass
            self._active -= 1

    # ── Main accept loop ──────────────────────────────────────────────────────

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind((self.host, self.port))
            server.listen(_BACKLOG)
            print(f"[*] SOCKS5 Proxy   : {self.host}:{self.port}")
            print(f"[*] Authentication : {'Enabled' if self.require_auth else 'Disabled'}")
            print(f"[*] UDP relay      : Enabled (Nat-Type)")
            print(f"[*] Thread pool    : {self._max_workers} workers\n")

            with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
                while self.running:
                    try:
                        client_sock, client_addr = server.accept()
                        pool.submit(self.handle_client, client_sock, client_addr)
                    except KeyboardInterrupt:
                        break
                    except OSError:
                        pass

        except OSError as e:
            print(f"[!] ERROR: {e}")
        finally:
            self.running = False
            server.close()
            print(
                f"\n[*] Proxy stopped."
                f"  total={self._total}"
                f"  auth_ok={self._auth_ok}"
                f"  auth_fail={self._auth_fail}"
            )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="VPN SOCKS5 Proxy with UDP support for NAT")
    parser.add_argument("--host",     help="Listen address")
    parser.add_argument("--port",     type=int, default=9898, help="Listen port (default 9898)")
    parser.add_argument("--user",     help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--workers",  type=int, default=256, help="Thread pool size (default 256)")
    args = parser.parse_args()

    proxy = VPNSocks5Proxy(
        host        = args.host,
        port        = args.port,
        username    = args.user,
        password    = args.password,
        max_workers = args.workers,
    )
    proxy.start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Shutdown requested")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
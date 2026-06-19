#!/usr/bin/env python3
"""
VPN Hybrid Proxy Server — Termux / Android Edition
=====================================================
Runs an HTTP CONNECT proxy and a SOCKS5 proxy at the same time, on two
separate ports, sharing the same VPN connection. Tuned for Android's
resource constraints (lower thread count, smaller buffers, no Windows-only
calls, optional termux-wake-lock reminder).

- HTTP proxy   : TCP only (HTTP/HTTPS via CONNECT). Simple, widely
                 compatible with apps/browsers that prefer HTTP proxies.
- SOCKS5 proxy : TCP (CONNECT) + UDP (UDP ASSOCIATE). The UDP path is what
                 makes Xbox NAT Type detection work, since Xbox uses STUN
                 (UDP) to determine NAT Type. HTTP cannot carry UDP at all,
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

_TCP_BUF        = 32768     # TCP relay buffer (32 KB) — lighter for phone RAM/CPU
_UDP_BUF        = 32768     # UDP relay buffer (32 KB)
_SELECT_TIMEOUT = 60.0      # select() idle timeout for TCP relay (seconds)
_UDP_IDLE       = 120.0     # UDP session idle timeout (seconds) — keeps STUN alive for Xbox
_DNS_TTL        = 300       # Successful DNS cache TTL (seconds)
_DNS_NEG_TTL    = 30        # Negative DNS cache TTL (seconds)
_BACKLOG        = 64        # TCP accept backlog — mobile NICs rarely need 128
_HTTP_HDR_LIMIT = 8192      # Max bytes read while parsing an HTTP request header


# ── DNS cache with per-entry TTL (shared by both proxies) ───────────────────

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

        try:
            ip = socket.gethostbyname(host)
        except OSError:
            ip = None

        ttl = _DNS_TTL if ip else _DNS_NEG_TTL
        with self._lock:
            self._store[host] = (ip, time.monotonic() + ttl)
        return ip


# ── Shared relay helpers (used by both HTTP and SOCKS5 paths) ───────────────

class _RelayMixin:
    """Common TCP relay and credential-check logic shared by both servers."""

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

                if e or not r:
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

    def _verify_credentials(self, user: bytes, pwd: bytes) -> bool:
        if not self.require_auth:
            return True
        return (
            hmac.compare_digest(user, self._user_b)
            and hmac.compare_digest(pwd, self._pwd_b)
        )

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


# ── HTTP CONNECT proxy (TCP only) ────────────────────────────────────────────

class HttpProxy(_RelayMixin):
    """
    Minimal HTTP/HTTPS proxy supporting the CONNECT method (for TLS tunnels)
    and plain GET/POST forwarding (for unencrypted HTTP).
    TCP only — HTTP has no mechanism to carry UDP, so this server cannot help
    with Xbox NAT Type. Use the SOCKS5 server below for that.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: Optional[str],
        password: Optional[str],
        max_workers: int,
        dns: _DnsCache,
    ):
        self.host         = host
        self.port         = port
        self.require_auth = bool(username and password)
        self.running      = True
        self._max_workers = max_workers
        self._dns         = dns

        self._user_b = username.encode() if username else b""
        self._pwd_b  = password.encode() if password else b""

        self._total  = 0
        self._active = 0

    # ── Basic auth header check (Proxy-Authorization: Basic base64) ──────────

    def _check_proxy_auth(self, headers: dict) -> bool:
        if not self.require_auth:
            return True
        auth = headers.get("proxy-authorization", "")
        if not auth.lower().startswith("basic "):
            return False
        import base64
        try:
            decoded = base64.b64decode(auth[6:].strip()).decode("utf-8", errors="replace")
            user, _, pwd = decoded.partition(":")
        except Exception:
            return False
        return self._verify_credentials(user.encode(), pwd.encode())

    @staticmethod
    def _parse_http_request(raw: bytes) -> Optional[Tuple[str, str, dict, bytes]]:
        """
        Parses the request line + headers from a raw HTTP request buffer.
        Returns (method, target, headers_dict, header_block) or None.
        """
        sep = raw.find(b"\r\n\r\n")
        if sep == -1:
            return None
        header_block = raw[:sep]
        lines = header_block.split(b"\r\n")
        if not lines:
            return None

        try:
            request_line = lines[0].decode("latin-1")
            method, target, _version = request_line.split(" ", 2)
        except ValueError:
            return None

        headers = {}
        for line in lines[1:]:
            if b":" not in line:
                continue
            k, _, v = line.partition(b":")
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()

        return method, target, headers, header_block

    def handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        self._total  += 1
        self._active += 1
        remote = None
        try:
            client_sock.settimeout(15)

            # Read until we have full headers (handles requests split across packets)
            raw = bytearray()
            while b"\r\n\r\n" not in raw and len(raw) < _HTTP_HDR_LIMIT:
                chunk = self._recv_exact(client_sock, 1)
                if chunk is None:
                    return
                raw += chunk

            parsed = self._parse_http_request(bytes(raw))
            if parsed is None:
                return
            method, target, headers, _ = parsed

            if not self._check_proxy_auth(headers):
                client_sock.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b'Proxy-Authenticate: Basic realm="proxy"\r\n'
                    b"Content-Length: 0\r\n\r\n"
                )
                return

            if method.upper() == "CONNECT":
                # target looks like "host:port" — used for HTTPS tunneling
                host, _, port_s = target.partition(":")
                port = int(port_s) if port_s else 443
            else:
                # Plain HTTP — pull host[:port] from the Host header or absolute URI
                host_hdr = headers.get("host", "")
                host, _, port_s = host_hdr.partition(":")
                port = int(port_s) if port_s else 80
                if not host:
                    return

            dest_ip = self._dns.resolve(host) if not re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else host
            if dest_ip is None:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return

            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(15)
            remote.connect((dest_ip, port))

            for s in (client_sock, remote):
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass

            if method.upper() == "CONNECT":
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                # Forward the original request bytes (request line + headers + any
                # body already buffered) straight through to the remote server.
                remote.sendall(bytes(raw))

            self._relay_tcp(client_sock, remote)
            client_sock = None
            remote = None

        except Exception:
            pass
        finally:
            for s in (client_sock, remote):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            self._active -= 1

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(_BACKLOG)
        print(f"[*] HTTP Proxy     : {self.host}:{self.port}  (TCP only)")

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            while self.running:
                try:
                    client_sock, client_addr = server.accept()
                    pool.submit(self.handle_client, client_sock, client_addr)
                except KeyboardInterrupt:
                    break
                except OSError:
                    pass

        server.close()


# ── SOCKS5 proxy (TCP + UDP — required for Xbox NAT Type) ──────────────────

class Socks5Proxy(_RelayMixin):
    def __init__(
        self,
        host: str,
        port: int,
        username: Optional[str],
        password: Optional[str],
        max_workers: int,
        dns: _DnsCache,
    ):
        self.host         = host
        self.port         = port
        self.require_auth = bool(username and password)
        self.running      = True
        self._max_workers = max_workers
        self._dns         = dns

        self._user_b = username.encode() if username else b""
        self._pwd_b  = password.encode() if password else b""

        self._total      = 0
        self._active     = 0
        self._auth_ok    = 0
        self._auth_fail  = 0
        self._udp_sess   = 0

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
                sock.sendall(b"\x05\xFF")
                return False
            sock.sendall(b"\x05\x02")

            if not self._recv_exact(sock, 1):
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
                sock.sendall(b"\x01\x00")
                self._auth_ok += 1
                return True
            sock.sendall(b"\x01\x01")
            self._auth_fail += 1
            return False

        sock.sendall(b"\x05\x00")
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
            sock.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
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
                sock.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6)
                return None

        elif atyp == 0x04:      # IPv6 — not supported
            sock.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return None

        else:
            return None

        return cmd, dest_ip, dest_port

    # ── UDP relay — fixes NAT Type ──────────────────────────────────────

    def _relay_udp(
        self,
        ctrl_sock: socket.socket,
        client_addr: Tuple[str, int],
    ) -> None:
        """
        Opens a local UDP socket and relays packets between the client and
        their destination.
        
        """
        self._udp_sess += 1
        relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            relay_sock.bind(("0.0.0.0", 0))
            relay_sock.setblocking(False)
            ctrl_sock.setblocking(False)

            _, local_port = relay_sock.getsockname()
            bound_ip = socket.inet_aton(
                self.host if self.host != "0.0.0.0" else "127.0.0.1"
            )
            reply = b"\x05\x00\x00\x01" + bound_ip + struct.pack(">H", local_port)
            try:
                ctrl_sock.sendall(reply)
            except OSError:
                return

            last_src: Optional[Tuple[str, int]] = None
            deadline = time.monotonic() + _UDP_IDLE

            while time.monotonic() < deadline:
                try:
                    r, _, _ = select.select([relay_sock, ctrl_sock], [], [], 5.0)
                except OSError:
                    break

                if not r:
                    continue

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

                    deadline = time.monotonic() + _UDP_IDLE

                    if last_src is None or addr == last_src:
                        parsed = self._parse_udp_header(data)
                        if parsed:
                            payload, dest = parsed
                            last_src = addr
                            try:
                                relay_sock.sendto(payload, dest)
                            except OSError:
                                pass
                    else:
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
            return None

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
            b"\x00\x00"
            + b"\x00"
            + b"\x01"
            + socket.inet_aton(src_addr[0])
            + struct.pack(">H", src_addr[1])
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
                self._relay_udp(client_sock, (dest_ip, dest_port))
                return

            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(15)
                remote.connect((dest_ip, dest_port))

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

                self._relay_tcp(client_sock, remote)
                client_sock = None

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

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(_BACKLOG)
        print(f"[*] SOCKS5 Proxy   : {self.host}:{self.port}  (TCP + UDP, NAT fix)")

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            while self.running:
                try:
                    client_sock, client_addr = server.accept()
                    pool.submit(self.handle_client, client_sock, client_addr)
                except KeyboardInterrupt:
                    break
                except OSError:
                    pass

        server.close()


# ── Address detection (Termux / Android) ─────────────────────────────────────

def detect_listen_address() -> str:
    """
    Detects the device's local Wi-Fi/hotspot IP using Termux-friendly tools
    (`ip addr`), since `ipconfig` does not exist on Android.
    Falls back to the Termux:API command if installed, then to 0.0.0.0
    (all interfaces) if detection fails entirely.
    """
    _IP_RE = re.compile(r"inet (\d+\.\d+\.\d+\.\d+)/\d+.*?\b(wlan\d+|rmnet\d+|ap\d+)")

    try:
        result = subprocess.run(
            ["ip", "addr"], capture_output=True, text=True, timeout=5
        )
        for m in _IP_RE.finditer(result.stdout):
            ip = m.group(1)
            if ip.startswith(("192.168.", "10.")):
                return ip
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["termux-wifi-connectioninfo"], capture_output=True, text=True, timeout=5
        )
        m = re.search(r'"ip"\s*:\s*"(\d+\.\d+\.\d+\.\d+)"', result.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass

    return "0.0.0.0"


# ── CLI / entry point ─────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="VPN Hybrid Proxy (HTTP + SOCKS5) for Termux/Android, with UDP support for NAT"
    )
    parser.add_argument("--host",       help="Listen address (auto-detected if omitted)")
    parser.add_argument("--http-port",  type=int, default=9897, help="HTTP proxy port (default 9897)")
    parser.add_argument("--socks-port", type=int, default=9898, help="SOCKS5 proxy port (default 9898)")
    parser.add_argument("--user",       help="Username for authentication (applies to both proxies)")
    parser.add_argument("--password",   help="Password for authentication (applies to both proxies)")
    parser.add_argument(
        "--workers", type=int, default=64,
        help="Thread pool size per server (default 64, lower than desktop for phone CPUs)"
    )
    args = parser.parse_args()

    host = args.host or detect_listen_address()
    dns  = _DnsCache()   # shared cache between HTTP and SOCKS5 servers

    http_proxy  = HttpProxy(host, args.http_port, args.user, args.password, args.workers, dns)
    socks_proxy = Socks5Proxy(host, args.socks_port, args.user, args.password, args.workers, dns)

    print(f"[*] Listen address : {host}")
    print(f"[*] Authentication : {'Enabled' if (args.user and args.password) else 'Disabled'}")

    http_thread = threading.Thread(target=http_proxy.start, daemon=True)
    http_thread.start()

    try:
        socks_proxy.start()   # runs on the main thread
    finally:
        http_proxy.running  = False
        socks_proxy.running = False


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Shutdown requested")
    except Exception as e:
        print(f"[!] Fatal error: {e}")

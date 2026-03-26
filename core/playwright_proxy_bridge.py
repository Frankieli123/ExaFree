from __future__ import annotations

import atexit
import base64
import logging
import select
import socket
import socketserver
import ssl
import threading
from typing import Optional
from urllib.parse import unquote, urlparse, urlsplit

import socks

from core.proxy_utils import format_no_proxy, normalize_proxy_url, sanitize_proxy_url

logger = logging.getLogger("exa.proxy.bridge")

_BRIDGES_LOCK = threading.Lock()
_BRIDGES: dict[str, "PlaywrightSocksBridge"] = {}


def _host_port_from_connect_target(target: str) -> tuple[str, int]:
    raw = str(target or "").strip()
    if not raw:
        raise ValueError("empty connect target")
    if raw.startswith("["):
        pos = raw.rfind("]:")
        if pos > 0:
            return raw[1:pos], int(raw[pos + 2 :])
    host, port = raw.rsplit(":", 1)
    return host, int(port)


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _BridgeHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        bridge: PlaywrightSocksBridge = self.server.bridge
        try:
            request_line = self.rfile.readline(65536)
            if not request_line:
                return
            method, target, version = request_line.decode("latin-1").strip().split(" ", 2)
            headers: list[bytes] = []
            while True:
                line = self.rfile.readline(65536)
                if not line or line in (b"\r\n", b"\n"):
                    break
                headers.append(line)

            if method.upper() == "CONNECT":
                logger.info("[PROXY] bridge CONNECT target=%s via=%s", target, sanitize_proxy_url(bridge.proxy_url))
                bridge.handle_connect(self.connection, target)
                return

            logger.info(
                "[PROXY] bridge %s target=%s via=%s",
                method.upper(),
                target,
                sanitize_proxy_url(bridge.proxy_url),
            )
            bridge.handle_http_request(
                client_sock=self.connection,
                method=method,
                target=target,
                version=version,
                header_lines=headers,
                body_reader=self.rfile,
            )
        except Exception as exc:
            try:
                self.connection.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
            except Exception:
                pass
            logger.warning("[PROXY] bridge request failed via=%s err=%s", sanitize_proxy_url(bridge.proxy_url), exc)


class PlaywrightSocksBridge:
    def __init__(self, proxy_url: str) -> None:
        self.proxy_url = normalize_proxy_url(proxy_url)
        self.parsed = urlparse(self.proxy_url)
        self.scheme = (self.parsed.scheme or "").lower()
        self.host = self.parsed.hostname or ""
        self.port = int(self.parsed.port or 0)
        self.username = unquote(self.parsed.username) if self.parsed.username is not None else None
        self.password = unquote(self.parsed.password) if self.parsed.password is not None else None
        self.rdns = self.scheme == "socks5h"
        self._server: Optional[_ThreadingTCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.local_url = ""

    def start(self) -> "PlaywrightSocksBridge":
        if self.local_url:
            return self

        server = _ThreadingTCPServer(("127.0.0.1", 0), _BridgeHandler)
        server.bridge = self
        thread = threading.Thread(target=server.serve_forever, name="playwright-socks-bridge", daemon=True)
        thread.start()
        self._server = server
        self._thread = thread
        self.local_url = f"http://127.0.0.1:{server.server_address[1]}"
        logger.info(
            "[PROXY] started playwright socks bridge upstream=%s local=%s",
            sanitize_proxy_url(self.proxy_url),
            self.local_url,
        )
        return self

    def close(self) -> None:
        if self._server is None:
            return
        try:
            self._server.shutdown()
        except Exception:
            pass
        try:
            self._server.server_close()
        except Exception:
            pass
        self._server = None
        self._thread = None

    def _open_upstream(self, host: str, port: int) -> socks.socksocket:
        if self.scheme in ("http", "https"):
            return self._open_http_proxy_tunnel(host, port)

        sock = socks.socksocket()
        sock.set_proxy(
            socks.SOCKS5,
            addr=self.host,
            port=self.port,
            rdns=self.rdns,
            username=self.username,
            password=self.password,
        )
        sock.settimeout(30)
        sock.connect((host, port))
        sock.settimeout(None)
        return sock

    def _open_proxy_transport(self) -> socket.socket:
        raw_sock = socket.create_connection((self.host, self.port), timeout=30)
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            wrapped = ctx.wrap_socket(raw_sock, server_hostname=self.host)
            wrapped.settimeout(30)
            return wrapped
        raw_sock.settimeout(30)
        return raw_sock

    def _build_proxy_auth_header(self) -> bytes:
        if self.username is None and self.password is None:
            return b""
        creds = f"{self.username or ''}:{self.password or ''}".encode("utf-8")
        token = base64.b64encode(creds).decode("ascii")
        return f"Proxy-Authorization: Basic {token}\r\n".encode("latin-1")

    @staticmethod
    def _recv_proxy_response_headers(sock: socket.socket) -> bytes:
        data = bytearray()
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def _open_http_proxy_tunnel(self, host: str, port: int) -> socket.socket:
        sock = self._open_proxy_transport()
        auth = self._build_proxy_auth_header()
        target = f"{host}:{port}"
        req = (
            f"CONNECT {target} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
        ).encode("latin-1") + auth + b"\r\n"
        sock.sendall(req)
        resp = self._recv_proxy_response_headers(sock)
        line = resp.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        logger.info(
            "[PROXY] upstream CONNECT %s via=%s -> %s",
            target,
            sanitize_proxy_url(self.proxy_url),
            line,
        )
        if " 200 " not in f" {line} " and not line.startswith("HTTP/1.1 200") and not line.startswith("HTTP/1.0 200"):
            try:
                sock.close()
            except Exception:
                pass
            raise OSError(f"http proxy CONNECT failed: {line}")
        sock.settimeout(None)
        return sock

    def _tunnel(self, client_sock: socket.socket, upstream_sock: socket.socket) -> None:
        try:
            while True:
                readable, _, _ = select.select([client_sock, upstream_sock], [], [], 60)
                if not readable:
                    continue
                for src in readable:
                    dst = upstream_sock if src is client_sock else client_sock
                    try:
                        chunk = src.recv(65536)
                    except Exception:
                        return
                    if not chunk:
                        return
                    dst.sendall(chunk)
        finally:
            try:
                upstream_sock.close()
            except Exception:
                pass
            try:
                client_sock.close()
            except Exception:
                pass

    def handle_connect(self, client_sock: socket.socket, target: str) -> None:
        host, port = _host_port_from_connect_target(target)
        upstream_sock = self._open_upstream(host, port)
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._tunnel(client_sock, upstream_sock)

    def handle_http_request(
        self,
        *,
        client_sock: socket.socket,
        method: str,
        target: str,
        version: str,
        header_lines: list[bytes],
        body_reader,
    ) -> None:
        if self.scheme in ("http", "https"):
            self._handle_http_via_http_proxy(
                client_sock=client_sock,
                method=method,
                target=target,
                version=version,
                header_lines=header_lines,
                body_reader=body_reader,
            )
            return

        parsed = urlsplit(target)
        host = parsed.hostname or ""
        port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        if not host:
            raise ValueError(f"invalid proxy request target: {target}")

        upstream_sock = self._open_upstream(host, port)
        try:
            outgoing = [f"{method} {path} {version}\r\n".encode("latin-1")]
            has_host = False
            content_length = 0
            for raw in header_lines:
                line = raw.decode("latin-1")
                name, _, value = line.partition(":")
                lowered = name.strip().lower()
                if lowered == "proxy-connection":
                    continue
                if lowered == "host":
                    has_host = True
                if lowered == "content-length":
                    try:
                        content_length = int(value.strip())
                    except Exception:
                        content_length = 0
                if lowered == "connection":
                    raw = b"Connection: close\r\n"
                outgoing.append(raw)
            if not has_host:
                host_header = host if port in (80, 443) else f"{host}:{port}"
                outgoing.append(f"Host: {host_header}\r\n".encode("latin-1"))
            outgoing.append(b"Connection: close\r\n\r\n")
            upstream_sock.sendall(b"".join(outgoing))
            if content_length > 0:
                body = body_reader.read(content_length)
                if body:
                    upstream_sock.sendall(body)

            while True:
                chunk = upstream_sock.recv(65536)
                if not chunk:
                    break
                client_sock.sendall(chunk)
        finally:
            try:
                upstream_sock.close()
            except Exception:
                pass
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_http_via_http_proxy(
        self,
        *,
        client_sock: socket.socket,
        method: str,
        target: str,
        version: str,
        header_lines: list[bytes],
        body_reader,
    ) -> None:
        upstream_sock = self._open_proxy_transport()
        try:
            outgoing = [f"{method} {target} {version}\r\n".encode("latin-1")]
            content_length = 0
            has_host = False
            has_proxy_auth = False
            for raw in header_lines:
                line = raw.decode("latin-1")
                name, _, value = line.partition(":")
                lowered = name.strip().lower()
                if lowered == "proxy-connection":
                    continue
                if lowered == "proxy-authorization":
                    has_proxy_auth = True
                    continue
                if lowered == "host":
                    has_host = True
                if lowered == "content-length":
                    try:
                        content_length = int(value.strip())
                    except Exception:
                        content_length = 0
                if lowered == "connection":
                    raw = b"Connection: close\r\n"
                outgoing.append(raw)

            if not has_host:
                parsed = urlsplit(target)
                host = parsed.hostname or ""
                port = parsed.port
                host_header = f"{host}:{port}" if port else host
                outgoing.append(f"Host: {host_header}\r\n".encode("latin-1"))

            if not has_proxy_auth:
                auth = self._build_proxy_auth_header()
                if auth:
                    outgoing.append(auth)

            outgoing.append(b"Connection: close\r\n\r\n")
            upstream_sock.sendall(b"".join(outgoing))
            if content_length > 0:
                body = body_reader.read(content_length)
                if body:
                    upstream_sock.sendall(body)

            while True:
                chunk = upstream_sock.recv(65536)
                if not chunk:
                    break
                client_sock.sendall(chunk)
        finally:
            try:
                upstream_sock.close()
            except Exception:
                pass
            try:
                client_sock.close()
            except Exception:
                pass


def proxy_needs_playwright_bridge(proxy_url: str) -> bool:
    normalized = normalize_proxy_url(proxy_url)
    if not normalized:
        return False
    parsed = urlparse(normalized)
    return (parsed.scheme or "").lower() in ("http", "https", "socks5", "socks5h") and (
        parsed.username is not None or parsed.password is not None
    )


def ensure_playwright_bridge(proxy_url: str) -> PlaywrightSocksBridge:
    normalized = normalize_proxy_url(proxy_url)
    with _BRIDGES_LOCK:
        bridge = _BRIDGES.get(normalized)
        if bridge is None:
            bridge = PlaywrightSocksBridge(normalized).start()
            _BRIDGES[normalized] = bridge
        return bridge


def build_playwright_bridge_proxy_settings(proxy_url: str, no_proxy: str = "") -> dict:
    bridge = ensure_playwright_bridge(proxy_url)
    settings = {"server": bridge.local_url}
    bypass = format_no_proxy(no_proxy)
    if bypass != "none":
        settings["bypass"] = bypass
    return settings


def close_all_playwright_bridges() -> None:
    with _BRIDGES_LOCK:
        bridges = list(_BRIDGES.values())
        _BRIDGES.clear()
    for bridge in bridges:
        try:
            bridge.close()
        except Exception:
            pass


atexit.register(close_all_playwright_bridges)

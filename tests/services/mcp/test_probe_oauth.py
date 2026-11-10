"""probe_server must key the OAuth store by the server name (#2587).

The Test route used to drop the name from its path, the probe passed ``""`` on
to the OAuth store, and the store refused the empty key — so every OAuth
server's Test died with ``Unsafe MCP server name`` before it could report
anything. Here the real SDK handshake runs against a local mock authorization
server, so both halves of the fix are pinned end to end: the client
registration lands under the probed name, and an unauthorized probe reports
needs-auth instead of crashing.
"""

from __future__ import annotations

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

import pytest

from deeptutor.services.mcp import oauth
from deeptutor.services.mcp.config import MCPServerConfig
from deeptutor.services.mcp.manager import SHARED_OWNER, probe_server


@pytest.fixture(autouse=True)
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from deeptutor.multi_user import paths

    admin_root = (tmp_path / "data").resolve()
    monkeypatch.setattr(paths, "ADMIN_WORKSPACE_ROOT", admin_root)
    monkeypatch.setattr(paths, "USERS_ROOT", admin_root / "users")
    monkeypatch.setattr(paths, "SYSTEM_ROOT", admin_root / "system")
    monkeypatch.setattr(paths, "_path_services", {})
    admin_root.mkdir(parents=True, exist_ok=True)
    return admin_root


class _MockOAuthMcpHandler(BaseHTTPRequestHandler):
    """Just enough OAuth + MCP surface to reach the store's client write.

    Every request answers the way the real endpoints would: the resource
    challenges with RFC 9728 metadata, the authorization server publishes
    discovery plus dynamic client registration, and registration succeeds.
    """

    def log_message(self, fmt: str, *args: object) -> None:  # keep pytest quiet
        pass

    def _send(self, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        base = f"http://127.0.0.1:{self.server.server_address[1]}"  # type: ignore[attr-defined]
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            self._send(200, {"resource": f"{base}/mcp", "authorization_servers": [base]})
        elif self.path.startswith("/.well-known/oauth-authorization-server"):
            self._send(
                200,
                {
                    "issuer": base,
                    "authorization_endpoint": f"{base}/authorize",
                    "token_endpoint": f"{base}/token",
                    "registration_endpoint": f"{base}/register",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                },
            )
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        base = f"http://127.0.0.1:{self.server.server_address[1]}"  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length) or b"{}") if length else {}
        if self.path == "/register":
            # OAuthClientInformationFull needs client_id and the echoed redirect_uris.
            self._send(
                201,
                {
                    "client_id": "mock-client-id",
                    "client_secret": "mock-secret",
                    "redirect_uris": request.get("redirect_uris", []),
                    "client_name": request.get("client_name", ""),
                },
            )
        elif self.path == "/mcp":
            self._send(
                401,
                {"error": "unauthorized"},
                headers={
                    "WWW-Authenticate": (
                        f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/mcp"'
                    )
                },
            )
        else:
            self._send(404, {"error": "not_found"})


@pytest.fixture
def mock_oauth_url() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockOAuthMcpHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/mcp"
    finally:
        server.shutdown()
        server.server_close()


def test_an_oauth_probe_keys_its_store_by_the_server_name(mock_oauth_url: str) -> None:
    cfg = MCPServerConfig(url=mock_oauth_url, auth="oauth")

    result = asyncio.run(probe_server(cfg, owner=SHARED_OWNER, server_name="sentry"))

    assert "Unsafe MCP server name" not in result["error"]
    assert result["ok"] is False
    assert "AuthorizationRequired" in result["error"]
    assert "sentry" in result["error"]

    stored = json.loads(oauth._store_path(SHARED_OWNER, "sentry").read_text(encoding="utf-8"))
    assert stored["client"]["client_id"] == "mock-client-id"


def test_a_probe_without_a_name_keeps_the_old_refusal(mock_oauth_url: str) -> None:
    cfg = MCPServerConfig(url=mock_oauth_url, auth="oauth")

    result = asyncio.run(probe_server(cfg, owner=SHARED_OWNER))

    assert "Unsafe MCP server name for an OAuth store: ''" in result["error"]

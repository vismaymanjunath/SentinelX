"""Ingest-only ASGI front for the ngrok tunnel.

Listens on 127.0.0.1 (plain HTTP; ngrok terminates public TLS and forwards here). It:
  * allows ONLY the five collector ingest routes (exact method + path) - everything else is 404, WebSockets are refused;
  * trusts X-Forwarded-Proto / X-Forwarded-For ONLY when the TCP peer is loopback (i.e. the local ngrok agent), so
    the existing "ingest requires TLS" rule (request.url.scheme == "https") is satisfied for tunnelled HTTPS requests
    and still returns 426 for anything that did not arrive over HTTPS;
  * never changes authentication: Bearer-key checks stay in saas.main.collector_auth.
"""
import json

ALLOWED = {
    ("POST", "/api/ingest/v1/payload"),
    ("POST", "/api/ingest/v1/heartbeat"),
    ("POST", "/api/ingest/v1/command-result"),
    ("GET", "/api/ingest/v1/ledger"),
    ("POST", "/api/ingest/v1/register"),
}
LOOPBACK = {"127.0.0.1", "::1"}


class PublicIngest:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        t = scope["type"]
        if t == "lifespan":
            return await self.app(scope, receive, send)
        if t == "websocket":
            await receive()
            return await send({"type": "websocket.close", "code": 1008})
        if (scope["method"], scope["path"]) not in ALLOWED:
            body = json.dumps({"detail": "not found"}).encode()
            await send({"type": "http.response.start", "status": 404,
                        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
            return await send({"type": "http.response.body", "body": body})
        scope = dict(scope)
        peer = (scope.get("client") or ("", 0))[0]
        if peer in LOOPBACK:  # only the local ngrok agent may assert the original scheme / client address
            h = {k: v for k, v in scope["headers"]}
            if h.get(b"x-forwarded-proto", b"").decode().split(",")[0].strip().lower() == "https":
                scope["scheme"] = "https"
            xff = h.get(b"x-forwarded-for", b"").decode().split(",")[0].strip()
            if xff:
                scope["client"] = (xff, 0)
        await self.app(scope, receive, send)

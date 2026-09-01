"""
Vercel serverless entry point.

Vercel's Python runtime looks for an ASGI application named `app` in this file.
The package lives under src/, which is not on the import path in the deployed
bundle, so add it before importing.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

os.environ.setdefault("CYPHERSCOPE_DATA_DIR", os.path.join(ROOT, "data"))

from cypherscope.webapp import app as _app  # noqa: E402

_PREFIX = "/api/index"


async def app(scope, receive, send):
    """Strip the Vercel function prefix so FastAPI sees the original path.

    The catch-all rewrite in vercel.json points every request at /api/index,
    and that rewritten path is what reaches the ASGI app.
    """
    if scope["type"] in ("http", "websocket"):
        path = scope.get("path", "")
        if path == _PREFIX or path.startswith(_PREFIX + "/"):
            scope = dict(scope)
            scope["path"] = path[len(_PREFIX):] or "/"
            raw = scope.get("raw_path")
            if raw:
                scope["raw_path"] = raw.replace(_PREFIX.encode(), b"", 1) or b"/"
    await _app(scope, receive, send)


__all__ = ["app"]

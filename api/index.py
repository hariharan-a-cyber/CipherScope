"""
Vercel serverless entry point.

Vercel's Python runtime looks for an ASGI application named `app` in this file.
The package lives under src/, which is not on the import path in the deployed
bundle, so add it before importing.
"""
import os
import sys
from urllib.parse import parse_qsl, urlencode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

os.environ.setdefault("CYPHERSCOPE_DATA_DIR", os.path.join(ROOT, "data"))

from cypherscope.webapp import app as _app  # noqa: E402

_PREFIX = "/api/index"


def _restore_path(scope):
    """Recover the URL the browser asked for.

    The catch-all rewrite in vercel.json sends every request to /api/index,
    and only that rewritten path reaches the ASGI app -- so the real path is
    smuggled through the __vpath query parameter, which rewrites do preserve.
    """
    params = parse_qsl(scope.get("query_string", b"").decode(), keep_blank_values=True)
    path = None
    rest = []
    for key, value in params:
        if key == "__vpath":
            path = value or "/"
        else:
            rest.append((key, value))

    if path is None:
        # No marker (local uvicorn, or Vercel forwarding the path directly).
        current = scope.get("path", "")
        if current == _PREFIX or current.startswith(_PREFIX + "/"):
            path = current[len(_PREFIX):] or "/"
        else:
            return scope

    scope = dict(scope)
    scope["path"] = path
    scope["raw_path"] = path.encode()
    scope["query_string"] = urlencode(rest).encode()
    return scope


async def app(scope, receive, send):
    if scope["type"] in ("http", "websocket"):
        scope = _restore_path(scope)
    await _app(scope, receive, send)


__all__ = ["app"]

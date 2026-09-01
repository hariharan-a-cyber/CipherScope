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

from cypherscope.webapp import app  # noqa: E402

__all__ = ["app"]

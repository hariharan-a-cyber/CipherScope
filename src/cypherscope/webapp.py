"""
Minimal web dashboard. Upload a PCAP (or pick a bundled sample) and see the
email TLS posture. Start it with:

    python -m cypherscope serve
"""
import os
import tempfile

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .analyze import analyze_pcap
from .report import build_report

PKG_DIR = os.path.dirname(os.path.abspath(__file__))

# Upload cap. Serverless platforms (Vercel included) reject request bodies over
# about 4.5 MB before the app ever sees them, so refuse early with a clear message
# instead of letting the platform return an opaque error.
MAX_UPLOAD_BYTES = 4 * 1024 * 1024


def _data_dir():
    """Locate the bundled sample captures.

    The layout differs between a source checkout and a deployed bundle, so try
    the known candidates in order rather than assuming a fixed relative path.
    """
    candidates = [
        os.environ.get("CYPHERSCOPE_DATA_DIR"),
        os.path.join(PKG_DIR, "data"),
        os.path.normpath(os.path.join(PKG_DIR, "..", "..", "data")),
        os.path.join(os.getcwd(), "data"),
    ]
    for path in candidates:
        if path and os.path.isdir(path):
            return path
    return ""


DATA_DIR = _data_dir()

app = FastAPI(title="CypherScope")
app.mount("/static", StaticFiles(directory=os.path.join(PKG_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(PKG_DIR, "templates"))


def _samples():
    if not DATA_DIR or not os.path.isdir(DATA_DIR):
        return []
    return sorted(f for f in os.listdir(DATA_DIR) if f.endswith(".pcap"))


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"samples": _samples()})


@app.get("/sample/{name}", response_class=HTMLResponse)
def scan_sample(request: Request, name: str):
    safe = os.path.basename(name)
    path = os.path.join(DATA_DIR, safe)
    if not os.path.exists(path):
        return templates.TemplateResponse(request, "index.html", {"samples": _samples(), "error": f"sample not found: {safe}"})
    report = build_report(safe, analyze_pcap(path))
    return templates.TemplateResponse(request, "report.html", {"report": report})


@app.post("/scan", response_class=HTMLResponse)
async def scan_upload(request: Request, pcap: UploadFile = File(...)):
    data = await pcap.read()
    if len(data) > MAX_UPLOAD_BYTES:
        mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        return templates.TemplateResponse(request, "index.html", {
            "samples": _samples(),
            "error": f"capture is too large for the hosted demo (limit {mb} MB). Run CypherScope locally for full size captures.",
        })
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        report = build_report(pcap.filename or "upload.pcap", analyze_pcap(tmp_path))
    except Exception as exc:
        return templates.TemplateResponse(request, "index.html", {"samples": _samples(), "error": f"could not analyse this file: {exc}"})
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            # On Windows scapy can leave a failed parse's file handle open
            # until GC runs; a leftover temp file is harmless, a 500 is not.
            pass
    return templates.TemplateResponse(request, "report.html", {"report": report})

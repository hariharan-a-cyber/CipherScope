"""
Minimal web dashboard. Upload a PCAP (or pick a bundled sample) and see the
email TLS posture. Start it with:

    python -m securemailscope serve
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
ROOT_DIR = os.path.normpath(os.path.join(PKG_DIR, "..", ".."))
DATA_DIR = os.path.join(ROOT_DIR, "data")

app = FastAPI(title="SecureMailScope")
app.mount("/static", StaticFiles(directory=os.path.join(PKG_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(PKG_DIR, "templates"))


def _samples():
    if not os.path.isdir(DATA_DIR):
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
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        report = build_report(pcap.filename or "upload.pcap", analyze_pcap(tmp_path))
    except Exception as exc:
        return templates.TemplateResponse(request, "index.html", {"samples": _samples(), "error": f"could not analyse this file: {exc}"})
    finally:
        os.unlink(tmp_path)
    return templates.TemplateResponse(request, "report.html", {"report": report})

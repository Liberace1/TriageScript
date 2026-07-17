"""Local web UI for TriageScript.

Offline-first and zero-execution: binds to 127.0.0.1 only, makes no network
calls, and only invokes the existing read-only analyzer. Uses the Python
standard library exclusively (no Flask / no added dependencies).

Run:
    python -m triagescript.web            # http://127.0.0.1:8742
    python -m triagescript.web --port 9000
"""
from __future__ import annotations

import argparse
import html
import os
import tempfile
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from triagescript.analyzer import analyze_vba_file
from triagescript.attack_map import TECHNIQUE_NAMES
from triagescript.analyzers.vba import SUPPORTED_EXTENSIONS

MAX_UPLOAD = 25 * 1024 * 1024  # 25 MB cap

# bundled demo document, located next to the project (TriageScript/sample.docm)
SAMPLE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "sample.docm"))

VERDICT_STYLE = {
    "CRITICAL": ("#ff4d4f", "Do not open. Escalate."),
    "HIGH":     ("#ff922b", "Treat as malicious."),
    "MEDIUM":   ("#fcc419", "Suspicious - investigate."),
    "LOW":      ("#51cf66", "No known-pattern indicators - not proof of safety."),
}

PAGE_CSS = """
* { box-sizing: border-box; }
body { margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:#0d1117; color:#e6edf3; }
a { color:#58a6ff; }
.wrap { max-width:920px; margin:0 auto; padding:32px 20px 64px; }
.header { display:flex; align-items:center; gap:14px; margin-bottom:4px; }
.logo { width:44px;height:44px;border-radius:10px;background:linear-gradient(135deg,#1f6feb,#8957e5);
        display:flex;align-items:center;justify-content:center;font-size:17px;font-weight:800;color:#fff;letter-spacing:.5px; }
h1 { font-size:26px; margin:0; letter-spacing:.3px; }
.tagline { color:#8b949e; font-size:14px; margin:2px 0 18px; }
.badges { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:26px; }
.badge { font-size:12px; padding:4px 10px; border-radius:20px; background:#161b22; border:1px solid #30363d; color:#9fb0c0; }
.badge b { color:#3fb950; }
.card { background:#161b22; border:1px solid #30363d; border-radius:14px; padding:22px; margin-bottom:18px; }
.drop { border:2px dashed #30363d; border-radius:14px; padding:44px 20px; text-align:center;
        transition:.15s; cursor:pointer; background:#0f141b; }
.drop.hover { border-color:#58a6ff; background:#111b2b; }
.drop h3 { margin:0 0 6px; font-weight:600; }
.drop p { margin:0; color:#8b949e; font-size:13px; }
.actions { display:flex; gap:12px; justify-content:center; align-items:center; margin-top:18px; }
.btn { display:inline-block; background:#238636; color:#fff; border:0; padding:10px 22px;
       border-radius:8px; font-size:14px; font-weight:600; cursor:pointer; text-decoration:none; }
.btn:hover { background:#2ea043; }
.btn-alt { background:transparent; border:1px solid #30363d; color:#c9d1d9; }
.btn-alt:hover { background:#161b22; border-color:#58a6ff; }
.exts { margin-top:14px; font-size:12px; color:#6e7681; }
.verdict { display:flex; align-items:center; gap:18px; }
.vscore { font-size:44px; font-weight:800; line-height:1; }
.vlabel { font-size:22px; font-weight:800; letter-spacing:.5px; }
.vsub { color:#8b949e; font-size:13px; margin-top:3px; }
.bar { height:12px; border-radius:8px; background:#0d1117; border:1px solid #30363d; overflow:hidden; margin:16px 0 4px; }
.bar > span { display:block; height:100%; }
.scale { display:flex; justify-content:space-between; font-size:11px; color:#6e7681; }
.sect-title { font-size:12px; text-transform:uppercase; letter-spacing:1px; color:#8b949e; margin:0 0 10px; }
.reason { display:flex; gap:10px; padding:10px 0; border-top:1px solid #21262d; }
.reason:first-of-type { border-top:0; }
.reason .plus { color:#f85149; font-weight:700; }
.reason .desc { flex:1; }
.reason .ind { display:block; color:#6e7681; font-size:12px; font-family:Consolas,monospace; margin-top:3px; word-break:break-all; }
.tid { font-size:11px; padding:2px 8px; border-radius:6px; background:#1f2937; color:#9fb0c0; white-space:nowrap; height:fit-content; }
.sfilter { width:100%; padding:8px 10px; border-radius:8px; border:1px solid #30363d; background:#0d1117;
           color:#e6edf3; font-family:Consolas,monospace; font-size:13px; margin-bottom:10px; }
.sfilter:focus { outline:none; border-color:#58a6ff; }
.slist { max-height:280px; overflow:auto; border:1px solid #21262d; border-radius:10px; }
.sitem { padding:6px 10px; border-top:1px solid #21262d; font-family:Consolas,monospace;
         font-size:12.5px; word-break:break-all; }
.sitem:first-child { border-top:0; }
.shint { color:#6e7681; font-size:12px; margin:8px 0 0; }
table.ioc { width:100%; border-collapse:collapse; font-size:14px; }
table.ioc td { padding:8px 10px; border-top:1px solid #21262d; font-family:Consolas,monospace; }
table.ioc td.k { color:#8b949e; width:60px; text-transform:uppercase; font-size:11px; letter-spacing:1px; }
.chips { display:flex; gap:8px; flex-wrap:wrap; }
.chip { font-size:12px; padding:6px 11px; border-radius:8px; background:#1c2333; border:1px solid #30363d; }
.chip b { color:#58a6ff; }
details { margin-top:6px; }
summary { cursor:pointer; color:#8b949e; font-size:13px; }
pre { background:#0d1117; border:1px solid #21262d; border-radius:10px; padding:14px; overflow:auto;
      font-family:Consolas,monospace; font-size:12.5px; color:#c9d1d9; max-height:320px; }
.err { border-color:#4d2226; background:#20141550; }
.err h3 { color:#ff7b72; margin:0 0 6px; }
.back { display:inline-block; margin-top:20px; font-size:14px; }
.footnote { color:#6e7681; font-size:12px; margin-top:26px; text-align:center; }
"""


def _printable(text: str) -> str:
    """Make a recovered string render-safe (decoded bytes can contain control chars)."""
    return "".join(ch if ch.isprintable() else "." for ch in text)


def _page(body: str) -> bytes:
    doc = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>TriageScript</title><style>" + PAGE_CSS + "</style></head><body><div class='wrap'>"
        "<div class='header'><div class='logo'>TS</div>"
        "<div><h1>TriageScript</h1></div></div>"
        "<div class='tagline'>Local VBA macro triage &middot; zero-execution static analysis</div>"
        "<div class='badges'>"
        "<span class='badge'><b>Offline</b> &middot; no network calls</span>"
        "<span class='badge'><b>Zero-execution</b> &middot; read-only parse</span>"
        "<span class='badge'><b>Local only</b> &middot; 127.0.0.1</span>"
        "</div>" + body +
        "<div class='footnote'>TriageScript &middot; CSC-842 &middot; analyzes and explains, never runs the macro<br>"
        "Detection is pattern-based; a LOW score is not proof of safety and novel obfuscation may go unflagged.</div>"
        "</div></body></html>"
    )
    return doc.encode("utf-8")


def render_index(message: str = "") -> bytes:
    exts = ", ".join(sorted(SUPPORTED_EXTENSIONS))
    msg = f"<div class='card err'><h3>Could not analyze</h3><p>{html.escape(message)}</p></div>" if message else ""
    body = (
        msg +
        "<form class='card' method='POST' action='/analyze' enctype='multipart/form-data' id='f'>"
        "<div class='drop' id='drop'>"
        "<h3>Drop a suspicious Office document here</h3>"
        "<p>or click to browse &middot; .docm, .xlsm, .doc, .xls, .pptm &hellip;</p>"
        "<input id='file' name='file' type='file' style='display:none' "
        "accept='.doc,.docm,.dotm,.xls,.xlsm,.xltm,.xlam,.ppt,.pptm,.potm,.ppam' required>"
        f"<div class='exts'>Supported: {html.escape(exts)}</div>"
        "</div>"
        "<div class='actions'>"
        "<button class='btn' type='submit'>Analyze macro</button>"
        "<a class='btn btn-alt' href='/sample'>Try sample.docm</a>"
        "</div>"
        "</form>"
        "<script>"
        "const d=document.getElementById('drop'),i=document.getElementById('file'),f=document.getElementById('f');"
        "d.addEventListener('click',()=>i.click());"
        "['dragenter','dragover'].forEach(e=>d.addEventListener(e,ev=>{ev.preventDefault();d.classList.add('hover')}));"
        "['dragleave','drop'].forEach(e=>d.addEventListener(e,ev=>{ev.preventDefault();d.classList.remove('hover')}));"
        "d.addEventListener('drop',ev=>{ev.preventDefault();if(ev.dataTransfer.files.length){i.files=ev.dataTransfer.files;f.submit();}});"
        "i.addEventListener('change',()=>{if(i.files.length)f.submit();});"
        "</script>"
    )
    return _page(body)


def render_result(result, filename: str) -> bytes:
    if not result.success:
        return render_index(result.message)

    color, sub = VERDICT_STYLE.get(result.verdict, ("#8b949e", ""))
    pct = int(result.score * 100 / (result.max_score or 100))

    reasons = ""
    for hit in (result.contributions or []):
        ind = f"<span class='ind'>{html.escape(hit.indicator)}</span>" if hit.indicator else ""
        reasons += (
            "<div class='reason'><span class='plus'>[+]</span>"
            f"<span class='desc'>{html.escape(hit.description)}{ind}</span>"
            f"<span class='tid'>{html.escape(hit.technique_id)}</span></div>"
        )
    if not reasons:
        reasons = "<div class='reason'><span class='desc'>No suspicious indicators detected.</span></div>"

    ioc_rows = ""
    for url in (result.iocs or {}).get("urls", []):
        ioc_rows += f"<tr><td class='k'>url</td><td>{html.escape(url)}</td></tr>"
    for ip in (result.iocs or {}).get("ips", []):
        ioc_rows += f"<tr><td class='k'>ip</td><td>{html.escape(ip)}</td></tr>"
    ioc_card = (
        "<div class='card'><p class='sect-title'>Recovered IOCs</p>"
        f"<table class='ioc'>{ioc_rows}</table></div>" if ioc_rows else ""
    )

    strings_card = ""
    recovered = result.recovered or []
    if recovered:
        items = "".join(
            f"<div class='sitem'>{html.escape(_printable(text))}</div>" for text in recovered
        )
        strings_card = (
            "<div class='card'><p class='sect-title'>Recovered strings "
            f"({len(recovered)})</p>"
            "<input class='sfilter' id='sfilter' type='text' placeholder='Filter strings...'>"
            f"<div class='slist' id='slist'>{items}</div>"
            "<p class='shint'>Every string literal and decoded value recovered from the macro - "
            "shown even when it did not affect the score, so you can judge it yourself.</p>"
            "<script>"
            "const sf=document.getElementById('sfilter'),sl=document.getElementById('slist');"
            "sf.addEventListener('input',()=>{const q=sf.value.toLowerCase();"
            "for(const el of sl.children){el.style.display=el.textContent.toLowerCase().includes(q)?'':'none';}});"
            "</script></div>"
        )

    chips = ""
    for tid in (result.techniques or []):
        name = TECHNIQUE_NAMES.get(tid, "Unknown technique")
        chips += f"<span class='chip'><b>{html.escape(tid)}</b> &middot; {html.escape(name)}</span>"
    attack_card = (
        "<div class='card'><p class='sect-title'>MITRE ATT&amp;CK</p>"
        f"<div class='chips'>{chips}</div></div>" if chips else ""
    )

    source = "\n\n".join(m.code for m in (result.macros or []))
    source_card = (
        "<div class='card'><p class='sect-title'>Extracted macro source</p>"
        "<details><summary>Show decompiled VBA</summary>"
        f"<pre>{html.escape(source)}</pre></details></div>" if source.strip() else ""
    )

    body = (
        "<div class='card'>"
        "<div class='verdict'>"
        f"<div class='vscore' style='color:{color}'>{result.score}</div>"
        f"<div><div class='vlabel' style='color:{color}'>{html.escape(result.verdict)}</div>"
        f"<div class='vsub'>{html.escape(sub)} &middot; {html.escape(os.path.basename(filename))} (VBA)</div></div></div>"
        f"<div class='bar'><span style='width:{pct}%;background:{color}'></span></div>"
        f"<div class='scale'><span>0</span><span>score {result.score}/{result.max_score}</span><span>100</span></div>"
        "</div>"
        "<div class='card'><p class='sect-title'>Why</p>" + reasons + "</div>"
        + ioc_card + strings_card + attack_card + source_card +
        "<a class='back' href='/'>&larr; Analyze another file</a>"
    )
    return _page(body)


def _parse_upload(body: bytes, content_type: str):
    """Minimal multipart/form-data parser -> (filename, file_bytes) or (None, None)."""
    marker = "boundary="
    if marker not in content_type:
        return None, None
    boundary = content_type.split(marker, 1)[1].strip().strip('"')
    delim = ("--" + boundary).encode()
    for part in body.split(delim):
        head_end = part.find(b"\r\n\r\n")
        if head_end == -1:
            continue
        headers = part[:head_end].decode("latin-1", "replace")
        if 'name="file"' not in headers or "filename=" not in headers:
            continue
        fname = headers.split("filename=", 1)[1].split("\r\n", 1)[0].strip().strip('"')
        if not fname:
            continue
        data = part[head_end + 4:]
        if data.endswith(b"\r\n"):
            data = data[:-2]
        return os.path.basename(fname), data
    return None, None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the console quiet
        pass

    def _send(self, payload: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(render_index())
        elif self.path == "/sample":
            if os.path.exists(SAMPLE_PATH):
                self._send(render_result(analyze_vba_file(SAMPLE_PATH), "sample.docm"))
            else:
                self._send(render_index("Bundled sample.docm was not found next to the tool."))
        elif self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        else:
            self._send(render_index(), 404)

    def do_POST(self):
        if self.path != "/analyze":
            self._send(render_index(), 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_UPLOAD:
            self._send(render_index("File missing or exceeds the 25 MB limit."))
            return
        body = self.rfile.read(length)
        fname, data = _parse_upload(body, self.headers.get("Content-Type", ""))
        if not fname or data is None:
            self._send(render_index("No file was received. Please choose a document."))
            return

        suffix = os.path.splitext(fname)[1] or ".bin"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        try:
            tmp.write(data)
            tmp.close()
            result = analyze_vba_file(tmp.name)
            self._send(render_result(result, fname))
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="TriageScript local web UI (offline, zero-execution).")
    parser.add_argument("--port", type=int, default=8742)
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default localhost only)")
    parser.add_argument("--no-browser", action="store_true", help="do not auto-open a browser")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"TriageScript UI  ->  {url}   (Ctrl+C to stop)")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

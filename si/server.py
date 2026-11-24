"""Loopback-only stdlib web wrapper around the existing CLI pipeline."""
from __future__ import annotations

import contextlib
import html
import io
import tempfile
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from .cli import investigate
from .gallery import GALLERY_BANNER, _case_inputs

MAX_REQUEST_BYTES = 512 * 1024 * 1024


def _cases(cases_dir: Path):
    available = {}
    for name, _truth, elf, core in _case_inputs(cases_dir):
        if elf is not None and core is not None and elf.is_file() and core.is_file():
            available[name] = (elf, core)
    return available


def _page(cases, report=None, error=None):
    options = "".join(f'<option value="{html.escape(name, quote=True)}">{html.escape(name)}</option>' for name in cases)
    result = ""
    if report is not None:
        result = '<h2>Investigation report</h2><iframe title="Investigation report" srcdoc="' + html.escape(report, quote=True) + '"></iframe>'
    if error:
        result = '<p class="error">' + html.escape(error) + '</p>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Software Investigator</title>
<style>body{{margin:0;background:#f3f5f7;color:#14212b;font:20px/1.5 system-ui,Segoe UI,sans-serif}}header{{background:#102b3f;color:white;padding:1.2rem 2rem}}h1{{font-size:2rem;margin:0}}.banner{{background:#ffefbd;color:#362800;padding:.8rem 1rem;border-left:7px solid #a56b00;font-weight:700}}main{{max-width:1100px;margin:1.5rem auto;padding:0 1rem}}form{{background:#fff;border:2px solid #687d8a;border-radius:8px;padding:1.2rem;margin:1rem 0}}label{{display:block;font-weight:700;margin:.8rem 0 .25rem}}select,input,button{{font:inherit;padding:.55rem;max-width:100%}}button{{margin-top:1rem;background:#124d72;color:white;border:0;border-radius:6px;padding:.7rem 1.2rem;font-weight:700;cursor:pointer}}.error{{background:#fee;color:#700;padding:1rem}}iframe{{width:100%;height:75vh;min-height:600px;border:2px solid #687d8a;background:white}}.hint{{font-size:.9rem}}</style></head><body>
<header><h1>Software Investigator</h1><p class="banner">{GALLERY_BANNER}</p></header><main>
<p>Select a generated case or upload an ELF and core. Uploaded files are parsed as data and are never executed.</p>
<form method="post" action="/investigate" enctype="multipart/form-data"><label for="case">Committed case</label><select id="case" name="case"><option value="">Choose a case</option>{options}</select>
<p class="hint">Choose a case OR provide both files below.</p><label for="elf">ELF file</label><input id="elf" name="elf" type="file"><label for="core">Core file</label><input id="core" name="core" type="file"><br><button type="submit">Investigate</button></form>{result}</main></body></html>'''


def make_handler(cases_dir: Path):
    cases_dir = Path(cases_dir)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ("/", "/index.html"):
                self.send_error(404)
                return
            self._send(_page(_cases(cases_dir)))

        def do_POST(self):
            if self.path != "/investigate":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_REQUEST_BYTES:
                    self.send_error(413 if length > MAX_REQUEST_BYTES else 400, "Invalid upload size")
                    return
                body = self.rfile.read(length)
                content_type = self.headers.get("Content-Type", "")
                selected = None
                uploaded = {}
                if content_type.startswith("multipart/form-data"):
                    envelope = (f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n").encode("ascii") + body
                    message = BytesParser(policy=default).parsebytes(envelope)
                    for part in message.iter_parts():
                        field = part.get_param("name", header="content-disposition")
                        payload = part.get_payload(decode=True) or b""
                        filename = part.get_filename()
                        if field == "case" and not filename:
                            selected = payload.decode("utf-8", errors="replace")
                        elif field in ("elf", "core") and filename and payload:
                            uploaded[field] = payload
                elif content_type.startswith("application/x-www-form-urlencoded"):
                    fields = parse_qs(body.decode("utf-8", errors="replace"))
                    selected = fields.get("case", [""])[0]
                else:
                    self.send_error(415, "Use the investigation form")
                    return

                with tempfile.TemporaryDirectory(prefix="si-serve-") as temp_name:
                    temp = Path(temp_name)
                    if uploaded:
                        if set(uploaded) != {"elf", "core"}:
                            raise ValueError("Upload both an ELF and a core file.")
                        # Store under fixed generated names; never trust client path/filename.
                        elf = temp / "upload.elf"
                        core = temp / "upload.core"
                        elf.write_bytes(uploaded["elf"])
                        core.write_bytes(uploaded["core"])
                        case_name = "Uploaded artifacts"
                    else:
                        cases = _cases(cases_dir)
                        if not selected or selected not in cases:
                            raise ValueError("Select an available case or upload both files.")
                        elf, core = cases[selected]
                        case_name = selected
                    with contextlib.redirect_stdout(io.StringIO()):
                        investigate(elf, core, temp / "report", case_name)
                    report_html = (temp / "report" / "report.html").read_text(encoding="utf-8")
                self._send(_page(_cases(cases_dir), report=report_html))
            except Exception as exc:
                self._send(_page(_cases(cases_dir), error=f"Investigation could not be completed: {exc}"), status=400)

        def _send(self, body: str, status=200):
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            # Keep standard request logging, but avoid logging submitted data.
            super().log_message(format, *args)

    return Handler


def serve(host="127.0.0.1", port=8000, cases_dir="cases"):
    if host != "127.0.0.1":
        raise ValueError("The demo server must bind to 127.0.0.1 only.")
    server = HTTPServer((host, port), make_handler(Path(cases_dir)))
    print(f"Software Investigator serving on http://{host}:{port}/ (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

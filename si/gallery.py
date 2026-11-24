"""Build an offline, self-contained case gallery from available case artifacts."""
from __future__ import annotations

import contextlib
import html
import io
import json
from pathlib import Path

from .cli import investigate

GALLERY_BANNER = "MVP-0 technical proof on controlled cases. Not a benchmark. Not a finished product."


def _case_inputs(cases_dir: Path):
    """Yield each source case's preferred executable/core, including missing pairs."""
    for truth_path in sorted(cases_dir.glob("*/ground_truth.json")):
        case_dir = truth_path.parent
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        elf_paths = sorted((case_dir / "build").glob("*.elf"))
        paired = [(p, p.with_suffix(".core")) for p in elf_paths if p.with_suffix(".core").is_file()]
        if paired:
            # Keep the gallery compact: represent each case once, preferring debug.
            elf, core = next((pair for pair in paired if pair[0].stem == "debug"), paired[0])
            yield case_dir.name, truth, elf, core
        else:
            elf = next((p for p in elf_paths if p.stem == "debug"), elf_paths[0] if elf_paths else None)
            yield case_dir.name, truth, elf, (elf.with_suffix(".core") if elf else None)


def _summary(report: dict):
    results = report.get("verification", {}).get("hypotheses", [])
    if not results:
        return "Not available", "UNDETERMINED"
    chosen = next((r for r in results if r.get("status") == "SUPPORTED"), None)
    if chosen is None:
        chosen = next((r for r in results if r.get("status") == "UNDETERMINED"), results[0])
    return chosen["hypothesis"]["id"], chosen["status"]


def _missing_report(case_name: str, elf: Path | None, core: Path | None) -> str:
    expected = [str(p) for p in (elf, core) if p is not None]
    missing = [p for p in expected if not Path(p).is_file()]
    details = "Required case artifacts are missing: " + (", ".join(missing) if missing else "ELF and core files.")
    return ("<!doctype html><meta charset='utf-8'><title>Case artifacts unavailable</title>"
            "<style>body{font:20px system-ui;color:#18212b;margin:2rem;line-height:1.5}h1{font-size:2rem}</style>"
            f"<h1>{html.escape(case_name)}</h1><p>{html.escape(details)}</p>")


def build_gallery(out_dir="dist", cases_dir="cases"):
    out = Path(out_dir)
    cases = Path(cases_dir)
    out.mkdir(parents=True, exist_ok=True)
    entries = []
    report_dir = out / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    for case_name, truth, elf, core in _case_inputs(cases):
        slug = case_name
        case_report_dir = report_dir / slug
        if elf is None or core is None or not elf.is_file() or not core.is_file():
            report_html = _missing_report(case_name, elf, core)
            top, status, matched = "Not available", "UNDETERMINED", False
        else:
            # Run the exact CLI investigation pipeline, suppressing its terminal summary.
            with contextlib.redirect_stdout(io.StringIO()):
                verification = investigate(elf, core, case_report_dir, case_name)
            report_html = (case_report_dir / "report.html").read_text(encoding="utf-8")
            top, status = _summary({"verification": verification})
            matched = top == truth.get("expected_top_hypothesis")
        case_report_dir.mkdir(parents=True, exist_ok=True)
        report_path = case_report_dir / "report.html"
        report_path.write_text(report_html, encoding="utf-8")
        entries.append({"name": case_name, "top": top, "status": status,
                        "expected": truth.get("expected_top_hypothesis"), "match": matched,
                        "report": report_path.relative_to(out).as_posix(), "report_html": report_html})

    # Escape '<' so case data cannot terminate the inline script element.
    data = json.dumps(entries, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    page = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Software Investigator — Case Gallery</title><style>
:root{{color-scheme:light}}*{{box-sizing:border-box}}body{{margin:0;background:#f3f5f7;color:#14212b;font:20px/1.45 system-ui,Segoe UI,sans-serif}}
header{{padding:1.2rem 1.7rem;background:#102b3f;color:#fff}}h1{{margin:.1rem 0;font-size:2rem}}.banner{{margin:.8rem 0 0;padding:.65rem 1rem;background:#ffefbd;color:#362800;border-left:7px solid #a56b00;font-weight:700}}
.layout{{display:grid;grid-template-columns:minmax(280px,35vw) 1fr;min-height:calc(100vh - 135px)}}aside{{padding:1rem;background:#e5ebef;border-right:2px solid #aab8c1;overflow:auto}}main{{padding:1rem;min-width:0}}
.case{{width:100%;display:block;text-align:left;padding:1rem;margin:0 0 .7rem;border:2px solid #687d8a;border-radius:8px;background:#fff;color:#14212b;font:inherit;cursor:pointer}}.case[aria-current=true]{{outline:4px solid #1769aa;border-color:#1769aa}}
.case strong{{display:block;font-size:1.15rem;margin-bottom:.35rem}}.meta{{display:block;font-size:.9rem;overflow-wrap:anywhere}}.status{{font-weight:800}}.match{{font-weight:700}}iframe{{display:block;width:100%;height:calc(100vh - 185px);min-height:650px;border:2px solid #687d8a;background:white}}
@media(max-width:850px){{.layout{{grid-template-columns:1fr}}aside{{border-right:0;border-bottom:2px solid #aab8c1}}iframe{{height:75vh;min-height:500px}}}}
</style></head><body><header><h1>Software Investigator</h1><p class="banner">{GALLERY_BANNER}</p></header>
<div class="layout"><aside id="cases" aria-label="Cases"></aside><main><iframe id="report" title="Selected case report"></iframe></main></div>
<script>const cases={data};const list=document.getElementById('cases');const frame=document.getElementById('report');
function selectCase(index){{document.querySelectorAll('.case').forEach((b,i)=>b.setAttribute('aria-current',i===index?'true':'false'));frame.srcdoc=cases[index].report_html;}}
cases.forEach((c,i)=>{{const b=document.createElement('button');b.className='case';b.type='button';b.innerHTML='<strong></strong><span class="meta"></span><span class="meta"></span><span class="meta"></span>';
b.querySelector('strong').textContent=c.name;b.querySelectorAll('.meta')[0].textContent='Top hypothesis: '+c.top;b.querySelectorAll('.meta')[1].textContent='Status: '+c.status;b.querySelector('.meta:last-child').textContent='Ground truth: '+(c.expected||'unavailable')+' · Match: '+(c.match?'YES':'NO');b.addEventListener('click',()=>selectCase(i));list.appendChild(b);}});
if(cases.length)selectCase(0);else{{list.textContent='No case directories with ground_truth.json were found.';}}
</script></body></html>'''
    index = out / "index.html"
    index.write_text(page, encoding="utf-8")
    return index

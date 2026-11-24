import html,json
BANNER='MVP-0 technical proof on a small set of controlled cases. Not a benchmark. Not a finished product.'
def write(out,ibr,abr,verification,metadata=None):
    from pathlib import Path
    p=Path(out);p.mkdir(parents=True,exist_ok=True)
    (p/'ibr.json').write_text(json.dumps(ibr.json(),indent=2,default=str))
    (p/'abr.json').write_text(json.dumps(abr.json(),indent=2))
    report={'banner':BANNER,'metadata':metadata or {},'evidence':[e.__dict__ for e in ibr.evidence],'analysis':abr.json(),'verification':verification,'gaps':abr.gaps}
    (p/'report.json').write_text(json.dumps(report,indent=2))
    rows=''.join(f"<tr><td>{html.escape(e.id)}</td><td>{html.escape(e.kind)}</td><td><pre>{html.escape(str(e.value))}</pre></td><td>{html.escape(e.provenance)}</td></tr>" for e in ibr.evidence)
    hyps=''.join(f"<section><h2>{html.escape(x['hypothesis']['title'])} — {html.escape(x['status'])}</h2><p>{html.escape(x['hypothesis']['explanation'])}</p><ul>"+''.join(f"<li>{html.escape(r['statement'])}: <b>{r['status']}</b></li>" for r in x['predictions'])+'</ul></section>' for x in verification['hypotheses'])
    doc=f'''<!doctype html><meta charset="utf-8"><title>Software Investigator report</title><style>body{{font:20px system-ui;background:#fff;color:#18212b;margin:3rem;line-height:1.5}}h1{{font-size:2.5rem}}.banner{{padding:1rem;background:#fff2cc;border-left:8px solid #8a5a00}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #9aa4ad;padding:.5rem;text-align:left;vertical-align:top}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}section{{padding:1rem;border:1px solid #aab4bd;margin:1rem 0}}</style><h1>Software Investigator</h1><p class="banner">{BANNER}</p><p>Case: {html.escape(str((metadata or {}).get('case','unspecified')))}</p><h2>Faulting instruction</h2><pre>{html.escape(str(abr.instruction))}\nEffective address: {html.escape(str(abr.effective_address))}</pre><h2>Hypotheses</h2>{hyps}<h2>Contradictions</h2><pre>{html.escape(str(verification['contradictions']))}</pre><h2>Gaps and unknowns</h2><pre>{html.escape(str(abr.gaps))}</pre><h2>Next experiment</h2><pre>{html.escape(str(verification['next_experiment']))}</pre><h2>Evidence</h2><table><thead><tr><th>ID</th><th>Kind</th><th>Value</th><th>Provenance</th></tr></thead><tbody>{rows}</tbody></table>'''
    (p/'report.html').write_text(doc)
    return report

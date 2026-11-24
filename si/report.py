import html
import json
from pathlib import Path

BANNER = 'MVP-0 technical proof on a small set of controlled cases. Not a benchmark. Not a finished product.'


def write(out, ibr, abr, verification, metadata=None):
    p = Path(out)
    p.mkdir(parents=True, exist_ok=True)
    (p / 'ibr.json').write_text(json.dumps(ibr.json(), indent=2, default=str), encoding='utf-8')
    (p / 'abr.json').write_text(json.dumps(abr.json(), indent=2), encoding='utf-8')
    report = {
        'banner': BANNER,
        'metadata': metadata or {},
        'evidence': [e.__dict__ for e in ibr.evidence],
        'analysis': abr.json(),
        'verification': verification,
        'gaps': abr.gaps,
    }
    (p / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')

    rows = ''.join(
        '<tr><td>{}</td><td>{}</td><td><pre>{}</pre></td><td>{}</td></tr>'.format(
            html.escape(e.id), html.escape(e.kind), html.escape(str(e.value)), html.escape(e.provenance))
        for e in ibr.evidence
    )
    sections = []
    for item in verification['hypotheses']:
        hypothesis = item['hypothesis']
        support = ', '.join(hypothesis.get('supporting_evidence', [])) or 'none cited'
        predictions = ''.join(
            '<li>{}: <b>{}</b> ? Evidence: {}</li>'.format(
                html.escape(prediction['statement']),
                html.escape(prediction['status']),
                html.escape(', '.join(prediction.get('evidence_ids', [])) or 'none cited'))
            for prediction in item['predictions']
        )
        sections.append(
            '<section><h2>{} ? {}</h2><p>{}</p><p><b>Supporting evidence:</b> {}</p><ul>{}</ul></section>'.format(
                html.escape(hypothesis['title']), html.escape(item['status']),
                html.escape(hypothesis['explanation']), html.escape(support), predictions)
        )
    hypotheses_html = ''.join(sections)
    case_name = html.escape(str((metadata or {}).get('case', 'unspecified')))
    instruction = html.escape(str(abr.instruction))
    effective_address = html.escape(str(abr.effective_address))
    contradictions = html.escape(str(verification['contradictions']))
    gaps = html.escape(str(abr.gaps))
    next_experiment = html.escape(str(verification['next_experiment']))
    document = f'''<!doctype html><meta charset="utf-8"><title>Software Investigator report</title>
<style>body{{font:20px system-ui;background:#fff;color:#18212b;margin:3rem;line-height:1.5}}h1{{font-size:2.5rem}}.banner{{padding:1rem;background:#fff2cc;border-left:8px solid #8a5a00}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #9aa4ad;padding:.5rem;text-align:left;vertical-align:top}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}section{{padding:1rem;border:1px solid #aab4bd;margin:1rem 0}}</style>
<h1>Software Investigator</h1><p class="banner">{BANNER}</p><p>Case: {case_name}</p>
<h2>Faulting instruction</h2><pre>{instruction}\nEffective address: {effective_address}</pre>
<h2>Hypotheses</h2>{hypotheses_html}<h2>Contradictions</h2><pre>{contradictions}</pre>
<h2>Gaps and unknowns</h2><pre>{gaps}</pre><h2>Next experiment</h2><pre>{next_experiment}</pre>
<h2>Evidence</h2><table><thead><tr><th>ID</th><th>Kind</th><th>Value</th><th>Provenance</th></tr></thead><tbody>{rows}</tbody></table>'''
    (p / 'report.html').write_text(document, encoding='utf-8')
    return report

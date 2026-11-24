import argparse,json,sys,io
from contextlib import redirect_stdout
from pathlib import Path
from .parser import parse
from .analyzer import analyze
from .reasoner import Reasoner
from .verifier import verify
from .report import write,BANNER

def investigate(elf,core,out,case=None):
    ibr=parse(elf,core); abr=analyze(ibr); hs=Reasoner().generate(abr); v=verify(ibr,abr,hs); write(out,ibr,abr,v,{'case':case or Path(elf).stem,'elf':str(elf),'core':str(core)})
    tops=[x for x in v['hypotheses'] if x['status']=='SUPPORTED']
    status='Insufficient evidence' if not tops else ', '.join(x['hypothesis']['id'] for x in tops)
    print(f'{BANNER}\nCase: {case or Path(elf).stem}\nResult: {status}\nContradictions: {len(v["contradictions"])}\nReport: {out}')
    return v

def main():
    ap=argparse.ArgumentParser(prog='si'); sub=ap.add_subparsers(dest='cmd',required=True)
    inv=sub.add_parser('investigate'); inv.add_argument('--elf',required=True); inv.add_argument('--core',required=True); inv.add_argument('--out',required=True)
    gallery=sub.add_parser('gallery'); gallery.add_argument('--out',default='dist/')
    serve=sub.add_parser('serve'); serve.add_argument('--port',type=int,default=8000)
    sub.add_parser('demo'); a=ap.parse_args()
    if a.cmd=='investigate': investigate(a.elf,a.core,a.out)
    elif a.cmd=='gallery':
        from .gallery import build_gallery
        print(build_gallery(a.out))
    elif a.cmd=='serve':
        from .server import serve as serve_app
        serve_app(port=a.port)
    else:
        print(BANNER); print('case | top hypothesis | status | ground truth | match?')
        root=Path('cases'); any_case=False; missing=False; mismatch=False
        for truth in sorted(root.glob('*/ground_truth.json')):
            case=truth.parent; gt=json.loads(truth.read_text())
            elves=sorted((case/'build').glob('*.elf'))
            if not elves:
                print(f'{case.name} | unavailable | UNDETERMINED | {gt.get("expected_top_hypothesis")} | unavailable'); missing=True
                continue
            for elf in elves:
                core=elf.with_suffix('.core')
                if not core.exists():
                    print(f'{case.name}/{elf.stem} | unavailable | UNDETERMINED | {gt.get("expected_top_hypothesis")} | unavailable'); missing=True; continue
                with redirect_stdout(io.StringIO()): v=investigate(elf,core,Path('out')/case.name/elf.stem,case.name)
                any_case=True
                supported=[x for x in v['hypotheses'] if x['status']=='SUPPORTED']
                top=supported[0]['hypothesis']['id'] if supported else 'None'
                status=supported[0]['status'] if supported else ('REFUTED' if any(x['status']=='REFUTED' for x in v['hypotheses']) else 'UNDETERMINED')
                expected=gt.get('expected_top_hypothesis')
                match=top==expected
                print(f'{case.name}/{elf.stem} | {top} | {status} | {expected} | {match}')
                mismatch = mismatch or not match
        if not any_case: print('No generated real ELF/core pairs found. Build them on Linux with python tools/build_cases.py.')
        if missing or not any_case or mismatch: return 1
if __name__=='__main__': raise SystemExit(main())

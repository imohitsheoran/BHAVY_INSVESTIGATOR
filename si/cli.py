import argparse,json,sys
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
        root=Path('cases'); any_case=False
        for truth in sorted(root.glob('*/ground_truth.json')):
            case=truth.parent; gt=json.loads(truth.read_text())
            for elf in sorted((case/'build').glob('*.elf')):
                core=elf.with_suffix('.core')
                if not core.exists(): print(f'{case.name}/{elf.stem} | — | MISSING CORE | {gt.get("expected_root_cause_category")} | unavailable'); continue
                any_case=True; v=investigate(elf,core,Path('out')/case.name/elf.stem,case.name)
                supported=[x for x in v['hypotheses'] if x['status']=='SUPPORTED']; top=supported[0]['hypothesis']['id'] if supported else 'None'; expected=gt.get('expected_top_hypothesis'); print(f'{case.name}/{elf.stem} | {top} | {"SUPPORTED" if supported else "UNDETERMINED"} | {expected} | {top==expected}')
        if not any_case: print('No committed ELF/core cases found. Build and generate cores on Linux; see README.md.')
if __name__=='__main__': main()

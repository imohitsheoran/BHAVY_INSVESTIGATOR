"""Linux-only reproducible builder and core generator. Run from repository root."""
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
for case in ROOT.joinpath('cases').iterdir():
    src=next(case.glob('*.c'),None)
    if not src: continue
    build=case/'build'; build.mkdir(exist_ok=True)
    for variant,extra in [('debug',[]),('stripped',['-s'])]:
        exe=build/f'{variant}.elf'
        subprocess.run(['gcc','-O0','-g','-fno-omit-frame-pointer','-fno-pie','-no-pie',*extra,str(src),'-o',str(exe)],check=True)
        # GDB generates the committed core; the investigator never invokes it.
        script=f"run\ngenerate-core-file {exe.with_suffix('.core')}\nquit\n"
        subprocess.run(['gdb','-q','-batch','-ex','run','-ex',f'generate-core-file {exe.with_suffix(".core")}',str(exe)],check=False)

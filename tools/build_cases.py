"""Linux x86-64 builder for controlled ELF and authentic GDB-generated core files."""
import platform
import shutil
import subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]


def run(command):
    subprocess.run(command, check=True, cwd=ROOT)


def main():
    if platform.system() != 'Linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        raise SystemExit('Case generation requires Linux x86-64 with gcc, strip, and gdb installed.')
    gcc = shutil.which('gcc')
    strip = shutil.which('strip')
    gdb = shutil.which('gdb')
    if not gcc or not strip or not gdb:
        raise SystemExit('Missing required tools. Install gcc, binutils (strip), and gdb, then retry.')

    case_dirs = sorted(p for p in (ROOT / 'cases').iterdir() if p.is_dir())
    if not case_dirs:
        raise SystemExit('No case directories found.')
    for case_dir in case_dirs:
        sources = list(case_dir.glob('*.c'))
        if not sources:
            continue
        if len(sources) != 1:
            raise SystemExit(f'{case_dir.name}: expected exactly one C source, found {len(sources)}')
        source = sources[0]
        build_dir = case_dir / 'build'
        build_dir.mkdir(parents=True, exist_ok=True)
        debug_elf = build_dir / 'debug.elf'
        stripped_elf = build_dir / 'stripped.elf'
        run([gcc, '-O0', '-g', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', str(source), '-o', str(debug_elf)])
        shutil.copy2(debug_elf, stripped_elf)
        run([strip, str(stripped_elf)])
        for elf in (debug_elf, stripped_elf):
            core = elf.with_suffix('.core')
            if core.exists():
                core.unlink()
            run([gdb, '-q', '-batch', '-ex', 'set pagination off', '-ex', 'run',
                 '-ex', f'generate-core-file {core}', str(elf)])
            if not core.is_file() or core.stat().st_size == 0:
                raise SystemExit(f'gdb did not create a non-empty core file for {elf}')
            with core.open('rb') as stream:
                core_elf = ELFFile(stream)
                if core_elf['e_type'] != 'ET_CORE' or core_elf['e_machine'] != 'EM_X86_64':
                    raise SystemExit(f'gdb output is not an ELF64 x86-64 core: {core}')
            print(f'Generated {elf.relative_to(ROOT)} and {core.relative_to(ROOT)} ({core.stat().st_size} bytes)')


if __name__ == '__main__':
    main()

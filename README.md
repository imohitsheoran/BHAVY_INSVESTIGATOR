# Software Investigator MVP-0

MVP-0 technical proof on a small set of controlled cases. Not a benchmark. Not a finished product.

This is an offline, Linux x86-64 ELF/core investigation prototype. The reasoner is a rule-based hypothesis generator. The investigator parses supplied core files directly and never calls GDB. GDB is used only by the Linux case builder to create sample cores.

## Environment and install

Requires Linux x86-64, Python 3.10+, gcc, gdb, and make. Dependencies are pinned in `requirements.txt`. For fully offline installation, place compatible Linux wheels in `wheelhouse/` and run:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --find-links wheelhouse -r requirements.txt
```

Generate controlled ELF/core pairs on Linux:

```sh
python tools/build_cases.py
```

## CLI

```sh
python -m si investigate --elf cases/null_field_deref/build/debug.elf --core cases/null_field_deref/build/debug.core --out out/null
python -m si demo
python -m si gallery --out dist/
python -m si serve
make test
```

`si gallery` runs the same investigation pipeline for each case with an available ELF/core pair. It writes one report under `dist/reports/<case>/report.html` and a self-contained, offline `dist/index.html` gallery. Select a case from the left column to display its report. Cases with missing artifacts are identified as `UNDETERMINED`; no output is fabricated.

Open `dist/index.html` directly in a browser. The gallery uses only inline CSS and JavaScript and local report files; it makes no network calls.

`python -m si serve` starts a local browser UI at `http://127.0.0.1:8000/`. It lets you choose an available case or upload both an ELF and core. Upload the Linux x86-64 ELF executable and its matching ELF core dump (`ET_CORE`, often named `core` or `core.<pid>`); Windows `.exe`/`.dmp` files are not supported. If the built-in case list is empty, generate its pairs on Linux with `python tools/build_cases.py`. Uploaded files are saved only in a temporary directory, passed to the existing parser/report pipeline as data, and removed when the request finishes. The server is stdlib-only and binds only to loopback.

## Artifact status

The source tree includes case sources and a Linux build/core-generation script. ELF/core binaries and offline wheels must be generated on a compatible Linux x86-64 host. This Windows authoring environment has no Linux/WSL or Linux GDB, so authentic core artifacts are not generated here. `si demo` and the gallery identify absent cores rather than invent results.

# 3-minute live demo

1. `python -m si demo` — “This is a technical proof on controlled cases, not a benchmark.” Show the computed case table and call out any missing artifacts honestly.
2. `python -m si investigate --elf cases/null_field_deref/build/debug.elf --core cases/null_field_deref/build/debug.core --out out/null` — inspect the live evidence, instruction, effective address check, and hypotheses.
3. `python -m si gallery --out dist/` — open `dist/index.html`, select cases from the left, and inspect each generated report on the right. Explain that top hypothesis, status, and ground-truth match come from the current files.
4. Optional: `python -m si serve` — browse to `http://127.0.0.1:8000/`, choose a case or upload a pair, and submit it for investigation.
5. `python -m si investigate --elf cases/null_field_deref/build/stripped.elf --core cases/null_field_deref/build/stripped.core --out out/stripped` — show symbol degradation if artifacts have been built.
6. “The comparison with a plain LLM + GDB baseline has not been run yet; that is the next milestone.”

All ELF/core files must first be generated on Linux with `python tools/build_cases.py`.

# 3-minute live demo

1. `python -m si demo` — “This is a technical proof on controlled cases, not a benchmark.” Show the computed case table and explain any missing artifacts honestly.
2. `python -m si investigate --elf cases/null_field_deref/build/debug.elf --core cases/null_field_deref/build/debug.core --out out/null` — inspect evidence IDs, instruction, effective address check, and hypotheses.
3. Open `out/null/report.html` — walk through provenance, verifier predictions, contradictions and gaps.
4. `python -m si investigate --elf cases/null_field_deref/build/stripped.elf --core cases/null_field_deref/build/stripped.core --out out/stripped` — show symbol degradation when available.
5. “The comparison with a plain LLM + GDB baseline has not been run yet; that is the next milestone.”

All case/core files must first have been generated on Linux with `python tools/build_cases.py`.

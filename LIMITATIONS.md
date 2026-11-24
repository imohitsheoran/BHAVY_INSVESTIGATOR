# MVP-0 limitations

- Linux x86-64 ELF and SIGSEGV only; parser expects Linux x86-64 core note layouts.
- Controlled cases only; the supplied workspace did not have Linux/WSL or GDB, so no ELF/core artifacts or wheelhouse were generated here. The Linux build script is provided.
- No optimized-code support or tested stripped-PIE complexity; builder currently uses non-PIE executables.
- No heap analysis; use-after-free and heap corruption remain NOT TESTABLE.
- The reasoner is a rule-based hypothesis generator. There is no LLM backend enabled.
- No plain LLM + GDB baseline comparison has been run.
- NT_FILE external module build-ID validation and module byte lookup are not implemented; missing module bytes must be treated as gaps.
- Effective address handling covers simple x86-64 base/index/scale/displacement and RIP-relative forms; unsupported segmented operands remain uncomputed.
- The verifier's mapping checks use dumped PT_LOAD ranges only, so absence from a core snapshot does not prove process-level unmapped status.

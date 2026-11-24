import shutil
import json
import struct
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from si.analyzer import analyze
from si.parser import AT_ENTRY, AT_PHDR, NT_AUXV, NT_FILE, NT_PRSTATUS, NT_SIGINFO, parse
from si.reasoner import Reasoner
from si.report import write
from si.verifier import verify

ROOT = Path(__file__).resolve().parents[1]
CASES = ('null_field_deref', 'stack_overflow', 'wild_pointer', 'rodata_write')
KERNEL_X86_64_REG_ORDER = (
    'r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8',
    'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'orig_rax', 'rip', 'cs', 'eflags',
    'rsp', 'ss', 'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs',
)


def _pair(case_name):
    elf = ROOT / 'cases' / case_name / 'build' / 'debug.elf'
    core = ROOT / 'cases' / case_name / 'build' / 'debug.core'
    if not elf.is_file() or not core.is_file():
        pytest.skip(f'real committed ELF/core artifacts missing for {case_name}; generate on Linux with python tools/build_cases.py')
    return elf, core


@pytest.mark.parametrize('case_name', CASES)
def test_real_core_notes_registers_siginfo_auxv_and_rip(case_name):
    elf, core = _pair(case_name)
    ibr = parse(elf, core)
    raw_registers = raw_siginfo = raw_auxv = raw_file = None
    with core.open('rb') as stream:
        core_elf = ELFFile(stream)
        for segment in core_elf.iter_segments():
            if segment['p_type'] != 'PT_NOTE':
                continue
            for note in segment.iter_notes():
                kind = note['n_type']
                desc = note.get('n_descdata')
                if kind in ('NT_PRSTATUS', NT_PRSTATUS) and desc and len(desc) >= 112 + 27 * 8:
                    raw_registers = dict(zip(KERNEL_X86_64_REG_ORDER, struct.unpack_from('<27Q', desc, 112)))
                elif kind in ('NT_SIGINFO', NT_SIGINFO) and desc and len(desc) >= 24:
                    signo, err, code = struct.unpack_from('<3i', desc, 0)
                    raw_siginfo = {'si_signo': signo, 'si_errno': err, 'si_code': code,
                                   'si_addr': struct.unpack_from('<Q', desc, 16)[0]}
                elif kind in ('NT_AUXV', NT_AUXV) and desc:
                    raw_auxv = {}
                    for offset in range(0, len(desc) - 15, 16):
                        tag, value = struct.unpack_from('<QQ', desc, offset)
                        if tag == 0:
                            break
                        raw_auxv[tag] = value
                elif kind in ('NT_FILE', NT_FILE) and desc:
                    count, _page_size = struct.unpack_from('<QQ', desc, 0)
                    raw_file = [struct.unpack_from('<QQQ', desc, 16 + i * 24) for i in range(count)]
    assert ibr.core['header']['type'] == 'ET_CORE'
    assert ibr.core['header']['machine'] == 'EM_X86_64'
    assert raw_registers is not None and raw_siginfo is not None and raw_auxv is not None and raw_file is not None
    assert ibr.registers == raw_registers
    assert ibr.core['siginfo'] == raw_siginfo
    assert ibr.core['auxv'] == raw_auxv
    assert [(m['start'], m['end']) for m in ibr.mappings] == [(a, b) for a, b, _ in raw_file]
    assert ibr.core['siginfo']['si_signo'] == 11
    assert isinstance(ibr.core['siginfo']['si_addr'], int)
    assert ibr.registers['rip'] > 0
    assert ibr.registers['rsp'] > 0
    assert ibr.core['auxv'].get(AT_ENTRY, 0) > 0
    assert ibr.core['auxv'].get(AT_PHDR, 0) > 0
    bias = next(e.value for e in ibr.evidence if e.kind == 'load_bias')
    assert bias == ibr.core['auxv'][AT_ENTRY] - ibr.elf['header']['entry']
    with elf.open('rb') as stream:
        executable = ELFFile(stream)
        program_headers = list(executable.iter_segments())
        phdr = next((p['p_vaddr'] for p in program_headers if p['p_type'] == 'PT_PHDR'), None)
        if phdr is None:
            e_phoff = executable['e_phoff']
            load = next(p for p in program_headers if p['p_type'] == 'PT_LOAD' and p['p_offset'] <= e_phoff < p['p_offset'] + p['p_filesz'])
            phdr = load['p_vaddr'] + e_phoff - load['p_offset']
    assert bias == ibr.core['auxv'][AT_PHDR] - phdr
    assert any(e.kind == 'file_mappings' for e in ibr.evidence), 'NT_FILE raw descriptor was not parsed'


@pytest.mark.parametrize('case_name', CASES)
def test_real_core_fault_instruction_effective_address_matches_siginfo(case_name, tmp_path):
    elf, core = _pair(case_name)
    ibr = parse(elf, core)
    abr = analyze(ibr)
    assert abr.instruction is not None
    assert abr.instruction['address'] == ibr.registers['rip']
    assert abr.effective_address['status'] == 'COMPUTED'
    assert abr.effective_address['address'] == ibr.core['siginfo']['si_addr']
    hypotheses = Reasoner().generate(abr)
    verification = verify(ibr, abr, hypotheses)
    ground_truth = json.loads((ROOT / 'cases' / case_name / 'ground_truth.json').read_text(encoding='utf-8'))
    supported = [item for item in verification['hypotheses'] if item['status'] == 'SUPPORTED']
    assert supported, f'no hypothesis is supported for {case_name}'
    assert supported[0]['hypothesis']['id'] == ground_truth['expected_top_hypothesis']
    known = {e.id for e in ibr.evidence}
    for result in verification['hypotheses']:
        assert set(result['hypothesis']['supporting_evidence']) <= known
        for prediction in result['predictions']:
            assert set(prediction['evidence_ids']) <= known
    report = write(tmp_path / case_name, ibr, abr, verification, {'case': case_name})
    page = (tmp_path / case_name / 'report.html').read_text(encoding='utf-8')
    assert 'Supporting evidence:' in page
    assert any(e.id in page for e in ibr.evidence)


def test_real_core_byte_flip_changes_report(tmp_path):
    elf, original_core = _pair('null_field_deref')
    changed_core = tmp_path / 'modified.core'
    shutil.copyfile(original_core, changed_core)
    original_ibr = parse(elf, original_core)
    rip = original_ibr.registers['rip']
    candidates = [s for s in original_ibr.segments if s['filesz'] and not (s['vaddr'] <= rip < s['vaddr'] + s['filesz'])]
    assert candidates, 'no non-code PT_LOAD bytes available for a safe core mutation'
    segment = candidates[0]
    offset = segment['offset'] + segment['filesz'] - 1
    with changed_core.open('r+b') as stream:
        stream.seek(offset)
        current = stream.read(1)
        assert len(current) == 1
        stream.seek(offset)
        stream.write(bytes([current[0] ^ 1]))

    def make_report(core_path, out):
        ibr = parse(elf, core_path)
        abr = analyze(ibr)
        hypotheses = Reasoner().generate(abr)
        result = verify(ibr, abr, hypotheses)
        return write(out, ibr, abr, result, {'case': 'null_field_deref'})

    before = make_report(original_core, tmp_path / 'before')
    after = make_report(changed_core, tmp_path / 'after')
    assert before['evidence'] != after['evidence']
    assert (tmp_path / 'before' / 'report.html').read_bytes() != (tmp_path / 'after' / 'report.html').read_bytes()
    before_hash = next(e['value'] for e in before['evidence'] if e['kind'] == 'core_sha256')
    after_hash = next(e['value'] for e in after['evidence'] if e['kind'] == 'core_sha256')
    assert before_hash != after_hash

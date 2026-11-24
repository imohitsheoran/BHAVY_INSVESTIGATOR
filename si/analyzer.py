import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *
from .abr import ABR
from .ibr import Evidence

def analyze(ibr):
    regs=ibr.registers; rip=regs.get('rip'); si=ibr.core.get('siginfo',{}).get('si_addr'); facts=[]; gaps=list(ibr.gaps); contradictions=[]; insn=None; ea={'status':'NOT_COMPUTABLE','reason':'faulting RIP unavailable'}
    def ids(*kinds): return [e.id for e in ibr.evidence if e.kind in kinds]
    def record(kind,value,provenance):
        number=max((int(e.id[1:]) for e in ibr.evidence if e.id.startswith('E') and e.id[1:].isdigit()),default=0)+1
        item=Evidence(f'E{number:03d}',kind,value,provenance); ibr.evidence.append(item)
        facts.append({'kind':kind,'value':value,'evidence_ids':[item.id]})
        return item.id
    register_ids=ids('registers'); siginfo_ids=ids('siginfo'); segment_ids=ids('core_segment')
    if rip is not None:
        try:
            b=ibr.read_memory(rip,15)
            memory_id=ibr.evidence[-1].id if ibr.evidence and ibr.evidence[-1].kind=='memory_read' else None
            md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
            ins=next(md.disasm(b,rip,1),None)
            if not ins: raise ValueError('no instruction decoded at RIP')
            insn={'address':rip,'bytes':ins.bytes.hex(),'mnemonic':ins.mnemonic,'op_str':ins.op_str,'size':ins.size}
            instruction_id=record('faulting_instruction',insn,f'Decoded at RIP from '+(f'{memory_id} memory bytes' if memory_id else 'available executable bytes'))
            memop=next((o for o in ins.operands if o.type==X86_OP_MEM),None)
            if memop is None: ea={'status':'NO_MEMORY_OPERAND','reason':'instruction has no explicit memory operand'}
            else:
                m=memop.mem
                if m.segment in (X86_REG_FS,X86_REG_GS): ea={'status':'NOT_COMPUTABLE','reason':'FS/GS segment based operand unsupported'}
                else:
                    base=ins.address+ins.size if m.base==X86_REG_RIP else regs.get(ins.reg_name(m.base),0) if m.base else 0
                    index=regs.get(ins.reg_name(m.index),0) if m.index else 0
                    val=(base+index*m.scale+m.disp)&((1<<64)-1)
                    ea={'status':'COMPUTED','address':val,'si_addr':si,'match':val==si,'expression':f'{base:#x} + {index:#x} * {m.scale} + {m.disp:#x}'}
                    if val!=si: contradictions.append(f'Computed operand address {val:#x} differs from si_addr {si:#x}.')
                    refs=[instruction_id]+register_ids+siginfo_ids
                    check_id=record('effective_address_check',ea,'Derived from '+', '.join(refs))
                    facts[-1]['evidence_ids']=[check_id]+refs
        except Exception as e: gaps.append(f'Faulting instruction unavailable: {e}')
    stack=next((s for s in ibr.segments if s['vaddr']<=regs.get('rsp',0)<s['vaddr']+s['memsz']),None)
    observed_mapped=(si is not None and (
        any(s['vaddr']<=si<s['vaddr']+s['memsz'] for s in ibr.segments) or
        any(m['start']<=si<m['end'] for m in ibr.mappings)))
    if si is None: cls={'kind':'unknown'}
    elif si<0x1000: cls={'kind':'near_null','offset':si}
    elif stack and abs(si-regs.get('rsp',0))<0x10000: cls={'kind':'stack_adjacent','stack_start':stack['vaddr'],'stack_end':stack['vaddr']+stack['memsz'],'rsp':regs.get('rsp')}
    elif ibr.core.get('siginfo',{}).get('si_code')==2 and observed_mapped: cls={'kind':'mapped_permission_violation'}
    elif ibr.core.get('siginfo',{}).get('si_code')==2: cls={'kind':'permission_violation_mapping_unobserved'}
    elif ibr.core.get('siginfo',{}).get('si_code')==1: cls={'kind':'unmapped'}
    else: cls={'kind':'unknown_or_noncanonical','si_code':ibr.core.get('siginfo',{}).get('si_code')}
    clsrefs=siginfo_ids+register_ids+segment_ids+ids('file_mappings')
    class_id=record('fault_classification',cls,'Derived from '+', '.join(clsrefs))
    facts[-1]['evidence_ids']=[class_id]+clsrefs
    return ABR(facts,insn,ea,cls,gaps,contradictions)

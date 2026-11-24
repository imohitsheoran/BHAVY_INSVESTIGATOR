import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *
from .abr import ABR

def analyze(ibr):
    regs=ibr.registers; rip=regs.get('rip'); si=ibr.core.get('siginfo',{}).get('si_addr'); facts=[]; gaps=list(ibr.gaps); contradictions=[]; insn=None; ea={'status':'NOT_COMPUTABLE','reason':'faulting RIP unavailable'}
    if rip is not None:
        try:
            b=ibr.read_memory(rip,15)
            md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
            ins=next(md.disasm(b,rip,1),None)
            if not ins: raise ValueError('no instruction decoded at RIP')
            insn={'address':rip,'bytes':ins.bytes.hex(),'mnemonic':ins.mnemonic,'op_str':ins.op_str,'size':ins.size}
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
                    facts.append({'kind':'effective_address_check','value':ea})
        except Exception as e: gaps.append(f'Faulting instruction unavailable: {e}')
    stack=next((s for s in ibr.segments if s['vaddr']<=regs.get('rsp',0)<s['vaddr']+s['memsz']),None)
    if si is None: cls={'kind':'unknown'}
    elif si<0x1000: cls={'kind':'near_null','offset':si}
    elif stack and abs(si-regs.get('rsp',0))<0x10000: cls={'kind':'stack_adjacent','stack_start':stack['vaddr'],'stack_end':stack['vaddr']+stack['memsz'],'rsp':regs.get('rsp')}
    elif ibr.core.get('siginfo',{}).get('si_code')==2: cls={'kind':'mapped_permission_violation'}
    elif ibr.core.get('siginfo',{}).get('si_code')==1: cls={'kind':'unmapped'}
    else: cls={'kind':'unknown_or_noncanonical','si_code':ibr.core.get('siginfo',{}).get('si_code')}
    return ABR(facts,insn,ea,cls,gaps,contradictions)

"""ELF/core parser. All parser facts carry source provenance and stable IDs."""
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from .ibr import IBR, Evidence

REGS=['r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs']
NT_PRSTATUS=1; NT_SIGINFO=0x53494749; NT_AUXV=6; NT_FILE=0x46494c45

def _note_data(note):
    d=note['n_desc']
    return d if isinstance(d,bytes) else bytes(d)

def parse(elf_path, core_path):
    elf_path=Path(elf_path); core_path=Path(core_path); evidence=[]; n=0; gaps=[]
    def add(k,v,p):
        nonlocal n
        n+=1; evidence.append(Evidence(f'E{n:03d}',k,v,p)); return v
    with elf_path.open('rb') as f:
        ef=ELFFile(f)
        eh={'type':ef['e_type'],'machine':ef['e_machine'],'entry':ef['e_entry'],'class':ef.elfclass,'little_endian':ef.little_endian}
        ph=[{'type':p['p_type'],'flags':p['p_flags'],'offset':p['p_offset'],'vaddr':p['p_vaddr'],'filesz':p['p_filesz'],'memsz':p['p_memsz']} for p in ef.iter_segments()]
        syms=[]
        for sec in ef.iter_sections():
            if sec.name=='.note.gnu.build-id': pass
            if sec['sh_type']=='SHT_SYMTAB':
                syms.extend({'name':s.name,'value':s['st_value'],'size':s['st_size']} for s in sec.iter_symbols() if s.name)
        elf={'header':eh,'program_headers':ph,'sections':[s.name for s in ef.iter_sections()],'symbols':syms,'pie':eh['type']=='ET_DYN'}
        if not syms:gaps.append('No full symbol table; function names may be unavailable.')
        for p in ph:
            if p['type']=='PT_NOTE':
                for note in ef.iter_segments():
                    if note['p_type']!='PT_NOTE': continue
                    for x in note.iter_notes():
                        if x['n_type']=='NT_GNU_BUILD_ID': elf['build_id']=x['n_desc']; add('elf_build_id',elf['build_id'],'ELF PT_NOTE GNU build-id')
                    break
    with core_path.open('rb') as cf:
        c=ELFFile(cf)
        if c['e_type']!='ET_CORE': raise ValueError('core file is not ET_CORE')
        segments=[]; notes=[]
        for s in c.iter_segments():
            if s['p_type']=='PT_LOAD': segments.append({'vaddr':s['p_vaddr'],'memsz':s['p_memsz'],'offset':s['p_offset'],'filesz':s['p_filesz'],'flags':s['p_flags']})
            elif s['p_type']=='PT_NOTE': notes += list(s.iter_notes())
        regs={}; siginfo={}; auxv={}; mappings=[]
        for note in notes:
            typ=note['n_type']; data=_note_data(note)
            if typ=='NT_PRSTATUS':
                # Linux x86-64 elf_prstatus: regs begin at byte 112; user_regs_struct is 27 x 8 bytes.
                if len(data)>=112+27*8:
                    vals=struct.unpack_from('<27Q',data,112); regs=dict(zip(REGS,vals)); add('registers',regs,'Core PT_NOTE NT_PRSTATUS, x86-64 user_regs_struct order')
            elif typ=='NT_SIGINFO':
                if len(data)>=24:
                    signo,err,code=struct.unpack_from('<3i',data,0); addr=struct.unpack_from('<Q',data,16)[0]
                    siginfo={'si_signo':signo,'si_errno':err,'si_code':code,'si_addr':addr}; add('siginfo',siginfo,'Core PT_NOTE NT_SIGINFO')
            elif typ=='NT_AUXV':
                fmt='<QQ'; size=16
                for off in range(0,len(data)-size+1,size):
                    tag,val=struct.unpack_from(fmt,data,off)
                    if tag==0:break
                    auxv[tag]=val
                add('auxv',auxv,'Core PT_NOTE NT_AUXV')
            elif typ=='NT_FILE':
                if len(data)>=16:
                    count,page=struct.unpack_from('<QQ',data,0); off=16; triples=[]
                    for _ in range(count): triples.append(struct.unpack_from('<QQQ',data,off)); off+=24
                    names=data[off:].split(b'\0'); mappings=[{'start':a,'end':b,'file_offset':o*page,'path':names[i].decode(errors='replace') if i<len(names) else ''} for i,(a,b,o) in enumerate(triples)]
                    add('file_mappings',mappings,'Core PT_NOTE NT_FILE')
        if not regs:gaps.append('NT_PRSTATUS register note missing or truncated.')
        if not siginfo:gaps.append('NT_SIGINFO missing or truncated.')
        if not auxv:gaps.append('NT_AUXV missing or truncated.')
        core={'header':{'type':c['e_type'],'machine':c['e_machine']},'siginfo':siginfo,'auxv':auxv}
    bias=None
    if 'AT_ENTRY' in auxv and elf['header']['entry']:
        bias=auxv['AT_ENTRY']-elf['header']['entry']; add('load_bias',bias,'Derived as core NT_AUXV AT_ENTRY - ELF e_entry')
    for seg in segments:add('core_segment',seg,'Core PT_LOAD')
    # Load executable PT_LOAD bytes for fallback, retaining file offsets.
    file_loads=[p for p in ph if p['type']=='PT_LOAD' and p['filesz']]
    def readmem(addr,size):
        with core_path.open('rb') as f:
            for s in segments:
                if s['vaddr']<=addr and addr+size<=s['vaddr']+s['filesz']:
                    f.seek(s['offset']+addr-s['vaddr']); return f.read(size),'core PT_LOAD'
        for p in file_loads:
            start=p['vaddr']+(bias or 0)
            if start<=addr and addr+size<=start+p['filesz']:
                with elf_path.open('rb') as f:
                    f.seek(p['offset']+addr-start); return f.read(size),'ELF PT_LOAD fallback'
        raise KeyError(f'address 0x{addr:x} is unavailable in core and ELF')
    def memory(addr,size):
        b,source=readmem(addr,size); add('memory_read',{'address':addr,'size':size,'bytes':b.hex()},source); return b
    return IBR(elf,core,regs,mappings,segments,evidence,gaps,memory)

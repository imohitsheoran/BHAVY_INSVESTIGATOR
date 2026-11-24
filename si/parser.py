"""ELF/core parser. All parser facts carry source provenance and stable IDs."""
import hashlib
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from .ibr import IBR, Evidence

REGS=['r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs']
NT_PRSTATUS=1; NT_SIGINFO=0x53494749; NT_AUXV=6; NT_FILE=0x46494c45
AT_PHDR=3; AT_ENTRY=9

def _note_data(note):
    # pyelftools keeps raw bytes in n_descdata. NT_FILE's parsed n_desc is
    # a Construct Container, so converting n_desc directly is unsafe.
    data=note.get('n_descdata')
    if isinstance(data,bytes): return data
    if isinstance(data,(bytearray,memoryview)): return bytes(data)
    desc=note.get('n_desc')
    if isinstance(desc,bytes): return desc
    if isinstance(desc,(bytearray,memoryview)): return bytes(desc)
    raise ValueError(f"unsupported descriptor type: {type(desc).__name__}")

def _is_note(note_type, number, name):
    return note_type == name or note_type == number

def parse(elf_path, core_path):
    elf_path=Path(elf_path); core_path=Path(core_path); evidence=[]; n=0; gaps=[]
    def add(k,v,p):
        nonlocal n
        n+=1; evidence.append(Evidence(f'E{n:03d}',k,v,p)); return v
    with elf_path.open('rb') as f:
        ef=ELFFile(f)
        eh={'type':ef['e_type'],'machine':ef['e_machine'],'entry':ef['e_entry'],'phoff':ef['e_phoff'],'class':ef.elfclass,'little_endian':ef.little_endian}
        if eh['machine']!='EM_X86_64' or ef.elfclass!=64 or not ef.little_endian:
            raise ValueError('only little-endian ELF64 x86-64 executables are supported')
        ph=[{'type':p['p_type'],'flags':p['p_flags'],'offset':p['p_offset'],'vaddr':p['p_vaddr'],'filesz':p['p_filesz'],'memsz':p['p_memsz']} for p in ef.iter_segments()]
        syms=[]
        for sec in ef.iter_sections():
            if sec['sh_type']=='SHT_SYMTAB':
                syms.extend({'name':s.name,'value':s['st_value'],'size':s['st_size']} for s in sec.iter_symbols() if s.name)
        elf={'header':eh,'program_headers':ph,'sections':[s.name for s in ef.iter_sections()],'symbols':syms,'pie':eh['type']=='ET_DYN'}
        if not syms:gaps.append('No full symbol table; function names may be unavailable.')
        for note_segment in ef.iter_segments():
            if note_segment['p_type']!='PT_NOTE': continue
            for x in note_segment.iter_notes():
                if x['n_type']=='NT_GNU_BUILD_ID':
                    elf['build_id']=x['n_desc']; add('elf_build_id',elf['build_id'],'ELF PT_NOTE GNU build-id')
    with core_path.open('rb') as cf:
        c=ELFFile(cf)
        if c['e_type']!='ET_CORE': raise ValueError('core file is not ET_CORE')
        if c['e_machine']!='EM_X86_64' or c.elfclass!=64 or not c.little_endian:
            raise ValueError('only little-endian ELF64 x86-64 core files are supported')
        segments=[]; notes=[]
        for s in c.iter_segments():
            if s['p_type']=='PT_LOAD': segments.append({'vaddr':s['p_vaddr'],'memsz':s['p_memsz'],'offset':s['p_offset'],'filesz':s['p_filesz'],'flags':s['p_flags']})
            elif s['p_type']=='PT_NOTE':
                try: notes += list(s.iter_notes())
                except Exception as exc: gaps.append(f'Could not safely decode core PT_NOTE segment: {exc}')
        regs={}; siginfo={}; auxv={}; mappings=[]
        for note in notes:
            typ=note['n_type']
            try: data=_note_data(note)
            except (ValueError,TypeError) as exc:
                gaps.append(f'Could not decode {typ} note descriptor: {exc}')
                continue
            if _is_note(typ,NT_PRSTATUS,'NT_PRSTATUS'):
                # Linux x86-64 elf_prstatus: regs begin at byte 112; user_regs_struct is 27 x 8 bytes.
                if len(data)>=112+27*8:
                    vals=struct.unpack_from('<27Q',data,112); regs=dict(zip(REGS,vals)); add('registers',regs,'Core PT_NOTE NT_PRSTATUS, x86-64 user_regs_struct order')
                else: gaps.append(f'NT_PRSTATUS descriptor truncated: expected at least 328 bytes, got {len(data)}.')
            elif _is_note(typ,NT_SIGINFO,'NT_SIGINFO'):
                if len(data)>=24:
                    signo,err,code=struct.unpack_from('<3i',data,0); addr=struct.unpack_from('<Q',data,16)[0]
                    siginfo={'si_signo':signo,'si_errno':err,'si_code':code,'si_addr':addr}; add('siginfo',siginfo,'Core PT_NOTE NT_SIGINFO')
                else: gaps.append(f'NT_SIGINFO descriptor truncated: expected at least 24 bytes, got {len(data)}.')
            elif _is_note(typ,NT_AUXV,'NT_AUXV'):
                size=16; terminated=False
                for off in range(0,len(data)-size+1,size):
                    tag,val=struct.unpack_from('<QQ',data,off)
                    if tag==0: terminated=True; break
                    auxv[tag]=val
                if len(data)%size: gaps.append(f'NT_AUXV has {len(data)%size} trailing byte(s).')
                if not terminated: gaps.append('NT_AUXV is missing its AT_NULL terminator.')
                add('auxv',auxv,'Core PT_NOTE NT_AUXV (integer tags per ELF auxv ABI)')
            elif _is_note(typ,NT_FILE,'NT_FILE'):
                if len(data)<16:
                    gaps.append(f'NT_FILE descriptor truncated: got {len(data)} bytes.')
                    continue
                count,page=struct.unpack_from('<QQ',data,0); off=16
                if count>(len(data)-16)//24:
                    gaps.append(f'NT_FILE mapping table is truncated: {count} entries declared.')
                    continue
                triples=[struct.unpack_from('<QQQ',data,off+i*24) for i in range(count)]
                names=data[off+count*24:].split(b'\0')
                if names and names[-1]==b'': names.pop()
                if len(names)<count: gaps.append(f'NT_FILE has {count} mappings but only {len(names)} file names.')
                mappings=[{'start':a,'end':b,'file_offset':o*page,'path':names[i].decode(errors='replace') if i<len(names) else ''} for i,(a,b,o) in enumerate(triples)]
                add('file_mappings',mappings,'Core PT_NOTE NT_FILE raw descriptor (range triples plus page-based offsets)')
        if not regs:gaps.append('NT_PRSTATUS register note missing or truncated.')
        if not siginfo:gaps.append('NT_SIGINFO missing or truncated.')
        if not auxv:gaps.append('NT_AUXV missing or truncated.')
        core={'header':{'type':c['e_type'],'machine':c['e_machine']},'siginfo':siginfo,'auxv':auxv}
    # For ET_DYN, AT_ENTRY - e_entry and AT_PHDR - the ELF's in-memory
    # program-header address independently identify the load bias.
    entry_bias=(auxv[AT_ENTRY]-elf['header']['entry']) if AT_ENTRY in auxv else None
    phdr_vaddr=next((p['vaddr'] for p in ph if p['type']=='PT_PHDR'),None)
    if phdr_vaddr is None:
        for p in ph:
            if p['type']=='PT_LOAD' and p['offset']<=elf['header']['phoff']<p['offset']+p['filesz']:
                phdr_vaddr=p['vaddr']+elf['header']['phoff']-p['offset']; break
    phdr_bias=(auxv[AT_PHDR]-phdr_vaddr) if AT_PHDR in auxv and phdr_vaddr is not None else None
    if entry_bias is not None and phdr_bias is not None and entry_bias!=phdr_bias:
        gaps.append(f'Load-bias methods disagree: AT_ENTRY gives {entry_bias:#x}, AT_PHDR gives {phdr_bias:#x}.')
    bias=entry_bias if entry_bias is not None else phdr_bias
    if bias is not None:
        method='NT_AUXV AT_ENTRY (tag 9) - ELF e_entry' if entry_bias is not None else 'NT_AUXV AT_PHDR (tag 3) - ELF in-memory program-header address'
        add('load_bias',bias,'Derived as '+method)
    else:
        gaps.append('Load bias unavailable: NT_AUXV lacks usable AT_ENTRY (tag 9) and AT_PHDR (tag 3).')
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
    digest=hashlib.sha256()
    with core_path.open('rb') as cf:
        for block in iter(lambda: cf.read(1024*1024),b''): digest.update(block)
    add('core_sha256',digest.hexdigest(),'SHA-256 of the supplied core file bytes')
    return IBR(elf,core,regs,mappings,segments,evidence,gaps,memory)

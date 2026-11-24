def verify(ibr,abr,hypotheses):
    out=[]; ev=ibr.evidence
    addr=ibr.core.get('siginfo',{}).get('si_addr'); code=ibr.core.get('siginfo',{}).get('si_code')
    mapped=any(s['vaddr']<=addr<s['vaddr']+s['memsz'] for s in ibr.segments) if addr is not None else None
    for h in hypotheses:
        results=[]
        if h.id=='H-NULL': vals=[(addr is not None and addr<0x1000,'near-null address'),(abr.effective_address.get('match'),'effective address equals si_addr')]
        elif h.id=='H-STACK':
            smap=next((s for s in ibr.segments if s['vaddr']<=ibr.registers.get('rsp',0)<s['vaddr']+s['memsz']),None)
            vals=[(abr.classification.get('kind')=='stack_adjacent','fault address near stack mapping'),(smap is not None,'RSP inside observed core stack mapping')]
        elif h.id=='H-WILD': vals=[(code==1,'si_code is SEGV_MAPERR'),(mapped is False,'fault address outside observed PT_LOAD mappings')]
        elif h.id=='H-PERM': vals=[(code==2,'si_code is SEGV_ACCERR'),(mapped is True,'fault address inside observed PT_LOAD mapping')]
        else: vals=[]
        for ok,label in vals: results.append({'statement':label,'status':'NOT_TESTABLE' if ok is None else 'PASS' if ok else 'FAIL','reason':'required value unavailable' if ok is None else None})
        statuses=[r['status'] for r in results]; status='REFUTED' if 'FAIL' in statuses else 'SUPPORTED' if statuses.count('PASS')>=2 else 'UNDETERMINED'
        if h.id=='H-UAF': status='UNDETERMINED'
        out.append({'hypothesis':h.json(),'predictions':results,'status':status})
    return {'hypotheses':out,'contradictions':abr.contradictions,'insufficient_evidence':all(x['status']!='SUPPORTED' for x in out),'next_experiment':['Provide matching module binaries/build IDs and symbols.','Reproduce with allocator instrumentation or a controlled diagnostic run.']}

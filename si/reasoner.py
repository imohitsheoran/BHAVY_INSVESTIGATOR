from dataclasses import dataclass,asdict
@dataclass
class Prediction:
    statement:str
    evidence_needed:list
@dataclass
class Hypothesis:
    id:str; title:str; explanation:str; supporting_evidence:list; predictions:list; testability:str='TESTABLE'
    def json(self):return asdict(self)

class Reasoner:
    def generate(self,abr):
        c=abr.classification.get('kind'); ea=abr.effective_address; hs=[]
        def add(id,title,explain,ev,preds): hs.append(Hypothesis(id,title,explain,ev,[asdict(x) for x in preds]))
        ev=[x['id'] for x in []]
        if c=='near_null': add('H-NULL','Near-null field dereference','The fault address is near zero, consistent with a null object pointer plus a field offset.',[],[Prediction('Fault address is below 0x1000.',[]),Prediction('Computed effective address matches si_addr.',[])])
        if c=='stack_adjacent': add('H-STACK','Stack exhaustion or runaway recursion','The fault address is near the observed stack mapping and stack pointer.',[],[Prediction('Fault address is adjacent to stack mapping.',[]),Prediction('Stack pointer lies in the affected stack mapping.',[])])
        if c=='unmapped': add('H-WILD','Wild pointer into unmapped memory','The faulting address was reported as unmapped; corrupted or invalid pointer use is possible.',[],[Prediction('si_code indicates unmapped memory.',[]),Prediction('Faulting address is outside observed core mappings.',[])])
        if c=='mapped_permission_violation': add('H-PERM','Access violation on a mapped region','The kernel reports an access violation on mapped memory.',[],[Prediction('si_code indicates SEGV_ACCERR.',[]),Prediction('Fault address is inside a mapped region.',[])])
        hs.append(Hypothesis('H-UAF','Use-after-free or heap corruption','Heap lifetime and allocator state are not represented in this evidence set.',[],[], 'NOT TESTABLE with current evidence'))
        return hs

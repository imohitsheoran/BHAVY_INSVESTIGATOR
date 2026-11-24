from dataclasses import dataclass, asdict


@dataclass
class Prediction:
    statement: str
    evidence_needed: list


@dataclass
class Hypothesis:
    id: str
    title: str
    explanation: str
    supporting_evidence: list
    predictions: list
    testability: str = 'TESTABLE'

    def json(self):
        return asdict(self)


class Reasoner:
    """Rule-based hypothesis generator with evidence references from ABR facts."""
    def generate(self, abr):
        cls = abr.classification.get('kind')
        facts = abr.facts

        def refs(*kinds):
            found = []
            for fact in facts:
                if fact.get('kind') in kinds:
                    found.extend(fact.get('evidence_ids', []))
            return list(dict.fromkeys(found))

        siginfo = refs('fault_classification')
        address = refs('effective_address_check')
        register_and_map = refs('fault_classification')
        hypotheses = []

        def add(hid, title, explanation, supporting, predictions):
            hypotheses.append(Hypothesis(hid, title, explanation,
                                         list(dict.fromkeys(supporting)),
                                         [asdict(p) for p in predictions]))

        if cls == 'near_null':
            add('H-NULL', 'Near-null field dereference',
                'The fault address is near zero, consistent with a null object pointer plus a field offset.',
                siginfo + address,
                [Prediction('Fault address is below 0x1000.', siginfo),
                 Prediction('Computed effective address matches si_addr.', address)])
        if cls == 'stack_adjacent':
            add('H-STACK', 'Stack exhaustion or runaway recursion',
                'The fault address is near the observed stack mapping and stack pointer.',
                siginfo + register_and_map,
                [Prediction('Fault address is adjacent to stack mapping.', siginfo),
                 Prediction('Stack pointer lies in the affected stack mapping.', register_and_map)])
        if cls == 'unmapped':
            add('H-WILD', 'Wild pointer into unmapped memory',
                'The faulting address was reported as unmapped; corrupted or invalid pointer use is possible.',
                siginfo,
                [Prediction('si_code indicates unmapped memory.', siginfo),
                 Prediction('Fault address is outside observed core mappings.', siginfo)])
        if cls == 'mapped_permission_violation':
            add('H-PERM', 'Access violation on a mapped region',
                'The kernel reports an access violation on mapped memory.',
                siginfo,
                [Prediction('si_code indicates SEGV_ACCERR.', siginfo),
                 Prediction('Fault address is inside a mapped region.', siginfo)])
        hypotheses.append(Hypothesis('H-UAF', 'Use-after-free or heap corruption',
                                     'Heap lifetime and allocator state are not represented in this evidence set.',
                                     [], [], 'NOT TESTABLE with current evidence'))
        return hypotheses

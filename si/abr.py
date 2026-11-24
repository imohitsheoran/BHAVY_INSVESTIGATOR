from dataclasses import dataclass, asdict

@dataclass
class ABR:
    facts: list
    instruction: dict | None
    effective_address: dict
    classification: dict
    gaps: list
    contradictions: list
    def json(self): return asdict(self)

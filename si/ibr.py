from dataclasses import dataclass, asdict
from typing import Any

@dataclass
class Evidence:
    id: str
    kind: str
    value: Any
    provenance: str

@dataclass
class IBR:
    elf: dict
    core: dict
    registers: dict
    mappings: list
    segments: list
    evidence: list[Evidence]
    gaps: list[str]
    _memory: Any = None

    def json(self):
        d=asdict(self); d.pop('_memory',None); return d

    def read_memory(self, address: int, size: int):
        """Read core memory first, then executable bytes for file-backed PT_LOAD."""
        if self._memory is None: raise ValueError('memory reader unavailable')
        return self._memory(address,size)

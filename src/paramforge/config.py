from dataclasses import dataclass, field
from pathlib import Path
import json, os

@dataclass
class Config:
    timeout: float = 10.0
    workers: int = 10
    rate_limit: float = 5.0
    max_depth: int = 2
    max_requests: int = 1000
    output: str = "results"
    redact_sensitive_values: bool = True
    allow_domains: list[str] = field(default_factory=list)
    deny_domains: list[str] = field(default_factory=list)
    @classmethod
    def load(cls, path: str|None = None):
        c = cls()
        p = Path(path or os.getenv("PARAMFORGE_CONFIG", "paramforge.yaml"))
        if p.exists():
            text = p.read_text()
            if p.suffix == ".json": data = json.loads(text)
            else:
                try:
                    import yaml; data = yaml.safe_load(text) or {}
                except ImportError: data = {}
            for section in data.values():
                if isinstance(section, dict):
                    for k,v in section.items():
                        if hasattr(c,k): setattr(c,k,v)
        return c

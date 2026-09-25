from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any

@dataclass
class Finding:
    name: str
    value: str = ""
    url: str = ""
    endpoint: str = ""
    host: str = ""
    method: str = "GET"
    source: str = "direct"
    classification: str = "unknown"
    confidence: float = 0.5
    interest_score: int = 0
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    redacted: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    def to_dict(self): return asdict(self)

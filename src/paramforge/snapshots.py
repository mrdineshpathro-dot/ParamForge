"""Snapshot persistence and deterministic change detection."""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path
from .intelligence import compare, statistics

def save(findings, directory: str, label: str|None=None, metadata=None) -> Path:
 p=Path(directory); p.mkdir(parents=True,exist_ok=True); name=label or datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'); out=p/f'{name}.json'
 out.write_text(json.dumps({'created':datetime.now(timezone.utc).isoformat(),'metadata':metadata or {},'statistics':statistics(findings),'findings':findings},indent=2,default=str)); return out

def load(path: str):
 data=json.loads(Path(path).read_text()); return data.get('findings',data if isinstance(data,list) else [])

def diff(left: str, right: str): return compare(load(left),load(right))

def write_diff(result, path: str):
 Path(path).write_text(json.dumps(result,indent=2,default=str)); return Path(path)

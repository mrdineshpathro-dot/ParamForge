"""Filesystem-isolated workspaces without unsafe path interpolation."""
from pathlib import Path
import json, re

def safe_name(value):
 value=re.sub(r'[^A-Za-z0-9._-]+','-',value).strip('-')
 if not value: raise ValueError('workspace name cannot be empty')
 return value[:80]
class WorkspaceManager:
 def __init__(self, root='~/.paramforge/workspaces'):
  self.root=Path(root).expanduser(); self.root.mkdir(parents=True,exist_ok=True)
 def path(self,name): return self.root/safe_name(name)
 def create(self,name):
  p=self.path(name); p.mkdir(parents=True,exist_ok=True); (p/'workspace.json').write_text(json.dumps({'name':safe_name(name),'version':1},indent=2)); return p
 def list(self): return sorted(p.name for p in self.root.iterdir() if p.is_dir())
 def delete(self,name):
  p=self.path(name)
  if p.resolve().parent != self.root.resolve(): raise ValueError('invalid workspace path')
  import shutil
  if p.exists(): shutil.rmtree(p)
 def stats(self,name):
  p=self.path(name); return {'name':p.name,'files':sum(1 for x in p.rglob('*') if x.is_file())} if p.exists() else None

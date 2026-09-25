"""Safe local plugin discovery. Plugins are inspected, never executed during listing."""
from pathlib import Path
import importlib.util

def discover(directory='plugins'):
 root=Path(directory); result=[]
 if not root.exists(): return result
 for path in sorted(root.glob('*.py')):
  if path.name.startswith('_'): continue
  result.append({'name':path.stem,'path':str(path),'enabled':True})
 return result

def plugin_info(name, directory='plugins'):
 for x in discover(directory):
  if x['name']==name: return x
 return None

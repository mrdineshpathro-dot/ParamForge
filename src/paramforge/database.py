import sqlite3, json
from pathlib import Path
from .models import Finding
SCHEMA='''CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, started TEXT DEFAULT CURRENT_TIMESTAMP, target TEXT, mode TEXT);CREATE TABLE IF NOT EXISTS parameters(id INTEGER PRIMARY KEY, scan_id INTEGER, name TEXT, value TEXT, url TEXT, endpoint TEXT, host TEXT, method TEXT, source TEXT, classification TEXT, confidence REAL, interest_score INTEGER, first_seen TEXT, last_seen TEXT, redacted INTEGER, metadata TEXT);CREATE INDEX IF NOT EXISTS idx_params_name ON parameters(name);CREATE INDEX IF NOT EXISTS idx_params_score ON parameters(interest_score);CREATE INDEX IF NOT EXISTS idx_params_scan ON parameters(scan_id);'''
class Database:
 def __init__(self,path): self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self.con=sqlite3.connect(self.path); self.con.executescript(SCHEMA); self.con.commit()
 def add_scan(self,target,mode='passive'): cur=self.con.execute('INSERT INTO scans(target,mode) VALUES (?,?)',(target,mode)); self.con.commit(); return cur.lastrowid
 def add(self,scan_id,f):
  d=f.to_dict(); self.con.execute('INSERT INTO parameters(scan_id,name,value,url,endpoint,host,method,source,classification,confidence,interest_score,first_seen,last_seen,redacted,metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(scan_id,d['name'],d['value'],d['url'],d['endpoint'],d['host'],d['method'],d['source'],d['classification'],d['confidence'],d['interest_score'],d['first_seen'],d['last_seen'],d['redacted'],json.dumps(d['metadata']))); self.con.commit()
 def findings(self,scan_id=None):
  q='SELECT name,value,url,endpoint,host,method,source,classification,confidence,interest_score,first_seen,last_seen,redacted,metadata FROM parameters'; args=()
  if scan_id: q+=' WHERE scan_id=?'; args=(scan_id,)
  rows=self.con.execute(q,args).fetchall(); keys=['name','value','url','endpoint','host','method','source','classification','confidence','interest_score','first_seen','last_seen','redacted','metadata']
  return [dict(zip(keys,r)) for r in rows]
 def close(self): self.con.close()

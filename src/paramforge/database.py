"""SQLite storage with additive migrations; existing v1 databases remain readable."""
from __future__ import annotations
import json, sqlite3, shutil
from pathlib import Path
from .models import Finding
SCHEMA_VERSION=2
BASE='''CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, started TEXT DEFAULT CURRENT_TIMESTAMP, target TEXT, mode TEXT);CREATE TABLE IF NOT EXISTS parameters(id INTEGER PRIMARY KEY, scan_id INTEGER, name TEXT, value TEXT, url TEXT, endpoint TEXT, host TEXT, method TEXT, source TEXT, classification TEXT, confidence REAL, interest_score INTEGER, first_seen TEXT, last_seen TEXT, redacted INTEGER, metadata TEXT);CREATE INDEX IF NOT EXISTS idx_params_name ON parameters(name);CREATE INDEX IF NOT EXISTS idx_params_score ON parameters(interest_score);CREATE INDEX IF NOT EXISTS idx_params_scan ON parameters(scan_id);'''
MIGRATION='''CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS migration_history(version INTEGER PRIMARY KEY, applied_at TEXT DEFAULT CURRENT_TIMESTAMP);CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY, label TEXT UNIQUE, created TEXT DEFAULT CURRENT_TIMESTAMP, path TEXT, metadata TEXT);CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, scan_id INTEGER, kind TEXT, payload TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, kind TEXT, object_key TEXT, body TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);'''
class Database:
 def __init__(self,path):
  self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self.con=sqlite3.connect(self.path); self.con.row_factory=sqlite3.Row; self.con.executescript(BASE); self.migrate()
 def migrate(self):
  self.con.executescript(MIGRATION)
  if self.con.execute('SELECT COUNT(*) FROM schema_version').fetchone()[0]==0: self.con.execute('INSERT INTO schema_version VALUES (?)',(1,)); self.con.execute('INSERT INTO migration_history(version) VALUES (1)')
  current=self.con.execute('SELECT version FROM schema_version').fetchone()[0]
  if current<2: self.con.execute('UPDATE schema_version SET version=2'); self.con.execute('INSERT OR IGNORE INTO migration_history(version) VALUES (2)')
  self.con.commit()
 def add_scan(self,target,mode='passive'):
  cur=self.con.execute('INSERT INTO scans(target,mode) VALUES (?,?)',(target,mode)); self.con.commit(); return cur.lastrowid
 def add(self,scan_id,f):
  d=f.to_dict() if hasattr(f,'to_dict') else f
  self.con.execute('INSERT INTO parameters(scan_id,name,value,url,endpoint,host,method,source,classification,confidence,interest_score,first_seen,last_seen,redacted,metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(scan_id,d.get('name'),d.get('value',''),d.get('url',''),d.get('endpoint',''),d.get('host',''),d.get('method','GET'),d.get('source','unknown'),d.get('classification','unknown'),d.get('confidence',0),d.get('interest_score',0),d.get('first_seen'),d.get('last_seen'),int(bool(d.get('redacted',False))),json.dumps(d.get('metadata',{})))); self.con.commit()
 def add_many(self,scan_id,findings):
  for f in findings: self.add(scan_id,f)
  self.con.commit()
 def findings(self,scan_id=None):
  q='SELECT name,value,url,endpoint,host,method,source,classification,confidence,interest_score,first_seen,last_seen,redacted,metadata FROM parameters'; args=()
  if scan_id is not None: q+=' WHERE scan_id=?'; args=(scan_id,)
  return [dict(r) for r in self.con.execute(q,args)]
 def search(self, term='', field='name', min_score=None, source=None, classification=None, host=None):
  allowed={'name','url','endpoint','host','source','classification'}; field=field if field in allowed else 'name'; q=f'SELECT * FROM parameters WHERE lower({field}) LIKE ?'; args=[f'%{term.lower()}%']
  for col,val,op in [('interest_score',min_score,'>='),('source',source,'='),('classification',classification,'='),('host',host,'=')]:
   if val is not None: q+=f' AND {col}{op}?'; args.append(val)
  return [dict(r) for r in self.con.execute(q,args)]
 def add_event(self,scan_id,kind,payload): self.con.execute('INSERT INTO events(scan_id,kind,payload) VALUES (?,?,?)',(scan_id,kind,json.dumps(payload))); self.con.commit()
 def add_note(self,kind,key,body): self.con.execute('INSERT INTO notes(kind,object_key,body) VALUES (?,?,?)',(kind,key,body)); self.con.commit()
 def stats(self): return {'schema_version':self.con.execute('SELECT version FROM schema_version').fetchone()[0],'scans':self.con.execute('SELECT COUNT(*) FROM scans').fetchone()[0],'parameters':self.con.execute('SELECT COUNT(*) FROM parameters').fetchone()[0],'events':self.con.execute('SELECT COUNT(*) FROM events').fetchone()[0]}
 def backup(self,destination): self.con.commit(); shutil.copy2(self.path,destination); return Path(destination)
 def vacuum(self): self.con.execute('VACUUM'); self.con.commit()
 def close(self): self.con.close()

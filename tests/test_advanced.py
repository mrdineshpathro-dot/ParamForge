import json
from paramforge.intelligence import normalize_name, compare, statistics, graph_edges
from paramforge.snapshots import save, diff
from paramforge.database import Database
from paramforge.discovery import extract_javascript

def test_normalization_and_graph():
 assert normalize_name('User-ID2') == 'user_id'
 data=[{'name':'redirect','host':'e.test','endpoint':'/login','source':'html','classification':'redirect','interest_score':80}]
 assert statistics(data)['unique_parameters']==1
 assert any(e['relation']=='accepts' for e in graph_edges(data))

def test_snapshot_compare(tmp_path):
 a=[{'name':'lang','host':'e','endpoint':'/x','source':'html'}]
 b=[{'name':'next','host':'e','endpoint':'/x','source':'js'}]
 p1=save(a,tmp_path,'one'); p2=save(b,tmp_path,'two'); result=diff(str(p1),str(p2))
 assert len(result['new'])==1 and len(result['removed'])==1

def test_database_migration_and_search(tmp_path):
 db=Database(tmp_path/'scan.db'); sid=db.add_scan('https://e.test'); db.add(sid,{'name':'redirect','classification':'redirect','interest_score':80,'source':'html'}); db.con.commit()
 assert db.stats()['schema_version']==2 and len(db.search('redir',min_score=70))==1
 db.close()

def test_javascript_is_parsed_as_untrusted_text():
 result=extract_javascript("fetch('/api/search?q=x')", 'https://e.test/')
 assert result['routes'] == ['https://e.test/api/search?q=x']
 assert any(item.name == 'q' for item in result['findings'])

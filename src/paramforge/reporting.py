import csv,json,html
from pathlib import Path

def export(findings,outdir, target='scan'):
 p=Path(outdir); p.mkdir(parents=True,exist_ok=True)
 (p/'parameters.json').write_text(json.dumps(findings,indent=2,default=str))
 with (p/'parameters.csv').open('w',newline='') as f:
  fields=['name','classification','endpoint','score','source','url']; w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
  for x in findings: w.writerow({'name':x.get('name'),'classification':x.get('classification'),'endpoint':x.get('endpoint'),'score':x.get('interest_score',x.get('score',0)),'source':x.get('source'),'url':x.get('url')})
 lines=['# ParamForge report','',f'**Target:** {target}',f'**Parameters:** {len(findings)}','', '| Name | Type | Score | Source |','|---|---|---:|---|']
 lines += [f"| {x.get('name')} | {x.get('classification')} | {x.get('interest_score',0)} | {x.get('source')} |" for x in sorted(findings,key=lambda x:x.get('interest_score',0),reverse=True)]
 (p/'report.md').write_text('\n'.join(lines))
 rows=''.join(f"<tr><td>{html.escape(str(x.get('name')))}</td><td>{html.escape(str(x.get('classification')))}</td><td>{x.get('interest_score',0)}</td><td>{html.escape(str(x.get('endpoint')))}</td></tr>" for x in findings)
 (p/'report.html').write_text(f'<!doctype html><meta charset="utf-8"><title>ParamForge report</title><style>body{{font:16px system-ui;background:#101522;color:#eee;padding:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{padding:.6rem;border-bottom:1px solid #39425c;text-align:left}}th{{color:#55d6be}}</style><h1>ParamForge</h1><p>{html.escape(target)} — {len(findings)} parameters</p><table><tr><th>Name</th><th>Type</th><th>Score</th><th>Endpoint</th></tr>{rows}</table>')
 (p/'parameters.txt').write_text('\n'.join(f"{x.get('name')}\t{x.get('classification')}\t{x.get('interest_score',0)}\t{x.get('url')}" for x in findings))
 return p

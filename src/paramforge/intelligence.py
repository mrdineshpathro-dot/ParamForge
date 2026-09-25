"""Offline-first analytics over normalized ParamForge findings."""
from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
import csv, json, re, unicodedata
from urllib.parse import unquote, urlsplit

ALIASES = {"q":"query", "kw":"keyword", "pg":"page", "uid":"user_id", "userid":"user_id", "redirect_uri":"redirect"}

def normalize_name(name: str) -> str:
    name = unicodedata.normalize("NFKC", unquote(str(name))).strip().casefold()
    name = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)
    name = re.sub(r"(?:[_-]?(?:v|ver|version)?\d+)$", "", name)
    name = re.sub(r"(?:[_-]?\d+)$", "", name)
    name = re.sub(r"[-\s]+", "_", name)
    return ALIASES.get(name, name)

def endpoint_template(path: str) -> str:
    return re.sub(r"/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,})(?=/|$)", "/{id}", path or "/")

def enrich(findings: list[dict]) -> list[dict]:
    groups = Counter(normalize_name(x.get("name", "")) for x in findings)
    sources = defaultdict(set)
    for x in findings: sources[normalize_name(x.get("name", ""))].add(x.get("source", "unknown"))
    result=[]
    for item in findings:
        x=dict(item); key=normalize_name(x.get("name", "")); x["normalized_name"]=key
        x["endpoint_template"]=endpoint_template(x.get("endpoint", ""))
        x["frequency"]=groups[key]; x["source_count"]=len(sources[key])
        x["discovery_confidence"]=round(min(1.0, float(x.get("confidence", .5)) + .05*max(0,len(sources[key])-1)), 3)
        result.append(x)
    return result

def statistics(findings: list[dict]) -> dict:
    fs=enrich(findings); urls={x.get("url") for x in fs if x.get("url")}; hosts={x.get("host") for x in fs if x.get("host")}
    return {"total_parameters":len(fs),"unique_parameters":len({x["normalized_name"] for x in fs}),"urls":len(urls),"hosts":len(hosts),"endpoints":len({(x.get("host"),x.get("endpoint_template",x.get("endpoint"))) for x in fs}),"sources":dict(Counter(x.get("source","unknown") for x in fs)),"classifications":dict(Counter(x.get("classification","unknown") for x in fs)),"scores":{"high":sum(x.get("interest_score",0)>=70 for x in fs),"medium":sum(40<=x.get("interest_score",0)<70 for x in fs),"low":sum(x.get("interest_score",0)<40 for x in fs)}}

def distribution(findings: list[dict], field="classification") -> list[tuple[str,int,float]]:
 c=Counter(x.get(field,"unknown") for x in findings); total=max(1,sum(c.values())); return [(k,v,round(v*100/total,1)) for k,v in c.most_common()]

def compare(old: list[dict], new: list[dict]) -> dict:
 key=lambda x:(x.get("host"),endpoint_template(x.get("endpoint","")),normalize_name(x.get("name","")))
 a={key(x):x for x in old}; b={key(x):x for x in new}
 return {"new":[b[k] for k in b.keys()-a.keys()],"removed":[a[k] for k in a.keys()-b.keys()],"changed":[{"before":a[k],"after":b[k]} for k in a.keys()&b.keys() if (a[k].get("classification"),a[k].get("source")) != (b[k].get("classification"),b[k].get("source"))]}

def graph_edges(findings: list[dict]) -> list[dict]:
 edges=set()
 for x in enrich(findings):
  d=x.get("host") or "unknown"; e=f"{d}{x.get('endpoint_template',x.get('endpoint','/'))}"; p=f"param:{x.get('normalized_name')}"; s=f"source:{x.get('source','unknown')}"
  edges.update([(d,e,"contains"),(e,p,"accepts"),(e,s,"observed_from")])
 return [{"source":a,"target":b,"relation":r} for a,b,r in sorted(edges)]

def export_graph(findings: list[dict], path: str, fmt: str|None=None):
 p=Path(path); fmt=(fmt or p.suffix.lstrip('.')).lower(); edges=graph_edges(findings)
 if fmt=='csv':
  with p.open('w',newline='') as f:
   w=csv.DictWriter(f,fieldnames=['source','target','relation']); w.writeheader(); w.writerows(edges)
 elif fmt=='dot':
  p.write_text('digraph ParamForge {\n'+'\n'.join(f'  "{e["source"]}" -> "{e["target"]}" [label="{e["relation"]}"];' for e in edges)+'\n}\n')
 elif fmt=='graphml':
  p.write_text('<?xml version="1.0"?><graphml xmlns="http://graphml.graphdrawing.org/xmlns"><graph edgedefault="directed">'+''.join(f'<edge source="{e["source"]}" target="{e["target"]}"/> ' for e in edges)+'</graph></graphml>')
 else: p.write_text(json.dumps({"edges":edges},indent=2))
 return p

def chart(findings: list[dict], field="classification", width=28) -> str:
 return "\n".join(f"{name:<16} {'█'*max(1,round(p/100*width)):<{width}} {p:>5.1f}%" for name,_,p in distribution(findings,field))

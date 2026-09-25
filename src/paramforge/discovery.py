from urllib.parse import urlparse, parse_qsl, urljoin
from html.parser import HTMLParser
import json, re
from .models import Finding
from .analysis import classify, score, redact

class HTMLDiscovery(HTMLParser):
    def __init__(self, base):
        super().__init__(); self.base=base; self.links=[]; self.forms=[]; self.scripts=[]; self.findings=[]; self._form=None
    def handle_starttag(self, tag, attrs):
        a=dict(attrs)
        if tag in ('a','link','img') and a.get('href' if tag!='img' else 'src'): self.links.append(urljoin(self.base,a.get('href',a.get('src'))))
        if tag=='script' and a.get('src'): self.scripts.append(urljoin(self.base,a['src']))
        if tag=='form': self._form={'action':urljoin(self.base,a.get('action','')), 'method':a.get('method','GET').upper(), 'names':[]}; self.forms.append(self._form)
        if self._form and tag in ('input','select','textarea') and a.get('name'): self._form['names'].append(a['name'])
    def handle_endtag(self, tag):
        if tag=='form': self._form=None

def extract_url(url, source='direct', method='GET', redact_values=True):
    p=urlparse(url); out=[]
    pairs=parse_qsl(p.query, keep_blank_values=True)
    # fragments commonly contain query-like data
    if p.fragment and '=' in p.fragment: pairs += parse_qsl(p.fragment.lstrip('?#'),keep_blank_values=True)
    for name,value in pairs:
        kind,conf=classify(name,value); val=redact(name,value) if redact_values else value
        s,_=score(name,value,classification=kind)
        out.append(Finding(name,val,url,f'{p.path or "/"}',p.netloc,method,source,kind,conf,s,redacted=val!=value))
    return out

def extract_json(value, url='', source='json'):
    try: data=json.loads(value)
    except (TypeError,json.JSONDecodeError): return []
    def walk(x):
        if isinstance(x,dict):
            for k,v in x.items():
                if isinstance(v,(str,int,float,bool)):
                    yield Finding(k,redact(k,str(v)),url,urlparse(url).path,urlparse(url).netloc,'POST',source,*classify(k,str(v)),interest_score=score(k,str(v),classification=classify(k,str(v))[0])[0])
                else: yield from walk(v)
        elif isinstance(x,list):
            for v in x: yield from walk(v)
    return list(walk(data))

def extract_html(html,url,source='html'):
    parser=HTMLDiscovery(url); parser.feed(html); findings=[]
    for form in parser.forms:
        for name in form['names']: findings += extract_url(form['action']+'?'+name+'=', 'form', form['method'])
    for link in parser.links: findings += extract_url(link,source)
    return parser, findings

def extract_javascript(script: str, base_url: str = '', source: str = 'javascript'):
    """Extract route-like strings and nearby parameter names without executing JavaScript."""
    routes=[]; findings=[]
    patterns=(r'''["']((?:https?://|/)(?:[^"'\\s]+))["']''', r'''(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest)[^;]{0,300}?["']([^"']+)["']''')
    for pattern in patterns:
        for match in re.findall(pattern,script,re.I):
            route=urljoin(base_url,match) if base_url else match
            if route not in routes: routes.append(route)
    for route in routes: findings.extend(extract_url(route,source))
    # Common query/body object keys are useful even when route values are templated.
    for name in set(re.findall(r'''(?:[?&]|[,{]\s*)([A-Za-z_][\w-]*)\s*[:=]''',script)):
        kind,conf=classify(name,''); findings.append(Finding(name,'',base_url,urlparse(base_url).path,urlparse(base_url).netloc,'GET',source,kind,conf,score(name,'',classification=kind)[0]))
    return {'routes':routes,'findings':findings,'websockets':re.findall(r'''wss?://[^"'\\s]+''',script,re.I)}

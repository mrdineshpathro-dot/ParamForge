import re
from collections import Counter
from urllib.parse import urlparse

KEYWORDS = {
 'id':'identifier','page':'pagination','offset':'pagination','limit':'pagination','search':'search',
 'q':'search','query':'search','sort':'sorting','order':'sorting','filter':'filtering','lang':'language',
 'locale':'language','redirect':'redirect','return':'redirect','next':'redirect','url':'url-like',
 'uri':'url-like','callback':'callback','file':'file-like','path':'path-like','template':'template-like',
 'ref':'reference','token':'token-like','key':'api-key-like','api_key':'api-key-like'
}
SENSITIVE = re.compile(r'(pass(word)?|secret|token|api[_-]?key|auth|cookie)', re.I)

def classify(name: str, value: str = '') -> tuple[str,float]:
    n=name.lower().replace('-','_')
    if n in KEYWORDS: return KEYWORDS[n], .96
    if any(x in n for x in ('search','query','keyword','term')): return 'search', .82
    if any(x in n for x in ('page','offset','limit')): return 'pagination', .82
    if re.fullmatch(r'[a-f0-9]{32,}', value, re.I): return 'hash-like', .8
    if re.fullmatch(r'\d{1,13}', value): return ('timestamp' if len(value)>9 else 'numeric-id'), .75
    if re.match(r'https?://', value): return 'url-like', .9
    return 'unknown', .45

def score(name: str, value: str, frequency=1, sources=1, classification='unknown') -> tuple[int,list[str]]:
    points= min(20, frequency*3)+min(15,sources*5); reasons=[]
    if classification != 'unknown': points += 20; reasons.append(f'{classification} naming/value pattern')
    if SENSITIVE.search(name): points += 12; reasons.append('sensitive-looking field (value redacted)')
    if classification in ('redirect','url-like','file-like','path-like','callback'): points += 18
    if frequency > 1: reasons.append(f'appears across {frequency} observations')
    return min(100,points), reasons

def redact(name,value): return '[REDACTED]' if SENSITIVE.search(name) else value

def fingerprint(url):
    p = urlparse(url)
    path = re.sub(r'/\\d+', '/{id}', p.path)
    return p.netloc + path + '?'

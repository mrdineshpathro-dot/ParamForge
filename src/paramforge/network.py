import time
from urllib.parse import urlparse
import httpx
from .discovery import extract_url, extract_html
class Scope:
 def __init__(self, target, allow=(), deny=()):
  self.host=urlparse(target).netloc.lower(); self.allow=set(x.lower() for x in allow) or {self.host}; self.deny=set(x.lower() for x in deny)
 def permits(self,url):
  h=urlparse(url).netloc.lower(); return h in self.allow and h not in self.deny
class Client:
 def __init__(self,timeout=10, rate_limit=5): self.client=httpx.Client(timeout=timeout,follow_redirects=True,headers={'User-Agent':'ParamForge/1.0'}); self.interval=1/rate_limit if rate_limit else 0; self.last=0
 def get(self,url):
  time.sleep(max(0,self.interval-(time.monotonic()-self.last))); self.last=time.monotonic(); return self.client.get(url)
 def close(self): self.client.close()
def scan_url(url, client, scope, crawl=False):
 if not scope.permits(url): return [], [], None
 try:
  response=client.get(url); parser, findings=extract_html(response.text,url) if 'text/html' in response.headers.get('content-type','') else (None,extract_url(url))
  return findings, (parser.links if parser else []), response
 except httpx.HTTPError: return [],[],None

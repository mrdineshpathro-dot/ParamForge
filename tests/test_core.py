from paramforge.discovery import extract_url, extract_html, extract_json
from paramforge.analysis import classify, redact

def test_url_extraction_and_classification():
 f=extract_url('https://example.test/items?page=2&redirect=https%3A%2F%2Fexample.org')
 assert {x.name for x in f}=={'page','redirect'}
 assert next(x for x in f if x.name=='page').classification=='pagination'
 assert next(x for x in f if x.name=='redirect').interest_score>0

def test_sensitive_redaction(): assert redact('api_key','secret')=='[REDACTED]'

def test_html_and_json():
 p,f=extract_html('<a href="/search?q=one">x</a><form action="/login"><input name="return"></form>','https://e.test/')
 assert 'https://e.test/search?q=one' in p.links and any(x.name=='q' for x in f)
 assert any(x.name=='return' for x in extract_html('<form action="/x"><input name="return"></form>','https://e.test/')[1])
 assert extract_json('{"page": 3}', 'https://e.test/api')[0].name=='page'

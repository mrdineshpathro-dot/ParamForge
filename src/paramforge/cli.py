from pathlib import Path
import json,sys,platform,sqlite3
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from . import __version__
from .config import Config
from .discovery import extract_url
from .network import Client,Scope,scan_url
from .database import Database
from .reporting import export
app=typer.Typer(help='Advanced URL Parameter Discovery & Recon Intelligence Framework',no_args_is_help=True); console=Console()

def banner(): console.print(Panel('[bold cyan]PARAMFORGE[/bold cyan]\nAdvanced Parameter Discovery Framework\n[dim]by Mr Dinesh Pathro[/dim]',border_style='magenta'))
@app.callback()
def root(): pass
@app.command()
def version(): """Display version information."""; console.print(f'ParamForge v{__version__}\nAdvanced Parameter Discovery Framework\nAuthor: Mr Dinesh Pathro')
@app.command()
def doctor():
 """Check local runtime health."""
 banner()
 checks=[('Python 3.11+',sys.version_info>=(3,11)),('SQLite',sqlite3.sqlite_version is not None),('UTF-8',sys.stdout.encoding.lower().replace('-','')=='utf8'),('Write permissions',Path('.').is_dir())]
 for n,ok in checks:
  console.print(f"{'[green]✓[/green]' if ok else '[red]✗[/red]'} {n}")
@app.command()
def scan(target: str=typer.Argument(None), url: str=typer.Option(None,'-u'), list_file: Path=typer.Option(None,'-l'), output: Path=typer.Option('results','--output','-o'), passive: bool=typer.Option(False), crawl: bool=typer.Option(False), workers:int=typer.Option(10), rate_limit:float=typer.Option(5), timeout:float=typer.Option(10), allow_domain:list[str]=typer.Option([], '--allow-domain'), deny_domain:list[str]=typer.Option([], '--deny-domain'), no_color:bool=typer.Option(False)):
 """Discover and rank parameters from authorized URLs."""
 global console
 if no_color: console=Console(no_color=True)
 banner(); inputs=[]
 if target or url: inputs.append(target or url)
 if list_file: inputs += [x.strip() for x in list_file.read_text().splitlines() if x.strip() and not x.startswith('#')]
 if not inputs: inputs=[x.strip() for x in sys.stdin if x.strip()]
 if not inputs: raise typer.BadParameter('provide TARGET, -u, -l, or stdin')
 allf=[]; client=Client(timeout,rate_limit)
 try:
  for item in inputs:
   if not item.startswith(('http://','https://')): item='https://'+item
   scope=Scope(item,allow_domain or [__import__('urllib.parse',fromlist=['urlparse']).urlparse(item).netloc],deny_domain)
   f=extract_url(item,'direct'); links=[]; response=None
   if not passive:
    f2,links,response=scan_url(item,client,scope,crawl); f += f2
   allf += f
   console.print(f'[cyan]{item}[/cyan]  [green]{len(f)} parameters[/green]')
 finally: client.close()
 # value-independent dedupe
 unique={ (x.name,x.host,x.endpoint,x.classification):x for x in allf }; findings=[x.to_dict() for x in unique.values()]
 dest=output/(__import__('urllib.parse',fromlist=['urlparse']).urlparse(inputs[0]).netloc or 'scan'); export(findings,dest,inputs[0]); db=Database(dest/'scan.db'); sid=db.add_scan(inputs[0],'passive' if passive else 'active')
 for x in unique.values(): db.add(sid,x)
 db.close(); console.print(f'\n[bold green]Scan completed[/bold green] — {len(findings)} unique parameters\nResults saved to {dest}')
@app.command()
def crawl(target: str=typer.Argument(...), output: Path=typer.Option('results','--output','-o'), rate_limit: float=typer.Option(5), timeout: float=typer.Option(10)):
 """Crawl one authorized target with controlled requests."""
 scan(target=target, output=output, crawl=True, rate_limit=rate_limit, timeout=timeout)

@app.command()
def config():
 """Print a starter configuration template."""
 console.print('''target:\n  max_depth: 2\n  timeout: 10\nnetwork:\n  workers: 10\n  rate_limit: 5\n  retries: 2\ndiscovery:\n  crawl: false\n  javascript: true\noutput:\n  directory: ./results\nprivacy:\n  redact_sensitive_values: true''')

@app.command()
def update():
 """Show the safe update workflow (no network execution)."""
 console.print('Install the latest signed release with: git pull && pip install -e .')

@app.command()
def analyze(results: Path=typer.Argument(...,exists=True)): 
 """Inspect a JSON result file."""; data=json.loads(results.read_text()); table=Table(title='Parameter inventory'); [table.add_column(c) for c in ('Parameter','Type','Endpoint','Score','Source')]
 for x in sorted(data,key=lambda y:y.get('interest_score',0),reverse=True): table.add_row(str(x.get('name')),str(x.get('classification')),str(x.get('endpoint')),str(x.get('interest_score',0)),str(x.get('source')))
 console.print(table)
@app.command()
def report(database: Path=typer.Argument(...,exists=True), output: Path=typer.Option('report')):
 """Export a SQLite scan database."""; db=Database(database); p=export(db.findings(),output,'SQLite scan'); db.close(); console.print(f'Report written to {p}')
if __name__=='__main__': app()

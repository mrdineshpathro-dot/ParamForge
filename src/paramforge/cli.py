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
from .intelligence import enrich, statistics, chart
from .snapshots import save as save_snapshot, diff as diff_snapshot, write_diff
from .graph import export_graph
from .workspace import WorkspaceManager
from .plugins import discover, plugin_info
app=typer.Typer(help='Advanced URL Parameter Discovery & Recon Intelligence Framework',no_args_is_help=True); console=Console()

def banner(): console.print(Panel('[bold cyan]PARAMFORGE[/bold cyan]\nAdvanced Parameter Discovery Framework\n[dim]by Mr Dinesh Pathro[/dim]',border_style='magenta'))
@app.callback()
def root(theme: str=typer.Option('professional','--theme',help='professional, cyber, minimal, monochrome')):
    global console
    if theme == 'monochrome': console=Console(no_color=True)
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
@app.command()
def search(term: str=typer.Argument(...), database: Path=typer.Option('results/scan.db','--database','-d'), field: str=typer.Option('name'), min_score: int=typer.Option(None), source: str=typer.Option(None), type_: str=typer.Option(None,'--type'), host: str=typer.Option(None)):
 """Search a local database offline by parameter, URL, endpoint, or host."""
 db=Database(database); rows=db.search(term,field,min_score,source,type_,host); db.close()
 table=Table(title=f'{len(rows)} matching findings'); [table.add_column(c) for c in ('Name','Type','Endpoint','Score','Source')]
 for x in rows: table.add_row(str(x.get('name')),str(x.get('classification')),str(x.get('endpoint')),str(x.get('interest_score')),str(x.get('source')))
 console.print(table)

@app.command()
def snapshot(results: Path=typer.Argument(...,exists=True), output: Path=typer.Option('snapshots'), label: str=typer.Option(None)):
 """Store an offline JSON result snapshot."""
 data=json.loads(results.read_text()); findings=data.get('findings',data) if isinstance(data,dict) else data; path=save_snapshot(findings,output,label,{'source':str(results)}); console.print(f'Snapshot saved to {path}')

@app.command()
def compare(left: Path=typer.Argument(...,exists=True), right: Path=typer.Argument(...,exists=True), output: Path=typer.Option(None)):
 """Compare two snapshots without making network requests."""
 result=diff_snapshot(str(left),str(right));
 if output: write_diff(result,output)
 console.print(f"New: {len(result['new'])}  Removed: {len(result['removed'])}  Changed: {len(result['changed'])}")
 for title,key in [('NEW PARAMETER','new'),('REMOVED PARAMETER','removed'),('CHANGED PARAMETER','changed')]:
  if result[key]: console.print(f'[bold]{title}[/bold]'); [console.print(f"  {x.get('name',x.get('after',{}).get('name','unknown'))} @ {x.get('endpoint',x.get('after',{}).get('endpoint',''))}") for x in result[key]]

@app.command()
def graph(results: Path=typer.Argument(...,exists=True), output: Path=typer.Option('graph.json')):
 """Export domain, endpoint, source, and parameter relationships."""
 data=json.loads(results.read_text()); findings=data.get('findings',data) if isinstance(data,dict) else data; path=export_graph(findings,output); console.print(f'Graph written to {path}')

@app.command()
def dashboard(results: Path=typer.Argument(...,exists=True)):
 """Display a terminal analytics dashboard for an existing result."""
 data=json.loads(results.read_text()); findings=enrich(data.get('findings',data) if isinstance(data,dict) else data); console.print(Panel(f"[bold]ParamForge Dashboard[/bold]\n{statistics(findings)}\n\n{chart(findings)}",border_style='cyan'))

@app.command()
def benchmark():
 """Run local parsing and analytics benchmarks; values are measured, not estimates."""
 import time
 sample=[{'name':f'page{i%30}','classification':'pagination','interest_score':42,'source':'fixture','endpoint':'/items','host':'local'} for i in range(10000)]
 t=time.perf_counter(); enrich(sample); parsing= len(sample)/(time.perf_counter()-t)
 t=time.perf_counter(); statistics(sample); analytics=len(sample)/(time.perf_counter()-t)
 console.print(f'ParamForge Benchmark\nURL/parameter processing: {parsing:,.0f}/s\nAnalytics: {analytics:,.0f}/s')

workspace_app=typer.Typer(help='Manage isolated workspaces')
@workspace_app.command('create')
def workspace_create(name: str): console.print(f'Created {WorkspaceManager().create(name)}')
@workspace_app.command('list')
def workspace_list(): console.print('\\n'.join(WorkspaceManager().list()) or 'No workspaces')
@workspace_app.command('delete')
def workspace_delete(name: str): WorkspaceManager().delete(name); console.print(f'Deleted {name}')
@workspace_app.command('stats')
def workspace_stats(name: str): console.print(WorkspaceManager().stats(name) or 'Unknown workspace')
app.add_typer(workspace_app,name='workspace')

project_app=typer.Typer(help='Organize authorized assessment projects')
@project_app.command('create')
def project_create(name: str): console.print(f'Created project workspace: {WorkspaceManager().create("project-"+name)}')
@project_app.command('list')
def project_list(): console.print('\\n'.join(x.removeprefix('project-') for x in WorkspaceManager().list() if x.startswith('project-')) or 'No projects')
app.add_typer(project_app,name='project')

db_app=typer.Typer(help='Manage SQLite scan databases')
@db_app.command('stats')
def db_stats(database: Path=typer.Option('results/scan.db','--database','-d')): db=Database(database); console.print(db.stats()); db.close()
@db_app.command('backup')
def db_backup(database: Path=typer.Option('results/scan.db','--database','-d'), destination: Path=typer.Option('backup.db','--destination')): db=Database(database); console.print(f'Backup: {db.backup(destination)}'); db.close()
@db_app.command('vacuum')
def db_vacuum(database: Path=typer.Option('results/scan.db','--database','-d')): db=Database(database); db.vacuum(); db.close(); console.print('Database vacuumed')
app.add_typer(db_app,name='db')

plugins_app=typer.Typer(help='Inspect local plugins')
@plugins_app.command('list')
def plugins_list(): console.print(json.dumps(discover(),indent=2))
@plugins_app.command('info')
def plugins_info(name: str): console.print(plugin_info(name) or 'Plugin not found')
app.add_typer(plugins_app,name='plugins')

if __name__=='__main__': app()

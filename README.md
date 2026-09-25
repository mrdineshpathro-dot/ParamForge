# ParamForge
## Advanced URL Parameter Discovery & Recon Intelligence Framework

ParamForge is a safe, explainable reconnaissance tool for discovering, normalizing, classifying, correlating, scoring, and reporting URL, HTML-form, JSON, and JavaScript-adjacent parameters. It does not exploit findings or send destructive payloads.

Created by **Mr Dinesh Pathro**. Support: https://buymeacoffee.com/mrdineshpathro

## Installation

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
paramforge doctor
```

## Usage

```bash
paramforge scan https://example.com --passive
paramforge scan -l urls.txt --crawl --rate-limit 5 --output results
cat urls.txt | paramforge scan --passive
paramforge analyze results/example.com/parameters.json
paramforge report results/example.com/scan.db --output report
paramforge version
```

Every request is scope checked, rate limited, bounded by explicit input, and sensitive-looking values are redacted by default. Use only on systems you own or are authorized to assess. Respect program scope, privacy, applicable law, and target rate limits.

## Outputs

Each scan writes JSON, CSV, TXT, Markdown, HTML, and SQLite files. JSON findings carry name, example value, URL, endpoint, host, source, method, classification, confidence, score, timestamps, and redaction metadata.

## Architecture

The small, dependency-light core is organized into configuration, typed findings, discovery/parsing, network/scope controls, SQLite persistence, reporting, and Typer/Rich CLI layers. The analyzer includes explainable keyword, value-shape, frequency, source, and sensitivity heuristics.

## Testing

```bash
python -m pytest -q
python -m compileall src
```

## Responsible use

ParamForge is intended for authorized penetration testing, in-scope bug bounty work, owned systems, educational labs, and defensive research. Passive mode avoids network requests; active mode is deliberately controlled and does not implement credential attacks, bypasses, exploit payloads, or denial-of-service behavior.

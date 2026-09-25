# troubleshooting

This ParamForge subsystem is offline-first, deterministic, and designed for authorized assessment. Use the corresponding CLI help for options. Inputs are treated as untrusted data; downloaded scripts are parsed as text and never executed.

## Operational notes

Results are persisted in SQLite or JSON, sensitive values are redacted by default, and changes are observations rather than vulnerability claims. Keep targets within written authorization and configured scope.

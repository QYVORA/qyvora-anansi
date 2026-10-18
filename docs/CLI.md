# CLI Reference

`anansi` follows the shared QYVORA tier grammar:

```
anansi <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

| Command | Purpose |
|---------|---------|
| `anansi recon completion` | Generate a shell completion script |
| `anansi recon exploit` | PoC/exploitation layer: list, inspect and run exploit modules |
| `anansi recon help` | Help about any command |
| `anansi recon scan` | Run a scan against a target |
| `anansi recon tui` | start the interactive terminal application |
| `anansi recon updates` | Update the ANANSI CLI from official QYVORA releases |
| `anansi recon version` | Print the ANANSI CLI version |

## exploit

| Command | Purpose |
|---------|---------|
| `anansi exploit info` | Show metadata for one exploit module |
| `anansi exploit list` | List available exploit modules |
| `anansi exploit run` | Run one exploit module against a URL (requires --authorized) |

## report

| Command | Purpose |
|---------|---------|
| `anansi report completion` | Generate a shell completion script |
| `anansi report exploit` | PoC/exploitation layer: list, inspect and run exploit modules |
| `anansi report help` | Help about any command |
| `anansi report scan` | Run a scan against a target |
| `anansi report tui` | start the interactive terminal application |
| `anansi report updates` | Update the ANANSI CLI from official QYVORA releases |
| `anansi report version` | Print the ANANSI CLI version |

## Utilities

| Command | Purpose |
|---------|---------|
| `anansi scan` | Run a scan against a target |
| `anansi tui` | start the interactive terminal application |
| `docs script <file>` | Run a `.qs` script with the shared scripting engine (`run`/`build` subcommands) |

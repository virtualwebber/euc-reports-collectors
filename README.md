# EUC Reports — Collectors

Public distribution and **self-update source** for the EUC Reports data collectors.

## Published

- **`Get-OnPremComponentsData.ps1`** — Citrix on-premises component collector (Cloud Connector /
  StoreFront / FAS / VDA / Provisioning Server): machine spec, Citrix component versions,
  StoreFront + IIS/TLS hardening, FAS configuration & health (incl. KB5014754 strong certificate
  binding), PVS farm, and performance sampling. Produces one `OnPrem-<server>-<timestamp>.json`
  per server for the Citrix DaaS report.

## Self-update

On launch (interactive only), the collector reads the tiny **`Get-OnPremComponentsData.version`** file
in this repo (a few bytes) and compares it to its own `$script:_version`. Only if that says a newer
version exists does it download the full `.ps1`, then offer to update and relaunch — so the routine
check is very lightweight.

- Skip with `-SkipUpdateCheck`; also skipped in headless runs (`-NoSplash`).
- Fail-safe: short timeout, silent on any failure (no/limited internet is fine).
- The current file is backed up to `<name>.bak` before it is replaced.

> This repo must stay **public** so servers can fetch the raw files anonymously over HTTPS. There is no
> token in the distributed script.

## Files

| File | Purpose |
|---|---|
| `Get-OnPremComponentsData.ps1` | The collector script (the full download served on update). |
| `Get-OnPremComponentsData.version` | Tiny version marker read by the launch-time check (a few bytes). |

## Releasing

1. Bump `$script:_version` in the script (`YYYY-MM-DD` or `YYYY-MM-DD.rev`) — it must increase
   ([version] comparison).
2. Copy the script here **and** write its version into `Get-OnPremComponentsData.version` (derive it
   from the script's `$script:_version` so the two never drift), then commit and push to `main`.

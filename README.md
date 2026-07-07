# EUC Reports — Collectors

Public distribution and **self-update source** for the EUC Reports data collectors.

## Published

- **`Get-OnPremComponentsData.ps1`** — Citrix on-premises component collector (Cloud Connector /
  StoreFront / FAS / VDA / Provisioning Server): machine spec, Citrix component versions,
  StoreFront + IIS/TLS hardening, FAS configuration & health (incl. KB5014754 strong certificate
  binding), PVS farm, and performance sampling. Produces one `OnPrem-<server>-<timestamp>.json`
  per server for the Citrix DaaS report.

## Self-update

On launch (interactive only), the collector reads the raw copy of itself in this repo — specifically
its `$script:_version` line — and, if a newer version is available, offers to download it and relaunch.

- Skip with `-SkipUpdateCheck`; also skipped in headless runs (`-NoSplash`).
- Fail-safe: short timeout, silent on any failure (no/limited internet is fine).
- The current file is backed up to `<name>.bak` before it is replaced.

> This repo must stay **public** so servers can fetch the raw file anonymously over HTTPS. There is no
> token in the distributed script.

## Releasing

Bump `$script:_version` in the script (`YYYY-MM-DD` or `YYYY-MM-DD.rev`), commit, and push to `main`.
The collector compares versions with `[version]` semantics, so every release must increase it.

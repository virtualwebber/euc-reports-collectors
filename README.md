# EUC Reports — Collectors

Public distribution and **self-update source** for the EUC Reports data collectors.

## Published

- **`Get-OnPremComponentsData.ps1`** — Citrix on-premises component collector (Cloud Connector /
  StoreFront / FAS / VDA / Provisioning Server): machine spec, Citrix component versions,
  StoreFront + IIS/TLS hardening, FAS configuration & health (incl. KB5014754 strong certificate
  binding), PVS farm, and performance sampling. Produces one `OnPrem-<server>-<timestamp>.json`
  per server for the Citrix DaaS report.
- **`Get-ProfilesData.ps1`** — User-profile storage collector (FSLogix / Citrix Profile Management
  shares, on Azure Files and on-premises SMB): share and root NTFS permissions, per-folder size/file
  inventory, and evidence of which profile solution is in use. Produces one
  `<Customer>-Profiles-Data-<timestamp>.json` for the User Profiles report.
- **`Get-AVDData.ps1`** — Azure Virtual Desktop collector (host pools, session hosts, application
  groups, workspaces, scaling plans, FSLogix storage, Key Vaults, Log Analytics, RBAC) across the
  selected subscriptions via the Azure ARM APIs. Produces one `<Customer>-AVD-Data-<timestamp>.json`
  for the AVD report.
- **`Get-VsphereData.ps1`** — VMware vSphere hosting collector (host + VM utilisation for a cluster or a
  single host via a vCenter/VCSA): host CPU/memory, per-VM vCPU/RAM, live CPU usage, CPU Ready time, and
  vCPU:core overcommit. **API only — no PowerCLI or any module** (vSphere Web Services SOAP API over
  HTTPS). Produces one `<Customer>-Vsphere-Data-<timestamp>.json` for the Hosting report.

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
| `Get-ProfilesData.ps1` | The user-profile storage collector (the full download served on update). |
| `Get-ProfilesData.version` | Tiny version marker for the profiles collector. |
| `Get-AVDData.ps1` | The Azure Virtual Desktop collector (the full download served on update). |
| `Get-AVDData.version` | Tiny version marker for the AVD collector. |
| `Get-VsphereData.ps1` | The VMware vSphere hosting collector (the full download served on update). |
| `Get-VsphereData.version` | Tiny version marker for the vSphere collector. |

## Version numbers

The **authoritative version** of each collector is the plain `YYYY-MM-DD` (or `YYYY-MM-DD.rev`) string held in
its **`*.version`** file — the same value as the script's `# Version:` header and `$script:_version`. There is
**no `v` prefix**. A `v` shown anywhere else (the collector's launch dialog, the report footer, or a Git commit
message) is cosmetic display only; the un-prefixed string in the `.version` file is canonical.

## Releasing

1. Bump `$script:_version` in the script (`YYYY-MM-DD` or `YYYY-MM-DD.rev`) — it must increase
   ([version] comparison).
2. Copy the script here **and** write its version into `Get-OnPremComponentsData.version` (derive it
   from the script's `$script:_version` so the two never drift), then commit and push to `main`.

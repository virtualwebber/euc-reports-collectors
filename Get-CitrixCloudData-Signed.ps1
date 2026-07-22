#Requires -Version 5.1
# Version: 2026-07-22.4   (keep in lock-step with $script:_version below)

<#
.SYNOPSIS
    Collects Citrix Cloud (DaaS) environment data for health check reporting.

.DESCRIPTION
    Authenticates to Citrix Cloud using OAuth2 client credentials (Client ID + Secret).
    The client secret is encrypted with Windows DPAPI and stored in the customer config file -
    it is only decryptable by the same Windows user on the same machine.
    Outputs a portable JSON file consumed offline by Get-CitrixReport.ps1.

.PARAMETER CustomerName
    Load a named customer config directly, skipping the selection dialog.

.PARAMETER ConfigFile
    Full path to a specific .config.json file to load.

.PARAMETER OutputPath
    Override the output folder from config.

.PARAMETER SkipAdvisor
    Skip Citrix's Advisor site check. The Advisor scan runs by default - it is the one on-demand action in the
    collection (it triggers a scan and updates the console's Advisor blade) and adds ~15-60s. Use this switch
    to skip it for scripted runs; interactive runs can untick the dialog checkbox (the choice is saved per
    customer).

.EXAMPLE
    .\Get-CitrixCloudData.ps1
    # Interactive - shows customer selection dialog

.EXAMPLE
    .\Get-CitrixCloudData.ps1 -CustomerName "Acme Corp" -SkipAdvisor
    # Non-interactive, skipping the Citrix Advisor site check

.EXAMPLE
    .\Get-CitrixCloudData.ps1 -CustomerName "Acme Corp"
    # Loads saved config and runs non-interactively
#>

[CmdletBinding()]
param(
    [string]$CustomerName,
    [string]$ConfigFile,
    [string]$OutputPath,
    # Optional: encrypt the collected data file with this password (writes <name>.cdenc instead of
    # .json). OFF by default - omit it and the output stays plaintext .json exactly as before.
    [System.Security.SecureString]$EncryptPassword,
    # Skip the Citrix Advisor site check (it runs by default - the one on-demand scan in the collection).
    # Interactive runs untick the dialog checkbox instead (saved per customer). See .PARAMETER SkipAdvisor.
    [switch]$SkipAdvisor,
    # Skip the launch-time self-update check (mirrors the on-prem collector's -SkipUpdateCheck).
    [switch]$SkipUpdateCheck
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

#region ── Assemblies & Script-Scope Globals ──────────────────────────────────

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Web

#region ── Data-file encryption (opt-in, self-contained) ──────────────────────
# Portable password-based encryption for the output data file. OFF unless -EncryptPassword is given.
# AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC); PBKDF2 key derivation (Rfc2898DeriveBytes 3-arg SHA1
# form - identical output on .NET Framework 5.1 and .NET Core 7, so a file encrypted here decrypts on
# the report/app service). No AesGcm (PS7-only). The password is never written to the file or a log.
$script:_cdEncMarker = '_cdenc'; $script:_cdEncVer = 1; $script:_cdEncIter = 200000
function ConvertFrom-SecureStringPlain ([System.Security.SecureString]$Secure) {
    if (-not $Secure) { return '' }
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
function Get-CdEncKeys ([string]$PwText, [byte[]]$Salt) {
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($PwText, $Salt, $script:_cdEncIter)
    try { $b = $kdf.GetBytes(64); @{ Aes = $b[0..31]; Mac = $b[32..63] } } finally { $kdf.Dispose() }
}
function Test-CitrixDataEncrypted ([string]$Raw) {
    if (-not $Raw) { return $false }
    $t = $Raw.TrimStart([char]0xFEFF, ' ', "`t", "`r", "`n")
    if (-not $t.StartsWith('{')) { return $false }
    try { [bool]((($t | ConvertFrom-Json) | Get-Member -Name $script:_cdEncMarker -ErrorAction SilentlyContinue)) } catch { $false }
}
function Protect-CitrixData ([string]$PlainJson, [System.Security.SecureString]$Password) {
    if (-not $Password -or $Password.Length -eq 0) { throw 'Protect-CitrixData: a password is required.' }
    $pw = ConvertFrom-SecureStringPlain $Password
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16; $rng.GetBytes($salt); $iv = New-Object byte[] 16; $rng.GetBytes($iv); $rng.Dispose()
    $keys = Get-CdEncKeys $pw $salt
    $aes = [System.Security.Cryptography.Aes]::Create(); $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $keys.Aes; $aes.IV = $iv
    try { $e = $aes.CreateEncryptor(); $pb = [System.Text.Encoding]::UTF8.GetBytes($PlainJson); $ct = $e.TransformFinalBlock($pb, 0, $pb.Length); $e.Dispose() } finally { $aes.Dispose() }
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, [byte[]]$keys.Mac)
    try { $mac = $hmac.ComputeHash([byte[]](@([byte]$script:_cdEncVer) + $salt + $iv + $ct)) } finally { $hmac.Dispose() }
    ([ordered]@{ $script:_cdEncMarker = $script:_cdEncVer; alg = 'AES-256-CBC+HMAC-SHA256'; kdf = 'PBKDF2-SHA1'; iter = $script:_cdEncIter
        salt = [Convert]::ToBase64String($salt); iv = [Convert]::ToBase64String($iv); ct = [Convert]::ToBase64String($ct); mac = [Convert]::ToBase64String($mac) } | ConvertTo-Json)
}
function Unprotect-CitrixData ([string]$Raw, [System.Security.SecureString]$Password) {
    if (-not (Test-CitrixDataEncrypted $Raw)) { return $Raw }
    if (-not $Password -or $Password.Length -eq 0) { throw 'This data file is encrypted - a password is required to open it.' }
    $env = $Raw | ConvertFrom-Json; $pw = ConvertFrom-SecureStringPlain $Password
    $salt = [Convert]::FromBase64String($env.salt); $iv = [Convert]::FromBase64String($env.iv)
    $ct = [Convert]::FromBase64String($env.ct); $mac = [Convert]::FromBase64String($env.mac); $ver = [byte][int]$env.$($script:_cdEncMarker)
    $keys = Get-CdEncKeys $pw $salt
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, [byte[]]$keys.Mac)
    try { $expected = $hmac.ComputeHash([byte[]](@($ver) + $salt + $iv + $ct)) } finally { $hmac.Dispose() }
    $ok = $mac.Length -eq $expected.Length; for ($i = 0; $i -lt $expected.Length; $i++) { if ($i -lt $mac.Length) { $ok = $ok -and ($mac[$i] -eq $expected[$i]) } }
    if (-not $ok) { throw 'Could not decrypt the data file - the password is incorrect (or the file has been altered).' }
    $aes = [System.Security.Cryptography.Aes]::Create(); $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $keys.Aes; $aes.IV = $iv
    try { $d = $aes.CreateDecryptor(); $pb = $d.TransformFinalBlock($ct, 0, $ct.Length); $d.Dispose() } finally { $aes.Dispose() }
    [System.Text.Encoding]::UTF8.GetString($pb)
}
#endregion

$script:_version      = '2026-07-22.4'
# Version format is YYYY-MM-DD; add a .N suffix ONLY for a second or later release on the SAME day
# (e.g. 2026-07-15, then 2026-07-15.1, .2 ...). A new day's first release needs no suffix.
# Self-update: the launch check fetches update-manifest.json from euc-reports-collectors, compares this
# file's SHA-256 to the manifest entry for its own name, and if they differ downloads the published .ps1
# BYTE-EXACT (Invoke-WebRequest -OutFile), verifies its hash (and Authenticode signature when the manifest
# marks it signed) before replacing itself. Byte-exact + hash/signature verified so a signed collector
# stays signed. The published Get-CitrixCloudData.ps1 is the SIGNED copy of this script.
$script:_manifestUrl    = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/update-manifest.json'
$script:_updateRawBase  = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main'
$script:_selfName       = 'Get-CitrixCloudData-Signed.ps1'
$script:_scriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
# Configs (including the DPAPI-encrypted client secret) live in the user's
# local profile, not in the repo. LocalAppData is per-user + per-machine,
# which matches DPAPI's protection scope.
$script:_appDataDir   = Join-Path $env:LOCALAPPDATA 'Citrix-DaaS-Report'
$script:_configDir    = Join-Path $script:_appDataDir 'configs'
$script:_outputDir    = Join-Path $script:_scriptDir 'Outputs'
$script:_debugLogPath = Join-Path $script:_scriptDir 'CitrixCloudData-Debug.log'
$script:_splash       = $null
$script:_splashStatus = $null
$script:_token        = $null
$script:_customerId   = $null
$script:_siteId       = $null
$script:_siteObj      = $null
$script:_daasBase     = 'https://api.cloud.com/cvad/manage'
$script:_authHeaders  = @{}
$script:_lastStatus   = 0       # HTTP status of the most recent Invoke-CitrixApi call
$script:_collectStatus = [ordered]@{}  # per-resource collection status (e.g. 'AccessDenied') surfaced to the report
$script:_deniedPaths  = @()     # every path that returned 401/403 - drives the end-of-run access-denied summary

#region ── Read-only guards ──────────────────────────────────────────────────
# This collector is READ-ONLY: it never mutates Citrix and never deletes files it does not own. These
# guards enforce that at runtime, and Assert-CollectorReadOnly.ps1 checks it statically at build/publish.
#
# HTTP: every request is GET except two POSTs - the OAuth token request and the optional Advisor scan
# trigger. There are NO PUT/PATCH/DELETE calls. The allowlist is SINGLE-QUOTED so the literal
# $generateRecommendations in the Advisor URI is not treated as a PowerShell variable; -like treats $ as
# a literal, so these patterns match the real URIs.
$script:_allowedPostUri = @(
    '*/cctrustoauth2/*/tokens/clients'          # OAuth2 client-credentials token
    '*/Advisor/$generateRecommendations*'       # Advisor site-check trigger (skippable with -SkipAdvisor)
)
function Assert-HttpAllowed ([string]$Method, [string]$Uri) {
    if ($Method -eq 'Get') { return }
    if ($Method -eq 'Post') {
        foreach ($p in $script:_allowedPostUri) { if ($Uri -like $p) { return } }
    }
    throw "Read-only collector: refusing a $Method request to '$Uri'. Only GET (plus the OAuth token and Advisor-scan POSTs) is permitted."
}
# All outbound HTTP goes through these wrappers so the method guard cannot be bypassed. The real
# Invoke-RestMethod / Invoke-WebRequest appear ONLY inside them (the static audit enforces that).
function Invoke-SafeRest {
    param([string]$Uri, [string]$Method = 'Get', [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec, [switch]$UseBasicParsing)
    Assert-HttpAllowed $Method $Uri
    $p = @{ Method = $Method; Uri = $Uri }
    if ($Headers)     { $p.Headers     = $Headers }
    if ($PSBoundParameters.ContainsKey('Body')) { $p.Body = $Body }
    if ($ContentType) { $p.ContentType = $ContentType }
    if ($TimeoutSec)  { $p.TimeoutSec  = $TimeoutSec }
    if ($UseBasicParsing) { $p.UseBasicParsing = $true }
    $p.ErrorAction = 'Stop'   # every caller try/catches; keep errors terminating so they surface
    Invoke-RestMethod @p
}
function Invoke-SafeWeb {
    param([string]$Uri, [string]$Method = 'Get', [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec, [switch]$UseBasicParsing, [string]$OutFile)
    Assert-HttpAllowed $Method $Uri
    $p = @{ Method = $Method; Uri = $Uri }
    if ($Headers)     { $p.Headers     = $Headers }
    if ($PSBoundParameters.ContainsKey('Body')) { $p.Body = $Body }
    if ($ContentType) { $p.ContentType = $ContentType }
    if ($TimeoutSec)  { $p.TimeoutSec  = $TimeoutSec }
    if ($UseBasicParsing) { $p.UseBasicParsing = $true }
    if ($OutFile)     { $p.OutFile     = $OutFile }   # byte-exact download (preserves a signature); used by self-update
    $p.ErrorAction = 'Stop'   # every caller try/catches; keep errors terminating so they surface
    Invoke-WebRequest @p
}
# Files: a delete/move may only ever touch a path the collector OWNS - its temp files, its config dir,
# its output folder, or its own script folder (self / .bak / .NEW). Remove-OwnedItem / Move-OwnedItem are
# the only wrappers that call the real Remove-Item / Move-Item (the static audit enforces that).
$script:_ownedRoots = @(
    [System.IO.Path]::GetTempPath()
    $script:_appDataDir
    $script:_outputDir
    $script:_scriptDir
) | Where-Object { $_ } | ForEach-Object { try { [System.IO.Path]::GetFullPath($_).TrimEnd('\', '/') } catch { $_ } }
function Assert-OwnedPath ([string]$Path, [string]$Op = 'modify') {
    $full = try { [System.IO.Path]::GetFullPath($Path) } catch { throw "Read-only collector: refusing to $Op an unresolvable path '$Path'." }
    foreach ($r in $script:_ownedRoots) {
        if ($full.Equals($r, [System.StringComparison]::OrdinalIgnoreCase) -or
            $full.StartsWith($r + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) { return }
    }
    throw "Read-only collector: refusing to $Op '$full' - it is outside the collector's own folders (temp / config / output / script)."
}
function Remove-OwnedItem ([string]$Path) {
    Assert-OwnedPath $Path 'delete'
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}
function Move-OwnedItem ([string]$Path, [string]$Destination) {
    Assert-OwnedPath $Path        'move'
    Assert-OwnedPath $Destination 'move'
    Move-Item -LiteralPath $Path -Destination $Destination -Force
}
#endregion

foreach ($dir in $script:_configDir, $script:_outputDir) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

# One-time migration: move any configs from the legacy in-repo location to LocalAppData.
$script:_legacyConfigDir = Join-Path $script:_scriptDir 'configs'
if (Test-Path $script:_legacyConfigDir) {
    Get-ChildItem -Path $script:_legacyConfigDir -Filter '*.config.json' -ErrorAction SilentlyContinue | ForEach-Object {
        $dest = Join-Path $script:_configDir $_.Name
        if (-not (Test-Path $dest)) {
            try { Move-OwnedItem $_.FullName $dest } catch {}
        }
    }
}

# DWM P/Invoke for square corners on Windows 11
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class CitrixDataDwm {
    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
}
'@
} catch {}

$script:_dwmAttr   = 33
$script:_dwmSquare = 1

function Set-SquareCorners ([System.Windows.Window]$Window) {
    $Window.Add_SourceInitialized({
        param($s, $e)
        try {
            $h = (New-Object System.Windows.Interop.WindowInteropHelper($s)).Handle
            [void][CitrixDataDwm]::DwmSetWindowAttribute($h, $script:_dwmAttr, [ref]$script:_dwmSquare, 4)
        } catch {}
    })
}

function New-ThemedWindow ([string]$Xaml) {
    $rdr = [System.Xml.XmlNodeReader]::new([xml]$Xaml)
    $win = [Windows.Markup.XamlReader]::Load($rdr)
    Set-SquareCorners -Window $win
    return $win
}

#endregion

#region ── Logging ───────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $script:_debugLogPath -Value $line -ErrorAction SilentlyContinue
    if ($Level -eq 'ERROR') { Write-Warning $Message }
}

function Start-DebugLog {
    Set-Content -Path $script:_debugLogPath -Value (@(
        '=' * 70
        "Citrix DaaS Data Collector  v$($script:_version)"
        "Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        "User    : $env:USERDOMAIN\$env:USERNAME"
        "Machine : $env:COMPUTERNAME"
        '=' * 70
    ) -join "`n") -ErrorAction SilentlyContinue
    Write-Log 'Collector starting'
}

#endregion

#region ── Config ────────────────────────────────────────────────────────────

function Get-ConfigList {
    if (-not (Test-Path $script:_configDir)) { return @() }
    @(Get-ChildItem -Path $script:_configDir -Filter '*.config.json' |
        ForEach-Object { $_.BaseName -replace '\.config$', '' })
}

function Read-CollectConfig ([string]$Name) {
    $path = Join-Path $script:_configDir "$Name.config.json"
    if (-not (Test-Path $path)) { return $null }
    try {
        $json = Get-Content $path -Raw | ConvertFrom-Json
        $cfg  = [ordered]@{}
        $json.PSObject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value }
        return $cfg
    } catch {
        Write-Log "Failed to read config '$Name': $_" 'ERROR'
        return $null
    }
}

function Save-CollectConfig ([hashtable]$Config) {
    $name = $Config['CustomerName'] -replace '[^\w\-]', '_'
    $path = Join-Path $script:_configDir "$name.config.json"
    try {
        $Config | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
        Write-Log "Config saved: $path"
    } catch {
        Write-Log "Failed to save config: $_" 'ERROR'
    }
}

#endregion

#region ── Credential Helpers (DPAPI) ────────────────────────────────────────

function Protect-Secret ([string]$Plaintext) {
    $secure = ConvertTo-SecureString -String $Plaintext -AsPlainText -Force
    return $secure | ConvertFrom-SecureString
}

function Unprotect-Secret ([string]$Encrypted) {
    try {
        $secure = $Encrypted | ConvertTo-SecureString
        $ptr    = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        return  [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
    } catch {
        throw "Failed to decrypt client secret. Was this config created by a different user or on a different machine? Error: $_"
    } finally {
        if ($ptr) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    }
}

#endregion

#region ── WPF Helpers ───────────────────────────────────────────────────────

function Show-MsgBox {
    param(
        [string]$Message,
        [string]$Title = 'Citrix DaaS Collector',
        [ValidateSet('Info','Warning','Error')][string]$Icon = 'Info'
    )
    $iconChar  = switch ($Icon) { 'Error' { '&#x2716;' } 'Warning' { '&#x26A0;' } default { '&#x2139;' } }
    $iconColor = switch ($Icon) { 'Error' { '#D83B01' } 'Warning' { '#CA5010' }   default { '#0078D4'  } }
    $msg = [System.Security.SecurityElement]::Escape($Message)
    $ttl = [System.Security.SecurityElement]::Escape($Title)
    $win = New-ThemedWindow @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$ttl" SizeToContent="WidthAndHeight" MinWidth="320" MaxWidth="520"
        WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources>
    <Style x:Key="BlueBtn" TargetType="Button">
      <Setter Property="Background" Value="#0078D4"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                            TextBlock.Foreground="{TemplateBinding Foreground}"/>
        </Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#005BA1"/></Trigger>
        </ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <StackPanel Margin="20,18,20,16">
    <DockPanel Margin="0,0,0,16">
      <TextBlock Text="$iconChar" Foreground="$iconColor" FontSize="24" DockPanel.Dock="Left"
                 VerticalAlignment="Top" Margin="0,0,14,0"/>
      <TextBlock Text="$msg" TextWrapping="Wrap" VerticalAlignment="Center"
                 FontSize="13" Foreground="#1F2937"/>
    </DockPanel>
    <Button x:Name="btnOk" Content="OK" Width="80" HorizontalAlignment="Right" Padding="0,7"
            Style="{StaticResource BlueBtn}"/>
  </StackPanel>
</Window>
"@
    $win.FindName('btnOk').Add_Click({ $win.Close() })
    $null = $win.ShowDialog()
}

#endregion

#region ── Self-update check (GitHub) ────────────────────────────────────────
# On interactive launch, check euc-reports-collectors for a newer version of THIS script and offer to
# update in place. Fully optional and fail-safe: short timeout, silent on any failure (some machines
# have no/limited internet), skipped for scripted (-ConfigFile / -CustomerName) runs and -SkipUpdateCheck.

# 'YYYY-MM-DD' / 'YYYY-MM-DD.rev' (or dotted) -> [version] so releases compare monotonically.
function ConvertTo-CollectorVersion ([string]$Text) {
    if (-not "$Text") { return $null }
    $t = "$Text".Trim()
    if ($t -match '^(\d{4})[-.](\d{1,2})[-.](\d{1,2})(?:\.(\d+))?$') {
        $rev = if ($matches[4]) { [int]$matches[4] } else { 0 }
        try { return [version]::new([int]$matches[1], [int]$matches[2], [int]$matches[3], $rev) } catch { return $null }
    }
    try { return [version]$t } catch { return $null }
}

# Themed Update/Skip prompt. Returns $true to update, $false to skip.
function Show-UpdatePrompt ([string]$Local, [string]$Remote) {
    $script:_updChoice = $false
    $l = [System.Security.SecurityElement]::Escape($Local); $r = [System.Security.SecurityElement]::Escape($Remote)
    $win = New-ThemedWindow @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Update available" SizeToContent="WidthAndHeight" MinWidth="380" MaxWidth="520"
        WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources>
    <Style x:Key="BlueBtn" TargetType="Button">
      <Setter Property="Background" Value="#0078D4"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextBlock.Foreground="{TemplateBinding Foreground}"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#005BA1"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="GreyBtn" TargetType="Button">
      <Setter Property="Background" Value="#E1E4EA"/><Setter Property="Foreground" Value="#1F2937"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#CDD0D8"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <StackPanel Margin="22,20,22,16">
    <TextBlock Text="A newer version of the collector is available." FontSize="14" FontWeight="Bold" Foreground="#1F2937" Margin="0,0,0,8"/>
    <TextBlock FontSize="13" Foreground="#555" TextWrapping="Wrap" Margin="0,0,0,4">
      <Run Text="Installed: "/><Run Text="$l" FontWeight="SemiBold"/><Run Text="    Available: "/><Run Text="$r" FontWeight="SemiBold" Foreground="#0078D4"/>
    </TextBlock>
    <TextBlock Text="Update now? The script will download the new version and relaunch." FontSize="12" Foreground="#8a8f98" TextWrapping="Wrap" Margin="0,0,0,16"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="btnSkip" Content="Not now" Width="90" Padding="0,7" Style="{StaticResource GreyBtn}" Margin="0,0,8,0"/>
      <Button x:Name="btnUpdate" Content="Update" Width="100" Padding="0,7" Style="{StaticResource BlueBtn}"/>
    </StackPanel>
  </StackPanel>
</Window>
"@
    $win.FindName('btnUpdate').Add_Click({ $script:_updChoice = $true; $win.Close() })
    $win.FindName('btnSkip').Add_Click({ $script:_updChoice = $false; $win.Close() })
    $null = $win.ShowDialog()
    return [bool]$script:_updChoice
}

function Invoke-CitrixCloudUpdateCheck {
    # Interactive only: the scripted -ConfigFile / -CustomerName entry paths (automation) skip it, as does -SkipUpdateCheck.
    if ($SkipUpdateCheck -or $ConfigFile -or $CustomerName -or -not $script:_manifestUrl) { return }
    $self = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    if (-not $self) { return }
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
        # 1. Fetch the tiny manifest and find this collector's entry.
        $mresp = Invoke-SafeWeb -Uri $script:_manifestUrl -UseBasicParsing -TimeoutSec 6
        $manifest = "$($mresp.Content)" | ConvertFrom-Json
        $entry = @($manifest.files) | Where-Object { $_.name -eq $script:_selfName } | Select-Object -First 1
        if (-not $entry -or -not $entry.sha256) { Write-Log "Update check: no manifest entry for $($script:_selfName) - skipping" 'WARN'; return }
        $wantHash = "$($entry.sha256)".ToUpperInvariant()
        # 2. Compare my own bytes to the manifest. Same hash -> nothing to do.
        $myHash = (Get-FileHash -LiteralPath $self -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($myHash -eq $wantHash) { Write-Log "Update check: up to date (v$($script:_version), hash matches manifest)"; return }
        # Never downgrade: only proceed when the manifest version is >= mine (a same-version, different-hash
        # entry is the unsigned->signed migration, which we DO want).
        $rv = ConvertTo-CollectorVersion "$($entry.version)"; $lv = ConvertTo-CollectorVersion $script:_version
        if ($rv -and $lv -and $rv -lt $lv) { Write-Log "Update check: manifest v$($entry.version) older than local v$($script:_version) - skipping" 'WARN'; return }
        Write-Log "Update check: update available - local v$($script:_version), manifest v$($entry.version)$(if ($entry.signed) { ' (signed)' })"
        if (-not (Show-UpdatePrompt $script:_version "$($entry.version)")) { Write-Log 'Update check: user chose Not now'; return }
        # 3. Download the published script BYTE-EXACT (preserves any signature).
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("CitrixCloudCollector-$([guid]::NewGuid().ToString('N')).ps1")
        Invoke-SafeWeb -Uri "$($script:_updateRawBase)/$($script:_selfName)" -UseBasicParsing -TimeoutSec 30 -OutFile $tmp | Out-Null
        # 4. Verify BEFORE replacing anything: hash matches the manifest, it parses, and - when the manifest
        #    marks it signed - its Authenticode signature is valid.
        $why = ''
        $dlHash = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($dlHash -ne $wantHash) { $why = "hash mismatch after download (expected $wantHash, got $dlHash)" }
        if (-not $why) {
            $tk = $null; $perr = $null
            [System.Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$tk, [ref]$perr) | Out-Null
            if ($perr -and $perr.Count) { $why = "parse errors ($($perr[0].Message))" }
        }
        if (-not $why -and $entry.signed) {
            $sig = Get-AuthenticodeSignature -LiteralPath $tmp
            if ($sig.Status -ne 'Valid') { $why = "Authenticode signature is $($sig.Status), expected Valid" }
        }
        if ($why) {
            Remove-OwnedItem $tmp
            Show-MsgBox "The downloaded update did not validate; keeping the current version.`n`n$why" -Icon Warning
            Write-Log "Update check: download failed validation - $why - aborting" 'WARN'; return
        }
        # 5. Back up, replace BYTE-EXACT (Copy-Item, not Set-Content, so the signature survives), relaunch.
        try {
            Copy-Item -LiteralPath $self -Destination "$self.bak" -Force -ErrorAction SilentlyContinue
            Copy-Item -LiteralPath $tmp -Destination $self -Force
        } catch {
            $alt = Join-Path (Split-Path $self -Parent) 'Get-CitrixCloudData.NEW.ps1'
            try { Copy-Item -LiteralPath $tmp -Destination $alt -Force } catch {}
            Remove-OwnedItem $tmp
            Show-MsgBox "Couldn't replace the running script (permissions?). The new version was saved as:`n$alt`n`nReplace the old script with it and re-run." -Icon Warning
            Write-Log "Update check: could not overwrite $self - saved new version to $alt" 'WARN'; return
        }
        Remove-OwnedItem $tmp
        Write-Log "Update check: updated $self to v$($entry.version) - relaunching"
        Show-MsgBox "Updated to version $($entry.version).`n`nThe collector will now relaunch." -Icon Info
        try { Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $self + '"') } catch { Write-Log "Relaunch failed: $($_.Exception.Message)" 'WARN' }
        exit 0
    } catch {
        Write-Log "Update check skipped: $(("$($_.Exception.Message)" -replace '\s+', ' '))"
    }
}

#endregion

#region ── WPF Splash Screen ─────────────────────────────────────────────────

function Show-Splash {
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Citrix DaaS Collector" Height="170" Width="440"
        WindowStartupLocation="CenterScreen" WindowStyle="None"
        AllowsTransparency="True" Background="Transparent" Topmost="True"
        FontFamily="Segoe UI">
    <Border x:Name="SplashBorder" CornerRadius="6" Background="White"
            BorderBrush="#DDE1E7" BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect BlurRadius="24" ShadowDepth="3" Opacity="0.12" Color="#000000"/>
        </Border.Effect>
        <StackPanel VerticalAlignment="Center" Margin="32,24">
            <TextBlock Text="Citrix DaaS - Data Collector"
                       FontSize="15" FontWeight="Bold" Foreground="#0078D4"
                       HorizontalAlignment="Center" Margin="0,0,0,6"/>
            <TextBlock x:Name="StatusText" Text="Starting..."
                       FontSize="12" Foreground="#555"
                       HorizontalAlignment="Center" Margin="0,0,0,18"/>
            <ProgressBar x:Name="Bar" IsIndeterminate="True"
                         Height="3" Background="#E8EAED" Foreground="#0078D4"
                         BorderThickness="0"/>
        </StackPanel>
    </Border>
</Window>
'@
    $win = New-ThemedWindow $xaml
    $script:_splash       = $win
    $script:_splashStatus = $win.FindName('StatusText')

    # Show() is non-blocking; the window lives on this (the main) thread.
    # Pump the dispatcher once so it renders before we continue.
    $script:_splash.Show()
    $script:_splash.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    Write-Log 'Splash shown'
}

function Set-SplashStatus ([string]$Message) {
    Write-Log $Message
    if ($script:_splash -and $script:_splashStatus) {
        $script:_splash.Dispatcher.Invoke([Action]{ $script:_splashStatus.Text = $Message },
            [System.Windows.Threading.DispatcherPriority]::Render)
    }
}

function Close-Splash {
    if ($script:_splash) {
        try { $script:_splash.Close() } catch {}
        $script:_splash = $null
    }
}

#endregion

#region ── WPF Dialogs ───────────────────────────────────────────────────────

function Show-CustomerDialog {
    $configs = Get-ConfigList

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Citrix DaaS Report" Width="460" SizeToContent="Height"
        WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        Background="#F4F6F9" FontFamily="Segoe UI" FontSize="13">
    <Window.Resources>
        <Style x:Key="BlueBtn" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/><Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="12"/><Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
                <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                    <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                      TextBlock.Foreground="{TemplateBinding Foreground}"/>
                </Border>
                <ControlTemplate.Triggers>
                    <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#005BA1"/></Trigger>
                    <Trigger Property="IsPressed"   Value="True"><Setter TargetName="bd" Property="Background" Value="#004E8C"/></Trigger>
                </ControlTemplate.Triggers>
            </ControlTemplate></Setter.Value></Setter>
        </Style>
        <Style x:Key="GreyBtn" TargetType="Button">
            <Setter Property="Background" Value="#E1E4EA"/><Setter Property="Foreground" Value="#1F2937"/>
            <Setter Property="BorderThickness" Value="0"/><Setter Property="FontSize" Value="12"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
                <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                    <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                </Border>
                <ControlTemplate.Triggers>
                    <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#CDD0D8"/></Trigger>
                </ControlTemplate.Triggers>
            </ControlTemplate></Setter.Value></Setter>
        </Style>
    </Window.Resources>
    <StackPanel Margin="24,20,24,20">
        <DockPanel Margin="0,0,0,16">
            <TextBlock Text="&#x1F5A5;" FontSize="26" Foreground="#0078D4" DockPanel.Dock="Left"
                       VerticalAlignment="Center" Margin="0,0,12,0"/>
            <StackPanel>
                <TextBlock Text="Citrix DaaS Report" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
                <TextBlock Text="Data Collection" FontSize="12" Foreground="#555" Margin="0,2,0,0"/>
            </StackPanel>
        </DockPanel>

        <TextBlock Text="Saved Customers" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
        <ComboBox x:Name="CustomerCombo" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1"
                  Background="White" FontSize="12" Margin="0,0,0,16"/>

        <Rectangle Height="1" Fill="#DDE1E7" Margin="0,0,0,14"/>

        <TextBlock Text="New Customer Name" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox x:Name="NewNameBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1"
                 Background="White" FontSize="12" Margin="0,0,0,16"/>

        <Rectangle Height="1" Fill="#DDE1E7" Margin="0,0,0,12"/>
        <CheckBox x:Name="ChkSessionDetail"
                  Content="Collect session detail (individual user sessions: user, client device, IP)"
                  FontSize="11" Foreground="#555" IsChecked="False" Margin="0,0,0,10"/>
        <CheckBox x:Name="ChkAdvisor"
                  Content="Run Citrix Advisor site check (on by default; extra ~15-60s, triggers a scan in the console)"
                  FontSize="11" Foreground="#555" IsChecked="True" Margin="0,0,0,16"/>

        <TextBlock Text="Encrypt output (optional - leave blank for plaintext .json; a password writes .cdenc)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,6"/>
        <PasswordBox x:Name="EncryptBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,16"/>

        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="CancelBtn" Content="Cancel" Width="80" Padding="0,7"
                    Style="{StaticResource GreyBtn}" Margin="0,0,8,0"/>
            <Button x:Name="OkBtn" Content="Continue" Width="100" Padding="0,7"
                    Style="{StaticResource BlueBtn}"/>
        </StackPanel>
        <TextBlock x:Name="VersionText" HorizontalAlignment="Right" Margin="0,12,0,0" FontSize="10" Foreground="#9aa4b2"/>
    </StackPanel>
</Window>
'@
    $win = New-ThemedWindow $xaml
    $win.FindName('VersionText').Text = "Version $($script:_version)"

    $combo    = $win.FindName('CustomerCombo')
    $newName  = $win.FindName('NewNameBox')
    $chkSession = $win.FindName('ChkSessionDetail')
    $chkAdvisor = $win.FindName('ChkAdvisor')
    $encryptBox = $win.FindName('EncryptBox')
    $okBtn    = $win.FindName('OkBtn')
    $cancel   = $win.FindName('CancelBtn')

    $configs | ForEach-Object { [void]$combo.Items.Add($_) }
    if ($combo.Items.Count -gt 0) { $combo.SelectedIndex = 0 }

    # Pre-tick the per-run options from saved config when a customer is selected
    $combo.Add_SelectionChanged({
        $name = "$($combo.SelectedItem)"
        if ($name) {
            $cfg = Read-CollectConfig -Name $name
            if ($cfg) {
                $chkSession.IsChecked = [bool]$cfg['CollectSessionDetail']
                # Advisor defaults ON - a config without the key predates the option, so treat absent as ticked.
                $chkAdvisor.IsChecked = ($null -eq $cfg['IncludeAdvisor']) -or [bool]$cfg['IncludeAdvisor']
            }
        }
    })
    # Initialise for the default selection
    if ($combo.SelectedItem) {
        $initCfg = Read-CollectConfig -Name "$($combo.SelectedItem)"
        if ($initCfg) {
            $chkSession.IsChecked = [bool]$initCfg['CollectSessionDetail']
            $chkAdvisor.IsChecked = ($null -eq $initCfg['IncludeAdvisor']) -or [bool]$initCfg['IncludeAdvisor']
        }
    }

    $script:_dlgResult = [ordered]@{ Action = 'Cancel'; CustomerName = ''; IsNew = $false; CollectSessionDetail = $false; IncludeAdvisor = $false; EncryptPassword = $null }

    $okBtn.Add_Click({
        $encPw = if ($encryptBox.Password) { ConvertTo-SecureString $encryptBox.Password -AsPlainText -Force } else { $null }
        $newText = $newName.Text.Trim()
        if ($newText) {
            Write-Log "Customer dialog: 'New' chosen - '$newText'"
            $script:_dlgResult = [ordered]@{ Action = 'New'; CustomerName = $newText; IsNew = $true; CollectSessionDetail = [bool]$chkSession.IsChecked; IncludeAdvisor = [bool]$chkAdvisor.IsChecked; EncryptPassword = $encPw }
            $win.DialogResult = $true
            $win.Close()
        } elseif ($combo.SelectedItem) {
            Write-Log "Customer dialog: 'Load' chosen - '$($combo.SelectedItem)'"
            $script:_dlgResult = [ordered]@{ Action = 'Load'; CustomerName = "$($combo.SelectedItem)"; IsNew = $false; CollectSessionDetail = [bool]$chkSession.IsChecked; IncludeAdvisor = [bool]$chkAdvisor.IsChecked; EncryptPassword = $encPw }
            $win.DialogResult = $true
            $win.Close()
        } else {
            Write-Log "Customer dialog: OK clicked with no selection and no new name" 'WARN'
            Show-MsgBox 'Select a saved customer or enter a new customer name.' -Icon Warning
        }
    })
    $cancel.Add_Click({ Write-Log 'Customer dialog: cancelled'; $win.DialogResult = $false; $win.Close() })

    Write-Log "Showing customer dialog ($($configs.Count) saved config(s): $($configs -join ', '))"
    $win.ShowDialog() | Out-Null
    Write-Log "Customer dialog closed -> Action=$($script:_dlgResult['Action']) Customer='$($script:_dlgResult['CustomerName'])'"
    return $script:_dlgResult
}

function Show-CloudSetupDialog ([string]$CustomerName) {
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Citrix Cloud Setup" Width="500" SizeToContent="Height"
        WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        Background="#F4F6F9" FontFamily="Segoe UI" FontSize="13">
    <Window.Resources>
        <Style x:Key="BlueBtn" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/><Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="12"/><Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
                <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                    <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                      TextBlock.Foreground="{TemplateBinding Foreground}"/>
                </Border>
                <ControlTemplate.Triggers>
                    <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#005BA1"/></Trigger>
                    <Trigger Property="IsPressed"   Value="True"><Setter TargetName="bd" Property="Background" Value="#004E8C"/></Trigger>
                </ControlTemplate.Triggers>
            </ControlTemplate></Setter.Value></Setter>
        </Style>
        <Style x:Key="GreyBtn" TargetType="Button">
            <Setter Property="Background" Value="#E1E4EA"/><Setter Property="Foreground" Value="#1F2937"/>
            <Setter Property="BorderThickness" Value="0"/><Setter Property="FontSize" Value="12"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
                <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
                    <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                </Border>
                <ControlTemplate.Triggers>
                    <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#CDD0D8"/></Trigger>
                </ControlTemplate.Triggers>
            </ControlTemplate></Setter.Value></Setter>
        </Style>
    </Window.Resources>
    <StackPanel Margin="24,20,24,20">
        <DockPanel Margin="0,0,0,14">
            <TextBlock Text="&#x1F511;" FontSize="24" Foreground="#0078D4" DockPanel.Dock="Left"
                       VerticalAlignment="Center" Margin="0,0,12,0"/>
            <StackPanel>
                <TextBlock Text="Citrix Cloud Credentials" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
                <TextBlock Text="API client configuration" FontSize="12" Foreground="#555" Margin="0,2,0,0"/>
            </StackPanel>
        </DockPanel>

        <Border Background="White" BorderBrush="#DDE1E7" BorderThickness="1" CornerRadius="4"
                Padding="12,10" Margin="0,0,0,16">
            <TextBlock TextWrapping="Wrap" FontSize="12" Foreground="#555"
                Text="Create an API client in Citrix Cloud &gt; Identity &amp; Access Management &gt; API Access. The client secret is encrypted using your Windows credentials and stored locally."/>
        </Border>

        <TextBlock Text="Customer ID" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox x:Name="CustomerIdBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1"
                 Background="White" FontSize="12" Margin="0,0,0,12"/>

        <TextBlock Text="Client ID" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox x:Name="ClientIdBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1"
                 Background="White" FontSize="12" Margin="0,0,0,12"/>

        <TextBlock Text="Client Secret" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
        <PasswordBox x:Name="SecretBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1"
                     Background="White" FontSize="12" Margin="0,0,0,20"/>

        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="CancelBtn" Content="Cancel" Width="80" Padding="0,8"
                    Style="{StaticResource GreyBtn}" Margin="0,0,8,0"/>
            <Button x:Name="SaveBtn" Content="Save &amp; Connect" Width="130" Padding="0,8"
                    Style="{StaticResource BlueBtn}"/>
        </StackPanel>
    </StackPanel>
</Window>
'@
    $win     = New-ThemedWindow $xaml

    $custId  = $win.FindName('CustomerIdBox')
    $clntId  = $win.FindName('ClientIdBox')
    $secret  = $win.FindName('SecretBox')
    $save    = $win.FindName('SaveBtn')
    $cancel  = $win.FindName('CancelBtn')

    $script:_setupResult = $null
    $save.Add_Click({
        $missing = @()
        if (-not $custId.Text.Trim()) { $missing += 'Customer ID' }
        if (-not $clntId.Text.Trim()) { $missing += 'Client ID' }
        if (-not $secret.Password)    { $missing += 'Client Secret' }
        if ($missing) {
            Show-MsgBox "Required fields missing:`n`n- $($missing -join "`n- ")" -Icon Warning
            return
        }
        $script:_setupResult = [ordered]@{
            CustomerName          = $CustomerName
            CustomerId            = $custId.Text.Trim()
            ClientId              = $clntId.Text.Trim()
            ClientSecretEncrypted = Protect-Secret $secret.Password
        }
        $win.DialogResult = $true
    })
    $cancel.Add_Click({ $win.DialogResult = $false })

    if ($win.ShowDialog()) { return $script:_setupResult }
    return $null
}

function Show-CompletionDialog ([string]$OutputFile, [int]$ErrorCount) {
    $icon = if ($ErrorCount -gt 0) { 'Warning' } else { 'Info' }
    $msg  = "Collection complete.`n`nOutput file:`n$OutputFile"
    if ($ErrorCount -gt 0) {
        $msg += "`n`n$ErrorCount resource(s) had collection errors. See CitrixCloudData-Debug.log for details."
    }
    Show-MsgBox $msg -Icon $icon
}

#endregion

#region ── Authentication ────────────────────────────────────────────────────

function Connect-CitrixCloud ([hashtable]$Config) {
    Set-SplashStatus 'Authenticating to Citrix Cloud...'
    $customerId = $Config['CustomerId']
    $clientId   = $Config['ClientId']
    $secret     = Unprotect-Secret $Config['ClientSecretEncrypted']

    $tokenUri = "https://api.cloud.com/cctrustoauth2/$customerId/tokens/clients"
    $body     = "grant_type=client_credentials" +
                "&client_id=$([Uri]::EscapeDataString($clientId))" +
                "&client_secret=$([Uri]::EscapeDataString($secret))"

    try {
        $resp = Invoke-SafeRest -Method Post -Uri $tokenUri `
                    -ContentType 'application/x-www-form-urlencoded' -Body $body
        $script:_token      = $resp.access_token
        $script:_customerId = $customerId
        $script:_authHeaders = @{
            'Authorization'     = "CWSAuth bearer=$($script:_token)"
            'Citrix-CustomerId' = $customerId
            'Accept'            = 'application/json'
            'Content-Type'      = 'application/json; charset=utf-8'
        }
        Write-Log "Authenticated to Citrix Cloud. Token expires in $($resp.expires_in)s"
    } catch {
        Write-Log "Authentication failed: $_" 'ERROR'
        throw "Citrix Cloud authentication failed. Check Customer ID, Client ID, and Client Secret.`n`nDetail: $_"
    }

    # Resolve the DaaS site ID and add it as the Citrix-InstanceId header,
    # which all /cvad/manage resource endpoints require.
    Set-SplashStatus 'Resolving DaaS site...'
    try {
        $me = Invoke-SafeRest -Method Get -Uri "$($script:_daasBase)/me" -Headers $script:_authHeaders
        $site = $null
        if ($me.Customers) {
            foreach ($cust in $me.Customers) {
                if ($cust.Sites -and $cust.Sites.Count -gt 0) { $site = $cust.Sites[0]; break }
            }
        }
        if (-not $site) { throw 'No site found in /me response.' }
        $script:_siteId  = $site.Id
        $script:_siteObj = $site
        $script:_authHeaders['Citrix-InstanceId'] = $script:_siteId
        Write-Log "DaaS site resolved: '$($site.Name)' (Id=$($script:_siteId))"
    } catch {
        Write-Log "Failed to resolve DaaS site via /me: $_" 'ERROR'
        throw "Could not resolve the Citrix DaaS site. Ensure the API client has DaaS read permission.`n`nDetail: $_"
    }
}

#endregion

#region ── API Infrastructure ────────────────────────────────────────────────

function Invoke-CitrixApi {
    param(
        [string]$Path,            # Relative to $script:_daasBase  e.g. '/DeliveryGroups'
        [string]$FullUrl = '',    # Override with absolute URL for non-DaaS endpoints
        [hashtable]$Query = @{},
        [hashtable]$ExtraHeaders = @{},  # Per-call headers merged over the auth headers
        [switch]$Quiet            # Log failures as INFO (used for endpoint discovery probes)
    )
    $uri = if ($FullUrl) { $FullUrl } else { "$($script:_daasBase)$Path" }

    if ($Query.Count) {
        $qs  = ($Query.GetEnumerator() | ForEach-Object {
                    "$([Uri]::EscapeDataString($_.Key))=$([Uri]::EscapeDataString($_.Value))" }) -join '&'
        $uri = "$uri`?$qs"
    }

    $headers = $script:_authHeaders
    if ($ExtraHeaders.Count) {
        $headers = @{}; foreach ($k in $script:_authHeaders.Keys) { $headers[$k] = $script:_authHeaders[$k] }
        foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] }
    }

    try {
        $r = Invoke-SafeRest -Method Get -Uri $uri -Headers $headers
        $script:_lastStatus = 200
        return $r
    } catch {
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        $script:_lastStatus = $status
        $body   = ''
        if ($_.Exception.Response -and ($Quiet -or $status -ge 400)) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = [System.IO.StreamReader]::new($stream)
                $body   = $reader.ReadToEnd()
                if ($body.Length -gt 400) { $body = $body.Substring(0, 400) + '...' }
            } catch { }
        }
        # A 401/403 is a permission problem, not a code failure. Its full response body (the Citrix SDK
        # error dump - transaction id, stack, "insufficient administrative privilege") is useful for
        # troubleshooting but must NOT flood the console: it goes to the debug-log FILE only (WARN), not
        # to ERROR which Write-Log mirrors to the console. Genuine errors (5xx, timeouts) keep ERROR so
        # they still surface live. The concise per-call denial line and the end-of-run summary are enough
        # on screen.
        $denied = ($status -eq 401 -or $status -eq 403)
        if ($Quiet)      { Write-Log "Probe [$status] GET $uri$(if ($body) { " | $body" })" 'INFO' }
        elseif ($denied) { Write-Log "API [$status] GET $uri$(if ($body) { " | $body" })" 'WARN' }
        else             { Write-Log "API [$status] GET $uri - $_$(if ($body) { " | $body" })" 'ERROR' }
        if ($denied) {
            $what = if ($FullUrl) { $FullUrl } else { $Path }
            Write-Log "ACCESS DENIED [$status] $what - the API client's admin lacks permission for this" 'WARN'
            # For the end-of-run summary, record direct calls by their (clean) path. Probe candidates
            # are -Quiet and tried in bunches; Invoke-ApiProbe records the friendly section label once
            # instead, so the summary reads by section rather than by raw candidate URL.
            if (-not $Quiet) { $script:_deniedPaths += $what }
        }
        return $null
    }
}

# Tries each candidate URL in turn (quietly) and returns the first response that
# returns data, logging which one worked. Used for undocumented platform endpoints.
function Invoke-ApiProbe ([string]$Label, [string[]]$Candidates) {
    $denied = $false   # any candidate returned 401/403 (authorized identity, insufficient rights)
    foreach ($url in $Candidates) {
        $resp = Invoke-CitrixApi -FullUrl $url -Quiet
        if ($resp) {
            Write-Log "$Label`: endpoint discovered -> $url"
            return $resp
        }
        if ($script:_lastStatus -eq 401 -or $script:_lastStatus -eq 403) { $denied = $true }
    }
    # Preserve the access-denied signal: a later 404 candidate would otherwise mask an
    # earlier 403, hiding the real cause (the API client lacks permission, not "no data").
    if ($denied) {
        $script:_lastStatus = 403
        Write-Log "$Label`: ACCESS DENIED (401/403) - the API client's admin lacks permission for this" 'WARN'
        $script:_deniedPaths += $Label   # friendly section name for the end-of-run summary
        return $null
    }
    Write-Log "$Label`: no candidate endpoint responded ($($Candidates.Count) tried)" 'WARN'
    return $null
}

# Some Citrix Cloud platform APIs (e.g. GACS) require standard OAuth2 Bearer auth
# rather than the custom CWSAuth bearer= scheme. This variant uses Bearer.
function Invoke-BearerApi {
    param([string]$FullUrl, [switch]$Quiet)
    $headers = @{
        'Authorization'     = "Bearer $($script:_token)"
        'Citrix-CustomerId' = $script:_customerId
        'Accept'            = 'application/json'
    }
    try {
        return Invoke-SafeRest -Method Get -Uri $FullUrl -Headers $headers
    } catch {
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        $body   = ''
        if ($_.Exception.Response) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = [System.IO.StreamReader]::new($stream)
                $body   = $reader.ReadToEnd()
                if ($body.Length -gt 400) { $body = $body.Substring(0, 400) + '...' }
            } catch { }
        }
        if ($Quiet) { Write-Log "BearerProbe [$status] GET $FullUrl$(if ($body) { " | $body" })" 'INFO' }
        else        { Write-Log "BearerAPI [$status] GET $FullUrl - $_$(if ($body) { " | $body" })" 'ERROR' }
        return $null
    }
}

# Invoke-RestMethod auto-converts ISO date strings to [datetime]. Stringifying
# those in the machine's culture yields ambiguous MM/dd/yyyy values that misparse
# downstream. Normalise any date to round-trip ISO 8601 so the reporter is safe.
function ConvertTo-Iso ($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
        return $dt.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    return "$Value"
}

function Get-PagedResults {
    param(
        [string]$Path,
        [string]$FullUrl = '',
        [string]$ItemsProperty = 'Items',
        [int]$PageSize = 250
    )
    $all   = [System.Collections.Generic.List[object]]::new()
    $token = $null

    do {
        $query = @{ limit = "$PageSize" }
        if ($token) { $query['continuationToken'] = $token }

        $resp = if ($FullUrl) {
            Invoke-CitrixApi -FullUrl $FullUrl -Query $query
        } else {
            Invoke-CitrixApi -Path $Path -Query $query
        }

        if (-not $resp) { break }

        # Pick the items array by checking whether the property EXISTS - not
        # whether it is truthy. An empty Items array ([]) is falsy in PS, so a
        # truthiness test would fall through and wrap the response envelope as a
        # bogus all-null row. Only treat $resp as a single item when it carries
        # no items property at all (e.g. a bare object endpoint).
        $propNames = @($resp.PSObject.Properties.Name)
        $items = if     ($ItemsProperty -and $propNames -contains $ItemsProperty) { $resp.$ItemsProperty }
                 elseif ($propNames -contains 'Items')                            { $resp.Items }
                 elseif ($propNames -contains 'items')                            { $resp.items }
                 else                                                             { @($resp) }

        foreach ($item in @($items)) { if ($null -ne $item) { $all.Add($item) } }
        $token = $resp.ContinuationToken
    } while ($token)

    # Unary comma prevents PowerShell from unrolling an empty array to $null,
    # so callers always receive an array (and .Count is reliable).
    return ,$all.ToArray()
}

# Pages a Citrix Monitor OData v4 query. Unlike the DaaS API (ContinuationToken),
# Monitor OData returns `{ value:[...], "@odata.nextLink":"..." }` - follow the
# nextLink until exhausted. $RelativeUrl is appended to the monitorodata base.
function Get-MonitorOData ([string]$RelativeUrl, [int]$MaxPages = 500) {
    $all  = [System.Collections.Generic.List[object]]::new()
    $url  = "https://api.cloud.com/monitorodata/$RelativeUrl"
    $page = 0
    while ($url -and $page -lt $MaxPages) {
        $resp = Invoke-CitrixApi -FullUrl $url -Quiet
        if (-not $resp) { break }
        $val = if ($resp.PSObject.Properties['value']) { $resp.value } else { @($resp) }
        foreach ($item in @($val)) { if ($null -ne $item) { $all.Add($item) } }
        # @odata.nextLink may be absolute OR relative (e.g. "Sessions?$skiptoken=...").
        # Resolve it against the current URL so paging actually advances - passing a
        # relative link straight to -FullUrl would fail and silently stop after page 1.
        $next = if ($resp.PSObject.Properties['@odata.nextLink']) { "$($resp.'@odata.nextLink')" } else { '' }
        if ($next) {
            try { $url = [Uri]::new([Uri]$url, $next).AbsoluteUri } catch { $url = $next }
        } else { $url = '' }
        $page++
    }
    if ($page -ge $MaxPages) { Write-Log "Monitor OData: hit max page cap ($MaxPages) for $RelativeUrl" 'WARN' }
    Write-Log "Monitor OData: $($all.Count) row(s) over $page page(s) for $($RelativeUrl.Split('?')[0])"
    return ,$all.ToArray()
}

# Logs the first raw API object for an endpoint so its real field names can be
# confirmed from the debug log when mappings come back empty.
function Write-RawSample ([string]$Label, $Obj) {
    if ($null -eq $Obj) { Write-Log "$Label raw sample: <null>"; return }
    try {
        $j = $Obj | ConvertTo-Json -Depth 6 -Compress
        if ($j.Length -gt 2500) { $j = $j.Substring(0, 2500) + '...(truncated)' }
        Write-Log "$Label raw sample: $j"
    } catch { Write-Log "$Label raw sample: <unserializable>" }
}

#endregion

#region ── Cloud Resource Collection ─────────────────────────────────────────

function Get-CloudResourceLocations {
    Set-SplashStatus 'Collecting resource locations...'
    $cid   = $script:_customerId
    $items = Get-PagedResults -FullUrl 'https://api.cloud.com/resourcelocations' -ItemsProperty 'items'

    # Cloud Connectors / Connector Appliances are reported by the edgeservers (a.k.a.
    # connectors) registry, keyed by resource location. Probe for it and build a
    # per-resource-location connector summary.
    # The console reads edge servers from agenthub with connectorType=All, which returns
    # Cloud Connectors AND Connector Appliances across all RLs in one call. The older
    # api.cloud.com/connectors feed only returns Windows Cloud Connectors (appliances are
    # absent), so it's kept only as a fallback.
    $connResp = Invoke-ApiProbe 'Resource location connectors' @(
        "https://agenthub.citrixworkspacesapi.net/$cid/edgeservers?connectorType=All"
        "https://api.cloud.com/connectors"
        "https://registry.citrixworkspacesapi.net/$cid/edgeservers"
        "https://api.cloud.com/edgeservers"
    )
    if ($connResp) { Write-RawSample 'EdgeServers' $connResp }
    # NOTE: /connectors returns a bare JSON array. Check for an array FIRST - using
    # $connResp.items on an array member-enumerates to an array of nulls, and a PS
    # array of 2+ elements is always truthy, which would silently yield null rows.
    $connSrc = if (-not $connResp) { @() }
               elseif ($connResp -is [array]) { $connResp }
               elseif ($connResp.items) { $connResp.items }
               elseif ($connResp.Items) { $connResp.Items }
               elseif ($connResp -is [System.Collections.IEnumerable] -and -not ($connResp -is [string])) { $connResp }
               else { @($connResp) }
    # Group connectors by resource-location id (the /connectors feed keys this as
    # `location`), splitting by connector type. connectorType 'Windows' is a Cloud
    # Connector; appliance types are Connector Appliances.
    $connByRl = @{}
    $connDetailByRl = @{}   # per-RL connector detail (FQDN / version / status), keyed by RL id
    foreach ($c in @($connSrc)) {
        if ($null -eq $c) { continue }
        $rlId = ''
        foreach ($k in 'location','resourceLocationId','resourceLocation','locationId') {
            if ($c.PSObject.Properties[$k] -and "$($c.$k)") { $rlId = "$($c.$k)"; break }
        }
        if (-not $rlId) { continue }
        if (-not $connByRl.ContainsKey($rlId)) { $connByRl[$rlId] = [ordered]@{ CloudConnectors=0; ConnectorAppliances=0; FasServers=0 } }
        $ctype = ''
        foreach ($k in 'connectorType','product','type') {
            if ($c.PSObject.Properties[$k] -and "$($c.$k)") { $ctype = "$($c.$k)".ToLower(); break }
        }
        # connectorType: "Windows" = a (Windows) Cloud Connector; "Unified" (Linux-based)
        # or "*appliance*" = a Connector Appliance. FAS servers are NOT in this feed -
        # they come from the dedicated FAS hub service below.
        $isAppliance = ($ctype -match 'appliance|unified')
        if ($isAppliance) { $connByRl[$rlId]['ConnectorAppliances']++ }
        else              { $connByRl[$rlId]['CloudConnectors']++ }
        # Per-connector detail for the report - field names vary across the connector feeds, so probe.
        # NB: the edgeservers feed leaves `status` = "Unknown" for Cloud Connectors; the real health
        # signals are versionState / inMaintenance / lastContactDate. Capture them raw and let the
        # report derive a displayed status (collector just collects; report interprets).
        $cFqdn = ''; foreach ($k in 'fqdn','name','machineName','dnsName','displayName') { if ($c.PSObject.Properties[$k] -and "$($c.$k)") { $cFqdn = "$($c.$k)"; break } }
        $cVer  = ''; foreach ($k in 'version','currentVersion','productVersion','buildNumber') { if ($c.PSObject.Properties[$k] -and "$($c.$k)") { $cVer = "$($c.$k)"; break } }
        $cState = ''; foreach ($k in 'status','state','registrationState','connectivityStatus') { if ($c.PSObject.Properties[$k] -and "$($c.$k)") { $cState = "$($c.$k)"; break } }
        if (-not $cState -and $c.PSObject.Properties['available']) { $cState = if ([bool]$c.available) { 'Available' } else { 'Unavailable' } }
        $cVerState = ''; if ($c.PSObject.Properties['versionState'] -and "$($c.versionState)") { $cVerState = "$($c.versionState)" }
        $cMaint = $false; if ($c.PSObject.Properties['inMaintenance']) { $cMaint = [bool]$c.inMaintenance }
        $cLastContact = ''; foreach ($k in 'lastContactDate','lastContact','lastSeen') { if ($c.PSObject.Properties[$k] -and "$($c.$k)") { $cLastContact = "$($c.$k)"; break } }
        if (-not $connDetailByRl.ContainsKey($rlId)) { $connDetailByRl[$rlId] = [System.Collections.Generic.List[object]]::new() }
        [void]$connDetailByRl[$rlId].Add([ordered]@{ Fqdn = $cFqdn; Version = $cVer; State = $cState; Kind = $(if ($isAppliance) { 'Connector Appliance' } else { 'Cloud Connector' }); VersionState = $cVerState; InMaintenance = $cMaint; LastContact = $cLastContact })
    }
    Write-Log "Resource location connectors: $(@($connSrc).Count) connector(s) across $($connByRl.Count) location group(s)"

    # FAS servers register with the dedicated FAS hub service (NOT the connector
    # registry), so the console's per-RL "FAS Servers" tile reads from here. Uses the
    # same CWSAuth client token. Group the servers by their resource-location id.
    $fasResp = Invoke-CitrixApi -FullUrl "https://fashub.citrixworkspacesapi.net/$cid/FasServers" -Quiet
    if ($fasResp) { Write-RawSample 'FasServers' $fasResp }
    $fasSrc = if (-not $fasResp) { @() }
              elseif ($fasResp -is [array]) { $fasResp }
              elseif ($fasResp.items) { $fasResp.items }
              elseif ($fasResp.Items) { $fasResp.Items }
              elseif ($fasResp -is [System.Collections.IEnumerable] -and -not ($fasResp -is [string])) { $fasResp }
              else { @($fasResp) }
    $fasByRl = @{}
    foreach ($fs in @($fasSrc)) {
        if ($null -eq $fs -or $fs -is [string]) { continue }
        $rlId = ''
        foreach ($k in 'resourceLocationId','location','resourceLocation','locationId') {
            if ($fs.PSObject.Properties[$k] -and "$($fs.$k)") { $rlId = "$($fs.$k)"; break }
        }
        $fqdn = ''
        foreach ($k in 'fqdn','address','machineName','name','dnsName') {
            if ($fs.PSObject.Properties[$k] -and "$($fs.$k)") { $fqdn = "$($fs.$k)"; break }
        }
        $ver = ''
        foreach ($k in 'version','currentVersion','productVersion') {
            if ($fs.PSObject.Properties[$k] -and "$($fs.$k)") { $ver = "$($fs.$k)"; break }
        }
        $state = ''
        foreach ($k in 'status','state','registrationState') {
            if ($fs.PSObject.Properties[$k] -and "$($fs.$k)") { $state = "$($fs.$k)"; break }
        }
        # FAS hub reports reachability via an `available` bool rather than a status string.
        if (-not $state -and $fs.PSObject.Properties['available']) { $state = if ([bool]$fs.available) { 'Available' } else { 'Unavailable' } }
        if (-not $rlId) { $rlId = '_unmapped' }
        if (-not $fasByRl.ContainsKey($rlId)) { $fasByRl[$rlId] = [System.Collections.Generic.List[object]]::new() }
        [void]$fasByRl[$rlId].Add([ordered]@{ Fqdn = $fqdn; Version = $ver; State = $state })
    }
    Write-Log "FAS servers: $(@($fasSrc).Count) server(s) across $($fasByRl.Count) location group(s)"

    # Maintenance schedule: the console reads it from the AgentHub service (not the
    # resourcelocations feed). Returns a bare array keyed by `location` (= RL id):
    #   [{ location, dayOfWeek:"Sunday"|"Undefined", start:"HH:mm:ss", order }]
    # dayOfWeek "Undefined" = no window set (updates apply as soon as available).
    # The schedule timezone is the resource location's own timeZone.
    $maintResp = Invoke-CitrixApi -FullUrl "https://agenthub.citrixworkspacesapi.net/$cid/maintenance/" -Quiet
    $maintApiAvailable = [bool]$maintResp
    if ($maintResp) { Write-RawSample 'ResourceLocationMaintenance' $maintResp }
    $maintByRl = @{}
    foreach ($m in @($maintResp)) {
        if ($null -eq $m -or -not "$($m.location)") { continue }
        $maintByRl["$($m.location)"] = $m
    }

    $results = @($items | ForEach-Object {
        $rl = $_
        $rlId = "$($rl.id)"
        $counts = if ($connByRl.ContainsKey($rlId)) { $connByRl[$rlId] } else { [ordered]@{ CloudConnectors=0; ConnectorAppliances=0; FasServers=0 } }
        # Count/detail from the List directly: @() on a single-element list unrolls the
        # OrderedDictionary's entries (PS 5.1), inflating the count. .Count / .ToArray() are safe.
        $fasCount = 0; $fasDetail = @()
        if ($fasByRl.ContainsKey($rlId)) { $fasCount = $fasByRl[$rlId].Count; $fasDetail = $fasByRl[$rlId].ToArray() }
        $ccDetail = @()
        if ($connDetailByRl.ContainsKey($rlId)) { $ccDetail = $connDetailByRl[$rlId].ToArray() }

        $maintEnabled = $false; $maintDay = ''; $maintHour = ''
        if ($maintByRl.ContainsKey($rlId)) {
            $m   = $maintByRl[$rlId]
            $day = "$($m.dayOfWeek)"
            if ($day -and $day -ne 'Undefined') {
                $maintEnabled = $true
                $maintDay = $day
                if ("$($m.start)") {
                    try { $maintHour = ([datetime]::ParseExact("$($m.start)", 'HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)).ToString('h:mm tt', [Globalization.CultureInfo]::InvariantCulture) }
                    catch { $maintHour = "$($m.start)" }
                }
            }
        }

        [ordered]@{
            Id                  = $rl.id
            Name                = $rl.name
            InternalOnly        = $rl.internalOnly
            TimeZone            = $rl.timeZone
            CloudConnectors     = [int]$counts['CloudConnectors']
            ConnectorAppliances = [int]$counts['ConnectorAppliances']
            CloudConnectorDetail = $ccDetail
            FasServers          = $fasCount
            FasServerDetail     = $fasDetail
            MaintenanceApiAvailable = $maintApiAvailable
            MaintenanceEnabled  = $maintEnabled
            MaintenanceDay      = $maintDay
            MaintenanceHour     = $maintHour
            MaintenanceTimeZone = $rl.timeZone
        }
    })
    Write-Log "Resource locations: $($results.Count) (maintenance API: $maintApiAvailable)"
    return $results
}

# NOTE: Identity providers, Cloud StoreFront configuration, and Cloud administrators are
# separate Citrix Cloud *platform* services (not DaaS), and their REST endpoints
# are not cleanly documented. When $script:_collectPlatform is on, each function
# probes a list of candidate URLs (modern api.cloud.com + legacy
# citrixworkspacesapi.net) and uses whichever responds, logging the winner to the
# debug log. Inspect CitrixCloudData-Debug.log after a run to see what worked.
$script:_collectPlatform = $true

function Get-CloudIdentityProviders {
    if (-not $script:_collectPlatform) { Write-Log 'Identity providers: skipped'; return @() }
    Set-SplashStatus 'Collecting identity providers...'
    $cid  = $script:_customerId
    # Two-pass approach: get the full type list then overlay enabled/disabled status.
    # GET /identityProviders returns a string array of all configured types (TitleCase).
    # GET /identityProviders/all/status returns an enabled-flag dict (lowercase keys).
    # Merge both so every type gets a status where available.
    $listResp   = Invoke-CitrixApi -FullUrl "https://cws.citrixworkspacesapi.net/$cid/identityProviders" -Quiet
    $statusResp = Invoke-CitrixApi -FullUrl "https://cws.citrixworkspacesapi.net/$cid/identityProviders/all/status" -Quiet
    if (-not $listResp -and -not $statusResp) {
        if ($script:_lastStatus -eq 401 -or $script:_lastStatus -eq 403) { $script:_collectStatus['IdentityProviders'] = 'AccessDenied' }
        Write-Log 'Identity providers: no endpoint responded' 'WARN'; return @()
    }
    if ($listResp)   { Write-RawSample 'IdentityProviders' $listResp }
    if ($statusResp) { Write-RawSample 'IdentityProvidersStatus' $statusResp }

    # Build lowercase-keyed status lookup from /all/status
    $statusMap = @{}
    if ($statusResp -and $statusResp.identityProviderEnabled) {
        $statusResp.identityProviderEnabled.PSObject.Properties | ForEach-Object {
            $statusMap[$_.Name.ToLower()] = if ($_.Value -eq $true) { 'Enabled' } else { 'Disabled' }
        }
    }

    # Determine the type list source: prefer the array from /identityProviders, fall back to status map keys
    $typeList = @(
        if ($listResp -and $listResp -is [System.Collections.IEnumerable] -and -not ($listResp -is [string])) {
            $listResp
        } elseif ($statusMap.Count -gt 0) {
            $statusMap.Keys
        }
    )
    # "Policy" is a conditional-authentication catalog entry, not a usable IdP - drop it.
    $typeList = @($typeList | Where-Object { "$_".ToLower() -ne 'policy' })

    $results = @($typeList | ForEach-Object {
        $typeStr  = "$_"
        $typeLow  = $typeStr.ToLower()
        $status   = if ($statusMap.ContainsKey($typeLow)) { $statusMap[$typeLow] } else { $null }
        # Fetch per-provider detail (configured instances / domains). The detail
        # endpoint shape varies per type; capture instances generically so the
        # report can expand each provider. Citrix Identity has no config to fetch.
        $instances = @()
        if ($typeLow -ne 'citrix') {
            $detail = Invoke-CitrixApi -FullUrl "https://cws.citrixworkspacesapi.net/$cid/identityProviders/$typeLow" -Quiet
            if ($detail) {
                Write-RawSample "IdentityProvider_$typeStr" $detail
                $instances = ConvertTo-IdpInstanceList $detail
            }
        }
        [ordered]@{
            Type        = $typeStr
            Status      = $status
            DisplayName = $null
            Domain      = $null
            Details     = $null
            Instances   = $instances
        }
    })
    Write-Log "Identity providers: $($results.Count)"
    return $results
}

# Normalises a per-IdP detail response into a flat list of configured instances.
# All provider types share one union schema (idpNickname, domains[], connectorsCount,
# azureAdConnection{}, additionalStatusInfo{}, issuerFqdn, url, ...). We pull the
# fields the report expands per provider: name, domains, connectors, connection
# state, and a type-specific detail (Azure tenant, SAML cert expiry, gateway FQDN).
function ConvertTo-IdpInstanceList ($detail) {
    $src = if ($null -eq $detail) { @() }
           elseif ($detail.items) { $detail.items }
           elseif ($detail.Items) { $detail.Items }
           elseif ($detail -is [System.Collections.IEnumerable] -and -not ($detail -is [string])) { $detail }
           else { @($detail) }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($it in @($src)) {
        if ($null -eq $it) { continue }

        $aad = $it.azureAdConnection
        $asi = $it.additionalStatusInfo

        # Display name: nickname > Azure display name > SAML auth-domain name.
        $name = $null
        if ("$($it.idpNickname)") { $name = "$($it.idpNickname)" }
        elseif ($aad -and "$($aad.authDomainDisplayName)") { $name = "$($aad.authDomainDisplayName)" }
        elseif ("$($it.authDomainName)") { $name = "$($it.authDomainName)" }

        # Domains: AD/AdOtp carry a domains[] list; others fall back per type.
        $domains = ''
        if ($it.domains -and @($it.domains).Count -gt 0) {
            $domains = (@($it.domains | ForEach-Object { if ($_.PSObject.Properties['name']) { "$($_.name)" } else { "$_" } }) -join ', ')
        } elseif ($aad -and "$($aad.authDomainName)") {
            $domains = "$($aad.authDomainName)"
        } elseif ("$($it.issuerFqdn)") {
            $domains = "$($it.issuerFqdn)"
        }

        # Connection state: Azure carries an explicit boolean; otherwise use enabled.
        $state = ''
        if ($aad -and $null -ne $aad.connectionStatus) {
            $state = if ($aad.connectionStatus -eq $true) { 'Connected' } else { 'Not connected' }
        } elseif ($null -ne $it.enabled) {
            $state = if ($it.enabled -eq $true) { 'Enabled' } else { 'Disabled' }
        }

        # Type-specific detail line shown under the instance.
        $detailBits = @()
        if ($asi -and "$($asi.tid)")                { $detailBits += "Tenant: $($asi.tid)" }
        if ($asi -and "$($asi.samlCertExpiration)") { $detailBits += "Cert expires: $($asi.samlCertExpiration)" }
        if ("$($it.issuerFqdn)")                    { $detailBits += "Issuer: $($it.issuerFqdn)" }
        if ($null -ne $it.connectorsCount -and "$($it.connectorsCount)") { $detailBits += "Connectors: $($it.connectorsCount)" }
        if ("$($it.url)")                           { $detailBits += "URL: $($it.url)" }

        # Skip non-informative placeholder instances (typically a disabled provider
        # with no configured tenant/domain/detail) - the top-level status already says so.
        $detailStr = ($detailBits -join '  •  ')
        if (-not $name -and -not $domains -and -not $detailStr) { continue }

        [void]$out.Add([ordered]@{
            Name       = if ($name) { $name } else { '(default)' }
            Domains    = $domains
            State      = $state
            Connectors = if ($null -ne $it.connectorsCount) { "$($it.connectorsCount)" } else { '' }
            InstanceId = if ("$($it.idpInstanceId)") { "$($it.idpInstanceId)" } else { '' }
            Url        = if ("$($it.url)") { "$($it.url)" } else { '' }
            Detail     = $detailStr
        })
    }
    return ,$out.ToArray()
}

function Get-ConditionalAuthPolicies {
    if (-not $script:_collectPlatform) { Write-Log 'Conditional auth: skipped'; return ,@() }
    Set-SplashStatus 'Collecting conditional authentication policies...'
    $cid = $script:_customerId
    $resp = Invoke-ApiProbe 'Conditional auth policies' @(
        "https://cws.citrixworkspacesapi.net/$cid/conditionalAccessPolicies"
        "https://cws.citrixworkspacesapi.net/$cid/authentication/conditionalAccessPolicies"
        "https://cws.citrixworkspacesapi.net/$cid/identityProviders/conditionalAccessPolicies"
        "https://cws.citrixworkspacesapi.net/$cid/conditionalAuth/policies"
        "https://cws.citrixworkspacesapi.net/$cid/conditionalAuthentication/policies"
        "https://api.cloud.com/trust/v1/$cid/conditionalAccessPolicies"
    )
    if (-not $resp) {
        if ($script:_lastStatus -eq 401 -or $script:_lastStatus -eq 403) { $script:_collectStatus['ConditionalAuthPolicies'] = 'AccessDenied' }
        Write-Log 'Conditional auth: no endpoint responded'; return ,@()
    }
    Write-RawSample 'ConditionalAuthPolicies' $resp
    # Response shape: { "policySets": [{ "id", "name", "type", "policies": [...], ... }] }
    $src = if ($resp.policySets) { $resp.policySets } `
           elseif ($resp.Items)  { $resp.Items }   elseif ($resp.items)  { $resp.items } `
           elseif ($resp -is [System.Collections.IEnumerable] -and -not ($resp -is [string])) { $resp } `
           else { @($resp) }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($p in @($src)) {
        if ($null -eq $p) { continue }
        # Each policy set carries an ordered list of rules in `policies`. A rule has
        # one or more `conditions` (operator/source/values) and a `result` that names
        # the resultant IdP as "<idpType>:<idpInstanceId>" (e.g. "azuread:<guid>").
        $rules = [System.Collections.Generic.List[object]]::new()
        foreach ($rule in @($p.policies)) {
            if ($null -eq $rule) { continue }
            $conds = [System.Collections.Generic.List[object]]::new()
            foreach ($c in @($rule.conditions)) {
                if ($null -eq $c) { continue }
                # values may be a scalar, an array of objects ({displayName,value}),
                # or empty - normalise to a flat string array of the actual values.
                $rawVals = @(
                    if ($null -eq $c.values) { }
                    elseif ($c.values -is [System.Collections.IEnumerable] -and -not ($c.values -is [string])) { $c.values }
                    else { $c.values }
                )
                $vals = @($rawVals | ForEach-Object {
                    if ($null -eq $_) { return }
                    if ($_.PSObject -and $_.PSObject.Properties['value']) { "$($_.value)" }
                    elseif ($_.PSObject -and $_.PSObject.Properties['displayName'] -and "$($_.displayName)") { "$($_.displayName)" }
                    else { "$_" }
                } | Where-Object { "$_".Length -gt 0 })
                [void]$conds.Add([ordered]@{
                    Source   = if ($c.source)   { "$($c.source)" }   else { '' }
                    Operator = if ($c.operator) { "$($c.operator)" } else { '' }
                    Values   = $vals
                })
            }
            # Split "<idpType>:<id>" into a friendly IdP type + instance id.
            $resultRaw  = if ($rule.result) { "$($rule.result)" } else { '' }
            $resultType = if ($resultRaw -match '^([^:]+):') { $matches[1] } else { $resultRaw }
            $resultId   = if ($resultRaw -match ':(.+)$')    { $matches[1] } else { '' }
            [void]$rules.Add([ordered]@{
                Name         = if ($rule.name) { "$($rule.name)" } else { '' }
                Priority     = if ($null -ne $rule.priority) { [int]$rule.priority } else { $null }
                Enabled      = if ($null -ne $rule.enabled)  { [bool]$rule.enabled } else { $true }
                Conditions   = $conds.ToArray()
                ResultType   = $resultType
                ResultIdpId  = $resultId
            })
        }
        # Order rules by priority so the report reflects evaluation order.
        $orderedRules = @($rules | Sort-Object { if ($null -ne $_['Priority']) { $_['Priority'] } else { [int]::MaxValue } })
        [void]$out.Add([ordered]@{
            Name        = if ($p.name)       { $p.name }       else { $null }
            PolicyType  = if ($p.type)       { $p.type }       else { $null }
            RulesCount  = $orderedRules.Count
            Id          = if ($p.id)         { $p.id }         else { $null }
            Rules       = $orderedRules
        })
    }
    Write-Log "Conditional auth policies: $($out.Count)"
    return ,$out.ToArray()
}

function Get-StoreCustomDomains ([string]$StoreGuid) {
    # Query the Citrix custom-domain-service for a store's custom (vanity) Cloud StoreFront URL(s).
    # It returns each configured custom domain with Citrix's own certificate record - expiry and type,
    # where type 'Managed' means Citrix provisioned and auto-renews the certificate (Citrix-provided)
    # and anything else means the customer uploaded their own (customer-provided). The service host is
    # geo-routed (us / eu / ap-s); the first geo that answers is cached for the remaining stores.
    # Discovered via browser F12 capture. Empty array on any failure so collection continues.
    if (-not $StoreGuid) { return @() }
    $cid  = $script:_customerId
    $geos = if ($script:_cdGeo) { @($script:_cdGeo) } else { @('us', 'eu', 'ap-s') }
    foreach ($geo in $geos) {
        $url  = "https://custom-domain-service.$geo.wsp.cloud.com/services/custom-domain-service/customers/$cid/stores/$StoreGuid/customdomains"
        $resp = Invoke-CitrixApi -FullUrl $url -Quiet
        if ($resp) {
            $script:_cdGeo = $geo
            $out = [System.Collections.Generic.List[object]]::new()
            foreach ($it in @($resp.items)) {
                if (-not $it -or -not $it.domain) { continue }
                $ci   = $it.certificateInformation
                $type = if ($ci) { "$($ci.type)" } else { '' }
                $exp  = ''
                if ($ci -and $ci.expiry) {
                    try { $exp = ([datetimeoffset]"$($ci.expiry)").UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { $exp = "$($ci.expiry)" }
                }
                [void]$out.Add([ordered]@{
                    Host     = "$($it.domain)"
                    State    = "$($it.state)"
                    CertType = $type
                    NotAfter = $exp
                    # 'Managed' = Citrix-provisioned & auto-renewed; anything else = customer-supplied.
                    Provider = if ($type -eq 'Managed') { 'Citrix' } else { 'Customer' }
                    Error    = ''
                })
            }
            return $out.ToArray()
        }
        if ($script:_lastStatus -eq 401 -or $script:_lastStatus -eq 403) {
            Write-Log "Cloud StoreFront config: custom-domain-service denied ($($script:_lastStatus)) for store $StoreGuid"
            return @()
        }
    }
    Write-Log "Cloud StoreFront config: custom-domain-service returned no data for store $StoreGuid"
    return @()
}

function Get-WorkspaceConfig {
    if (-not $script:_collectPlatform) { Write-Log 'Cloud StoreFront config: skipped'; return [ordered]@{} }
    Set-SplashStatus 'Collecting Cloud StoreFront configuration...'
    $cid = $script:_customerId

    # The console's Cloud StoreFront > Access page reads from the StoreFront
    # configuration service. Returns { entitled, items:[ <store config> ] } where each
    # store carries its workspace URLs, authentication IdP, adaptive access, branding,
    # 2FA, self-service, and feature preferences. Discovered via browser F12 capture.
    $resp = Invoke-CitrixApi -FullUrl "https://storefrontconfiguration.citrixworkspacesapi.net/$cid/storeconfigs" -Quiet
    if (-not $resp) {
        Write-Log 'Cloud StoreFront config: storeconfigs endpoint unavailable'
        return [ordered]@{ ApiAvailable = $false; Stores = @() }
    }
    Write-RawSample 'WorkspaceStoreConfigs' $resp
    $src = if ($resp.items) { $resp.items } elseif ($resp.Items) { $resp.Items } `
           elseif ($resp -is [System.Collections.IEnumerable] -and -not ($resp -is [string])) { $resp } else { @($resp) }

    $stores = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($src)) {
        if ($null -eq $s) { continue }
        $prefs = $s.preferences
        $style = $s.userStyle
        $signIn = if ($prefs) { $prefs.customerSignInPolicy } else { $null }
        $branding = [ordered]@{
            BackgroundColor = if ($style) { "$($style.backgroundColor)" } else { '' }
            TextColor       = if ($style) { "$($style.textColor)" } else { '' }
            LinkColor       = if ($style) { "$($style.linkColor)" } else { '' }
            HeaderLogo      = if ($style -and $style.headerLogo) { 'Custom' } else { 'Default' }
            LogonLogo       = if ($style -and $style.logonLogo) { 'Custom' } else { 'Default' }
        }
        $domainList = @($s.storeFrontDomains | ForEach-Object { "$_" })
        # Custom (vanity) Cloud StoreFront URL(s) for this store, from the Citrix custom-domain-service:
        # each custom domain plus Citrix's certificate expiry and type (Managed = Citrix auto-renewed;
        # otherwise customer-supplied).
        $customDomains = Get-StoreCustomDomains "$($s.storeGuid)"
        if (@($customDomains).Count) {
            Write-Log "Cloud StoreFront config: store $($s.storeId) custom domain(s): $((@($customDomains) | ForEach-Object { $_.Host }) -join ', ')"
        }
        [void]$stores.Add([ordered]@{
            StoreId               = "$($s.storeId)"
            StoreGuid             = "$($s.storeGuid)"
            Domains               = $domainList
            CustomDomains         = @($customDomains)
            WorkspaceUrlEnabled   = [bool]$s.workSpaceUrlEnabled
            AuthIdpType           = "$($s.idpType)"
            AuthConfigId          = "$($s.idpConfigId)"
            AuthNickname          = if ($s.idpNickname) { "$($s.idpNickname)" } else { '' }
            AdaptiveAccessEnabled = [bool]$s.adaptiveAccessNLSEnabled
            FasEnabled            = [bool]$s.fasEnabled
            ExternalUserSSOEnabled= [bool]$s.externalUserSSOEnabled
            TwoFactorEnabled      = if ($s.twoFactorAuth) { [bool]$s.twoFactorAuth.enabled } else { $false }
            AzureAdSsoEnabled     = if ($prefs) { [bool]$prefs.azureAdSsoEnabled } else { $false }
            FavoritesEnabled      = if ($prefs) { [bool]$prefs.favoritesEnabled } else { $false }
            WorkspaceHomeEnabled  = if ($prefs) { [bool]$prefs.workspaceHomeEnabled } else { $false }
            AutoLaunchDesktop     = if ($prefs) { [bool]$prefs.autoLaunchDesktopEnabled } else { $false }
            SignInPolicyEnabled   = if ($signIn) { [bool]$signIn.signInPolicyEnabled } else { $false }
            DisabledServices      = @($s.disabledServices | ForEach-Object { "$_" })
            Branding              = $branding
        })
    }

    # Service Continuity (connection leasing) site properties. Region-routed host;
    # try the global api.cloud.com first, then the regional api-us variant. Needs the
    # X-Xd-CustomerId header. Shape captured via Write-RawSample for field mapping.
    $scResp = Invoke-CitrixApi -FullUrl "https://api.cloud.com/leasingservice/api/v1/clis_service/siteproperties/$cid" -ExtraHeaders @{ 'X-Xd-CustomerId' = $cid } -Quiet
    if (-not $scResp) {
        $scResp = Invoke-CitrixApi -FullUrl "https://api-us.cloud.com/leasingservice/api/v1/clis_service/siteproperties/$cid" -ExtraHeaders @{ 'X-Xd-CustomerId' = $cid } -Quiet
    }
    $serviceContinuity = [ordered]@{ ApiAvailable = [bool]$scResp }
    if ($scResp) {
        Write-RawSample 'ServiceContinuity' $scResp
        # Flat object of connection-leasing site properties (verified shape).
        $serviceContinuity['Enabled']                = [bool]$scResp.resourceLeasingEnabled
        $serviceContinuity['LeaseValidityDays']       = if ($null -ne $scResp.resourceLeaseValidityPeriodInDays) { [int]$scResp.resourceLeaseValidityPeriodInDays } else { $null }
        $serviceContinuity['DeleteLeasesOnLogOff']     = [bool]$scResp.deleteResourceLeasesOnLogOff
        $serviceContinuity['BypassAuthForCached']      = [bool]$scResp.bypassAuthForCachedResources
    }

    Write-Log "Cloud StoreFront config: $($stores.Count) store(s); service continuity: $($serviceContinuity['ApiAvailable'])"
    return [ordered]@{
        ApiAvailable      = $true
        Entitled          = [bool]$resp.entitled
        Stores            = $stores.ToArray()
        ServiceContinuity = $serviceContinuity
    }
}

function Get-NetworkLocations {
    if (-not $script:_collectPlatform) { Write-Log 'Network locations: skipped'; return ,@() }
    Set-SplashStatus 'Collecting network locations...'
    # Network Location Service (NLS) base URL: https://network-location.cloud.com
    # Source: citrix/sample-scripts/workspace/NLS2.psm1 - uses /location/v1/sites
    # Auth: same CWSAuth bearer + Citrix-CustomerId headers as other cloud APIs.
    $resp = Invoke-ApiProbe 'Network locations' @(
        "https://network-location.cloud.com/location/v1/sites"
        "https://network-location.cloud.com/location/v2/sites"
        "https://network-location.cloud.com/location/v1/networklocations"
    )
    if (-not $resp) {
        if ($script:_lastStatus -eq 401 -or $script:_lastStatus -eq 403) { $script:_collectStatus['NetworkLocations'] = 'AccessDenied' }
        Write-Log 'Network locations: no candidate endpoint responded' 'WARN'; return ,@()
    }
    Write-RawSample 'NetworkLocations' $resp
    # NLS response: { "sites": [...] } — ipv4Ranges (string[]), tags (string[]), internal (bool)
    $src = if ($resp.sites)  { $resp.sites }  elseif ($resp.Sites)  { $resp.Sites } `
           elseif ($resp.Items) { $resp.Items } elseif ($resp.items) { $resp.items } `
           elseif ($resp -is [System.Collections.IEnumerable] -and -not ($resp -is [string])) { $resp } `
           else { @($resp) }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($loc in @($src)) {
        $ipRanges = @($loc.ipv4Ranges | ForEach-Object { "$_" })
        $tags     = @($loc.tags       | ForEach-Object { "$_" })
        $network  = if ($null -ne $loc.internal) { if ($loc.internal) { 'Internal' } else { 'External' } } `
                    elseif ($loc.network) { "$($loc.network)" } else { '' }
        [void]$out.Add([ordered]@{
            Id          = "$($loc.id)"
            Name        = if ($loc.name) { "$($loc.name)" } else { '' }
            IpRanges    = $ipRanges
            Tags        = $tags
            Network     = $network
            Description = if ($loc.description) { "$($loc.description)" } else { '' }
        })
    }
    Write-Log "Network locations: $($out.Count)"
    return ,$out.ToArray()
}

function Get-CitrixLicensing {
    Set-SplashStatus 'Collecting licensing...'
    # Citrix Cloud licensing is per-entitlement, per-model - there is no single "list entitlements" API.
    # Each product is queried by its known code (discovered via the console's F12 network capture); a 200
    # becomes an entitlement, a 404 means "not entitled" (skipped), and a 403 means the API client lacks the
    # Licensing permission. Hosts: cloudlicense.citrixworkspacesapi.net for Concurrent/Gateway/SPA/Endpoint
    # Management; api.cloud.com/licensing for the DaaS User/Device model.
    $cid  = $script:_customerId
    $cl   = "https://cloudlicense.citrixworkspacesapi.net/$cid"
    $ents = [System.Collections.Generic.List[object]]::new()
    $anyDenied = $false

    # --- DaaS: Concurrent model first (cloudlicense), else User/Device (api.cloud.com) ---
    $ccu = Invoke-CitrixApi -FullUrl "$cl/license/enterprise/cloud/cvad/ccu/summary?UsageType=device&LicenseModel=Concurrent" -Quiet
    if ($ccu -and $ccu.currentCcu) {
        Write-RawSample 'Licensing-DaaS-CCU' $ccu
        $cur = $ccu.currentCcu
        $peak = { param($p) if ($p) { [ordered]@{ Assigned = [int]$p.assignedLicenseCount; When = ConvertTo-Iso $p.reportTime } } else { $null } }
        $daasEnt = [ordered]@{
            Product='DaaS'; ProductCode='cvad'; Model='Concurrent'; Status='OK'
            Total=[int]$cur.totalLicenseCount; Assigned=[int]$cur.assignedLicenseCount
            Available=([int]$cur.totalLicenseCount - [int]$cur.assignedLicenseCount)
            ReportTime=(ConvertTo-Iso $cur.reportTime)
            Peaks=[ordered]@{ Last24h=(& $peak $ccu.last24HoursPeak); Month=(& $peak $ccu.monthPeak); AllTime=(& $peak $ccu.allTimePeak) }
        }
        # Active Use (monthly / daily concurrent usage) - the console's "Active Use" tile, a separate service.
        $au = Invoke-CitrixApi -FullUrl "https://activeuse.citrixworkspacesapi.net/$cid/cloudlicenseactiveuse/products/xenappxendesktop/current?licenseModel=Concurrent" -Quiet
        if ($au) {
            Write-RawSample 'Licensing-DaaS-ActiveUse' $au
            $daasEnt['ActiveUse'] = [ordered]@{
                MonthlyValue=[int]$au.monthlyActiveUseValue; MonthlyPct=[double]$au.monthlyActiveUsePercentage
                DailyValue=[int]$au.dailyActiveUseValue;     DailyPct=[double]$au.dailyActiveUsePercentage
            }
        }
        [void]$ents.Add($daasEnt)
    } else {
        if ($script:_lastStatus -eq 403) { $anyDenied = $true }
        $ud = Invoke-CitrixApi -FullUrl 'https://api.cloud.com/licensing/license/enterprise/cloud/cvad/ud/current' -Quiet
        if ($ud -and ($ud.productName -or $ud.totalAvailableLicenseCount)) {
            Write-RawSample 'Licensing-DaaS-UD' $ud
            [void]$ents.Add([ordered]@{
                Product='DaaS'; ProductCode='cvad'; Model='User/Device'; Status='OK'
                ProductName="$($ud.productName)"; Edition="$($ud.productEdition)"
                Total=[int]$ud.totalAvailableLicenseCount; Used=[int]$ud.totalUsageCount; Available=[int]$ud.remainingLicenseCount
                UserUsed=$(if ($ud.userLicenseUsage) { [int]$ud.userLicenseUsage.totalUsageCount } else { $null })
                DeviceUsed=$(if ($ud.deviceLicenseUsage) { [int]$ud.deviceLicenseUsage.totalUsageCount } else { $null })
            })
        } elseif ($script:_lastStatus -eq 403) { $anyDenied = $true }
    }

    # --- Gateway (NetScaler Gateway Service) - termed bandwidth. ngs/bandwidth/summary (bandwidth in GB) is
    #     the most widely accessible endpoint; fall back to the newer per-product entitlement (bandwidth in
    #     MB) if it's unavailable. ---
    $gwTerms = $null
    $gw = Invoke-CitrixApi -FullUrl "$cl/license/enterprise/cloud/ngs/bandwidth/summary" -Quiet
    if ($gw -and @($gw.termedUsages).Count) {
        Write-RawSample 'Licensing-Gateway' $gw
        $gwTerms = @(foreach ($t in @($gw.termedUsages)) {
            [ordered]@{ AvailableGB=[math]::Round([double]$t.availableBandwidth, 1); UsedGB=[math]::Round([double]$t.bandwidthUsage, 3)
                        Start=(ConvertTo-Iso $t.entitlementStartDate); End=(ConvertTo-Iso $t.entitlementEndDate); Type="$($t.subscriptionType)" }
        })
    } else {
        $gwDenied = ($script:_lastStatus -eq 403)
        $gw2 = Invoke-CitrixApi -FullUrl "$cl/cloudlicenseusages/products/netscalergateway/current/bandwidth/entitlement" -Quiet
        if ($gw2 -and @($gw2.termedUsages).Count) {
            Write-RawSample 'Licensing-Gateway' $gw2
            $gwTerms = @(foreach ($t in @($gw2.termedUsages)) {
                [ordered]@{ AvailableGB=[math]::Round([double]$t.totalAvailableBandwidth / 1024, 1); UsedGB=[math]::Round([double]$t.totalBandwidthUsage / 1024, 3)
                            Start=(ConvertTo-Iso $t.entitlementStartDate); End=(ConvertTo-Iso $t.entitlementEndDate); Type="$($t.entitlementType)" }
            })
        } elseif ($gwDenied -or $script:_lastStatus -eq 403) { $anyDenied = $true }
    }
    if ($gwTerms) { [void]$ents.Add([ordered]@{ Product='Gateway'; ProductCode='netscalergateway'; Model='Bandwidth'; Status='OK'; Terms=$gwTerms }) }

    # --- User-based products (Secure Private Access, Endpoint Management) - common current-usage shape ---
    foreach ($prod in @(
        [ordered]@{ Code='secureworkspaceaccess'; Display='Secure Private Access' },
        [ordered]@{ Code='xenmobile';             Display='Endpoint Management' }
    )) {
        $r = Invoke-CitrixApi -FullUrl "$cl/cloudlicenseusages/products/$($prod.Code)/current" -Quiet
        if ($r -and ($r.productName -or $r.totalAvailableLicenseCount)) {
            Write-RawSample "Licensing-$($prod.Code)" $r
            $exp = $r.nextExpiredLicenses
            [void]$ents.Add([ordered]@{
                Product=$prod.Display; ProductCode=$prod.Code; Status='OK'
                ProductName="$($r.productName)"; Edition="$($r.productEdition)"; Model=$(if ($r.licenseModel) { "$($r.licenseModel)" } else { 'User' })
                Total=[int]$r.totalAvailableLicenseCount; Used=[int]$r.totalUsageCount; Available=[int]$r.remainingLicenseCount
                NextExpiry=$(if ($exp) { ConvertTo-Iso $exp.nextExpiredTime } else { '' })
                DaysToExpire=$(if ($exp -and $null -ne $exp.daysToExpire) { [int]$exp.daysToExpire } else { $null })
                ExpiringCount=$(if ($exp) { [int]$exp.totalCount } else { $null })
            })
        } elseif ($script:_lastStatus -eq 403) { $anyDenied = $true }
    }

    # A 403 with no readable product = the Service Principal lacks the Licensing permission. Record one note
    # rather than an empty section (no vacuous "no data" when the truth is "not permitted").
    if ($ents.Count -eq 0 -and $anyDenied) { [void]$ents.Add([ordered]@{ Product='Licensing'; Status='AccessDenied' }) }

    Write-Log "Licensing: $($ents.Count) entitlement(s) - $((@($ents) | ForEach-Object { "$($_.Product):$($_.Status)" }) -join ', ')"
    return ,[ordered]@{ Entitlements = $ents.ToArray() }
}

function Get-CloudAdministrators {
    if (-not $script:_collectPlatform) { Write-Log 'Cloud administrators: skipped'; return @() }
    Set-SplashStatus 'Collecting cloud administrators...'
    $cid  = $script:_customerId
    $resp = Invoke-ApiProbe 'Cloud administrators' @(
        "https://api.cloud.com/administrators"
        "https://api.cloud.com/identity/administrators"
        "https://core.citrixworkspacesapi.net/$cid/administrators"
    )
    if (-not $resp) {
        if ($script:_lastStatus -eq 401 -or $script:_lastStatus -eq 403) { $script:_collectStatus['CloudAdministrators'] = 'AccessDenied' }
        return @()
    }
    $src = if ($resp.items) { $resp.items } elseif ($resp.Items) { $resp.Items } else { @($resp) }
    $results = @($src | ForEach-Object {
        [ordered]@{
            UserId      = $_.userId
            DisplayName = $_.displayName
            Email       = $_.email
            Type        = $_.type
            AccessType  = $_.accessType
            Roles       = @($_.roles | ForEach-Object { $_.roleName })
        }
    })
    Write-Log "Cloud administrators: $($results.Count)"
    return $results
}

# Citrix Cloud "Identity and access management > API access" surfaces three lists:
# Service principals (OAuth API clients), Secure clients, and Product registrations.
# The service-principals endpoint is documented (GET /serviceprincipals); the other
# two are probed. Raw samples are logged so the shapes can be verified after a run.
function Get-ServicePrincipals {
    if (-not $script:_collectPlatform) { Write-Log 'Service principals: skipped'; return ,@() }
    Set-SplashStatus 'Collecting service principals...'
    $cid  = $script:_customerId
    $resp = Invoke-ApiProbe 'Service principals' @(
        "https://api.cloud.com/serviceprincipals"
        "https://api.cloud.com/serviceprincipals?take=100"
        "https://trust.citrixworkspacesapi.net/$cid/serviceprincipals"
    )
    if (-not $resp) {
        if ($script:_lastStatus -eq 403) { $script:_collectStatus['ServicePrincipals'] = 'AccessDenied'; Write-Log 'Service principals: access denied (API client lacks permission)' 'WARN' }
        else { Write-Log 'Service principals: no endpoint responded' }
        return ,@()
    }
    Write-RawSample 'ServicePrincipals' $resp
    $src = if ($resp.items) { $resp.items } elseif ($resp.Items) { $resp.Items } `
           elseif ($resp -is [System.Collections.IEnumerable] -and -not ($resp -is [string])) { $resp } else { @($resp) }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($sp in @($src)) {
        if ($null -eq $sp) { continue }
        $createdBy = if ($sp.creator -and $sp.creator.name) { "$($sp.creator.name)" } `
                     elseif ($sp.createdBy) { "$($sp.createdBy)" } else { '' }
        $secretExp = if ($sp.primary -and $sp.primary.expirationDate) { "$($sp.primary.expirationDate)" } else { '' }
        [void]$out.Add([ordered]@{
            Name         = if ($sp.name)             { "$($sp.name)" }             elseif ($sp.displayName) { "$($sp.displayName)" } else { '' }
            ClientId     = if ($sp.clientId)         { "$($sp.clientId)" }         elseif ($sp.id) { "$($sp.id)" } else { '' }
            CreatedBy    = $createdBy
            CreatedDate  = ConvertTo-Iso $sp.createdDate
            AccessType   = if ($sp.accessType)       { "$($sp.accessType)" }       else { '' }
            LastAccessed = ConvertTo-Iso $sp.lastAccessedDate
            SecretExpiry = ConvertTo-Iso $secretExp
        })
    }
    Write-Log "Service principals: $($out.Count)"
    return ,$out.ToArray()
}

# Legacy "Secure Clients" (the predecessor to Service Principals). The console lists
# them from the delegated-administration service. Their existence is a migration
# signal - Citrix recommends moving to Service Principals.
function Get-SecureClients {
    if (-not $script:_collectPlatform) { Write-Log 'Secure clients: skipped'; return ,@() }
    Set-SplashStatus 'Collecting secure clients...'
    $cid = $script:_customerId
    $resp = Invoke-CitrixApi -FullUrl "https://delegatedadministration.citrixworkspacesapi.net/$cid/secureclients" -Quiet
    if (-not $resp) {
        if ($script:_lastStatus -eq 403) { $script:_collectStatus['SecureClients'] = 'AccessDenied'; Write-Log 'Secure clients: access denied (API client lacks permission)' 'WARN' }
        else { Write-Log 'Secure clients: endpoint unavailable' }
        return ,@()
    }
    Write-RawSample 'SecureClients' $resp
    # Defensive source extraction (array first - PS truthiness trap on bare arrays).
    $src = if ($resp -is [array]) { $resp }
           elseif ($resp.items) { $resp.items }
           elseif ($resp.Items) { $resp.Items }
           elseif ($resp -is [System.Collections.IEnumerable] -and -not ($resp -is [string])) { $resp }
           else { @($resp) }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($c in @($src)) {
        if ($null -eq $c -or $c -is [string]) { continue }
        $name = ''
        foreach ($k in 'clientName','name','displayName','description') { if ($c.PSObject.Properties[$k] -and "$($c.$k)") { $name = "$($c.$k)"; break } }
        $id = ''
        foreach ($k in 'clientId','id','secureClientId') { if ($c.PSObject.Properties[$k] -and "$($c.$k)") { $id = "$($c.$k)"; break } }
        $createdBy = ''
        foreach ($k in 'creatorUserName','creatorUserId','createdBy') { if ($c.PSObject.Properties[$k] -and "$($c.$k)") { $createdBy = "$($c.$k)"; break } }
        # The API can return a phantom placeholder row with every identifier null
        # (only legacy/customer set). Skip records that carry no real identity.
        if (-not $name -and -not $id -and -not $createdBy -and -not "$($c.principal)" -and -not "$($c.userId)") { continue }
        [void]$out.Add([ordered]@{
            Name        = $name
            ClientId    = $id
            CreatedBy   = $createdBy
            CreatedDate = if ($c.PSObject.Properties['createdDate']) { ConvertTo-Iso $c.createdDate } else { '' }
            LastUsed    = if ($c.PSObject.Properties['lastUsedDate']) { ConvertTo-Iso $c.lastUsedDate } else { '' }
            Legacy      = if ($null -ne $c.legacy) { [bool]$c.legacy } else { $false }
        })
    }
    Write-Log "Secure clients: $($out.Count)"
    return ,$out.ToArray()
}

# Product registrations (Connector Appliances, FAS servers, etc. registered to the
# customer). Served by the trust/network API. Each registration carries deviceInfo
# properties (hostname, product) plus a registration time.
function Get-ProductRegistrations {
    if (-not $script:_collectPlatform) { Write-Log 'Product registrations: skipped'; return ,@() }
    Set-SplashStatus 'Collecting product registrations...'
    $cid = $script:_customerId
    # Brace the variable: "$cid?limit" would parse "cid?limit" as one (null) name.
    $resp = Invoke-CitrixApi -FullUrl "https://trust.citrixnetworkapi.net/root/trust/v1/registeredproducts/${cid}?limit=-1" -Quiet
    if (-not $resp) { Write-Log 'Product registrations: endpoint unavailable'; return ,@() }
    Write-RawSample 'ProductRegistrations' $resp
    $src = if ($resp -is [array]) { $resp }
           elseif ($resp.products) { $resp.products }
           elseif ($resp.items) { $resp.items }
           elseif ($resp.Items) { $resp.Items }
           elseif ($resp.registeredProducts) { $resp.registeredProducts }
           elseif ($resp -is [System.Collections.IEnumerable] -and -not ($resp -is [string])) { $resp }
           else { @($resp) }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($src)) {
        if ($null -eq $r) { continue }
        # deviceInfo.properties is an array of { property, value, displayName[] }.
        $props = @{}
        if ($r.deviceInfo -and $r.deviceInfo.properties) {
            foreach ($p in @($r.deviceInfo.properties)) {
                $pn = "$($p.property)"; if ($pn) { $props[$pn.ToLower()] = "$($p.value)" }
            }
        }
        $name = if ($props.ContainsKey('hostname')) { $props['hostname'] } elseif ($props.ContainsKey('name')) { $props['name'] } else { '' }
        $product = if ($props.ContainsKey('product')) { $props['product'] } else { '' }
        [void]$out.Add([ordered]@{
            Name           = $name
            ProductType    = $product
            Service        = if ("$($r.service)") { "$($r.service)" } else { '' }
            RegisteredDate = if ($r.PSObject.Properties['registrationTime']) { ConvertTo-Iso $r.registrationTime } else { '' }
            InstanceId     = if ("$($r.instanceID)") { "$($r.instanceID)" } else { "$($r.instanceId)" }
        })
    }
    Write-Log "Product registrations: $($out.Count)"
    return ,$out.ToArray()
}

# Raw logon-performance data from the Citrix Monitor OData API (last 14 days). One
# row per session with its logon duration + delivery group; the reporter aggregates
# into per-day averages/counts and draws the charts. RAW only - no aggregation here.
# 14 days matches Citrix's raw detailed-session retention; older data is groomed.
function Get-LogonPerformance {
    Set-SplashStatus 'Collecting logon performance (Monitor, 14 days)...'
    $since  = (Get-Date).ToUniversalTime().AddDays(-14).ToString('yyyy-MM-ddTHH:mm:ssZ')
    # Build the OData query; URL-encode the $filter value (spaces, colons, commas).
    # Filter to sessions WITH a measured LogOnDuration - these are the logon events
    # Director's "Number of logons" tracks, and it keeps the result set small enough to
    # return the full retained window (dropping the filter over-counts app/reconnect
    # sessions AND truncates older days to the newest rows).
    $filter  = [Uri]::EscapeDataString("StartDate gt cast($since,Edm.DateTimeOffset) and LogOnDuration ne null")
    $expand  = [Uri]::EscapeDataString('Machine($expand=DesktopGroup($select=Id,Name))')
    $select  = [Uri]::EscapeDataString('SessionKey,StartDate,LogOnDuration')
    $rel    = "Sessions?`$select=$select&`$expand=$expand&`$filter=$filter"
    $rows = Get-MonitorOData $rel
    if (-not $rows -or @($rows).Count -eq 0) { Write-Log 'Logon performance: no data / endpoint unavailable'; return ,@() }
    Write-RawSample 'LogonPerformance' (@($rows)[0])
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($rows)) {
        if ($null -eq $s) { continue }
        $dg = if ($s.Machine -and $s.Machine.DesktopGroup) { $s.Machine.DesktopGroup } else { $null }
        if (-not $dg -or -not "$($dg.Name)") { continue }
        $ms = if ($null -eq $s.LogOnDuration) { $null } else { [int]$s.LogOnDuration }
        [void]$out.Add([ordered]@{
            DeliveryGroup   = "$($dg.Name)"
            DeliveryGroupId = "$($dg.Id)"
            StartDate       = ConvertTo-Iso $s.StartDate
            LogOnDurationMs = $ms
        })
    }
    Write-Log "Logon performance: $($out.Count) measured logon(s) over 14 days"
    return ,$out.ToArray()
}

# Citrix Cloud "Identity and access management > Domains" lists AD forests with the
# domains under each AND per-domain connectivity status (the red/amber/green icons).
# Primary source: the forests/domains endpoint (carries the status). Falls back to
# deriving forest/domain from the AD identity provider detail if that is unavailable.
function Get-IdentityDomains {
    if (-not $script:_collectPlatform) { Write-Log 'Identity domains: skipped'; return ,@() }
    Set-SplashStatus 'Collecting identity domains...'
    $cid = $script:_customerId

    $out = [System.Collections.Generic.List[object]]::new()

    # --- Primary: forests/domains (includes connectivity status) ---
    $fd = Invoke-CitrixApi -FullUrl "https://cws.citrixworkspacesapi.net/$cid/forests/domains?skip=0&take=100&showHiddenDomain=false" -Quiet
    if ($fd) {
        Write-RawSample 'ForestsDomains' $fd
        $fsrc = if ($fd -is [array]) { $fd } elseif ($fd.items) { $fd.items } elseif ($fd.Items) { $fd.Items } `
                elseif ($fd.forests) { $fd.forests } elseif ($fd.domains) { $fd.domains } `
                elseif ($fd -is [System.Collections.IEnumerable] -and -not ($fd -is [string])) { $fd } else { @($fd) }
        foreach ($entry in @($fsrc)) {
            if ($null -eq $entry) { continue }
            # An entry may be a forest carrying nested domains, or a flat domain row.
            $forestName = ''
            foreach ($k in 'forest','forestName','name') { if ($entry.PSObject.Properties[$k] -and "$($entry.$k)") { $forestName = "$($entry.$k)"; break } }
            # The console "Forest Preferred Connector Type" maps from adRoutePreference
            # (WindowsAgent = Cloud Connector); fall back to connectivity.
            $connType = ''
            $route = "$($entry.adRoutePreference)"
            if ($route -match 'WindowsAgent|CloudConnector') { $connType = 'Cloud Connector' }
            elseif ($route) { $connType = $route }
            elseif ("$($entry.connectivity)") { $connType = "$($entry.connectivity)" }
            $agentCount = if ($null -ne $entry.agentCount) { [int]$entry.agentCount } else { $null }
            $domainList = if ($entry.domains) { @($entry.domains) } else { @($entry) }
            foreach ($d in $domainList) {
                if ($null -eq $d) { continue }
                $dn = if ($d -is [string]) { "$d" } else {
                    $v=''; foreach ($k in 'name','domainName','domain','fqdn') { if ($d.PSObject.Properties[$k] -and "$($d.$k)") { $v="$($d.$k)"; break } }; $v
                }
                $online = $null; $subscribed = $null
                if ($d -isnot [string]) {
                    if ($null -ne $d.isOnline)    { $online = [bool]$d.isOnline }
                    if ($null -ne $d.subscribed)  { $subscribed = [bool]$d.subscribed }
                }
                # Status mirrors the console icon: isOnline=false -> red (not reachable);
                # online but not subscribed -> amber (reachable, unused); online+subscribed -> green.
                # StatusLevel drives the report colour explicitly (avoids fragile text matching).
                $status = ''; $statusLevel = ''
                if     ($online -eq $false) { $status = 'Not reachable'; $statusLevel = 'Error' }
                elseif ($online -eq $true -and $subscribed -eq $false) { $status = 'Reachable'; $statusLevel = 'Warning' }
                elseif ($online -eq $true) { $status = 'Reachable'; $statusLevel = 'Ok' }
                $forest = if ($forestName) { $forestName } else { $dn }
                [void]$out.Add([ordered]@{
                    Forest=$forest; Domain=$dn; ConnectorType=$connType
                    Connectors=$agentCount; Status=$status; StatusLevel=$statusLevel
                })
            }
        }
        if ($out.Count -gt 0) { Write-Log "Identity domains: $($out.Count) (forests/domains)"; return ,$out.ToArray() }
    }

    # --- Fallback: derive from AD identity provider detail (no per-domain status) ---
    $resp = Invoke-CitrixApi -FullUrl "https://cws.citrixworkspacesapi.net/$cid/identityProviders/ad" -Quiet
    if (-not $resp) { Write-Log 'Identity domains: no source available'; return ,@() }
    Write-RawSample 'IdentityDomains' $resp
    $item = if ($resp.items) { @($resp.items)[0] } elseif ($resp.Items) { @($resp.Items)[0] } else { $resp }
    $connType = if ($item -and $item.connectorsCount -and [int]$item.connectorsCount -gt 0) { 'Cloud Connector' } else { '' }
    if ($item -and $item.forestPerDomain) {
        foreach ($prop in $item.forestPerDomain.PSObject.Properties) {
            $forest = "$($prop.Value)"
            $domain = if ($forest) { $forest } else { "$($prop.Name)" }
            [void]$out.Add([ordered]@{ Forest=$forest; Domain=$domain; ConnectorType=$connType; Status='' })
        }
    } elseif ($item -and $item.domains) {
        foreach ($d in @($item.domains)) {
            $dn = if ($d.PSObject.Properties['name']) { "$($d.name)" } else { "$d" }
            [void]$out.Add([ordered]@{ Forest=$dn; Domain=$dn; ConnectorType=$connType; Status='' })
        }
    }
    Write-Log "Identity domains: $($out.Count) (AD detail fallback)"
    return ,$out.ToArray()
}

#endregion

#region ── DaaS Resource Collection ──────────────────────────────────────────

function Get-CitrixSites {
    Set-SplashStatus 'Collecting site information...'
    # The DaaS API exposes the site via /me (already resolved at auth time) and
    # /Sites/{id} for detail. Use the resolved site, enriched with /Sites/{id}.
    $detail = if ($script:_siteId) { Invoke-CitrixApi -Path "/Sites/$($script:_siteId)" } else { $null }
    $src    = if ($detail) { $detail } else { $script:_siteObj }
    if (-not $src) { Write-Log 'Sites: none'; return @() }
    # Site settings are a dedicated sub-resource, NOT scalar props of /Sites/{id}. The
    # console's Settings page calls /Sites/{id}/Settings (orchestration API); the public
    # Manage API mirrors it at the same relative path. Pull every scalar field generically
    # so the report's Settings section reflects whatever the API returns (no hardcoded list).
    $settingsResp = if ($script:_siteId) { Invoke-CitrixApi -Path "/Sites/$($script:_siteId)/Settings" } else { $null }
    if ($settingsResp) { Write-RawSample 'SiteSettings' $settingsResp }
    $settings = [ordered]@{}
    if ($settingsResp) {
        foreach ($pr in $settingsResp.PSObject.Properties) {
            $v = $pr.Value
            if ($null -eq $v) { continue }
            if ($v -is [string] -or $v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [datetime]) {
                $settings[$pr.Name] = if ($v -is [datetime]) { ConvertTo-Iso $v } else { $v }
            }
        }
    }
    # AotSetting - the console's "Log server" setting (Always-on Tracing log forwarding). It is NOT in
    # the default /Settings projection, so it must be requested by name. 'fields' is a PROJECTION: asking
    # for AotSetting returns every OTHER property as null, so this has to be a SECOND call merged in -
    # adding fields= to the call above would silently blank DnsResolutionEnabled and
    # TrustRequestsSentToTheXmlServicePortEnabled, which the report already checks.
    # Kept as a nested object (the loop above takes scalars only): the report needs Server, Port and the
    # three Enabled* flags together to tell "no log server" from "log server set but forwarding nothing".
    $aotResp = if ($script:_siteId) { Invoke-CitrixApi -Path "/Sites/$($script:_siteId)/Settings" -Query @{ fields = 'AotSetting' } } else { $null }
    if ($aotResp -and $aotResp.AotSetting) {
        $a = $aotResp.AotSetting
        Write-RawSample 'SiteSettings.AotSetting' $a
        $settings['AotSetting'] = [ordered]@{
            Server                      = "$($a.Server)"
            Port                        = [int]$a.Port
            EnabledOnDeliveryController = [bool]$a.EnabledOnDeliveryController
            EnabledOnAllDeliveryGroups  = [bool]$a.EnabledOnAllDeliveryGroups
            EnabledOnDeliveryGroups     = @(if ($a.EnabledOnDeliveryGroups) { $a.EnabledOnDeliveryGroups | ForEach-Object { "$_" } })
            ResourceLocationId          = "$($a.LogServerResourceLocationId)"
            # LogServerApiKey is a CREDENTIAL for the log service - record only that one is set. The JSON
            # is a customer deliverable and is not encrypted unless -EncryptPassword was used.
            HasApiKey                   = [bool]$a.LogServerApiKey
        }
    }
    $results = @([ordered]@{
        SiteId         = $src.Id
        SiteName       = $src.Name
        ProductCode    = $src.ProductCode
        ProductEdition = $src.ProductEdition
        ProductVersion = $src.ProductVersion
        Settings       = $settings
    })
    Write-Log "Sites: $($results.Count) ($($settings.Count) settings)"
    return $results
}

function Get-CitrixZones {
    Set-SplashStatus 'Collecting zones...'
    $items = Get-PagedResults -Path '/Zones'
    Write-Log "Zones: $($items.Count)"
    return @($items | ForEach-Object {
        [ordered]@{
            ZoneId      = $_.Id
            ZoneName    = $_.Name
            Description = $_.Description
            IsPrimary   = $_.IsPrimary
        }
    })
}

function Get-Backups {
    # Citrix DaaS "Backup and Restore" - the configuration backups the site can be restored from.
    # /BackupRestore lists the current backups; the creation time is encoded in the backup name
    # (B_YYYY_MM_DD_HH_MM_SS_..), with RelatedDate as a fallback.
    Set-SplashStatus 'Collecting backup and restore...'
    $resp  = Invoke-CitrixApi -Path '/BackupRestore' -Quiet
    $items = if ($resp -and $resp.Items) { @($resp.Items) } else { @() }
    $schedResp = Invoke-CitrixApi -Path '/BackupRestore/Schedules' -Quiet
    $scheds    = if ($schedResp -and $schedResp.Items) { @($schedResp.Items) } else { @() }
    Write-Log "Backup and restore: $(@($items).Count) backup(s), $(@($scheds).Count) schedule(s)"
    $mapped = @(@($items) | Where-Object { $_ } | ForEach-Object {
        $b = $_
        $created = ''
        if ("$($b.BackupName)" -match '(\d{4})_(\d{2})_(\d{2})_(\d{2})_(\d{2})_(\d{2})') {
            $created = "$($Matches[1])-$($Matches[2])-$($Matches[3])T$($Matches[4]):$($Matches[5]):$($Matches[6])Z"
        } elseif ($b.RelatedDate) { $created = ConvertTo-Iso $b.RelatedDate }
        # Component counts (non-zero) from the backup's Details, for a "what's in it" summary.
        $contents = [ordered]@{}
        if ($b.Details) { foreach ($p in $b.Details.PSObject.Properties) { $n = 0; [void][int]::TryParse("$($p.Value)", [ref]$n); if ($n -gt 0) { $contents[$p.Name] = $n } } }
        [ordered]@{
            Name          = "$($b.BackupName)"
            Notes         = "$($b.Notes)"
            Created       = $created
            Successful    = [bool]$b.Result
            Pinned        = [bool]$b.Pinned
            Administrator = "$($b.AdministratorName)"
            DurationSec   = [int]$b.Duration
            SizeBytes     = [long]$b.BackupSize
            ScheduleName  = "$($b.ScheduleName)"
            Contents      = $contents
        }
    })
    return [ordered]@{
        Items = $mapped
        Schedules = @(@($scheds) | Where-Object { $_ } | ForEach-Object {
            [ordered]@{
                Name      = "$($_.Name)"
                Enabled   = [bool]$_.Enabled
                Frequency = "$($_.Frequency)"
                Days      = @($_.DaysInWeek | ForEach-Object { "$_" })
                StartTime = "$($_.StartTime)"
                TimeZone  = "$($_.TimeZoneId)"
                LastRun   = ConvertTo-Iso $_.LastRunTime
            }
        })
    }
}

function Get-AppPackages {
    # DaaS "App Packages" - App-V/MSIX/AppAttach packages, their isolation groups, and App-V servers.
    # Endpoints confirmed present (a backup's Details also reports AppVPackages/AppVIsolationGroups counts).
    # Field mapping for populated packages is best-effort (lab tenants have none) - raw is logged when present.
    Set-SplashStatus 'Collecting app packages...'
    $pkgResp = Invoke-CitrixApi -Path '/AppVPackages' -Quiet
    $isoResp = Invoke-CitrixApi -Path '/AppVIsolationGroups' -Quiet
    $srvResp = Invoke-CitrixApi -Path '/AppVServers' -Quiet
    $pkgs = if ($pkgResp -and $pkgResp.Items) { @($pkgResp.Items) } else { @() }
    $isos = if ($isoResp -and $isoResp.Items) { @($isoResp.Items) } else { @() }
    $srvs = if ($srvResp -and $srvResp.Items) { @($srvResp.Items) } else { @() }
    if (@($pkgs).Count) { Write-RawSample 'AppVPackages' $pkgResp }
    if (@($isos).Count) { Write-RawSample 'AppVIsolationGroups' $isoResp }
    Write-Log "App packages: $(@($pkgs).Count) package(s), $(@($isos).Count) isolation group(s), $(@($srvs).Count) server(s)"
    return [ordered]@{
        Packages = @(@($pkgs) | Where-Object { $_ } | ForEach-Object {
            [ordered]@{
                Name        = if ($_.Name) { "$($_.Name)" } elseif ($_.PackageName) { "$($_.PackageName)" } else { "$($_.DisplayName)" }
                PackageType = if ($_.PackageType) { "$($_.PackageType)" } elseif ($_.Type) { "$($_.Type)" } else { 'App-V' }
                Version     = "$($_.Version)"
                UsedBy      = if ($null -ne $_.UsedByApplicationCount) { [int]$_.UsedByApplicationCount } elseif ($null -ne $_.UsedBy) { $_.UsedBy } else { $null }
            }
        })
        IsolationGroups = @(@($isos) | Where-Object { $_ } | ForEach-Object { [ordered]@{ Name = "$($_.Name)"; Members = @($_.Packages | ForEach-Object { "$($_.Name)" }) } })
        Servers = @(@($srvs) | Where-Object { $_ } | ForEach-Object { [ordered]@{ Management = "$($_.ManagementServer)"; Publishing = "$($_.PublishingServer)"; Name = "$($_.Name)" } })
    }
}

# Autoscale (power management) configuration for one delivery group. The scalar settings ride on the per-DG
# detail response the caller already fetched (for SimpleAccessPolicy), so they cost no extra call; the power
# time schemes - the per-day peak windows + how many machines to keep powered on - are a separate sub-resource.
# Field names verified live against the DaaS Orchestration API (2026-07-16): the schemes express peak/pool as
# time-range arrays (PeakTimeRanges / PoolSizeSchedule), NOT the legacy 24-element PeakHours/PoolSize arrays
# (which the API returns null). $DgDetail may be $null if its call failed - the casts below then yield safe
# defaults (Enabled=$false, numbers 0, actions ''), and a non-power-managed group simply has no schemes.
function Get-DgAutoscale ([string]$DgId, $DgDetail) {
    $schemes = [System.Collections.Generic.List[object]]::new()
    $ptsResp = Invoke-CitrixApi -Path "/DeliveryGroups/$DgId/PowerTimeSchemes" -Quiet
    $ptsItems = if ($ptsResp -and $ptsResp.Items) { $ptsResp.Items } elseif ($ptsResp) { $ptsResp } else { @() }
    foreach ($s in @($ptsItems)) {
        if ($null -eq $s) { continue }
        $pool = [System.Collections.Generic.List[object]]::new()
        foreach ($ps in @($s.PoolSizeSchedule)) {
            if ($null -eq $ps) { continue }
            [void]$pool.Add([ordered]@{ TimeRange = "$($ps.TimeRange)"; PoolSize = [int]$ps.PoolSize })
        }
        $days  = @(); foreach ($d in @($s.DaysOfWeek))     { if ($null -ne $d) { $days  += "$d" } }
        $peaks = @(); foreach ($r in @($s.PeakTimeRanges)) { if ($null -ne $r) { $peaks += "$r" } }
        [void]$schemes.Add([ordered]@{
            Name                = "$($s.Name)"
            DisplayName         = "$($s.DisplayName)"
            DaysOfWeek          = $days
            PeakTimeRanges      = $peaks
            PoolUsingPercentage = [bool]$s.PoolUsingPercentage
            PoolSizeSchedule    = $pool.ToArray()
        })
    }
    # *Action values (Nothing/Suspend/Shutdown) are strings over REST; stringify defensively to match the
    # collector's pattern and dodge any PS 5.1 enum {value,Value} serialisation.
    return [ordered]@{
        Enabled                         = [bool]$DgDetail.AutoScaleEnabled
        AutoscalingEnabled              = [bool]$DgDetail.AutoscalingEnabled
        IsPowerManaged                  = [bool]$DgDetail.IsPowerManaged
        RestrictToTag                   = "$($DgDetail.RestrictAutoscaleTag)"
        PeakBufferSizePercent           = [int]$DgDetail.PeakBufferSizePercent
        OffPeakBufferSizePercent        = [int]$DgDetail.OffPeakBufferSizePercent
        PowerOffDelayMinutes            = [int]$DgDetail.PowerOffDelayMinutes
        ScaleDownActionDuringPeak       = "$($DgDetail.AutoscaleScaleDownActionDuringPeak)"
        ScaleDownActionDuringOffPeak    = "$($DgDetail.AutoscaleScaleDownActionDuringOffPeak)"
        PeakDisconnectAction            = "$($DgDetail.PeakDisconnectAction)"
        PeakDisconnectTimeoutMinutes    = [int]$DgDetail.PeakDisconnectTimeoutMinutes
        OffPeakDisconnectAction         = "$($DgDetail.OffPeakDisconnectAction)"
        OffPeakDisconnectTimeoutMinutes = [int]$DgDetail.OffPeakDisconnectTimeoutMinutes
        PeakLogOffAction                = "$($DgDetail.PeakLogOffAction)"
        PeakLogOffTimeoutMinutes        = [int]$DgDetail.PeakLogOffTimeoutMinutes
        OffPeakLogOffAction             = "$($DgDetail.OffPeakLogOffAction)"
        OffPeakLogOffTimeoutMinutes     = [int]$DgDetail.OffPeakLogOffTimeoutMinutes
        Schemes                         = $schemes.ToArray()
    }
}

function Get-DeliveryGroups {
    Set-SplashStatus 'Collecting delivery groups...'
    $items = Get-PagedResults -Path '/DeliveryGroups'
    Write-Log "Delivery groups: $($items.Count)"
    return @($items | ForEach-Object {
        $dg = $_
        # The list response omits SimpleAccessPolicy, which lists the assigned users/groups. Fetch the
        # delivery-group detail and capture the included principals so the report can flag individual-user
        # assignments (Citrix leading practice is to grant access only through security groups). A non-empty
        # UPN (PrincipalName) marks an individual user; security groups and system accounts have none.
        $incUsers = [System.Collections.Generic.List[object]]::new()
        $dgDetail = Invoke-CitrixApi -Path "/DeliveryGroups/$($dg.Id)" -Quiet
        $sap = if ($dgDetail) { $dgDetail.SimpleAccessPolicy } else { $null }
        if ($sap -and $sap.IncludedUserFilterEnabled) {
            foreach ($u in @($sap.IncludedUsers)) {
                if ($null -eq $u) { continue }
                [void]$incUsers.Add([ordered]@{
                    Name    = "$($u.DisplayName)"
                    Upn     = "$($u.PrincipalName)"
                    Account = "$($u.SamName)"
                    IsGroup = $u.IsGroup
                })
            }
        }
        [ordered]@{
            Id                           = $dg.Id
            Name                         = $dg.Name
            Description                  = $dg.Description
            Enabled                      = $dg.Enabled
            InMaintenanceMode            = $dg.InMaintenanceMode
            DeliveryType                 = $dg.DeliveryType
            SessionSupport               = $dg.SessionSupport
            TotalMachines                = $dg.TotalMachines
            RegisteredMachines           = $dg.RegisteredMachines
            TotalApplications            = $dg.TotalApplications
            TotalDesktops                = $dg.TotalDesktops
            SessionCount                 = $dg.SessionCount
            DisconnectedSessionCount     = $dg.DisconnectedSessionCount
            PeakConcurrentSessions       = $dg.PeakConcurrentSessions
            LoadEvaluatorName            = $dg.LoadEvaluatorName
            MinimumFunctionalLevel       = $dg.MinimumFunctionalLevel
            AutomaticPowerOnForAssigned  = $dg.AutomaticPowerOnForAssigned
            ShutdownDesktopsAfterUse     = $dg.ShutdownDesktopsAfterUse
            TurnOnAddedMachine           = $dg.TurnOnAddedMachine
            ReuseMachines                = $dg.ReuseMachines
            Tags                         = @($dg.Tags)
            Scopes                       = @($dg.Scopes | ForEach-Object { $_.ScopeName })
            IncludedUsers                = $incUsers.ToArray()
            Autoscale                    = Get-DgAutoscale $dg.Id $dgDetail
        }
    })
}

function Get-MachineCatalogs {
    Set-SplashStatus 'Collecting machine catalogs...'
    $items = Get-PagedResults -Path '/MachineCatalogs'
    Write-Log "Machine catalogs: $($items.Count)"
    return @($items | ForEach-Object {
        $mc = $_
        $ps = $mc.ProvisioningScheme
        # Surface any AD computer accounts the identity service has flagged 'tainted' (left unusable for
        # provisioning until reset). The list response omits account state, so fetch the catalog's accounts.
        $tainted = [System.Collections.Generic.List[object]]::new()
        $acctResp = Invoke-CitrixApi -Path "/MachineCatalogs/$($mc.Id)/MachineAccounts" -Quiet
        $accts = if ($acctResp -and $acctResp.Items) { $acctResp.Items } elseif ($acctResp) { @($acctResp) } else { @() }
        foreach ($a in @($accts)) { if ($a -and "$($a.State)" -eq 'Tainted') { [void]$tainted.Add("$($a.SamName)") } }
        # The catalog -> hosting connection link is NOT in the list response, and unlike SiteSettings
        # a ?fields=HypervisorConnection projection does not surface it either (both verified against
        # the live API). It only appears on the per-catalog detail. Without it every catalog reported
        # an empty connection, so HC-002 saw an empty "in use" set and declared every hosting
        # connection unreferenced. Skip the extra call for catalogs that cannot have a connection -
        # a manual, non-power-managed catalog (e.g. Remote PC) legitimately has none.
        $hcName = if ($mc.HypervisorConnection) { "$($mc.HypervisorConnection.Name)" } else { '' }
        if (-not $hcName -and (("$($mc.ProvisioningType)" -ne 'Manual') -or ("$($mc.IsPowerManaged)" -eq 'True'))) {
            $det = Invoke-CitrixApi -Path "/MachineCatalogs/$($mc.Id)" -Quiet
            if ($det -and $det.HypervisorConnection) { $hcName = "$($det.HypervisorConnection.Name)" }
        }
        [ordered]@{
            Id                     = $mc.Id
            Name                   = $mc.Name
            Description            = $mc.Description
            AllocationType         = $mc.AllocationType
            PersistUserChanges     = $mc.PersistUserChanges
            ProvisioningType       = $mc.ProvisioningType
            SessionSupport         = $mc.SessionSupport
            TotalCount             = $mc.TotalCount
            UnassignedCount        = $mc.UnassignedCount
            UsedCount              = $mc.UsedCount
            MachineType            = $mc.MachineType
            MinimumFunctionalLevel = $mc.MinimumFunctionalLevel
            IdentityType           = $mc.IdentityType
            ZoneName               = if ($mc.Zone) { $mc.Zone.Name } else { $null }
            HypervisorConnection   = $hcName
            # The list response inlines the full ProvisioningScheme. VM size is the ServiceOffering string
            # (e.g. Standard_D4s_v5); CpuCount/MemoryMB cover machine-profile catalogs that have no
            # ServiceOffering. MasterImage is an object {Name,XDPath} - the old '.MasterImagePath' property
            # never existed (it read as null on every catalog).
            MasterImagePath        = if ($ps -and $ps.MasterImage) { "$($ps.MasterImage.XDPath)" } else { $null }
            VmSize                 = if ($ps -and $ps.ServiceOffering) { "$($ps.ServiceOffering)" } else { $null }
            VmCpuCount             = if ($ps) { $ps.CpuCount } else { $null }
            VmMemoryMB             = if ($ps) { $ps.MemoryMB } else { $null }
            Tags                   = @($mc.Tags)
            Scopes                 = @($mc.Scopes | ForEach-Object { $_.ScopeName })
            TaintedAccounts        = $tainted.ToArray()
        }
    })
}

function Get-CitrixMachines {
    Set-SplashStatus 'Collecting machines / VDAs...'
    $items = Get-PagedResults -Path '/Machines'
    Write-Log "Machines: $($items.Count)"
    return @($items | ForEach-Object {
        $m = $_
        [ordered]@{
            Id                = $m.Id
            Name              = $m.Name
            DnsName           = $m.DnsName
            IPAddress         = $m.IPAddress
            MachineCatalog    = if ($m.MachineCatalog) { $m.MachineCatalog.Name } else { $null }
            DeliveryGroup     = if ($m.DeliveryGroup)  { $m.DeliveryGroup.Name  } else { $null }
            ZoneName          = if ($m.Zone)            { $m.Zone.Name           } else { $null }
            RegistrationState = $m.RegistrationState
            PowerState        = $m.PowerState
            SummaryState      = $m.SummaryState
            InMaintenanceMode = $m.InMaintenanceMode
            AgentVersion      = $m.AgentVersion
            FunctionalLevel   = $m.FunctionalLevel
            OSType            = $m.OSType
            OSVersionString   = $m.OSVersionString
            SessionCount      = $m.SessionCount
            AssociatedUsers   = @($m.AssociatedUsers | ForEach-Object { $_.FullName })
            Tags              = @($m.Tags)
            HostedMachineName = $m.HostedMachineName
            LastDeregisteredReason = $m.LastDeregisteredReason
        }
    })
}

function Resolve-DgNames ($RawObj, [hashtable]$DgMap) {
    # Try DeliveryGroups[] with .Name or .DeliveryGroupName (list endpoint shape varies)
    $names = @($RawObj.DeliveryGroups | ForEach-Object {
        if ($_.Name)              { $_.Name }
        elseif ($_.DeliveryGroupName) { $_.DeliveryGroupName }
    } | Where-Object { $_ })
    # Fallback: AssociatedDeliveryGroupUuids (UUID list) resolved via DG map
    if ($names.Count -eq 0 -and $RawObj.AssociatedDeliveryGroupUuids) {
        $names = @($RawObj.AssociatedDeliveryGroupUuids | ForEach-Object {
            if ($DgMap.ContainsKey("$_")) { $DgMap["$_"] }
        } | Where-Object { $_ })
    }
    return ,$names
}

function Get-CitrixApplications ([hashtable]$DgMap = @{}) {
    Set-SplashStatus 'Collecting applications...'
    $items = Get-PagedResults -Path '/Applications'
    Write-Log "Applications: $($items.Count)"
    return @($items | ForEach-Object {
        $app = $_
        $installed = if ($app.InstalledAppProperties) {
            [ordered]@{
                CommandLineExecutable = $app.InstalledAppProperties.CommandLineExecutable
                CommandLineArguments  = $app.InstalledAppProperties.CommandLineArguments
                WorkingDirectory      = $app.InstalledAppProperties.WorkingDirectory
            }
        } else { $null }

        [ordered]@{
            Id                      = $app.Id
            Name                    = $app.Name
            PublishedName           = $app.PublishedName
            Description             = $app.Description
            Enabled                 = $app.Enabled
            Visible                 = $app.Visible
            ApplicationType         = $app.ApplicationType
            InstalledAppProperties  = $installed
            DeliveryGroups          = Resolve-DgNames $app $DgMap
            FolderPath              = if ($app.ApplicationFolder) { $app.ApplicationFolder.Path } else { $null }
            Tags                    = @($app.Tags)
        }
    })
}

function Get-CitrixApplicationGroups ([hashtable]$DgMap = @{}) {
    Set-SplashStatus 'Collecting application groups...'
    $items = Get-PagedResults -Path '/ApplicationGroups'
    Write-Log "Application groups: $($items.Count)"
    return @($items | ForEach-Object {
        [ordered]@{
            Id                = $_.Id
            Name              = $_.Name
            Description       = $_.Description
            Enabled           = $_.Enabled
            RestrictToTag     = $_.RestrictToTag
            TotalApplications = $_.TotalApplications
            DeliveryGroups    = Resolve-DgNames $_ $DgMap
        }
    })
}

function Get-CitrixSessions {
    Set-SplashStatus 'Collecting sessions...'
    $items = Get-PagedResults -Path '/Sessions'
    Write-Log "Sessions: $($items.Count)"
    # Log first session's sub-object shapes to diagnose field differences across API versions
    if ($items.Count -gt 0) {
        $first = $items[0]
        Write-Log "Session[0] properties: $($first.PSObject.Properties.Name -join ', ')"
        if ($first.User)         { Write-Log "  User properties: $($first.User.PSObject.Properties.Name -join ', ')" }
        if ($first.Client)       { Write-Log "  Client properties: $($first.Client.PSObject.Properties.Name -join ', ')" }
        if ($first.Connection)   { Write-Log "  Connection properties: $($first.Connection.PSObject.Properties.Name -join ', ')" }
        if ($first.Machine)      { Write-Log "  Machine properties: $($first.Machine.PSObject.Properties.Name -join ', ')" }
        if ($first.Brokering)    { Write-Log "  Brokering properties: $($first.Brokering.PSObject.Properties.Name -join ', ')" }
    }
    return @($items | ForEach-Object {
        $s = $_
        # User: API returns sub-object with DisplayName / PrincipalName (not FullName / UPN)
        $userName = if ($s.User) {
            if ($s.User.DisplayName)     { $s.User.DisplayName }
            elseif ($s.User.FullName)    { $s.User.FullName }
            elseif ($s.User.Name)        { $s.User.Name }
            elseif ($s.User.SamName)     { $s.User.SamName }
            else { $null }
        } elseif ($s.UserName) { $s.UserName } else { $null }

        $upn = if ($s.User) {
            if ($s.User.PrincipalName)  { $s.User.PrincipalName }
            elseif ($s.User.UPN)        { $s.User.UPN }
            elseif ($s.User.Mail)       { $s.User.Mail }
            else { $null }
        } elseif ($s.UPN) { $s.UPN } else { $null }

        # DeliveryGroup: not a top-level property on sessions - try Machine or Brokering sub-objects
        $dgName = if ($s.Machine -and $s.Machine.DesktopGroup -and $s.Machine.DesktopGroup.Name) { $s.Machine.DesktopGroup.Name }
                  elseif ($s.Brokering -and $s.Brokering.DesktopGroup -and $s.Brokering.DesktopGroup.Name) { $s.Brokering.DesktopGroup.Name }
                  elseif ($s.DeliveryGroup -and $s.DeliveryGroup.Name) { $s.DeliveryGroup.Name }
                  elseif ($s.DeliveryGroupName) { $s.DeliveryGroupName } else { $null }

        # Client: nested under Client sub-object
        $clientName = if ($s.Client -and $s.Client.Name)     { $s.Client.Name }
                      elseif ($s.ClientName)                  { $s.ClientName } else { $null }
        $clientAddr = if ($s.Client -and $s.Client.Address)  { $s.Client.Address }
                      elseif ($s.ClientAddress)               { $s.ClientAddress } else { $null }
        $clientPlat = if ($s.Client -and $s.Client.ClientType){ $s.Client.ClientType }
                      elseif ($s.Client -and $s.Client.Platform) { $s.Client.Platform }
                      elseif ($s.ClientPlatform)              { $s.ClientPlatform } else { $null }

        # Protocol: nested under Connection sub-object
        $protocol = if ($s.Connection -and $s.Connection.Protocol) { $s.Connection.Protocol }
                    elseif ($s.Protocol)                             { $s.Protocol } else { $null }

        [ordered]@{
            SessionId         = $s.Id
            SessionType       = $s.SessionType
            State             = $s.State
            MachineName       = if ($s.Machine) { $s.Machine.Name } else { $null }
            DeliveryGroupName = $dgName
            UserName          = $userName
            UPN               = $upn
            StartTime         = $s.StartTime
            ConnectionTime    = $s.ConnectionTime
            DisconnectTime    = $s.DisconnectTime
            IdleTime          = $s.IdleTime
            ClientName        = $clientName
            ClientAddress     = $clientAddr
            ClientPlatform    = $clientPlat
            Protocol          = $protocol
            Applications      = @($s.Applications | ForEach-Object { $_.PublishedName })
        }
    })
}

function Get-CitrixPolicies {
    Set-SplashStatus 'Collecting policies...'
    # DaaS GPO policies are a two-step flow: list policy sets, then list policies per set.
    $setsResp = Invoke-CitrixApi -Path '/gpo/policySets'
    if (-not $setsResp) {
        Write-Log 'No policy sets returned (endpoint may require additional permissions)' 'WARN'
        return @()
    }
    $sets = if ($setsResp.Items) { $setsResp.Items } elseif ($setsResp.items) { $setsResp.items } else { @($setsResp) }
    Write-Log "Policy sets: $(@($sets).Count)"
    if (@($sets).Count) { Write-RawSample 'PolicySet[0]' @($sets)[0] }

    $allPolicies = [System.Collections.Generic.List[object]]::new()
    $sampleLogged = $false
    foreach ($set in $sets) {
        $setGuid = $set.policySetGuid
        if (-not $setGuid) { $setGuid = $set.PolicySetGuid }
        if (-not $setGuid) { continue }

        # Capture the policy-set type so the reporter can separate templates from
        # assigned policy sets. Field name varies; capture defensively.
        $setType = $set.policySetType
        if (-not $setType) { $setType = $set.type }
        if (-not $setType) { $setType = $set.policySetTypeName }
        $isTemplate = ("$setType" -match 'template') -or ("$($set.name)" -match 'template') -or [bool]$set.isTemplate

        # withSettings/withFilters are REQUIRED - without them /gpo/policies returns policy
        # metadata only (no settings, no filters/assignments), and the null lists then get
        # mangled into one empty entry by the `$null | ForEach-Object` quirk below.
        $polResp = Invoke-CitrixApi -Path '/gpo/policies' -Query @{ policySetGuid = "$setGuid"; withSettings = 'true'; withFilters = 'true' }
        if (-not $polResp) { continue }
        $policies = if ($polResp.Items) { $polResp.Items } elseif ($polResp.items) { $polResp.items } else { @($polResp) }
        if (-not $sampleLogged -and @($policies).Count) { Write-RawSample 'Policy[0]' @($policies)[0]; $sampleLogged = $true }

        foreach ($p in $policies) {
            $allPolicies.Add([ordered]@{
                PolicySetName = $set.name
                PolicySetGuid = $setGuid
                PolicySetType = "$setType"
                IsTemplate    = $isTemplate
                PolicyGuid    = $p.policyGuid
                PolicyName    = $p.policyName
                Description   = $p.description
                IsEnabled     = $p.isEnabled
                Priority      = $p.priority
                # Guard with `if ($p.x)`: piping a $null list to ForEach-Object iterates ONCE
                # (with $_ = $null), which would fabricate a single empty setting/filter.
                Settings      = @(if ($p.settings) { $p.settings | ForEach-Object {
                    [ordered]@{ Name = $_.settingName; Value = $_.settingValue; UseDefault = $_.useDefault; Guid = $_.settingGuid }
                } })
                # filterData holds the assignment target: for DesktopGroup it is JSON
                # {server,uuid} (uuid = delivery-group Id, resolved to a name in the report);
                # for other types (DesktopKind, OU, ...) it is a plain string.
                Filters       = @(if ($p.filters) { $p.filters | ForEach-Object {
                    [ordered]@{
                        Type      = $_.filterType
                        Data      = $_.filterData
                        IsAllowed = $_.isAllowed
                        IsEnabled = $_.isEnabled
                        Guid      = $_.filterGuid
                    }
                } })
            })
        }
    }
    Write-Log "Policies: $($allPolicies.Count)"
    return $allPolicies.ToArray()
}

function Get-CitrixHostingConnections {
    Set-SplashStatus 'Collecting hosting connections...'
    $items = Get-PagedResults -Path '/Hypervisors'
    Write-Log "Hosting connections: $($items.Count)"
    if ($items.Count) { Write-RawSample 'Hypervisor[0]' $items[0] }
    return @($items | ForEach-Object {
        # The list endpoint has no top-level State; connection health is under Fault.State
        # ('None' = no fault = healthy). Surface that as the State, keeping any fault reason.
        $faultState = if ($_.Fault) { "$($_.Fault.State)" } else { '' }
        [ordered]@{
            Id                = $_.Id
            Name              = $_.Name
            ConnectionType    = $_.ConnectionType
            State             = if ($faultState -in @('', 'None')) { 'Healthy' } else { $faultState }
            FaultReason       = if ($_.Fault) { "$($_.Fault.Reason)" } else { '' }
            InMaintenanceMode = $_.InMaintenanceMode
            ZoneName          = if ($_.Zone) { $_.Zone.Name } else { $null }
            Scopes            = @($_.Scopes | ForEach-Object { $_.ScopeName })
        }
    })
}

function Get-CitrixAdministrators {
    Set-SplashStatus 'Collecting DaaS administrators...'
    $items = Get-PagedResults -Path '/Admin/Administrators'
    Write-Log "DaaS administrators: $($items.Count)"
    if ($items.Count) { Write-RawSample 'Administrator[0]' $items[0] }
    return @($items | ForEach-Object {
        $a = $_
        # The delegated-admin model nests the identity under a User object.
        # DisplayName is the only reliably populated field: for a human admin it
        # is "Full Name (email@domain)"; an API client (a service principal from
        # API Access) has no email, just the client name (e.g. "AW-Dev").
        $display = $a.User.DisplayName
        if (-not $display) { $display = $a.User.SamName }
        if (-not $display) { $display = $a.User.PrincipalName }
        if (-not $display) { $display = $a.Name }
        # Split "Name (email)" into name + email; fall back to other UPN fields.
        $name  = $display
        $email = $null
        if ($display -match '^(.*?)\s*\(([^)]+@[^)]+)\)\s*$') {
            $name  = $matches[1].Trim()
            $email = $matches[2].Trim()
        }
        if (-not $email -and ($a.User.PrincipalName -match '@')) { $email = $a.User.PrincipalName }
        if (-not $email -and $a.User.Upn)  { $email = $a.User.Upn }
        if (-not $email -and $a.User.Mail) { $email = $a.User.Mail }

        # Raw fields only - the reporter decides User/Group/ApiClient from the Sid
        # (e.g. 'OID:/citrix/...' = secure client, 'OID:/azuread/...' = AAD group).
        $scopesAndRoles = if ($a.ScopesAndRoles) { $a.ScopesAndRoles } else { $a.Rights }
        [ordered]@{
            Id      = "$($a.User.Sid)"
            Name    = $name
            UPN     = $email
            Sid     = "$($a.User.Sid)"
            Enabled = $a.Enabled
            Rights  = @(if ($scopesAndRoles) {
                $scopesAndRoles | ForEach-Object {
                    $rn = if ($_.Role)  { $_.Role.Name }  else { $_.RoleName }
                    $sn = if ($_.Scope) { $_.Scope.Name } else { $_.ScopeName }
                    [ordered]@{ RoleName = $rn; ScopeName = $sn }
                }
            })
        }
    })
}

# Citrix Advisor site check. Advisor is Citrix's own recommendations engine (the DaaS 'Advisor' blade): an
# on-demand scan across Security / Reliability / Performance / Operational Excellence / Cost Optimization that
# returns ~50 candidate recommendations, each flagged IsRecommendationNeeded (whether it actually applies to
# this site) with the AffectedResources behind it. The scan changes NO site configuration - it only
# (re)generates the recommendation list the console shows. Flow: POST $generateRecommendations (async job) ->
# poll /Jobs/{id} -> GET /Advisor/Recommendations. Degrades gracefully: an API client without the rights to
# start the scan yields Status='AccessDenied'; a slow scan is read as-is once the poll times out.
function Get-AdvisorRecommendations {
    Set-SplashStatus 'Running Citrix Advisor site check...'
    $base   = $script:_daasBase
    $result = [ordered]@{ Status = 'OK'; Generated = ''; Recommendations = @() }

    # Advisor calls carry the console's consumer id (the trigger expects it; harmless on the reads).
    $ah = @{}; foreach ($k in $script:_authHeaders.Keys) { $ah[$k] = $script:_authHeaders[$k] }
    $ah['Citrix-Consumer-Id'] = 'WebStudio'
    # Invoke-WebRequest rejects a Content-Type entry in -Headers when -ContentType is also set, so drop it for
    # the POST and let -ContentType supply it.
    $postHeaders = @{}; foreach ($k in $ah.Keys) { if ($k -ne 'Content-Type') { $postHeaders[$k] = $ah[$k] } }

    # 1. Trigger the scan (async job). The job URL comes back in the Location header. The '$' in the action
    #    verb is literal (single-quoted), not a PowerShell variable.
    $body = '{"AspectNameList":["Security","Reliability","Performance","OperationalExcellence","CostOptimization"],"IsRunAllChecks":true,"RecommendationIdList":[]}'
    $jobUrl = $null
    try {
        $resp   = Invoke-SafeWeb -Method Post -Uri ($base + '/Advisor/$generateRecommendations?async=true') -Headers $postHeaders -Body $body -ContentType 'application/json' -UseBasicParsing
        $loc    = $resp.Headers['Location']; if ($loc -is [array]) { $loc = $loc[0] }
        $jobUrl = "$loc"
        Write-Log "Advisor: site check started (job $jobUrl)"
    } catch {
        $st = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        Write-Log "Advisor: could not start the site check [$st]: $_" 'WARN'
        if ($st -eq 401 -or $st -eq 403) { $result['Status'] = 'AccessDenied' }
    }

    # 2. Poll the job to completion (bounded - a large site can take a minute or two).
    if ($jobUrl) {
        $deadline = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
            try {
                $job = Invoke-SafeRest -Method Get -Uri $jobUrl -Headers $ah
                Set-SplashStatus "Citrix Advisor check: $($job.Status) $($job.OverallProgressPercent)%"
                if ("$($job.Status)" -match 'Complete|Success') { break }
                if ("$($job.Status)" -match 'Fail|Error')       { Write-Log "Advisor: job reported $($job.Status)" 'WARN'; break }
            } catch { Write-Log "Advisor: job poll error: $_" 'INFO' }
        }
    }

    # 3. Read the recommendations (also returns the previous scan's results if the trigger was skipped/denied).
    Set-SplashStatus 'Collecting Citrix Advisor recommendations...'
    $rec = Invoke-CitrixApi -Path '/Advisor/Recommendations' -Query @{ includeDismissed = 'false' } -ExtraHeaders @{ 'Citrix-Consumer-Id' = 'WebStudio' } -Quiet
    if ($null -eq $rec) {
        if ($script:_lastStatus -eq 401 -or $script:_lastStatus -eq 403) { $result['Status'] = 'AccessDenied' }
        elseif ($result['Status'] -eq 'OK') { $result['Status'] = 'NoData' }
        Write-Log "Advisor: no recommendations returned (status $($result['Status']))"
        return $result
    }
    $items = if ($null -ne $rec.Items) { $rec.Items } else { $rec }

    $mapped = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($items)) {
        if ($null -eq $r -or "$r" -eq 'null') { continue }
        [void]$mapped.Add([ordered]@{
            Id                        = "$($r.Id)"
            Recommendation            = "$($r.Recommendation)"
            Details                   = "$($r.Details)"
            Impact                    = "$($r.Impact)"
            Aspect                    = "$($r.Aspect)"
            Component                 = "$($r.Component)"
            IsRecommendationNeeded    = [bool]$r.IsRecommendationNeeded
            IsUsingCustomizedSettings = [bool]$r.IsUsingCustomizedSettings
            LastReportedTime          = ConvertTo-Iso $r.LastReportedTime
            # Full detail behind each recommendation (delivery groups / catalogs / machines / connections),
            # passed through as collected so the report can show what the console's expanded view shows.
            AffectedResources         = @($r.AffectedResources)
            Metadata                  = @($r.Metadata)
        })
    }
    $result['Recommendations'] = $mapped.ToArray()
    $needed = @($mapped | Where-Object { $_['IsRecommendationNeeded'] }).Count
    $result['Generated'] = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Write-Log "Advisor: $($mapped.Count) recommendations ($needed needed)"
    return $result
}

# Endpoint inventory, derived from the Advisor result. Advisor's Citrix Workspace app recommendations (End of
# Life + security vulnerabilities) carry per-DEVICE detail - one AffectedResource per endpoint (client name,
# address, platform, Workspace app version, domain, user, last connection) plus, for the security one, the
# CVEs affecting each device. We surface that as a dedicated top-level Endpoints dataset so the report's
# Endpoints section renders straight from it, without depending on Advisor's internal recommendation ids. One
# entry per applicable Workspace app recommendation. Empty when Advisor was not run or flagged nothing.
function ConvertTo-EndpointInventory ($Advisor) {
    if (-not $Advisor) { return @() }
    # The two Citrix Workspace app endpoint recommendations to surface: End of Life (REC_017) and security
    # vulnerabilities (REC_041). Advisor also emits a Low-impact 'Use consistent versions' rec (REC_018, often
    # hundreds of devices) with the same Component - deliberately excluded; it is not an endpoint-risk check.
    $endpointRecIds = @('REC_017', 'REC_041')
    $recs = @($Advisor['Recommendations']) | Where-Object {
        $_ -and ($endpointRecIds -contains "$($_['Id'])") -and $_['IsRecommendationNeeded']
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $recs) {
        $devices = New-Object System.Collections.Generic.List[object]
        $cveMap  = [ordered]@{}   # distinct CVEs across this recommendation's devices
        foreach ($e in @($r['AffectedResources'])) {
            if ($null -eq $e) { continue }
            $cveNames = New-Object System.Collections.Generic.List[string]
            foreach ($v in @($e.Vulnerabilities)) {
                if ($v -and $v.Name) {
                    [void]$cveNames.Add("$($v.Name)")
                    if (-not $cveMap.Contains("$($v.Name)")) {
                        $cveMap["$($v.Name)"] = [ordered]@{ Name = "$($v.Name)"; Article = "$($v.Article)"; Description = "$($v.Description)" }
                    }
                }
            }
            [void]$devices.Add([ordered]@{
                ClientName     = "$($e.ClientName)"
                ClientAddress  = "$($e.ClientAddress)"
                ClientPlatform = "$($e.ClientPlatform)"
                ClientVersion  = "$($e.ClientVersion)"
                Domain         = "$($e.Domain)"
                Username       = "$($e.Username)"
                ConnectionTime = ConvertTo-Iso $e.ConnectionTime
                Cves           = $cveNames.ToArray()
            })
        }
        [void]$out.Add([ordered]@{
            Id               = "$($r['Id'])"
            Recommendation   = "$($r['Recommendation'])"
            Impact           = "$($r['Impact'])"
            Aspect           = "$($r['Aspect'])"
            Details          = "$($r['Details'])"
            LastReportedTime = "$($r['LastReportedTime'])"
            DeviceCount      = $devices.Count
            Cves             = @($cveMap.Values)
            Devices          = $devices.ToArray()
        })
    }
    return $out.ToArray()
}

#endregion

#region ── Collection Orchestrator ───────────────────────────────────────────

function Invoke-Collection ([hashtable]$Config) {
    # Output goes to the script-relative Outputs folder by default (so it follows the script wherever it
    # runs from); an explicit -OutputPath overrides. Not persisted per-customer, matching the on-prem collector.
    $outPath = if ($OutputPath) { $OutputPath } else { $script:_outputDir }
    if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath | Out-Null }

    Show-Splash
    Connect-CitrixCloud -Config $Config

    $errors = 0
    function Collect ([string]$Label, [scriptblock]$Block) {
        try   { return & $Block }
        catch { $script:errors++; Write-Log "$Label error: $_" 'ERROR'; return @() }
    }

    # Cloud-level data
    $resourceLocations = Collect 'ResourceLocations' { Get-CloudResourceLocations }
    $networkLocations  = Collect 'NetworkLocations'  { Get-NetworkLocations }
    $identityProviders = Collect 'IdentityProviders' { Get-CloudIdentityProviders }
    $conditionalAuth   = Collect 'ConditionalAuth'   { Get-ConditionalAuthPolicies }
    $workspaceConfig   = Collect 'WorkspaceConfig'   { Get-WorkspaceConfig }
    $cloudAdmins       = Collect 'CloudAdmins'       { Get-CloudAdministrators }
    $licensing         = Collect 'Licensing'         { Get-CitrixLicensing }
    $servicePrincipals = Collect 'ServicePrincipals' { Get-ServicePrincipals }
    $secureClients     = Collect 'SecureClients'     { Get-SecureClients }
    $productRegs       = Collect 'ProductRegistrations' { Get-ProductRegistrations }
    $identityDomains   = Collect 'IdentityDomains'   { Get-IdentityDomains }

    # DaaS data
    $sites             = Collect 'Sites'             { Get-CitrixSites }
    $zones             = Collect 'Zones'             { Get-CitrixZones }
    $deliveryGroups    = Collect 'DeliveryGroups'    { Get-DeliveryGroups }
    $machineCatalogs   = Collect 'MachineCatalogs'   { Get-MachineCatalogs }
    $machines          = Collect 'Machines'          { Get-CitrixMachines }
    $dgMap = @{}; foreach ($dg in @($deliveryGroups)) { $dgMap["$($dg['Id'])"] = "$($dg['Name'])" }
    $applications      = Collect 'Applications'      { Get-CitrixApplications  -DgMap $dgMap }
    $appGroups         = Collect 'AppGroups'         { Get-CitrixApplicationGroups -DgMap $dgMap }
    $collectSessionDetail = [bool]$Config['CollectSessionDetail']
    $sessions          = if ($collectSessionDetail) { Collect 'Sessions' { Get-CitrixSessions } } else { @() }
    $policies          = Collect 'Policies'          { Get-CitrixPolicies }
    $hosting           = Collect 'Hosting'           { Get-CitrixHostingConnections }
    $admins            = Collect 'Administrators'    { Get-CitrixAdministrators }
    $backups           = Collect 'Backups'           { Get-Backups }
    $appPackages       = Collect 'AppPackages'       { Get-AppPackages }
    # Advisor runs Citrix's own site check (an async scan) and gathers the recommendations + affected
    # resources. It is the one on-demand action in the collection, so it sits last among the DaaS steps. It
    # runs by DEFAULT; skip it with -SkipAdvisor, or per-customer by unticking the dialog checkbox. A config
    # without the IncludeAdvisor key predates the option and defaults to ON.
    $includeAdvisor    = (-not $SkipAdvisor) -and (($null -eq $Config['IncludeAdvisor']) -or [bool]$Config['IncludeAdvisor'])
    $advisor           = if ($includeAdvisor) { Collect 'Advisor' { Get-AdvisorRecommendations } } else { $null }
    # Endpoint inventory (Citrix Workspace app versions / vulnerabilities per device) - derived from the
    # Advisor Workspace app recommendations, so it is present only when Advisor ran and flagged them.
    $endpoints         = Collect 'Endpoints' { ConvertTo-EndpointInventory $advisor }

    # Performance (Monitor OData) - raw logon-performance rows for the last 30 days.
    $logonPerf         = Collect 'LogonPerformance'  { Get-LogonPerformance }

    Set-SplashStatus 'Writing output file...'

    $output = [ordered]@{
        GeneratedAt        = (Get-Date).ToString('o')
        CollectorVersion   = $script:_version
        CustomerName       = $Config['CustomerName']
        CustomerId         = $Config['CustomerId']
        CollectionErrors   = $errors
        CollectionStatus   = $script:_collectStatus   # per-resource status (e.g. ServicePrincipals='AccessDenied')
        SessionDetailCollected = $collectSessionDetail
        AdvisorCollected   = $includeAdvisor   # false => Advisor was not run this collection (opt-in)
        # Citrix Cloud level
        ResourceLocations  = $resourceLocations
        NetworkLocations   = $networkLocations
        IdentityProviders         = $identityProviders
        ConditionalAuthPolicies   = $conditionalAuth
        WorkspaceConfig           = $workspaceConfig
        Licensing          = $licensing
        CloudAdministrators = $cloudAdmins
        ServicePrincipals   = $servicePrincipals
        SecureClients       = $secureClients
        ProductRegistrations = $productRegs
        IdentityDomains     = $identityDomains
        # DaaS / CVAD
        Sites              = $sites
        Zones              = $zones
        DeliveryGroups     = $deliveryGroups
        MachineCatalogs    = $machineCatalogs
        Machines           = $machines
        Applications       = $applications
        ApplicationGroups  = $appGroups
        Sessions           = $sessions
        Policies           = $policies
        HostingConnections = $hosting
        Administrators     = $admins
        Backups            = $backups
        AppPackages        = $appPackages
        Advisor            = $advisor
        Endpoints          = $endpoints
        # Performance
        LogonPerformance   = $logonPerf
    }

    # Normalise list fields so an empty collection serialises as [] rather than
    # null/{} (which the reporter would otherwise read as one phantom blank row).
    $listKeys = 'ResourceLocations','NetworkLocations','IdentityProviders','ConditionalAuthPolicies','CloudAdministrators',
                'ServicePrincipals','SecureClients','ProductRegistrations','IdentityDomains','Sites','Zones',
                'DeliveryGroups','MachineCatalogs','Machines','Applications','ApplicationGroups',
                'Sessions','Policies','HostingConnections','Administrators','LogonPerformance','Endpoints'
    foreach ($k in $listKeys) {
        $clean = @(@($output[$k]) | Where-Object {
            if ($null -eq $_) { $false }
            elseif ($_ -is [System.Collections.IDictionary]) { $_.Count -gt 0 }
            else { $true }
        })
        $output[$k] = $clean
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $safeName  = $Config['CustomerName'] -replace '[^\w\-]', '_'
    # Group outputs in a per-customer subfolder under the Outputs root.
    $custDir   = Join-Path $outPath $safeName
    if (-not (Test-Path $custDir)) { New-Item -ItemType Directory -Path $custDir -Force | Out-Null }
    $encrypt   = ($EncryptPassword -and $EncryptPassword.Length -gt 0)
    $outFile   = Join-Path $custDir ("$safeName-Citrix-Data-$timestamp." + $(if ($encrypt) { 'cdenc' } else { 'json' }))

    try {
        $json = $output | ConvertTo-Json -Depth 20
        if ($encrypt) { $json = Protect-CitrixData $json $EncryptPassword }
        Set-Content -Path $outFile -Value $json -Encoding UTF8
        Write-Log "Output written: $outFile ($([Math]::Round((Get-Item $outFile).Length / 1KB, 1)) KB)$(if ($encrypt) { ' [encrypted]' })"
    } catch {
        Write-Log "Failed to write JSON: $_" 'ERROR'
        $errors++
    }

    # One roll-up so the access-denials are impossible to miss without reading the whole log. These are
    # a permission problem on the API client's admin, not a collector fault - and they explain empty
    # sections (e.g. Endpoints is empty whenever Advisor is denied, since it is derived from Advisor).
    $denied = @($script:_deniedPaths | Select-Object -Unique)
    if ($denied.Count -gt 0) {
        Write-Log "Access denied on $($denied.Count) call(s) - the API client's admin lacks permission for: $($denied -join ', '). Dependent sections will be empty (e.g. Endpoints <- Advisor)." 'WARN'
        # One concise heads-up on the console (the per-call SDK detail stayed in the debug log). The
        # report marks each affected section "permissions not set to support data collection".
        Write-Warning "Access denied on $($denied.Count) API call(s) - the API client's admin lacks permission. Affected report sections will show 'permissions not set to support data collection'. Detail: $($script:_debugLogPath)"
    }

    Close-Splash
    Show-CompletionDialog -OutputFile $outFile -ErrorCount $errors
    return $outFile
}

#endregion

#region ── Entry Point ────────────────────────────────────────────────────────

Start-DebugLog

# Self-update check (interactive launch only; skipped for scripted -ConfigFile/-CustomerName runs and -SkipUpdateCheck).
Invoke-CitrixCloudUpdateCheck

$config = $null

if ($ConfigFile -and (Test-Path $ConfigFile)) {
    Write-Log "Loading config from file: $ConfigFile"
    $json = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    $config = [ordered]@{}
    $json.PSObject.Properties | ForEach-Object { $config[$_.Name] = $_.Value }

} elseif ($CustomerName) {
    $config = Read-CollectConfig -Name $CustomerName
    if (-not $config) {
        Write-Warning "No saved config found for '$CustomerName'. Run without parameters to create one."
        exit 1
    }

} else {
    $sel = Show-CustomerDialog
    if ($sel['Action'] -eq 'Cancel') { Write-Log 'User cancelled at customer dialog'; exit 0 }
    # Dialog password box wins only if -EncryptPassword wasn't already passed on the command line.
    if (-not $EncryptPassword -and $sel['EncryptPassword']) { $EncryptPassword = $sel['EncryptPassword'] }

    if ($sel['IsNew']) {
        Write-Log "Launching cloud setup dialog for new customer '$($sel['CustomerName'])'"
        $config = Show-CloudSetupDialog -CustomerName $sel['CustomerName']
        if (-not $config) { Write-Log 'Setup cancelled'; exit 0 }
        $config['CollectSessionDetail'] = [bool]$sel['CollectSessionDetail']
        $config['IncludeAdvisor']       = [bool]$sel['IncludeAdvisor']
        Save-CollectConfig -Config $config
    } else {
        Write-Log "Loading saved config for '$($sel['CustomerName'])'"
        $config = Read-CollectConfig -Name $sel['CustomerName']
        if (-not $config) {
            Write-Log "Read-CollectConfig returned null for '$($sel['CustomerName'])'" 'ERROR'
            Show-MsgBox "Could not load config for '$($sel['CustomerName'])'." -Icon Error
            exit 1
        }
        # Persist the per-run preferences from the dialog selection
        $config['CollectSessionDetail'] = [bool]$sel['CollectSessionDetail']
        $config['IncludeAdvisor']       = [bool]$sel['IncludeAdvisor']
        Save-CollectConfig -Config $config
        Write-Log "Config loaded: CustomerId='$($config['CustomerId'])' ClientId='$($config['ClientId'])' OutputPath='$($config['OutputPath'])' HasSecret=$([bool]$config['ClientSecretEncrypted'])"
    }
}

if (-not $config) {
    Write-Log 'No config resolved - exiting before collection' 'ERROR'
    Show-MsgBox 'No configuration was loaded. Nothing to collect.' -Icon Error
    exit 1
}

Write-Log "Starting collection for customer '$($config['CustomerName'])'"
Invoke-Collection -Config $config
Write-Log 'Collection routine returned'

#endregion


# SIG # Begin signature block
# MIIvfwYJKoZIhvcNAQcCoIIvcDCCL2wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD7RXSxReght3FQ
# hVR0jkoUIs4EhP3ghsxF42wvNMgXFKCCFDwwggVyMIIDWqADAgECAhB2U/6sdUZI
# k/Xl10pIOk74MA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDAzMTgwMDAwMDBaFw00NTAzMTgwMDAwMDBaMFMx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQD
# EyBHbG9iYWxTaWduIENvZGUgU2lnbmluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALYtxTDdeuirkD0DcrA6S5kWYbLl/6VnHTcc5X7s
# k4OqhPWjQ5uYRYq4Y1ddmwCIBCXp+GiSS4LYS8lKA/Oof2qPimEnvaFE0P31PyLC
# o0+RjbMFsiiCkV37WYgFC5cGwpj4LKczJO5QOkHM8KCwex1N0qhYOJbp3/kbkbuL
# ECzSx0Mdogl0oYCve+YzCgxZa4689Ktal3t/rlX7hPCA/oRM1+K6vcR1oW+9YRB0
# RLKYB+J0q/9o3GwmPukf5eAEh60w0wyNA3xVuBZwXCR4ICXrZ2eIq7pONJhrcBHe
# OMrUvqHAnOHfHgIB2DvhZ0OEts/8dLcvhKO/ugk3PWdssUVcGWGrQYP1rB3rdw1G
# R3POv72Vle2dK4gQ/vpY6KdX4bPPqFrpByWbEsSegHI9k9yMlN87ROYmgPzSwwPw
# jAzSRdYu54+YnuYE7kJuZ35CFnFi5wT5YMZkobacgSFOK8ZtaJSGxpl0c2cxepHy
# 1Ix5bnymu35Gb03FhRIrz5oiRAiohTfOB2FXBhcSJMDEMXOhmDVXR34QOkXZLaRR
# kJipoAc3xGUaqhxrFnf3p5fsPxkwmW8x++pAsufSxPrJ0PBQdnRZ+o1tFzK++Ol+
# A/Tnh3Wa1EqRLIUDEwIrQoDyiWo2z8hMoM6e+MuNrRan097VmxinxpI68YJj8S4O
# JGTfAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzANBgkqhkiG9w0BAQwFAAOCAgEA
# Xiu6dJc0RF92SChAhJPuAW7pobPWgCXme+S8CZE9D/x2rdfUMCC7j2DQkdYc8pzv
# eBorlDICwSSWUlIC0PPR/PKbOW6Z4R+OQ0F9mh5byV2ahPwm5ofzdHImraQb2T07
# alKgPAkeLx57szO0Rcf3rLGvk2Ctdq64shV464Nq6//bRqsk5e4C+pAfWcAvXda3
# XaRcELdyU/hBTsz6eBolSsr+hWJDYcO0N6qB0vTWOg+9jVl+MEfeK2vnIVAzX9Rn
# m9S4Z588J5kD/4VDjnMSyiDN6GHVsWbcF9Y5bQ/bzyM3oYKJThxrP9agzaoHnT5C
# JqrXDO76R78aUn7RdYHTyYpiF21PiKAhoCY+r23ZYjAf6Zgorm6N1Y5McmaTgI0q
# 41XHYGeQQlZcIlEPs9xOOe5N3dkdeBBUO27Ql28DtR6yI3PGErKaZND8lYUkqP/f
# obDckUCu3wkzq7ndkrfxzJF0O2nrZ5cbkL/nx6BvcbtXv7ePWu16QGoWzYCELS/h
# AtQklEOzFfwMKxv9cW/8y7x1Fzpeg9LJsy8b1ZyNf1T+fn7kVqOHp53hWVKUQY9t
# W76GlZr/GnbdQNJRSnC0HzNjI3c/7CceWeQIh+00gkoPP/6gHcH1Z3NFhnj0qinp
# J4fGGdvGExTDOUmHTaCX4GUT9Z13Vunas1jHOvLAzYIwggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB9YwggW+oAMCAQICDBP5pKkF
# uM2pjmiFPTANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjYwMzA2MTU1MzI0WhcNMjcwNDA5MTA1
# MTAxWjCCARwxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMREwDwYDVQQF
# EwgwMjUyMTI0OTETMBEGCysGAQQBgjc8AgEDEwJHQjELMAkGA1UEBhMCR0IxEjAQ
# BgNVBAgTCUJlcmtzaGlyZTEQMA4GA1UEBxMHUmVhZGluZzEsMCoGA1UECRMjR2Fp
# bnNib3JvdWdoIEhvdXNlLCBNYW5vciBGYXJtIFJvYWQxJzAlBgNVBAoTHlVsdGlt
# YSBCdXNpbmVzcyBTb2x1dGlvbnMgTHRkLjEnMCUGA1UEAxMeVWx0aW1hIEJ1c2lu
# ZXNzIFNvbHV0aW9ucyBMdGQuMSAwHgYJKoZIhvcNAQkBFhFpbnRzeXNAdWx0aW1h
# LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIjgA7v4mGJANaD0
# DujYYhb8zwXjSw7Y+hfDisURSte5AidBZIywCtdOoz5AUPVlRgS2xQC5F70oT5jy
# azYit36fzFxtC3q2+6QZHEEYxCaeug3eNnTgrH7QvvMqUWtHhxGCoHfmxIdHNabB
# KzcqlqIzr6UD/jOruH07FIjXuybyO2z3TJlcWVTxzk87cU3sw38LxsRExfqVZjp2
# g1bpfJvsIzkJrRMobM5VPJGGOUCGYAlE+Z9FekABAr37JSK3nyRVBNPOcqShExBO
# P9PFlDgzwW4a3GAL62fI7vQXjPCQAls1aybPymKd4GHFm+mbjkfIHn4QZRYmLPvq
# Jimwv8SYg9Z4TLHnxoI3jNyUttgpDPZ72cK82RPTxoQq35cwArmWQAJ06wCjqTAU
# HWENzZGXNwENr87JsdiuMi/Yz1RsFdMn24YXJjccxgnTYh6OZDUH8QWN5GRgyzAB
# H4TT6MMiqJ5fPO8mfxb//njWQ5s0F41kfokhARFOAMF39K6oWqWW27P3z26d70lg
# +ggmmv1yOOzTMyDT6SOFvs/MgjWUjrfKrmczJGxz0UbH1mUQ9DBx2W2FH4AJKY/Q
# /2Xtbw+Wo8GGCQkgKtnSP3XjE/InBgV1D0Cm4JOjZXm519BedT4AJoAdb6i9He/3
# o4N6h/IwVqJo9mDgGupSeajB6+WrAgMBAAGjggHUMIIB0DAOBgNVHQ8BAf8EBAMC
# B4AwgZ8GCCsGAQUFBwEBBIGSMIGPMEwGCCsGAQUFBzAChkBodHRwOi8vc2VjdXJl
# Lmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2djY3I0NWV2Y29kZXNpZ25jYTIwMjAu
# Y3J0MD8GCCsGAQUFBzABhjNodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9nc2dj
# Y3I0NWV2Y29kZXNpZ25jYTIwMjAwVQYDVR0gBE4wTDBBBgkrBgEEAaAyAQIwNDAy
# BggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9y
# eS8wBwYFZ4EMAQMwCQYDVR0TBAIwADBHBgNVHR8EQDA+MDygOqA4hjZodHRwOi8v
# Y3JsLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcmww
# HAYDVR0RBBUwE4ERaW50c3lzQHVsdGltYS5jb20wEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwHwYDVR0jBBgwFoAUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHQYDVR0OBBYEFI2g
# x0X+88flzfrbfLSAbjrVmPGYMA0GCSqGSIb3DQEBCwUAA4ICAQC0/YWw7b1kKNB0
# DmgOhts5ZOXcMuQ+6B6SEXASaYAlBbawmFKVGcjVRuZ2CXnzscH8JhpZXEakY72w
# Hh5sFr3aUCb3uJ0xyJbXcBV9lv5Old9qzK98Qgq1QBSsd0zUsA/lYhd1hkjb7l7C
# ZgVEe+mQtlJViIyvJZAY52FwBmr6aL798fyC5/3FzG3rJaAPYZivdcdlGPp6ogA6
# 6yu/Mo7p1rtKWQq/HDZH3KqCJynLndYli2HOsIog/MNzzdJiiFBCAsO2wyG+5Oto
# zAptJOEoCWXdDcm+1SDONtc+vl+I5q3iRAggJdmI6ySV8r/pHh1Hl9199hxQfNDk
# ruVcGdpOtok16EDA3+t1zuNdAfoBRYdCN4N5z35+wLLH2sxKLMY5ksLmgOc/ChDw
# PW+VGOCOy4x6Xf35N3i2vMTLqmINbA/guxOzKCsxLgi+blnS7OIBZP3jWVAzxEbW
# vGWL0S6AywGcKdq8yhYrVzHkeJ4RsrdkZHdPTvoTPoF2X92dUNIlqiHG3WZ6/3aK
# paZOtXTXrml259wsFxr8sZzfHWxfrVMpGC75mNCbwZZhhsNU5Xy3RbPkb31EmyNo
# cQEskqx9WePUCYLGKT3ioNwegxc79fFGFT4vea4GGSYhErRoW9D/325MZMyQ89lX
# tt3G/rTOcEVUPTYshnWkr6KsAPh8tTGCGpkwghqVAgEBMGwwXDELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMjAwBgNVBAMTKUdsb2JhbFNp
# Z24gR0NDIFI0NSBFViBDb2RlU2lnbmluZyBDQSAyMDIwAgwT+aSpBbjNqY5ohT0w
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgoB4bPwvivHGpTjas6xvN2WRnbCMLWlh4n4wO
# y4FMOLMwDQYJKoZIhvcNAQEBBQAEggIAIAbKO8lA+px1S0j9E3465Y5BHUUbQBoR
# HylNGieaKwnkjm7JYdRx5ndcMcZYSxYB2abs+BGq3OQTkleBLFpM9ORP4BUp4UMm
# b2u2zkLKQ7U2niCn4MY7PV5A+7xsg4OgibaWTv1MnP3n4nOJ9sYQmp29OKltcMLs
# UDNrytqiTjG1rAY/3sS4svksQOR3qJQDjSsrIk5a1ckl4CnYiiwFpSdikg7GjO7B
# SRMVpVKSRd3m+H5+dBYH2+naqOM+JG1oElTg4z1LU5erUG8c5hg8Pk7NWNmqIVLs
# nALqtyHM22adhQji135KN9nDgGTnZxgf4vGM+Njq4C0qABhS1eXVDGbhfhMo4OV9
# SDTof02vBll7Dmfpc6393kZv5/a69WH8a8t0l8a1WY95KTvCLs020rOeUW0MYnda
# DRnA7lz+RlLy8TdGwdpJcoI9cLigfrvzrKWlDpXtG8l+PK1gzEmFN2X2oT3n4m0i
# 4/dPHApPDQl7ADpyn2F8DHBcq7WPMTZ+1DZKKFeduoqHF+ym/aSl1tnIvii1DmCl
# udYOPMI+6WKdV7Pd6MSoZux4wuYXuCQB5Hl1o9obPkThhlBHeQYtcYtKn4EWWHWU
# FkhvWdncw6hpCy2A7FiRVz4fzXDWB2zHgQuFs1iZlYiprFJUV95owMY4LHqOwqqa
# Dl6PJGgfPHGhghd3MIIXcwYKKwYBBAGCNwMDATGCF2MwghdfBgkqhkiG9w0BBwKg
# ghdQMIIXTAIBAzEPMA0GCWCGSAFlAwQCAQUAMHgGCyqGSIb3DQEJEAEEoGkEZzBl
# AgEBBglghkgBhv1sBwEwMTANBglghkgBZQMEAgEFAAQgfD8mC4bnQ3iuev0Xdq62
# U5NnuJyjj6Ul695XxQHli1MCEQCGd7FJG9jZHo2kBhYE2Rw4GA8yMDI2MDcyMjE0
# MjUwMVqgghM6MIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG
# 9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# QTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQw
# OTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1
# OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYD
# VQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVy
# IDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q
# 6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPn
# Z8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSss
# p3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09
# ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98ok
# souTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+
# 3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsn
# qcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQ
# PdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbS
# LZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojT
# dS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoK
# RR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8E
# AjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTv
# b1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQw
# OTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0
# MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZI
# AYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk
# 9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tsh
# gb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9m
# zskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQ
# BHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+
# YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0c
# Ksb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY
# 7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcboj
# BcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05o
# xYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskK
# PIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjd
# NXOCIUjsarfNZzCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZI
# hvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1
# c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhE
# aWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAy
# MDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMKmEFy
# vjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8
# Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4d
# g2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2C
# QWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSO
# xm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFU
# Ut4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55Iu
# wnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1
# JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k6Mvq
# zfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1K
# hBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4
# RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8E
# CDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSME
# GDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8
# MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9P
# w5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFAT
# uNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sR
# UoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LU
# iwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0
# SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L
# 2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0
# vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFh
# Om0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+
# /j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4
# S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5
# t1wwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN8MIIDeAIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEy
# NTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCggdEw
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNjA3
# MjIxNDI1MDFaMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFN1iMKyGCi0wa9o4sWh5
# UjAH+0F+MC8GCSqGSIb3DQEJBDEiBCBFEekw/ldf75z98xWlHl2ho4npj/HAx8ot
# VyG5O67xpzA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCBKoD+iLNdchMVck4+Cjmdr
# nK7Ksz/jbSaaozTxRhEKMzANBgkqhkiG9w0BAQEFAASCAgBrXbu2Pqx9TMEqvfpE
# iV4pEbI76gE5swk5XzNWHTSAmiiNL30e/vS8kovxQQIe/4v/NapZ2+05hScsNY+0
# cM/7lJFtO6cu9FmT7osxx8dRhW491Lnt+p1a8JHtwfV6qNOaYc270wUP0Uo8yBEI
# Kye3QZZ9BCoeuc228r7hUBTksRVbDhFGA/iB4h01CLsDLEVkQyXHzk6hVOGMa+vO
# J/ZBNhu1Cs1RIbSRnSl9yXGaadUrziFyyayKl097P99aculNPMPDR2aaM0yA+SsV
# 53MzpeICzNhLhxOF6MGFxaVAATDwolkkGUkfJK0kM4a6563SjrK+HwCjPbZsz/Ts
# G0v+gkob/dvpui+owYMRzncy/6GslrwUK5ROW+gS82qLFG/FX3p2WrMpj7BfYkQF
# 95DFUnMO+woMKkfRNM12oQC7balEr8oSGfMXi29GTFlp2gIG0RLIz8Vxpt5fGKhv
# b23VXHs/+AjfIs1Nf7mS4TBsBIL+rK3sC+MnJNM462afBlTlB66pz3GjsPB1+S8Q
# FNlWCUORXFbVudRq1WeShjubB2yYKEdg0vie52rMqDqSCY5qbQZ4Cyp0uBZmZNHn
# 0qCTe86mVz8BQBE0KD+eCELbhUWBWS50ln49oIoeoTF7l5UTQFgadI5NkQOpDUDD
# kDNv1Xi956Ciqkyxuk7COC9OTA==
# SIG # End signature block

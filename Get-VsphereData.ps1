#Requires -Version 5.1
# Version: 2026-07-22   (keep in lock-step with $script:_version below and the published .version file)
<#
.SYNOPSIS
    Collects VMware vSphere host + VM utilisation data from a vCenter (VCSA) for the Hosting report.
    Pure API - uses the vSphere Web Services (SOAP) API over HTTPS via Invoke-WebRequest ONLY;
    no PowerCLI or any other PowerShell module is required or installed.

.DESCRIPTION
    Scopes to a whole cluster or a single ESXi host and captures, from vCenter's PerformanceManager
    and inventory:
      - Per host: physical cores/threads, CPU MHz, total + used CPU, total + used RAM, VM counts.
      - Per VM: vCPUs, allocated + used RAM, live CPU usage, and **CPU Ready %** (contention).
      - **CPU overcommit** per host and cluster (assigned vCPUs of powered-on VMs / physical cores).
    Runs offline of the report: it writes one JSON that Report\Get-HostingReport.ps1 renders with no
    vCenter access. Optionally encrypts the output (.cdenc), shared format with the other EUC reports.

.NOTES
    Compatibility: tested against vCenter / vSphere 8. It uses the vSphere Web Services (vim25 SOAP)
    API, which still exists in vSphere 9 but has NOT been tested against vSphere 9.

.PARAMETER VCenter        vCenter (VCSA) address - FQDN or IP.
.PARAMETER Username       vCenter user, e.g. administrator@vsphere.local (SSO domain usually required).
.PARAMETER Password       vCenter password (SecureString). Prompted in the dialog if omitted.
.PARAMETER Cluster        Collect this cluster (all its hosts). One of -Cluster / -VMHost.
.PARAMETER VMHost         Collect this single host (name as shown in vCenter).
.PARAMETER Customer       Customer name; groups output under Outputs\<Customer>.
.PARAMETER OutputPath     Override the output root (default: Outputs\ next to this script).
.PARAMETER ReadySamples   Real-time (20s) samples to average for CPU Ready (default 15 = ~5 min).
.PARAMETER EncryptPassword  Encrypt the output with this password (writes .cdenc instead of .json).
.PARAMETER NoSplash       Headless - no WPF splash/dialog (needs -VCenter/-Username/-Password/scope).
.PARAMETER SkipUpdateCheck  Skip the launch-time GitHub self-update check.

.EXAMPLE
    .\Get-VsphereData.ps1 -VCenter vcsa.lab.local -Username administrator@vsphere.local -Cluster Cluster
#>
[CmdletBinding()]
param(
    [string]$VCenter,
    [string]$Username,
    [System.Security.SecureString]$Password,
    [string]$Cluster,
    [string]$VMHost,
    [string]$Customer,
    [string]$OutputPath,
    [int]$ReadySamples = 15,
    [int]$DurationMinutes = 30,
    [switch]$NoPerf,
    [switch]$HostsOnly,
    [switch]$NoLiveView,
    [System.Security.SecureString]$EncryptPassword,
    [switch]$NoSplash,
    [switch]$SkipUpdateCheck
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

$script:_version = '2026-07-22'
# Self-update source (public euc-reports-collectors repo): the launch check reads a TINY .version file
# and downloads the full script only when a newer version exists AND the user accepts. Keep the
# '# Version:' header, this $script:_version, and the published .version file in lock-step per release.
# Self-update: fetch update-manifest.json, compare this file's SHA-256 to its manifest entry, and if they
# differ download the published .ps1 BYTE-EXACT (Invoke-WebRequest -OutFile), verify its hash (and signature
# when the manifest marks it signed) before replacing itself.
$script:_manifestUrl    = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/update-manifest.json'
$script:_updateRawBase  = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main'
$script:_selfName       = 'Get-VsphereData.ps1'

$script:_scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $script:_scriptDir) { $script:_scriptDir = (Get-Location).Path }
$script:_outputDir    = if ($OutputPath) { $OutputPath } else { Join-Path $script:_scriptDir 'Outputs' }
$script:_debugLogPath = Join-Path $script:_scriptDir 'VsphereData-Debug.log'
$script:_noSplash     = [bool]$NoSplash

# TLS + self-signed cert bypass. PS 5.1 uses the ServicePointManager callback; PS7 needs
# -SkipCertificateCheck (the callback is ignored there) and -SkipHttpErrorCheck to read SOAP faults.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
$script:_iwrExtra = @{}
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $script:_iwrExtra['SkipCertificateCheck'] = $true
    $script:_iwrExtra['SkipHttpErrorCheck']   = $true
} else {
    # 5.1: use a COMPILED delegate (not a PS scriptblock) so certificate validation also succeeds on the
    # background polling runspace's thread - a scriptblock callback is bound to its origin runspace and
    # fails when the TLS handshake runs on another thread.
    try {
        if (-not ([System.Management.Automation.PSTypeName]'VsphereCertBypass').Type) {
            Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class VsphereCertBypass {
    public static readonly RemoteCertificateValidationCallback Cb =
        delegate (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; };
}
'@
        }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [VsphereCertBypass]::Cb
    } catch {
        try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}
    }
}

#region -- Data-file encryption (opt-in, self-contained) ----------------------
# AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC); PBKDF2 (Rfc2898DeriveBytes 3-arg SHA1 form - identical
# on 5.1 and 7). Shared .cdenc format with the other EUC reports. Off unless -EncryptPassword given.
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
function Protect-ReportData ([string]$PlainJson, [System.Security.SecureString]$Password) {
    if (-not $Password -or $Password.Length -eq 0) { throw 'Protect-ReportData: a password is required.' }
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
#endregion

#region -- Logging ------------------------------------------------------------
function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $script:_debugLogPath -Value $line -ErrorAction SilentlyContinue
}
function Start-DebugLog {
    Set-Content -Path $script:_debugLogPath -Value (@(
        "=== vSphere Data Collector ===",
        "Version $($script:_version)  |  PS $($PSVersionTable.PSVersion)  |  $(Get-Date)"
    ) -join "`r`n") -ErrorAction SilentlyContinue
    Write-Log 'vSphere collector starting'
}
#endregion

#region -- WPF helpers (DWM, themed window, message box, splash) --------------
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class VsphereDwm {
    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
}
'@
} catch {}
$script:_dwmAttr = 33; $script:_dwmSquare = 1
function Set-SquareCorners ([System.Windows.Window]$Window) {
    $Window.Add_SourceInitialized({
        param($s, $e)
        try { $h = (New-Object System.Windows.Interop.WindowInteropHelper($s)).Handle; [void][VsphereDwm]::DwmSetWindowAttribute($h, $script:_dwmAttr, [ref]$script:_dwmSquare, 4) } catch {}
    })
}
function New-ThemedWindow ([string]$Xaml) {
    $rdr = [System.Xml.XmlNodeReader]::new([xml]$Xaml)
    $win = [Windows.Markup.XamlReader]::Load($rdr)
    Set-SquareCorners -Window $win
    return $win
}
function Show-MsgBox {
    param([string]$Message, [string]$Title = 'vSphere Data Collector', [ValidateSet('Info','Warning','Error')][string]$Icon = 'Info')
    if ($script:_noSplash) { Write-Host "[$Icon] $Message"; Write-Log $Message; return }
    $iconChar = switch ($Icon) { 'Error' { '&#x2716;' } 'Warning' { '&#x26A0;' } default { '&#x2139;' } }
    $iconCol  = switch ($Icon) { 'Error' { '#D83B01' } 'Warning' { '#CA5010' } default { '#0078D4' } }
    $m = [System.Security.SecurityElement]::Escape($Message); $t = [System.Security.SecurityElement]::Escape($Title)
    $win = New-ThemedWindow @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$t" SizeToContent="WidthAndHeight" MinWidth="340" MaxWidth="560" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources><Style x:Key="BlueBtn" TargetType="Button"><Setter Property="Background" Value="#0078D4"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/>
    <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextBlock.Foreground="{TemplateBinding Foreground}"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#005BA1"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style></Window.Resources>
  <Border CornerRadius="6" Background="White" BorderBrush="#DDE1E7" BorderThickness="1"><StackPanel Margin="22,20,22,16">
    <StackPanel Orientation="Horizontal" Margin="0,0,0,10"><TextBlock Text="$iconChar" FontSize="20" Foreground="$iconCol" Margin="0,0,10,0"/><TextBlock Text="$t" FontSize="15" FontWeight="Bold" Foreground="#1F2937" VerticalAlignment="Center"/></StackPanel>
    <TextBlock Text="$m" TextWrapping="Wrap" Foreground="#555" MaxWidth="480" Margin="0,0,0,16"/>
    <Button x:Name="btnOk" Content="OK" Width="90" HorizontalAlignment="Right" Padding="0,7" Style="{StaticResource BlueBtn}"/>
  </StackPanel></Border>
</Window>
"@
    $win.FindName('btnOk').Add_Click({ $win.Close() })
    $null = $win.ShowDialog()
}
$script:_splash = $null; $script:_splashStatus = $null
function Show-Splash {
    if ($script:_noSplash) { Write-Log 'Headless (-NoSplash): splash suppressed'; return }
    $win = New-ThemedWindow @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="vSphere Data Collector" Height="170" Width="520" WindowStartupLocation="CenterScreen" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="True" FontFamily="Segoe UI">
  <Border CornerRadius="6" Background="White" BorderBrush="#DDE1E7" BorderThickness="1"><Border.Effect><DropShadowEffect BlurRadius="24" ShadowDepth="3" Opacity="0.12" Color="#000000"/></Border.Effect>
    <StackPanel VerticalAlignment="Center" Margin="32,24">
      <TextBlock Text="Hosting - vSphere Data Collector" FontSize="15" FontWeight="Bold" Foreground="#0078D4" HorizontalAlignment="Center" Margin="0,0,0,6"/>
      <TextBlock x:Name="StatusText" Text="Starting..." FontSize="12" Foreground="#555" HorizontalAlignment="Stretch" TextAlignment="Center" TextTrimming="CharacterEllipsis" Margin="0,0,0,18"/>
      <ProgressBar x:Name="Bar" IsIndeterminate="True" Height="3" Background="#E8EAED" Foreground="#0078D4" BorderThickness="0"/>
    </StackPanel></Border>
</Window>
'@
    $script:_splash = $win; $script:_splashStatus = $win.FindName('StatusText')
    $win.Show(); [void]$win.Activate(); $win.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background); $win.Topmost = $false
    Write-Log 'Splash shown'
}
function Set-SplashStatus ([string]$Message) {
    Write-Log $Message
    if ($script:_splash -and $script:_splashStatus) {
        $script:_splash.Dispatcher.Invoke([Action]{ $script:_splashStatus.Text = $Message }, [System.Windows.Threading.DispatcherPriority]::Render)
    } elseif ($script:_noSplash) { Write-Host "  $Message" }
}
function Close-Splash { if ($script:_splash) { try { $script:_splash.Close() } catch {} ; $script:_splash = $null } }
#endregion

#region -- Self-update check (GitHub) -----------------------------------------
# On launch (interactive), check euc-reports-collectors for a newer version and offer to update in
# place. Optional, fail-safe: short timeout, silent on failure; skipped with -SkipUpdateCheck / -NoSplash.
function ConvertTo-CollectorVersion ([string]$Text) {
    if (-not "$Text") { return $null }
    $t = "$Text".Trim()
    if ($t -match '^(\d{4})[-.](\d{1,2})[-.](\d{1,2})(?:\.(\d+))?$') {
        $rev = if ($matches[4]) { [int]$matches[4] } else { 0 }
        try { return [version]::new([int]$matches[1], [int]$matches[2], [int]$matches[3], $rev) } catch { return $null }
    }
    try { return [version]$t } catch { return $null }
}
function Show-UpdatePrompt ([string]$Local, [string]$Remote) {
    $script:_updChoice = $false
    if ($script:_noSplash) { return $false }
    $l = [System.Security.SecurityElement]::Escape($Local); $r = [System.Security.SecurityElement]::Escape($Remote)
    $win = New-ThemedWindow @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Update available" SizeToContent="WidthAndHeight" MinWidth="380" MaxWidth="520" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources>
    <Style x:Key="BlueBtn" TargetType="Button"><Setter Property="Background" Value="#0078D4"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextBlock.Foreground="{TemplateBinding Foreground}"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#005BA1"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>
    <Style x:Key="GreyBtn" TargetType="Button"><Setter Property="Background" Value="#E1E4EA"/><Setter Property="Foreground" Value="#1F2937"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#CDD0D8"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>
  </Window.Resources>
  <StackPanel Margin="22,20,22,16">
    <TextBlock Text="A newer version of the collector is available." FontSize="14" FontWeight="Bold" Foreground="#1F2937" Margin="0,0,0,8"/>
    <TextBlock FontSize="13" Foreground="#555" TextWrapping="Wrap" Margin="0,0,0,4"><Run Text="Installed: "/><Run Text="$l" FontWeight="SemiBold"/><Run Text="    Available: "/><Run Text="$r" FontWeight="SemiBold" Foreground="#0078D4"/></TextBlock>
    <TextBlock Text="Update now? The script will download the new version and relaunch." FontSize="12" Foreground="#8a8f98" TextWrapping="Wrap" Margin="0,0,0,16"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button x:Name="btnSkip" Content="Not now" Width="90" Padding="0,7" Style="{StaticResource GreyBtn}" Margin="0,0,8,0"/><Button x:Name="btnUpdate" Content="Update" Width="100" Padding="0,7" Style="{StaticResource BlueBtn}"/></StackPanel>
  </StackPanel>
</Window>
"@
    $win.FindName('btnUpdate').Add_Click({ $script:_updChoice = $true; $win.Close() })
    $win.FindName('btnSkip').Add_Click({ $script:_updChoice = $false; $win.Close() })
    $null = $win.ShowDialog()
    return [bool]$script:_updChoice
}
function Invoke-VsphereUpdateCheck {
    if ($SkipUpdateCheck -or $script:_noSplash -or -not $script:_manifestUrl) { return }
    $self = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    if (-not $self) { return }
    try {
        # 1. Fetch the tiny manifest and find this collector's entry.
        $mresp = Invoke-WebRequest -Uri $script:_manifestUrl -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        $manifest = "$($mresp.Content)" | ConvertFrom-Json
        $entry = @($manifest.files) | Where-Object { $_.name -eq $script:_selfName } | Select-Object -First 1
        if (-not $entry -or -not $entry.sha256) { Write-Log "Update check: no manifest entry for $($script:_selfName)" 'WARN'; return }
        $wantHash = "$($entry.sha256)".ToUpperInvariant()
        # 2. Compare my own bytes to the manifest. Same hash -> nothing to do.
        $myHash = (Get-FileHash -LiteralPath $self -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($myHash -eq $wantHash) { Write-Log "Update check: up to date (v$($script:_version), hash matches manifest)"; return }
        # Never downgrade (a same-version, different-hash entry is the unsigned->signed migration, kept).
        $rv = ConvertTo-CollectorVersion "$($entry.version)"; $lv = ConvertTo-CollectorVersion $script:_version
        if ($rv -and $lv -and $rv -lt $lv) { Write-Log "Update check: manifest v$($entry.version) older than local v$($script:_version) - skipping" 'WARN'; return }
        if (-not (Show-UpdatePrompt $script:_version "$($entry.version)")) { return }
        # 3. Download the published script BYTE-EXACT (preserves any signature).
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("VsphereCollector-$([guid]::NewGuid().ToString('N')).ps1")
        Invoke-WebRequest -Uri "$($script:_updateRawBase)/$($script:_selfName)" -UseBasicParsing -TimeoutSec 30 -OutFile $tmp -ErrorAction Stop | Out-Null
        # 4. Verify BEFORE replacing: hash matches the manifest, it parses, and - when signed - its signature is valid.
        $why = ''
        $dlHash = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($dlHash -ne $wantHash) { $why = 'hash mismatch after download' }
        if (-not $why) { $tk = $null; $perr = $null; [System.Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$tk, [ref]$perr) | Out-Null; if ($perr -and $perr.Count) { $why = 'parse errors' } }
        if (-not $why -and $entry.signed) { $sig = Get-AuthenticodeSignature -LiteralPath $tmp; if ($sig.Status -ne 'Valid') { $why = "signature is $($sig.Status)" } }
        if ($why) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue; Show-MsgBox "The downloaded update did not validate ($why); keeping the current version." -Icon Warning; Write-Log "Update: $why" 'WARN'; return }
        # 5. Back up, replace BYTE-EXACT (Copy-Item, not Set-Content, so a signature survives), relaunch.
        try { Copy-Item -LiteralPath $self -Destination "$self.bak" -Force -ErrorAction SilentlyContinue; Copy-Item -LiteralPath $tmp -Destination $self -Force }
        catch { $alt = Join-Path (Split-Path $self -Parent) 'Get-VsphereData.NEW.ps1'; try { Copy-Item -LiteralPath $tmp -Destination $alt -Force } catch {}; Remove-Item $tmp -Force -ErrorAction SilentlyContinue; Show-MsgBox "Couldn't replace the running script (permissions?). Saved as:`n$alt" -Icon Warning; return }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        Show-MsgBox "Updated to version $($entry.version).`n`nThe collector will now relaunch." -Icon Info
        try { Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $self + '"') } catch {}
        exit 0
    } catch { Write-Log "Update check skipped: $(("$($_.Exception.Message)" -replace '\s+', ' '))" }
}
#endregion

#region -- vSphere Web Services (SOAP) API ------------------------------------
$script:_sdk = $null; $script:_ws = $null; $script:_svc = $null
function Invoke-Vim ([string]$Inner) {
    $body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><soapenv:Envelope xmlns:soapenv=`"http://schemas.xmlsoap.org/soap/envelope/`" xmlns:urn=`"urn:vim25`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`"><soapenv:Body>$Inner</soapenv:Body></soapenv:Envelope>"
    try {
        $r = Invoke-WebRequest -Uri $script:_sdk -Method Post -Body $body -ContentType 'text/xml; charset=utf-8' -Headers @{ SOAPAction = 'urn:vim25' } -WebSession $script:_ws -TimeoutSec 90 -UseBasicParsing @script:_iwrExtra
        $content = "$($r.Content)"
    } catch {
        $resp = $_.Exception.Response
        if ($resp) { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $content = $sr.ReadToEnd(); $sr.Close() } else { throw }
    }
    [xml]$x = $content
    if ($x.Envelope.Body.Fault) { throw "vSphere API fault: $($x.Envelope.Body.Fault.faultstring)" }
    return $x
}
function Connect-Vsphere ([string]$VC, [string]$User, [string]$PwPlain) {
    $script:_sdk = "https://$VC/sdk"
    $rsc = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><soapenv:Envelope xmlns:soapenv=`"http://schemas.xmlsoap.org/soap/envelope/`" xmlns:urn=`"urn:vim25`"><soapenv:Body><urn:RetrieveServiceContent><urn:_this type=`"ServiceInstance`">ServiceInstance</urn:_this></urn:RetrieveServiceContent></soapenv:Body></soapenv:Envelope>"
    $r = Invoke-WebRequest -Uri $script:_sdk -Method Post -Body $rsc -ContentType 'text/xml; charset=utf-8' -Headers @{ SOAPAction = 'urn:vim25' } -SessionVariable ws -TimeoutSec 30 -UseBasicParsing @script:_iwrExtra
    $script:_ws = $ws
    [xml]$x = "$($r.Content)"
    $script:_svc = $x.Envelope.Body.RetrieveServiceContentResponse.returnval
    $uE = [System.Security.SecurityElement]::Escape($User); $pE = [System.Security.SecurityElement]::Escape($PwPlain)
    $resp = Invoke-Vim "<urn:Login><urn:_this type=`"SessionManager`">$($script:_svc.sessionManager.'#text')</urn:_this><urn:userName>$uE</urn:userName><urn:password>$pE</urn:password></urn:Login>"
    return $resp.Envelope.Body.LoginResponse.returnval
}
function Disconnect-Vsphere { try { if ($script:_svc) { Invoke-Vim "<urn:Logout><urn:_this type=`"SessionManager`">$($script:_svc.sessionManager.'#text')</urn:_this></urn:Logout>" | Out-Null } } catch {} }
function Get-Prop ($o, [string]$Name) {
    $p = @($o.propSet) | Where-Object { $_.name -eq $Name } | Select-Object -First 1
    if (-not $p) { return $null }
    if ($null -ne $p.val.'#text') { return $p.val.'#text' }
    "$($p.val)"
}
function Get-PropMoRefs ($o, [string]$Name) {
    $p = @($o.propSet) | Where-Object { $_.name -eq $Name } | Select-Object -First 1
    if (-not $p) { return @() }
    @($p.val.ManagedObjectReference | ForEach-Object { "$($_.'#text')" } | Where-Object { $_ })
}
function New-CV ([string]$ContainerType, [string]$Container, [string]$ViewType) {
    (Invoke-Vim "<urn:CreateContainerView><urn:_this type=`"ViewManager`">$($script:_svc.viewManager.'#text')</urn:_this><urn:container type=`"$ContainerType`">$Container</urn:container><urn:type>$ViewType</urn:type><urn:recursive>true</urn:recursive></urn:CreateContainerView>").Envelope.Body.CreateContainerViewResponse.returnval.'#text'
}
function Get-ViewObjects ([string]$ViewMo, [string]$Type, [string[]]$Paths) {
    $ps = ($Paths | ForEach-Object { "<urn:pathSet>$_</urn:pathSet>" }) -join ''
    $inner = "<urn:RetrievePropertiesEx><urn:_this type=`"PropertyCollector`">$($script:_svc.propertyCollector.'#text')</urn:_this><urn:specSet><urn:propSet><urn:type>$Type</urn:type>$ps</urn:propSet><urn:objectSet><urn:obj type=`"ContainerView`">$ViewMo</urn:obj><urn:skip>true</urn:skip><urn:selectSet xsi:type=`"urn:TraversalSpec`"><urn:name>v</urn:name><urn:type>ContainerView</urn:type><urn:path>view</urn:path><urn:skip>false</urn:skip></urn:selectSet></urn:objectSet></urn:specSet><urn:options></urn:options></urn:RetrievePropertiesEx>"
    @((Invoke-Vim $inner).Envelope.Body.RetrievePropertiesExResponse.returnval.objects)
}
function Get-ObjectsByMoRef ([string]$Type, [string[]]$MoRefs, [string[]]$Paths) {
    if (@($MoRefs).Count -eq 0) { return @() }
    $ps = ($Paths | ForEach-Object { "<urn:pathSet>$_</urn:pathSet>" }) -join ''
    $objSet = (@($MoRefs) | ForEach-Object { "<urn:objectSet><urn:obj type=`"$Type`">$_</urn:obj></urn:objectSet>" }) -join ''
    $inner = "<urn:RetrievePropertiesEx><urn:_this type=`"PropertyCollector`">$($script:_svc.propertyCollector.'#text')</urn:_this><urn:specSet><urn:propSet><urn:type>$Type</urn:type>$ps</urn:propSet>$objSet</urn:specSet><urn:options></urn:options></urn:RetrievePropertiesEx>"
    @((Invoke-Vim $inner).Envelope.Body.RetrievePropertiesExResponse.returnval.objects)
}
function Get-CpuReadyCounterId {
    $r = Invoke-Vim "<urn:RetrieveProperties><urn:_this type=`"PropertyCollector`">$($script:_svc.propertyCollector.'#text')</urn:_this><urn:specSet><urn:propSet><urn:type>PerformanceManager</urn:type><urn:pathSet>perfCounter</urn:pathSet></urn:propSet><urn:objectSet><urn:obj type=`"PerformanceManager`">$($script:_svc.perfManager.'#text')</urn:obj></urn:objectSet></urn:specSet></urn:RetrieveProperties>"
    $ctrs = $r.Envelope.Body.RetrievePropertiesResponse.returnval.propSet.val.PerfCounterInfo
    (@($ctrs) | Where-Object { $_.groupInfo.key -eq 'cpu' -and $_.nameInfo.key -eq 'ready' -and $_.rollupType -eq 'summation' } | Select-Object -First 1).key
}
function Get-CpuReadyMs ([string[]]$VmMoRefs, [string]$CounterId, [int]$Samples) {
    $ready = @{}
    if (-not $CounterId -or @($VmMoRefs).Count -eq 0) { return $ready }
    $specs = (@($VmMoRefs) | ForEach-Object { "<urn:querySpec><urn:entity type=`"VirtualMachine`">$_</urn:entity><urn:maxSample>$Samples</urn:maxSample><urn:metricId><urn:counterId>$CounterId</urn:counterId><urn:instance></urn:instance></urn:metricId><urn:intervalId>20</urn:intervalId></urn:querySpec>" }) -join ''
    $r = Invoke-Vim "<urn:QueryPerf><urn:_this type=`"PerformanceManager`">$($script:_svc.perfManager.'#text')</urn:_this>$specs</urn:QueryPerf>"
    foreach ($m in @($r.Envelope.Body.QueryPerfResponse.returnval)) {
        $vals = @($m.value.value | ForEach-Object { [double]$_ })
        if ($vals.Count) { $ready["$($m.entity.'#text')"] = ($vals | Measure-Object -Average).Average }
    }
    $ready
}
# All perf counters (fetched once), for both CPU Ready and the host perf series.
function Get-AllPerfCounters {
    $r = Invoke-Vim "<urn:RetrieveProperties><urn:_this type=`"PropertyCollector`">$($script:_svc.propertyCollector.'#text')</urn:_this><urn:specSet><urn:propSet><urn:type>PerformanceManager</urn:type><urn:pathSet>perfCounter</urn:pathSet></urn:propSet><urn:objectSet><urn:obj type=`"PerformanceManager`">$($script:_svc.perfManager.'#text')</urn:obj></urn:objectSet></urn:specSet></urn:RetrieveProperties>"
    @($r.Envelope.Body.RetrievePropertiesResponse.returnval.propSet.val.PerfCounterInfo)
}
# Resolve a perf counter's id by group/name/rollup (e.g. cpu/usage/average).
function Get-PerfCounterId ([object]$Counters, [string]$Group, [string]$Name, [string]$Rollup) {
    (@($Counters) | Where-Object { $_.groupInfo.key -eq $Group -and $_.nameInfo.key -eq $Name -and $_.rollupType -eq $Rollup } | Select-Object -First 1).key
}
# --- Background transport: run the perf QueryPerf POST in a reused runspace so the UI thread stays
#     responsive during network I/O. The main thread pumps the window's dispatcher while it waits. ---
$script:_perfRs = $null
function Start-PerfRunspace {
    try { $script:_perfRs = [runspacefactory]::CreateRunspace(); $script:_perfRs.Open() }
    catch { Write-Log "Perf runspace unavailable (using synchronous polling): $_" 'WARN'; $script:_perfRs = $null }
}
function Stop-PerfRunspace {
    if ($script:_perfRs) { try { $script:_perfRs.Close(); $script:_perfRs.Dispose() } catch {} ; $script:_perfRs = $null }
}
# Like Invoke-Vim, but the POST runs in the background runspace and the UI is pumped while waiting. Falls
# back to synchronous Invoke-Vim when there's no runspace (headless). Returns $null if the user closed
# the live view mid-request.
function Invoke-VimPumped ([string]$Inner) {
    if (-not $script:_perfRs) { return Invoke-Vim $Inner }
    $body = "<?xml version=`"1.0`" encoding=`"UTF-8`"?><soapenv:Envelope xmlns:soapenv=`"http://schemas.xmlsoap.org/soap/envelope/`" xmlns:urn=`"urn:vim25`" xmlns:xsi=`"http://www.w3.org/2001/XMLSchema-instance`"><soapenv:Body>$Inner</soapenv:Body></soapenv:Envelope>"
    $ps = [powershell]::Create(); $ps.Runspace = $script:_perfRs
    [void]$ps.AddScript({
        param($body, $sdk, $ws, $iwrExtra)
        try {
            $r = Invoke-WebRequest -Uri $sdk -Method Post -Body $body -ContentType 'text/xml; charset=utf-8' -Headers @{ SOAPAction = 'urn:vim25' } -WebSession $ws -TimeoutSec 90 -UseBasicParsing @iwrExtra
            "$($r.Content)"
        } catch {
            $resp = $_.Exception.Response
            if ($resp) { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $c = $sr.ReadToEnd(); $sr.Close(); $c } else { throw }
        }
    }).AddArgument($body).AddArgument($script:_sdk).AddArgument($script:_ws).AddArgument($script:_iwrExtra)
    $h = $ps.BeginInvoke()
    $stopped = $false
    while (-not $h.IsCompleted) {
        if ($script:_perfViewClosed) { $stopped = $true; break }
        $w = if ($script:_perfWin) { $script:_perfWin } else { $script:_splash }
        if ($w) { try { $w.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background) } catch {} }
        Start-Sleep -Milliseconds 40
    }
    if ($stopped) { try { $ps.Stop() } catch {} ; $ps.Dispose(); return $null }
    $content = ''
    try { $content = ($ps.EndInvoke($h) | Select-Object -First 1) } finally { $ps.Dispose() }
    [xml]$x = "$content"
    if ($x.Envelope.Body.Fault) { throw "vSphere API fault: $($x.Envelope.Body.Fault.faultstring)" }
    return $x
}
# Latest real-time (20s) sample for many targets (host + VMs) in one QueryPerf.
# Returns moRef -> @{ Time; Cpu(%); Ram(%); Disk(MB/s); Net(Mbps) }. 'percent' counters are hundredths.
function Get-PerfLatest ($Targets, [hashtable]$Ids) {
    $out = @{}
    $idList = @($Ids.Values | Where-Object { $_ })
    if (@($Targets).Count -eq 0 -or $idList.Count -eq 0) { return $out }
    $metricIds = ($idList | ForEach-Object { "<urn:metricId><urn:counterId>$_</urn:counterId><urn:instance></urn:instance></urn:metricId>" }) -join ''
    $specs = (@($Targets) | ForEach-Object { "<urn:querySpec><urn:entity type=`"$($_.Type)`">$($_.Key)</urn:entity><urn:maxSample>1</urn:maxSample>$metricIds<urn:intervalId>20</urn:intervalId></urn:querySpec>" }) -join ''
    $r = Invoke-VimPumped "<urn:QueryPerf><urn:_this type=`"PerformanceManager`">$($script:_svc.perfManager.'#text')</urn:_this>$specs</urn:QueryPerf>"
    if (-not $r) { return $out }
    foreach ($rv in @($r.Envelope.Body.QueryPerfResponse.returnval)) {
        $mo = "$($rv.entity.'#text')"
        $tArr = @($rv.sampleInfo | ForEach-Object { "$($_.timestamp)" })
        $byId = @{}
        foreach ($series in @($rv.value)) { $vv = @($series.value | ForEach-Object { [double]$_ }); $byId["$($series.id.counterId)"] = if ($vv.Count) { $vv[$vv.Count - 1] } else { $null } }
        $cpu = $byId["$($Ids.Cpu)"]; $ram = $byId["$($Ids.Ram)"]; $dsk = $byId["$($Ids.Disk)"]; $net = $byId["$($Ids.Net)"]; $rdy = $byId["$($Ids.Ready)"]
        $out[$mo] = @{
            Time = if ($tArr.Count) { $tArr[$tArr.Count - 1] } else { '' }
            Cpu  = if ($null -ne $cpu) { [math]::Round($cpu / 100, 1) } else { 0 }
            Ram  = if ($null -ne $ram) { [math]::Round($ram / 100, 1) } else { 0 }
            Disk = if ($null -ne $dsk) { [math]::Round($dsk / 1024, 2) } else { 0 }
            Net  = if ($null -ne $net) { [math]::Round($net * 8 / 1000, 2) } else { 0 }
            ReadyMs = if ($null -ne $rdy) { [double]$rdy } else { $null }   # raw summation ms; -> %RDY/vCPU in the loop
        }
    }
    $out
}
# Empty, List-backed perf series (mutated in place during monitoring; serialises to JSON arrays).
function New-PerfSeries {
    [ordered]@{
        SampleCount = 0; IntervalSec = 20; StartTime = ''; EndTime = ''
        Times    = New-Object System.Collections.Generic.List[string]
        CpuPct   = New-Object System.Collections.Generic.List[double]
        RamPct   = New-Object System.Collections.Generic.List[double]
        DiskMBps = New-Object System.Collections.Generic.List[double]
        NetMbps  = New-Object System.Collections.Generic.List[double]
        ReadyPct = New-Object System.Collections.Generic.List[double]   # per-vCPU %RDY (VMs only)
    }
}
# Sleep in short slices, pumping the live/splash dispatcher so the UI repaints and Windows doesn't flag it hung.
function Start-SleepResponsive ([int]$Seconds) {
    $sliceMs = 250; $slices = [math]::Max(1, [int][math]::Round(($Seconds * 1000) / $sliceMs))
    for ($n = 0; $n -lt $slices; $n++) {
        if ($script:_perfViewClosed) { return }   # user closed the live view - stop waiting immediately
        Start-Sleep -Milliseconds $sliceMs
        $w = if ($script:_perfWin) { $script:_perfWin } else { $script:_splash }
        if ($w) { try { $w.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background) } catch {} }
    }
}

#region -- Live performance view (WPF) ----------------------------------------
$script:_perfWin = $null; $script:_perfStatus = $null; $script:_perfBar = $null; $script:_perfRows = @{}; $script:_perfViewClosed = $false
$script:_perfMetrics = @(
    @{ Key = 'Cpu';  Cap = 'CPU %';     Color = '#2563eb'; Max = 100; Unit = '%' }
    @{ Key = 'Ram';  Cap = 'RAM %';     Color = '#16a34a'; Max = 100; Unit = '%' }
    @{ Key = 'Disk'; Cap = 'Disk MB/s'; Color = '#9333ea'; Max = 0;   Unit = '' }
    @{ Key = 'Net';  Cap = 'Net Mbps';  Color = '#0891b2'; Max = 0;   Unit = '' }
    @{ Key = 'Ready'; Cap = 'CPU Rdy %'; Color = '#dc2626'; Max = 0;  Unit = '%' }
)
$script:_perfBrushCache = @{}
function Get-LiveBrush ([string]$Hex) {
    $b = $script:_perfBrushCache[$Hex]
    if (-not $b) { $b = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($Hex)); $b.Freeze(); $script:_perfBrushCache[$Hex] = $b }
    $b
}
function Show-VspherePerfView ($Targets) {
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="vSphere - Live Performance" Height="640" Width="1080" WindowStartupLocation="CenterScreen" Background="#F4F6F9" FontFamily="Segoe UI">
    <DockPanel Margin="16">
        <StackPanel DockPanel.Dock="Top" Margin="0,0,0,12">
            <TextBlock Text="vSphere - Live Performance" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
            <TextBlock x:Name="StatusText" Text="Starting..." FontSize="12" Foreground="#555" Margin="0,3,0,8"/>
            <ProgressBar x:Name="Bar" Minimum="0" Maximum="100" Value="0" Height="4" Background="#E8EAED" Foreground="#0078D4" BorderThickness="0"/>
        </StackPanel>
        <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel x:Name="RowsPanel"/></ScrollViewer>
    </DockPanel>
</Window>
'@
    $win = New-ThemedWindow $xaml
    $script:_perfWin = $win; $script:_perfStatus = $win.FindName('StatusText'); $script:_perfBar = $win.FindName('Bar'); $script:_perfViewClosed = $false; $script:_perfRows = @{}
    $rowsPanel = $win.FindName('RowsPanel')
    $lastKind = ''
    foreach ($tgt in $Targets) {
        $key = "$($tgt.Key)"
        if ($script:_perfRows.ContainsKey($key)) { continue }
        if ("$($tgt.Kind)" -ne $lastKind) {
            $hdrText = if ($tgt.Kind -eq 'Host') { 'Host' } else { 'Virtual Machines' }
            $hdr = [System.Windows.Markup.XamlReader]::Parse("<TextBlock xmlns=`"http://schemas.microsoft.com/winfx/2006/xaml/presentation`" Text=`"$hdrText`" FontSize=`"13`" FontWeight=`"Bold`" Foreground=`"#0F2C43`" Margin=`"2,14,0,6`"/>")
            [void]$rowsPanel.Children.Add($hdr)
            $lastKind = "$($tgt.Kind)"
        }
        $nameEsc = [System.Security.SecurityElement]::Escape("$($tgt.Name)")
        $kindEsc = [System.Security.SecurityElement]::Escape("$($tgt.Kind)")
        $kindColor = if ($tgt.Kind -eq 'Host') { '#0F6E6E' } else { '#6B7280' }
        $boxes = ''
        foreach ($m in $script:_perfMetrics) {
            $boxes += @"
<StackPanel Margin="0,0,10,0">
  <TextBlock Text="$($m.Cap)" FontSize="10" Foreground="#888"/>
  <TextBlock x:Name="$($m.Key)Val" Text="-" FontSize="12" FontWeight="SemiBold" Foreground="#1F2937"/>
  <Border Background="#F7F8FA" BorderBrush="#E8EAED" BorderThickness="1" CornerRadius="3" Margin="0,2,0,0">
    <Canvas Width="140" Height="38"><Polyline x:Name="$($m.Key)Poly" Stroke="$($m.Color)" StrokeThickness="1.5"/></Canvas>
  </Border>
</StackPanel>
"@
        }
        $rowXaml = @"
<Border xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Background="White" BorderBrush="#DDE1E7" BorderThickness="1" CornerRadius="6" Margin="0,0,0,8" Padding="12,10">
  <Grid>
    <Grid.ColumnDefinitions><ColumnDefinition Width="180"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
    <StackPanel Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0">
      <TextBlock Text="$nameEsc" FontWeight="Bold" FontSize="13" Foreground="#1F2937" TextTrimming="CharacterEllipsis"/>
      <Border Background="$kindColor" CornerRadius="3" Padding="6,2" HorizontalAlignment="Left" Margin="0,4,0,0">
        <TextBlock Text="$kindEsc" FontSize="10" FontWeight="SemiBold" Foreground="White"/>
      </Border>
    </StackPanel>
    <StackPanel Grid.Column="1" Orientation="Horizontal">$boxes</StackPanel>
  </Grid>
</Border>
"@
        $row = [System.Windows.Markup.XamlReader]::Parse($rowXaml)
        $entry = @{ Metrics = @{} }
        foreach ($m in $script:_perfMetrics) {
            $entry.Metrics[$m.Key] = @{
                Poly  = $row.FindName("$($m.Key)Poly")
                Label = $row.FindName("$($m.Key)Val")
                Vals  = [System.Collections.Generic.Queue[double]]::new()
                Max   = [double]$m.Max
                Unit  = "$($m.Unit)"
            }
        }
        $script:_perfRows[$key] = $entry
        [void]$rowsPanel.Children.Add($row)
    }
    $win.Add_Closed({ $script:_perfViewClosed = $true })
    $win.Show(); [void]$win.Activate()
    $win.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    $win.Topmost = $false
    Write-Log "Live performance view shown ($(@($Targets).Count) objects)"
}
function Set-VspherePerfStatus ([string]$Text) {
    Write-Log $Text
    if ($script:_perfWin -and $script:_perfStatus) { try { $script:_perfWin.Dispatcher.Invoke([Action]{ $script:_perfStatus.Text = $Text }, [System.Windows.Threading.DispatcherPriority]::Background) } catch {} }
}
# One async, batched UI update per tick (all rows + progress) so the sampling loop never blocks on the
# UI thread. BeginInvoke at Background priority repaints when the thread is idle (during the sleep pump).
function Update-VspherePerfBatch ([hashtable]$Samples, [double]$ProgressPct) {
    if (-not $script:_perfWin) { return }
    $rows = $script:_perfRows; $bar = $script:_perfBar
    $script:_perfWin.Dispatcher.Invoke([Action]{
        if ($bar) { $bar.Value = $ProgressPct }
        foreach ($key in $Samples.Keys) {
            $row = $rows["$key"]; if (-not $row) { continue }
            $vals = $Samples[$key]
            foreach ($id in @('Cpu', 'Ram', 'Disk', 'Net', 'Ready')) {
                $e = $row.Metrics[$id]; if (-not $e) { continue }
                $sv = $vals[$id]; if ($null -eq $sv) { continue }   # e.g. hosts have no CPU Ready
                $v = [double]$sv
                $q = $e.Vals; $q.Enqueue($v); while ($q.Count -gt 60) { [void]$q.Dequeue() }
                $arr = $q.ToArray(); $n = $arr.Length
                $w = 140.0; $h = 38.0
                if ($e.Max -gt 0) { $top = [double]$e.Max } else { $top = 0.0; for ($k = 0; $k -lt $n; $k++) { if ($arr[$k] -gt $top) { $top = $arr[$k] } }; if ($top -le 0) { $top = 1.0 } }
                $pts = New-Object System.Windows.Media.PointCollection
                for ($i = 0; $i -lt $n; $i++) {
                    $x = if ($n -le 1) { 0.0 } else { $w * $i / ($n - 1) }
                    $cv = [math]::Min($arr[$i], $top); $y = $h - ($h * ($cv / $top))
                    [void]$pts.Add([System.Windows.Point]::new($x, $y))
                }
                if ($n -le 1) { [void]$pts.Add([System.Windows.Point]::new($w, $pts[0].Y)) }
                $pts.Freeze(); $e.Poly.Points = $pts
                $e.Label.Text = if ($e.Max -eq 100) { '{0:N0}{1}' -f $v, $e.Unit } else { '{0:N1}' -f $v }
            }
        }
    }, [System.Windows.Threading.DispatcherPriority]::Render)
}
function Close-VspherePerfView {
    if ($script:_perfWin) { try { $script:_perfWin.Close() } catch {} ; $script:_perfWin = $null }
}
#endregion

# Active perf monitoring over -DurationMinutes: sample every 20s, append to each target's series,
# feed the live view, and write incrementally via $OnTick. Stops early if the user closes the live window.
function Invoke-PerfMonitor ($Targets, [hashtable]$Ids, $Data, [scriptblock]$OnTick) {
    $intervalSec = 20
    $ticks = [math]::Max(1, [int][math]::Round(($DurationMinutes * 60) / $intervalSec))
    $showLive = (-not $NoLiveView) -and (-not $script:_noSplash)
    if ($showLive) { try { Show-VspherePerfView $Targets; Close-Splash } catch { Write-Log "Live view failed: $_" 'WARN' } }   # one window: hide the splash behind the live view
    if (-not $script:_noSplash) { Start-PerfRunspace }   # poll the network off the UI thread so the window stays responsive
    for ($t = 0; $t -lt $ticks; $t++) {
        if ($script:_perfViewClosed) { break }
        Set-SplashStatus "Monitoring performance - sample $($t + 1) of $ticks..."
        Set-VspherePerfStatus "Monitoring - sample $($t + 1) of $ticks (every ${intervalSec}s) - $($Targets.Count) objects"
        $tickSamples = @{}
        try {
            $latest = Get-PerfLatest $Targets $Ids
            foreach ($tgt in $Targets) {
                $s = $latest["$($tgt.Key)"]; if (-not $s) { continue }
                $series = $tgt.Series
                # CPU Ready is VM-only: convert the summation ms to per-vCPU %RDY (null for hosts).
                $rp = if ("$($tgt.Kind)" -eq 'VM') {
                    $nc = [int]$tgt.Rec.NumCpu
                    if ($null -ne $s.ReadyMs -and $nc -gt 0) { [math]::Round($s.ReadyMs / 20000 * 100 / $nc, 2) } else { 0 }
                } else { $null }
                $s.Ready = $rp   # per-vCPU %RDY for the live view (null on hosts -> shown as '-')
                $last = if ($series.Times.Count) { $series.Times[$series.Times.Count - 1] } else { '' }
                if ("$($s.Time)" -and "$($s.Time)" -ne $last) {
                    $series.Times.Add("$($s.Time)")
                    $series.CpuPct.Add([double]$s.Cpu); $series.RamPct.Add([double]$s.Ram); $series.DiskMBps.Add([double]$s.Disk); $series.NetMbps.Add([double]$s.Net)
                    if ($null -ne $rp) { $series.ReadyPct.Add([double]$rp) }
                    $series.SampleCount = $series.Times.Count
                    if (-not $series.StartTime) { $series.StartTime = $series.Times[0] }
                    $series.EndTime = $series.Times[$series.Times.Count - 1]
                }
                $tickSamples["$($tgt.Key)"] = $s
            }
        } catch {
            Write-Log "Perf sample $($t + 1) failed: $_" 'WARN'
            if ($script:_perfRs) { Write-Log 'Perf polling: switching to synchronous mode after a background failure.' 'WARN'; Stop-PerfRunspace }
        }
        if ($showLive) { Update-VspherePerfBatch $tickSamples (100.0 * ($t + 1) / $ticks) }
        # Throttle the incremental write (full JSON serialise + disk) to ~once a minute + first/last tick
        # so it doesn't stall the UI thread every 20s.
        if ($OnTick -and ($t -eq ($ticks - 1) -or ($t % 3) -eq 0)) { try { & $OnTick $Data } catch { Write-Log "Incremental write failed: $_" 'WARN' } }
        if ($script:_perfViewClosed) { Write-Log 'Live view closed - stopping monitoring early'; break }
        if ($t -lt ($ticks - 1)) { Start-SleepResponsive $intervalSec }
    }
    Stop-PerfRunspace
    Close-VspherePerfView
    foreach ($tgt in $Targets) { if ($tgt.Series.Times.Count -eq 0) { $tgt.Rec['Perf'] = $null } }
}
#endregion

#region -- Collection ---------------------------------------------------------
$script:_hostPaths = @('name','parent','summary.hardware.numCpuCores','summary.hardware.numCpuThreads','summary.hardware.cpuMhz','summary.hardware.numCpuPkgs','summary.hardware.memorySize','summary.hardware.vendor','summary.hardware.model','summary.config.product.version','summary.config.product.build','summary.quickStats.overallCpuUsage','summary.quickStats.overallMemoryUsage','summary.quickStats.uptime','runtime.connectionState','runtime.powerState','vm')
$script:_vmPaths   = @('name','runtime.host','runtime.powerState','config.hardware.numCPU','config.hardware.memoryMB','summary.quickStats.overallCpuUsage','summary.quickStats.hostMemoryUsage','summary.quickStats.guestMemoryUsage','config.guestFullName')

function Get-MoRefName ([string]$Type, [string]$MoRef) {
    if (-not $MoRef) { return '' }
    $o = @(Get-ObjectsByMoRef $Type @($MoRef) @('name')) | Select-Object -First 1
    if ($o) { return (Get-Prop $o 'name') } ; ''
}

function Collect-VsphereData ([scriptblock]$OnTick) {
    $rootFolder = $script:_svc.rootFolder.'#text'
    $scopeType = ''; $scopeName = ''
    $hostObjs = @(); $vmObjs = @()

    if ($Cluster) {
        Set-SplashStatus "Locating cluster '$Cluster'..."
        $cv = New-CV 'Folder' $rootFolder 'ClusterComputeResource'
        $clObj = @(Get-ViewObjects $cv 'ClusterComputeResource' @('name')) | Where-Object { (Get-Prop $_ 'name') -eq $Cluster } | Select-Object -First 1
        if (-not $clObj) { throw "Cluster '$Cluster' was not found on $VCenter." }
        $clMo = $clObj.obj.'#text'
        Set-SplashStatus 'Reading hosts...'
        $hostObjs = Get-ViewObjects (New-CV 'ClusterComputeResource' $clMo 'HostSystem') 'HostSystem' $script:_hostPaths
        Set-SplashStatus 'Reading virtual machines...'
        $vmObjs   = Get-ViewObjects (New-CV 'ClusterComputeResource' $clMo 'VirtualMachine') 'VirtualMachine' $script:_vmPaths
        $scopeType = 'Cluster'; $scopeName = $Cluster
    } elseif ($VMHost) {
        Set-SplashStatus "Locating host '$VMHost'..."
        $hv = New-CV 'Folder' $rootFolder 'HostSystem'
        $allHosts = Get-ViewObjects $hv 'HostSystem' $script:_hostPaths
        $hostObj = @($allHosts) | Where-Object { (Get-Prop $_ 'name') -eq $VMHost } | Select-Object -First 1
        if (-not $hostObj) { throw "Host '$VMHost' was not found on $VCenter." }
        $hostObjs = @($hostObj)
        Set-SplashStatus 'Reading virtual machines...'
        $vmObjs   = Get-ObjectsByMoRef 'VirtualMachine' (Get-PropMoRefs $hostObj 'vm') $script:_vmPaths
        $scopeType = 'Host'; $scopeName = $VMHost
    } else { throw 'Specify -Cluster or -VMHost.' }

    # Choose which enumerated hosts / powered-on VMs get LIVE performance capture. Interactive only - the
    # launch dialog runs before we connect, so this is the first point we have the real inventory. Selection
    # populates $selHostMo / $selVmMo (MoRef sets) which gate the $targets loops below; the full host/VM
    # records + CPU Ready are still built for everything. Headless/param path keeps the prior behaviour.
    $selHostMo = New-Object System.Collections.Generic.HashSet[string]
    $selVmMo   = New-Object System.Collections.Generic.HashSet[string]
    if ((-not $NoPerf) -and (-not $script:_noSplash)) {
        $hostNameByMo = @{}
        $hostItems = foreach ($h in @($hostObjs)) {
            $mo = "$($h.obj.'#text')"; $nm = "$(Get-Prop $h 'name')"; $hostNameByMo[$mo] = $nm
            $model = "$(Get-Prop $h 'summary.hardware.model')"; $cores = [int](Get-Prop $h 'summary.hardware.numCpuCores')
            [pscustomobject]@{ Mo = $mo; Name = $nm; Sub = (@($model, $(if ($cores) { "$cores cores" })) | Where-Object { $_ }) -join '  ' }
        }
        $vmItems = foreach ($v in @($vmObjs)) {
            if ((Get-Prop $v 'runtime.powerState') -ne 'poweredOn') { continue }
            $mo = "$($v.obj.'#text')"; $nm = "$(Get-Prop $v 'name')"; $nc = [int](Get-Prop $v 'config.hardware.numCPU')
            $hn = $hostNameByMo["$(Get-Prop $v 'runtime.host')"]
            [pscustomobject]@{ Mo = $mo; Name = $nm; Sub = (@($(if ($nc) { "$nc vCPU" }), $hn) | Where-Object { $_ }) -join '  ' }
        }
        $vmItems = @($vmItems | Sort-Object Name)

        if ($script:_splash) { try { $script:_splash.Hide() } catch {} }
        $pick = Show-VspherePerfTargetDialog @($hostItems) $vmItems
        if ($script:_splash) { try { $script:_splash.Show(); [void]$script:_splash.Activate() } catch {} }
        if ($pick.Action -eq 'OK') {
            foreach ($m in @($pick.Hosts)) { [void]$selHostMo.Add("$m") }
            foreach ($m in @($pick.Vms))   { [void]$selVmMo.Add("$m") }
            Write-Log "Monitoring selection: $($selHostMo.Count) host(s), $($selVmMo.Count) VM(s)"
        } else {
            Write-Log 'Monitoring selection: skipped (static inventory only)'
        }
    } else {
        # Headless / param-driven: monitor all hosts, and all powered-on VMs unless -HostsOnly (prior default).
        foreach ($h in @($hostObjs)) { [void]$selHostMo.Add("$($h.obj.'#text')") }
        if (-not $HostsOnly) {
            foreach ($v in @($vmObjs)) { if ((Get-Prop $v 'runtime.powerState') -eq 'poweredOn') { [void]$selVmMo.Add("$($v.obj.'#text')") } }
        }
    }

    # Performance counters (fetched once): CPU Ready for powered-on VMs + host/VM live-monitoring counters.
    Set-SplashStatus 'Querying performance counters...'
    $allCtrs = Get-AllPerfCounters
    $counterId = Get-PerfCounterId $allCtrs 'cpu' 'ready' 'summation'
    $onVmMo = @($vmObjs | Where-Object { (Get-Prop $_ 'runtime.powerState') -eq 'poweredOn' } | ForEach-Object { "$($_.obj.'#text')" })
    $readyMs = Get-CpuReadyMs $onVmMo $counterId $ReadySamples
    $perfIds = @{
        Cpu   = Get-PerfCounterId $allCtrs 'cpu'  'usage' 'average'
        Ram   = Get-PerfCounterId $allCtrs 'mem'  'usage' 'average'
        Disk  = Get-PerfCounterId $allCtrs 'disk' 'usage' 'average'
        Net   = Get-PerfCounterId $allCtrs 'net'  'usage' 'average'
        Ready = $counterId   # cpu.ready.summation (VM-only; hosts return it but it's ignored)
    }

    # Monitoring targets (host + powered-on VMs): each carries a record reference + an empty series
    # that Invoke-PerfMonitor appends to over the duration.
    $targets = New-Object System.Collections.Generic.List[object]

    # VM records; associate to hosts by Where-Object (avoids a PS quirk indexing List-valued hashtables)
    $vmMeta = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($vmObjs)) {
        $mo = "$($v.obj.'#text')"
        $vmName = "$(Get-Prop $v 'name')"
        $numCpu = [int](Get-Prop $v 'config.hardware.numCPU')
        $on = (Get-Prop $v 'runtime.powerState') -eq 'poweredOn'
        $rMs = if ($readyMs.ContainsKey($mo)) { [double]$readyMs[$mo] } else { $null }
        $readyPct = if ($null -ne $rMs) { [math]::Round($rMs / 20000 * 100, 2) } else { $null }              # total across vCPUs
        $readyPerV = if ($null -ne $rMs -and $numCpu -gt 0) { [math]::Round($rMs / 20000 * 100 / $numCpu, 2) } else { $null }
        $rec = [ordered]@{
            Name         = $vmName
            PowerState   = "$(Get-Prop $v 'runtime.powerState')"
            NumCpu       = $numCpu
            MemoryMB     = [int](Get-Prop $v 'config.hardware.memoryMB')
            CpuUsageMhz  = [int](Get-Prop $v 'summary.quickStats.overallCpuUsage')
            MemActiveMB  = [int](Get-Prop $v 'summary.quickStats.guestMemoryUsage')
            MemConsumedMB= [int](Get-Prop $v 'summary.quickStats.hostMemoryUsage')
            CpuReadyPct  = $readyPct
            CpuReadyPerVcpuPct = $readyPerV
            GuestOs      = "$(Get-Prop $v 'config.guestFullName')"
            Perf         = $null
        }
        $vmMeta.Add([pscustomobject]@{ Mo = $mo; HostMo = "$(Get-Prop $v 'runtime.host')"; On = $on; NumCpu = $numCpu; Record = $rec })
        if ($on -and -not $NoPerf -and $selVmMo.Contains($mo)) {
            $rec['Perf'] = New-PerfSeries
            $targets.Add(@{ Key = $mo; Type = 'VirtualMachine'; Name = $vmName; Kind = 'VM'; Rec = $rec; Series = $rec['Perf'] })
        }
    }

    # host records
    $hostList = New-Object System.Collections.Generic.List[object]
    foreach ($h in @($hostObjs)) {
        $hMo = "$($h.obj.'#text')"
        $hName = "$(Get-Prop $h 'name')"
        $cores = [int](Get-Prop $h 'summary.hardware.numCpuCores')
        $mhz   = [int](Get-Prop $h 'summary.hardware.cpuMhz')
        $totMhz = $cores * $mhz
        $cpuU  = [int](Get-Prop $h 'summary.quickStats.overallCpuUsage')
        $memB  = [long](Get-Prop $h 'summary.hardware.memorySize')
        $memUMB= [int](Get-Prop $h 'summary.quickStats.overallMemoryUsage')
        $memUB = [long]$memUMB * 1MB
        $myVms = @($vmMeta | Where-Object { $_.HostMo -eq $hMo })
        $vcpuOn = (@($myVms | Where-Object { $_.On }) | ForEach-Object { [int]$_.NumCpu } | Measure-Object -Sum).Sum
        $vcpuOn = [int]$vcpuOn
        $clusterName = if ($scopeType -eq 'Cluster') { $scopeName } else { Get-MoRefName 'ClusterComputeResource' "$(Get-Prop $h 'parent')" }
        $hrec = [ordered]@{
            Name            = $hName
            Cluster         = $clusterName
            ConnectionState = "$(Get-Prop $h 'runtime.connectionState')"
            PowerState      = "$(Get-Prop $h 'runtime.powerState')"
            Vendor          = "$(Get-Prop $h 'summary.hardware.vendor')"
            Model           = "$(Get-Prop $h 'summary.hardware.model')"
            EsxiVersion     = "$(Get-Prop $h 'summary.config.product.version')"
            EsxiBuild       = "$(Get-Prop $h 'summary.config.product.build')"
            Cores           = $cores
            Threads         = [int](Get-Prop $h 'summary.hardware.numCpuThreads')
            Sockets         = [int](Get-Prop $h 'summary.hardware.numCpuPkgs')
            CpuMhz          = $mhz
            TotalCpuMhz     = $totMhz
            CpuUsageMhz     = $cpuU
            CpuUsagePct     = if ($totMhz) { [math]::Round($cpuU / $totMhz * 100, 1) } else { 0 }
            MemoryBytes     = $memB
            MemoryUsageBytes= $memUB
            MemoryUsagePct  = if ($memB) { [math]::Round($memUB / $memB * 100, 1) } else { 0 }
            UptimeSec       = [long](Get-Prop $h 'summary.quickStats.uptime')
            VmCount         = @($myVms).Count
            PoweredOnVmCount= @($myVms | Where-Object { $_.On }).Count
            VcpuAllocated   = $vcpuOn
            CpuOvercommit   = if ($cores) { [math]::Round($vcpuOn / $cores, 2) } else { 0 }
            Vms             = @(@($myVms | Sort-Object { -1 * [int]$_.NumCpu }) | ForEach-Object { $_.Record })
            Perf            = $null
        }
        $hostList.Add($hrec)
        if (-not $NoPerf -and $selHostMo.Contains($hMo)) {
            $hrec['Perf'] = New-PerfSeries
            $targets.Add(@{ Key = $hMo; Type = 'HostSystem'; Name = $hName; Kind = 'Host'; Rec = $hrec; Series = $hrec['Perf'] })
        }
    }

    $hostArr = $hostList.ToArray()   # never wrap a List[object] in @() - throws "Argument types do not match" on this PS
    $totCores = (@($hostArr) | ForEach-Object { [int]$_.Cores } | Measure-Object -Sum).Sum
    $totVcpu  = (@($hostArr) | ForEach-Object { [int]$_.VcpuAllocated } | Measure-Object -Sum).Sum
    $totVms   = (@($hostArr) | ForEach-Object { [int]$_.VmCount } | Measure-Object -Sum).Sum
    $totOn    = (@($hostArr) | ForEach-Object { [int]$_.PoweredOnVmCount } | Measure-Object -Sum).Sum
    $avgCpu   = if (@($hostArr).Count) { [math]::Round((@($hostArr) | ForEach-Object { [double]$_.CpuUsagePct } | Measure-Object -Average).Average, 1) } else { 0 }
    $avgMem   = if (@($hostArr).Count) { [math]::Round((@($hostArr) | ForEach-Object { [double]$_.MemoryUsagePct } | Measure-Object -Average).Average, 1) } else { 0 }

    $data = [ordered]@{
        SchemaType     = 'VsphereHosting'
        CollectorVersion = $script:_version
        GeneratedAt    = (Get-Date).ToString('o')
        CollectedBy    = "$env:USERDOMAIN\$env:USERNAME"
        CollectedFrom  = $env:COMPUTERNAME
        CustomerName   = $Customer
        VCenter        = $VCenter
        VCenterVersion = "$($script:_svc.about.fullName)"
        Scope          = [ordered]@{ Type = $scopeType; Name = $scopeName }
        ReadySampleWindowSec = $ReadySamples * 20
        PerfDurationMinutes  = if ($NoPerf) { 0 } else { $DurationMinutes }
        PerfIntervalSec      = 20
        Summary        = [ordered]@{
            HostCount = @($hostArr).Count; VmCount = [int]$totVms; PoweredOnVmCount = [int]$totOn
            TotalCores = [int]$totCores; TotalVcpuAllocated = [int]$totVcpu
            ClusterOvercommit = if ($totCores) { [math]::Round($totVcpu / $totCores, 2) } else { 0 }
            AvgCpuUsagePct = $avgCpu; AvgMemUsagePct = $avgMem
        }
        Hosts          = @($hostArr)
    }

    # Active performance monitoring over the chosen duration (with a live view when interactive).
    # Host(s) first so the live view leads with the host in its own section, then the VMs.
    $targetArr = $targets.ToArray()
    $targetArr = @(@($targetArr | Where-Object { $_.Kind -eq 'Host' }) + @($targetArr | Where-Object { $_.Kind -ne 'Host' }))
    if (-not $NoPerf -and $targetArr.Count -gt 0) {
        Invoke-PerfMonitor $targetArr $perfIds $data $OnTick
    }

    return $data
}
#endregion

#region -- Launch dialog ------------------------------------------------------
function Show-VsphereDialog {
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="vSphere Data Collector" SizeToContent="Height" Width="480" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources>
    <Style x:Key="BlueBtn" TargetType="Button"><Setter Property="Background" Value="#0078D4"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextBlock.Foreground="{TemplateBinding Foreground}"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#005BA1"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>
    <Style x:Key="GreyBtn" TargetType="Button"><Setter Property="Background" Value="#E1E4EA"/><Setter Property="Foreground" Value="#1F2937"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#CDD0D8"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>
  </Window.Resources>
  <Border Background="#F4F6F9" BorderThickness="0"><StackPanel Margin="26,22">
    <TextBlock Text="vSphere Data Collector" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
    <TextBlock Text="Host + VM utilisation, CPU Ready and overcommit from a vCenter (VCSA)" FontSize="12" Foreground="#555" Margin="0,2,0,16"/>
    <TextBlock Text="vCenter (VCSA) address" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
    <Border BorderBrush="#CDD0D6" BorderThickness="1" Background="White" Margin="0,0,0,12">
      <DockPanel LastChildFill="True">
        <TextBlock Text="https://" DockPanel.Dock="Left" Foreground="#8a8f98" FontSize="12" VerticalAlignment="Center" Margin="8,0,0,0"/>
        <TextBox x:Name="VcBox" BorderThickness="0" Background="Transparent" Padding="2,6,8,6" FontSize="12" VerticalContentAlignment="Center"/>
      </DockPanel>
    </Border>
    <TextBlock Text="Username (e.g. administrator@vsphere.local)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
    <TextBox x:Name="UserBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,12"/>
    <TextBlock Text="Password" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
    <PasswordBox x:Name="PwBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,12"/>
    <TextBlock Text="Scope" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
    <StackPanel Orientation="Horizontal" Margin="0,0,0,4"><RadioButton x:Name="RbCluster" Content="Cluster" IsChecked="True" Margin="0,0,18,0" Foreground="#1F2937"/><RadioButton x:Name="RbHost" Content="Single host" Foreground="#1F2937"/></StackPanel>
    <TextBox x:Name="ScopeBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,4"/>
    <TextBlock Text="Cluster name, or host name/IP for single host" FontSize="10" Foreground="#8a8f98" Margin="0,0,0,12"/>
    <TextBlock Text="Customer (optional - groups output under Outputs\&lt;Customer&gt;)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
    <TextBox x:Name="CustBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,12"/>
    <TextBlock Text="Encrypt output (optional - blank = plaintext .json; a password writes .cdenc)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
    <PasswordBox x:Name="EncBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,16"/>
    <Border Background="#F0F6FC" BorderBrush="#CFE4F7" BorderThickness="1" CornerRadius="4" Padding="10,8" Margin="0,0,0,16">
      <StackPanel>
        <CheckBox x:Name="PerfChk" Content="Capture live performance (host + VMs)" IsChecked="True" Foreground="#1F2937" FontSize="12"/>
        <StackPanel Orientation="Horizontal" Margin="22,8,0,0">
          <TextBlock Text="Monitor for" FontSize="11" Foreground="#555" VerticalAlignment="Center" Margin="0,0,6,0"/>
          <TextBox x:Name="DurBox" Text="30" Width="46" Padding="6,3" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" VerticalAlignment="Center"/>
          <TextBlock Text="minutes  (20s samples)" FontSize="11" Foreground="#555" VerticalAlignment="Center" Margin="6,0,0,0"/>
        </StackPanel>
        <CheckBox x:Name="LiveChk" Content="Show live view during monitoring" IsChecked="True" Foreground="#1F2937" FontSize="12" Margin="22,8,0,0"/>
        <TextBlock Text="After connecting you'll pick which hosts and VMs to monitor (hosts default on, VMs off)." FontSize="11" Foreground="#8a8f98" TextWrapping="Wrap" Margin="22,8,0,0"/>
      </StackPanel>
    </Border>
    <Grid><TextBlock x:Name="VersionText" Text="" FontSize="10" Foreground="#8a8f98" VerticalAlignment="Center" HorizontalAlignment="Left"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button x:Name="CancelBtn" Content="Cancel" Width="80" Padding="0,7" Style="{StaticResource GreyBtn}" Margin="0,0,8,0"/><Button x:Name="OkBtn" Content="Start" Width="100" Padding="0,7" Style="{StaticResource BlueBtn}"/></StackPanel></Grid>
  </StackPanel></Border>
</Window>
'@
    $win = New-ThemedWindow $xaml
    $win.FindName('VersionText').Text = "v$($script:_version)"
    $vcBox = $win.FindName('VcBox'); $userBox = $win.FindName('UserBox'); $pwBox = $win.FindName('PwBox')
    $rbCluster = $win.FindName('RbCluster'); $scopeBox = $win.FindName('ScopeBox'); $custBox = $win.FindName('CustBox'); $encBox = $win.FindName('EncBox')
    $perfChk = $win.FindName('PerfChk'); $durBox = $win.FindName('DurBox'); $liveChk = $win.FindName('LiveChk')
    # Monitor duration + live view only apply when performance capture is on; grey them out otherwise
    # (mirrors the on-prem collector).
    $syncPerf = {
        $on = [bool]$perfChk.IsChecked
        $durBox.IsEnabled  = $on
        $liveChk.IsEnabled = $on
        if (-not $on) { $liveChk.IsChecked = $false }
    }
    $perfChk.Add_Checked($syncPerf); $perfChk.Add_Unchecked($syncPerf)
    if ($VCenter) { $vcBox.Text = $VCenter }; if ($Username) { $userBox.Text = $Username }; if ($Cluster) { $scopeBox.Text = $Cluster }; if ($VMHost) { $win.FindName('RbHost').IsChecked = $true; $scopeBox.Text = $VMHost }
    $result = @{ Action = 'Cancel' }
    $win.FindName('OkBtn').Add_Click({
        if (-not $vcBox.Text.Trim() -or -not $userBox.Text.Trim() -or -not $scopeBox.Text.Trim() -or -not $pwBox.Password) { [System.Windows.MessageBox]::Show('Enter the vCenter, username, password and scope.', 'vSphere', 'OK', 'Warning') | Out-Null; return }
        # Strip any scheme/trailing slash a user pastes in - Connect-Vsphere adds https://...$VC/sdk itself.
        $result.Action = 'OK'; $result.VCenter = ($vcBox.Text.Trim() -replace '^\s*https?://\s*', '' -replace '\s*/+\s*$', ''); $result.Username = $userBox.Text.Trim()
        $result.Password = ConvertTo-SecureString $pwBox.Password -AsPlainText -Force
        $result.ScopeType = if ($rbCluster.IsChecked) { 'Cluster' } else { 'Host' }; $result.Scope = $scopeBox.Text.Trim(); $result.Customer = $custBox.Text.Trim()
        $result.Encrypt = if ($encBox.Password) { ConvertTo-SecureString $encBox.Password -AsPlainText -Force } else { $null }
        $result.NoPerf = -not $perfChk.IsChecked
        $dm = 30; [void][int]::TryParse($durBox.Text.Trim(), [ref]$dm); if ($dm -lt 1) { $dm = 1 }
        $result.DurationMinutes = $dm
        $result.NoLiveView = -not $liveChk.IsChecked
        $win.Close()
    })
    $win.FindName('CancelBtn').Add_Click({ $win.Close() })
    $null = $win.ShowDialog()
    $result
}

# Post-connect target picker: choose which enumerated hosts / powered-on VMs get LIVE performance capture.
# Shown only interactively, after the cluster inventory is known (the launch dialog runs before we connect,
# so it can't list real hosts/VMs). Hosts default ticked (all), VMs default un-ticked. Selection filters the
# live-monitoring $targets only - the full host/VM inventory + CPU Ready are still collected regardless.
# $HostItems / $VmItems: arrays of @{ Mo; Name; Sub }. Returns @{ Action='OK'|'Skip'; Hosts=@(mo); Vms=@(mo) }.
function Show-VspherePerfTargetDialog ($HostItems, $VmItems) {
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Select monitoring targets" Height="600" Width="500" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources>
    <Style x:Key="BlueBtn" TargetType="Button"><Setter Property="Background" Value="#0078D4"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextBlock.Foreground="{TemplateBinding Foreground}"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#005BA1"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>
    <Style x:Key="GreyBtn" TargetType="Button"><Setter Property="Background" Value="#E1E4EA"/><Setter Property="Foreground" Value="#1F2937"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#CDD0D8"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>
  </Window.Resources>
  <DockPanel Margin="22,20,22,16">
    <TextBlock DockPanel.Dock="Top" Text="Select what to monitor" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
    <TextBlock DockPanel.Dock="Top" Text="Live performance is captured only for the ticked items. The full cluster inventory (specs, CPU Ready, overcommit) is collected either way." FontSize="11" Foreground="#555" TextWrapping="Wrap" Margin="0,3,0,14"/>
    <Grid DockPanel.Dock="Bottom" Margin="0,14,0,0">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="SkipBtn" Content="Skip monitoring" Width="130" Padding="0,7" Style="{StaticResource GreyBtn}" Margin="0,0,8,0"/>
        <Button x:Name="StartBtn" Content="Start" Width="110" Padding="0,7" Style="{StaticResource BlueBtn}" IsDefault="True"/>
      </StackPanel>
    </Grid>
    <ScrollViewer VerticalScrollBarVisibility="Auto">
      <StackPanel>
        <Grid Margin="0,0,0,4">
          <TextBlock Text="Hosts" FontSize="12" FontWeight="SemiBold" Foreground="#1F2937" VerticalAlignment="Center"/>
          <CheckBox x:Name="HostAll" Content="Select all" IsChecked="True" HorizontalAlignment="Right" Foreground="#0078D4" FontSize="11"/>
        </Grid>
        <Border Background="White" BorderBrush="#E1E4EA" BorderThickness="1" CornerRadius="4" Padding="10,6">
          <StackPanel x:Name="HostsPanel"/>
        </Border>
        <Grid Margin="0,16,0,4">
          <TextBlock x:Name="VmHeader" Text="Virtual machines" FontSize="12" FontWeight="SemiBold" Foreground="#1F2937" VerticalAlignment="Center"/>
          <CheckBox x:Name="VmAll" Content="Select all" HorizontalAlignment="Right" Foreground="#0078D4" FontSize="11"/>
        </Grid>
        <Border Background="White" BorderBrush="#E1E4EA" BorderThickness="1" CornerRadius="4" Padding="10,6">
          <StackPanel x:Name="VmsPanel"/>
        </Border>
      </StackPanel>
    </ScrollViewer>
  </DockPanel>
</Window>
'@
    $win = New-ThemedWindow $xaml
    $hostsPanel = $win.FindName('HostsPanel'); $vmsPanel = $win.FindName('VmsPanel')
    $hostAll = $win.FindName('HostAll'); $vmAll = $win.FindName('VmAll'); $vmHeader = $win.FindName('VmHeader')
    $brDark = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString('#1F2937'))
    $brDim  = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString('#8a8f98'))

    $newCheck = {
        param($item, $checked)
        $cb = [System.Windows.Controls.CheckBox]::new()
        $cb.IsChecked = $checked; $cb.Tag = "$($item.Mo)"
        $cb.Margin = [System.Windows.Thickness]::new(2, 3, 0, 3)
        $cb.VerticalContentAlignment = 'Center'
        $sp = [System.Windows.Controls.StackPanel]::new()
        $t1 = [System.Windows.Controls.TextBlock]::new(); $t1.Text = "$($item.Name)"; $t1.FontSize = 12; $t1.Foreground = $brDark
        [void]$sp.Children.Add($t1)
        if ($item.Sub) { $t2 = [System.Windows.Controls.TextBlock]::new(); $t2.Text = "$($item.Sub)"; $t2.FontSize = 10; $t2.Foreground = $brDim; [void]$sp.Children.Add($t2) }
        $cb.Content = $sp
        $cb
    }

    $hostCbs = New-Object System.Collections.Generic.List[object]
    foreach ($h in @($HostItems)) { $cb = & $newCheck $h $true;  [void]$hostsPanel.Children.Add($cb); $hostCbs.Add($cb) }
    $vmCbs = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($VmItems))   { $cb = & $newCheck $v $false; [void]$vmsPanel.Children.Add($cb);   $vmCbs.Add($cb) }

    $vmHeader.Text = "Virtual machines ($($vmCbs.Count) powered-on)"
    if ($vmCbs.Count -eq 0) {
        $vmAll.Visibility = 'Collapsed'
        $none = [System.Windows.Controls.TextBlock]::new(); $none.Text = 'No powered-on VMs.'; $none.FontSize = 11; $none.Foreground = $brDim
        [void]$vmsPanel.Children.Add($none)
    }

    $hostAll.Add_Click({ $ck = [bool]$hostAll.IsChecked; foreach ($c in $hostCbs) { $c.IsChecked = $ck } })
    $vmAll.Add_Click({   $ck = [bool]$vmAll.IsChecked;   foreach ($c in $vmCbs)   { $c.IsChecked = $ck } })

    $result = @{ Action = 'Skip'; Hosts = @(); Vms = @() }
    $win.FindName('StartBtn').Add_Click({
        $result.Action = 'OK'
        $result.Hosts = @($hostCbs | Where-Object { $_.IsChecked } | ForEach-Object { "$($_.Tag)" })
        $result.Vms   = @($vmCbs   | Where-Object { $_.IsChecked } | ForEach-Object { "$($_.Tag)" })
        $win.Close()
    })
    $win.FindName('SkipBtn').Add_Click({ $result.Action = 'Skip'; $result.Hosts = @(); $result.Vms = @(); $win.Close() })
    [void]$win.Activate()
    $null = $win.ShowDialog()
    $result
}
#endregion

#region -- Entry point --------------------------------------------------------
if ($MyInvocation.InvocationName -eq '.') { return }   # dot-source for tests without running

Start-DebugLog
Invoke-VsphereUpdateCheck

# Resolve inputs (dialog when interactive and anything missing)
$needDialog = -not $script:_noSplash -and (-not $VCenter -or -not $Username -or -not $Password -or (-not $Cluster -and -not $VMHost))
if ($needDialog) {
    $sel = Show-VsphereDialog
    if ($sel.Action -eq 'Cancel') { Write-Log 'User cancelled at launch dialog'; exit 0 }
    $VCenter = $sel.VCenter; $Username = $sel.Username; $Password = $sel.Password; $Customer = $sel.Customer
    if ($sel.ScopeType -eq 'Cluster') { $Cluster = $sel.Scope; $VMHost = '' } else { $VMHost = $sel.Scope; $Cluster = '' }
    if ($sel.Encrypt) { $EncryptPassword = $sel.Encrypt }
    $NoPerf = [bool]$sel.NoPerf
    $NoLiveView = [bool]$sel.NoLiveView
    if ($sel.DurationMinutes) { $DurationMinutes = [int]$sel.DurationMinutes }
}
if (-not $VCenter -or -not $Username -or -not $Password -or (-not $Cluster -and -not $VMHost)) { throw 'Missing -VCenter / -Username / -Password / scope (-Cluster or -VMHost).' }

# Output target computed up-front so the monitoring loop can write incrementally (crash-safe long runs).
$encrypt = ($EncryptPassword -and $EncryptPassword.Length -gt 0)
$safeCustomer = if ($Customer) { ($Customer -replace '[^\w\-. ]', '_').Trim() } else { '' }
$outDir = if ($safeCustomer) { Join-Path $script:_outputDir $safeCustomer } else { $script:_outputDir }
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$base = if ($safeCustomer) { "$safeCustomer-Vsphere-Data-$stamp" } else { "Vsphere-Data-$stamp" }
$ext = if ($encrypt) { '.cdenc' } else { '.json' }
$outFile = Join-Path $outDir "$base$ext"
$writer = {
    param($d)
    $j = $d | ConvertTo-Json -Depth 12
    if ($encrypt) { Set-Content -Path $outFile -Value (Protect-ReportData $j $EncryptPassword) -Encoding UTF8 }
    else { Set-Content -Path $outFile -Value $j -Encoding UTF8 }
}

Show-Splash
$data = $null
try {
    Set-SplashStatus "Connecting to $VCenter..."
    $pwPlain = ConvertFrom-SecureStringPlain $Password
    $null = Connect-Vsphere $VCenter $Username $pwPlain
    $pwPlain = $null
    Write-Log "Connected to $VCenter as $Username"
    $data = Collect-VsphereData $writer
} catch {
    Close-Splash
    Write-Log "Collection failed: $($_.Exception.Message)" 'ERROR'
    Write-Log "Stack: $($_.ScriptStackTrace -replace '\s+',' ')" 'ERROR'
    Show-MsgBox "vSphere collection failed:`n`n$($_.Exception.Message)" -Icon Error
    Disconnect-Vsphere
    exit 1
}
Disconnect-Vsphere

# Final write (idempotent - the monitoring loop already wrote each tick).
try {
    & $writer $data
    Write-Log "Output written: $outFile ($([math]::Round((Get-Item $outFile).Length/1KB,1)) KB)$(if ($encrypt) { ' [encrypted]' })"
} catch { Write-Log "Failed to write output: $_" 'ERROR'; Show-MsgBox "Failed to write output:`n$($_.Exception.Message)" -Icon Error; exit 1 }

Close-Splash
$hc = @($data.Hosts).Count; $vc = [int]$data.Summary.VmCount; $oc = $data.Summary.ClusterOvercommit
Show-MsgBox "vSphere collection complete.`n`nScope: $($data.Scope.Type) '$($data.Scope.Name)'`nHosts: $hc   VMs: $vc   Overcommit: ${oc}:1`n`nOutput:`n$outFile" -Icon Info
if ($script:_noSplash) { Write-Host "Output: $outFile" }
#endregion

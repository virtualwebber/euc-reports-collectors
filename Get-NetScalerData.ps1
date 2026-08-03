#Requires -Version 5.1
# Version: 2026-08-03.3   (keep in lock-step with $script:CollectorVersion below and the published .version file)
<#
.SYNOPSIS
    Collects Citrix NetScaler (ADC) configuration data across appliances and saves it as JSON.

.DESCRIPTION
    Authenticates to each configured NetScaler appliance via the NITRO REST API, queries
    system, load balancing, content switching, SSL, Citrix Gateway, and WAF configuration,
    and saves the collected data to a single JSON file.

    Run Get-NetScalerReport.ps1 (in the Report\ folder) against the resulting JSON file
    to generate HTML reports without requiring NetScaler access.

.PARAMETER OutputPath
    Directory where the JSON data file will be saved. Defaults to the current directory.

.PARAMETER SkipUpdateCheck
    Skip the launch-time check for a newer published version of this collector.

.PARAMETER ApplianceHost
    Appliance hostname/IP. Supplying this together with -Username and -Password skips the WPF
    dialog entirely (headless/scripted collection) - a single appliance only; use the dialog for
    multi-appliance runs.

.PARAMETER Username
    NetScaler login username for headless collection. Requires -ApplianceHost and -Password.

.PARAMETER Password
    NetScaler login password (SecureString) for headless collection. Requires -ApplianceHost and
    -Username.

.PARAMETER CustomerName
    Customer name recorded in the output file for headless collection. Defaults to 'Customer'.

.PARAMETER ApplianceName
    Display name for the appliance in headless collection. Defaults to -ApplianceHost.

.EXAMPLE
    .\Get-NetScalerData.ps1

.EXAMPLE
    .\Get-NetScalerData.ps1 -OutputPath "C:\NetScalerData"

.EXAMPLE
    .\Get-NetScalerData.ps1 -SkipUpdateCheck

.EXAMPLE
    # Headless/scripted collection - no WPF dialog
    $pwd = Read-Host -AsSecureString
    .\Get-NetScalerData.ps1 -ApplianceHost 192.168.100.151 -Username nsroot -Password $pwd -OutputPath "C:\NetScalerData"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter()]
    [switch]$SkipUpdateCheck,

    [Parameter()]
    [string]$ApplianceHost,

    [Parameter()]
    [string]$Username,

    [Parameter()]
    [System.Security.SecureString]$Password,

    [Parameter()]
    [string]$CustomerName = 'Customer',

    [Parameter()]
    [string]$ApplianceName,
    # Directory this script should treat as its own location. Only needed when the collector is run from
    # inside an EXE wrapper (PS2EXE and similar), where PowerShell cannot work out where the script is.
    # Must be WRITABLE - the Outputs\ folder, the debug log and configs\ are all created under it.
    [string]$ScriptDir,
    # Write plain, unencrypted .json instead of a certificate-protected .cdenc.
    # TODO (agreed 2026-08-01): REMOVE once certificate protection has been used on a real
    # engagement - a documented way to turn protection off defeats defaulting it on.
    [switch]$NoProtect
)

$script:CollectorVersion = '2026-08-03.3'

# Self-update source - the public euc-reports-collectors repo (same feed as the other collectors).
$script:_manifestUrl   = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/update-manifest.json'
$script:_updateRawBase = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main'
$script:_selfName      = 'Get-NetScalerData.ps1'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# PS 5.1 defaults to TLS 1.0 — NetScaler management interfaces require TLS 1.2+.
# -bor rather than a flat assignment so an environment that already enabled TLS 1.3 keeps it.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

#region -- Optional data-file encryption (.cdenc) -------------------------------
# AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC), PBKDF2 via the 3-arg Rfc2898DeriveBytes SHA1 form -
# byte-identical on .NET Framework (PS 5.1, here) and .NET Core (PS 7, the report engine), so a file
# encrypted on a customer box decrypts in the report and the hosted app. Shared .cdenc format with
# the other EUC collectors. The password is never written to the file or a log.
# Unwraps a SecureString safely (frees the BSTR). Used for the appliance/host credential - NOT for file
# encryption, which is certificate-based and never handles a password.
function ConvertFrom-SecureStringPlain ([System.Security.SecureString]$Secure) {
    if (-not $Secure) { return '' }
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
$script:_cdEncMarker = '_cdenc'
$script:_noProtect   = $false   # -NoProtect: write plain .json instead of a protected .cdenc

# v2 - CERTIFICATE mode, the only mode. A random AES key encrypts the data and is RSA-wrapped to OUR
# public key, so collected data can only be opened by the holder of the private key. The customer running
# this script cannot read its own output: nothing here is capable of decryption, which is the point.
# There is deliberately NO password option - a second, weaker way to protect a file is one that
# eventually gets used by accident. -NoProtect writes plain .json instead.
$script:_cdEncVerCert = 2; $script:_cdEncAlg = 'AES-256-CBC+HMAC-SHA256'
# PUBLIC certificate (base64 DER), written here by encryption\New-DataProtectionCert.ps1. Public-only:
# it can lock a file and nothing more, so shipping it inside this script gives an attacker nothing.
$script:_dpCertB64 = 'MIIEHTCCAoWgAwIBAgIQERPpywxj96FC80CeAsKOSzANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBtFVUMgUmVwb3J0cyBEYXRhIFByb3RlY3Rpb24wHhcNMjYwODAzMDYyMjA0WhcNMzEwODAzMDYzMTU5WjAmMSQwIgYDVQQDDBtFVUMgUmVwb3J0cyBEYXRhIFByb3RlY3Rpb24wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDHxMuRIxWSyzTF6CEXXBtzPxgesxcdThK/PORvQ+CWar/b/gIaB63DDqGz0OvUsWyAAVPGiaaElmxQxux62x0J5ZpbVfRSwLbFbksrXq+fUMJI/fYDG49Klj/PKeTYX0lOCwr5rDI1JPSWuunp+3KK0Flvt8kx8HLVwGaHIbYCjxZ2k3d9yyHueSkGfDDoou28rVRVMH+3BZYNM7vD/fLk2AbkD7utM+D2eSvzNs/x1B8fzSTlOFCT5lDiY9N51GIR1tf2wxt/ft6gpz/YS7G5ECqKwMGcGDe1aNwSdnDjmZuA7e+AXIr0An0/xRGgwjY2ScjCpwhXdQwARBkGWcsTZG4VN9m4GM5iCDo+R95h9PG39jbRVdHPUqlSN+FF/rIwqYdzS//MG2xF7J8zg/ApygxKBEUSNT37eV/bgRAclEJqnR/SvHEXVZJI/J4/DmO/vhSZr/qV1szaZJU2Z2J+xlyML3f9+9O77sEE/hhOEgOQw5c+z4YYFtpyndIlJt0CAwEAAaNHMEUwDgYDVR0PAQH/BAQDAgQwMBQGA1UdJQQNMAsGCSsGAQQBgjdQATAdBgNVHQ4EFgQUrcDSJBxwg9rxEU/tavdbA4ZcByAwDQYJKoZIhvcNAQELBQADggGBABMmhGsPDt5zr4Lw5E7dZFrqoM2wvT+wXGjFSNc80cir6Mc/79fmxZrP5Ll0ws44m15UmybwOvm2JXTvXBeVWc5pBSiLVNQCMe+vWl1PUGSiQgQLt9lu+/lai6aDBhcAeV7ZoaPEVvN/PX+FQuvqiHD3muO29RKAwOuvSaYupftqPQ42qn1cSN8NQt1dXdyMV2uAdNVORmUKlobB9kP5F3Dd7Z8vqxlSlJcDBbGF+nAwr0ZRGP3Tz0ngCum/Lm23R4ilktvblGOxEzLaZRVtYnAKgq7UfefSo6lIf1gBhIvEiJH8dm2BIzCDWTDUYVH3lqLHNAtOJc24jGNH4Sc45aS1geY0smapvBopLKUbLJ/HruSeNiClhBPmdpDExvQMD+DJgFm44rBKZvHU+BymTNxn3XzsTEd9ePlBzGv/dLHq8s6zWlsITSu21bnFiorS1+EWKRIEJaA7FSte5sRNn66XD1c3uWAGHq9ytuoM2WLBFsJHrJJ+4Cl7Yy774etZPQ=='
# Length-prefixed fields, so the MAC input cannot be made ambiguous by shifting bytes between fields.
function Add-CdEncMacField ([System.IO.MemoryStream]$Stream, [byte[]]$Bytes) {
    $len = [BitConverter]::GetBytes([int]$Bytes.Length)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($len) }
    $Stream.Write($len, 0, 4)
    if ($Bytes.Length) { $Stream.Write($Bytes, 0, $Bytes.Length) }
}
# Authenticates the WHOLE header - ver, alg, kid, wkey, iv, ct - so no metadata can be altered undetected.
function Get-CdEncMacInput ([int]$Ver, [string]$Alg, [string]$Kid, [byte[]]$WKey, [byte[]]$Iv, [byte[]]$Ct) {
    $ms = New-Object System.IO.MemoryStream
    try {
        Add-CdEncMacField $ms ([byte[]]@([byte]$Ver))
        Add-CdEncMacField $ms ([System.Text.Encoding]::UTF8.GetBytes($Alg))
        Add-CdEncMacField $ms ([System.Text.Encoding]::UTF8.GetBytes($Kid))
        Add-CdEncMacField $ms $WKey; Add-CdEncMacField $ms $Iv; Add-CdEncMacField $ms $Ct
        $ms.ToArray()
    } finally { $ms.Dispose() }
}
function Clear-CdEncBytes ([byte[]]$B) { if ($B) { [Array]::Clear($B, 0, $B.Length) } }

function Protect-ReportDataCert ([string]$PlainJson) {
    if (-not $script:_dpCertB64) {
        throw 'No data-protection certificate is embedded in this collector, so the output cannot be protected. Re-run with -NoProtect to write plain JSON, or use a collector built after the certificate was issued.'
    }
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]][Convert]::FromBase64String($script:_dpCertB64))
    if ($cert.HasPrivateKey) { throw 'The embedded data-protection certificate contains a private key - it must be public-only.' }

    # Expiry is a PROMPT TO ROTATE, never a reason to stop: nothing validates a chain or a date, so an
    # expired key encrypts and decrypts exactly as before, and files already written stay readable.
    $daysLeft = [int]([math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays))
    if ($daysLeft -lt 0)      { Write-Log "Data-protection certificate EXPIRED on $($cert.NotAfter.ToString('yyyy-MM-dd')) - output is still protected and still readable, but the certificate should be rotated." 'WARN' }
    elseif ($daysLeft -lt 90) { Write-Log "Data-protection certificate expires in $daysLeft day(s) - plan a rotation." 'WARN' }

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $km = New-Object byte[] 64   # 32 bytes AES + 32 bytes HMAC: one key never does two jobs
        $rng.GetBytes($km)
        $iv = New-Object byte[] 16; $rng.GetBytes($iv)
    } finally { $rng.Dispose() }
    $aesKey = $km[0..31]; $macKey = $km[32..63]

    # GetRSAPublicKey, NOT $cert.PublicKey.Key: on PS 5.1 the latter returns the legacy
    # RSACryptoServiceProvider, which rejects OaepSHA256 - and that fails only on the customer's machine.
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    try { $wkey = $rsa.Encrypt($km, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256) }
    finally { if ($rsa) { $rsa.Dispose() } }

    $aes = [System.Security.Cryptography.Aes]::Create(); $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $aesKey; $aes.IV = $iv
    try { $e = $aes.CreateEncryptor(); $pb = [System.Text.Encoding]::UTF8.GetBytes($PlainJson); $ct = $e.TransformFinalBlock($pb, 0, $pb.Length); $e.Dispose() }
    finally { $aes.Dispose() }

    $kid = $cert.Thumbprint
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, [byte[]]$macKey)
    try { $mac = $hmac.ComputeHash((Get-CdEncMacInput $script:_cdEncVerCert $script:_cdEncAlg $kid $wkey $iv $ct)) } finally { $hmac.Dispose() }

    Clear-CdEncBytes $km; Clear-CdEncBytes $aesKey; Clear-CdEncBytes $macKey

    ([ordered]@{ $script:_cdEncMarker = $script:_cdEncVerCert; alg = $script:_cdEncAlg; kid = $kid
        wkey = [Convert]::ToBase64String($wkey); iv = [Convert]::ToBase64String($iv)
        ct = [Convert]::ToBase64String($ct); mac = [Convert]::ToBase64String($mac) } | ConvertTo-Json)
}

# ONE decision point for every output this collector writes, so separate write paths cannot drift apart.
function Protect-CollectorOutput ([string]$PlainJson) {
    if ($script:_noProtect) { return @{ Json = $PlainJson; Ext = 'json' } }
    return @{ Json = (Protect-ReportDataCert $PlainJson); Ext = 'cdenc' }
}
#endregion

#region -- WPF / DWM setup ----------------------------------------------------

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class NsDataDwm {
    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
}
'@ -ErrorAction Stop
} catch {}

$script:DwmCornerAttr   = 33
$script:DwmCornerSquare = 1

function Set-SquareCorners {
    param($Window)
    $Window.Add_SourceInitialized({
        param($s, $e)
        try {
            $h = (New-Object System.Windows.Interop.WindowInteropHelper($s)).Handle
            [void][NsDataDwm]::DwmSetWindowAttribute($h, $script:DwmCornerAttr, [ref]$script:DwmCornerSquare, 4)
        } catch {}
    })
}

function New-ThemedWindow {
    param([string]$Xaml)
    $rdr = [System.Xml.XmlNodeReader]::new([xml]$Xaml)
    $win = [Windows.Markup.XamlReader]::Load($rdr)
    Set-SquareCorners -Window $win
    return $win
}

function Show-MsgBox {
    param([string]$Message, [string]$Title = 'NetScaler Data Collector', [string]$Icon = 'Info')
    $iconChar  = switch ($Icon) { 'Error' { '&#x2716;' } 'Warning' { '&#x26A0;' } default { '&#x2139;' } }
    $iconColor = switch ($Icon) { 'Error' { '#D83B01' } 'Warning' { '#CA5010' } default { '#0E7C86' } }
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
      <Setter Property="Background" Value="#0E7C86"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                            TextBlock.Foreground="{TemplateBinding Foreground}"/>
        </Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#0D3A40"/></Trigger>
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

#region -- Self-update check (GitHub) ------------------------------------------
# On launch, check euc-reports-collectors for a newer version of THIS script and offer to update in
# place. Optional and fail-safe: short timeout, silent on any failure; skip with -SkipUpdateCheck.
# Matches the mechanism used by the other collectors (hash-verified against update-manifest.json).

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
    $l = [System.Security.SecurityElement]::Escape($Local); $r = [System.Security.SecurityElement]::Escape($Remote)
    $win = New-ThemedWindow @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Update available" SizeToContent="WidthAndHeight" MinWidth="380" MaxWidth="520"
        WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources>
    <Style x:Key="BlueBtn" TargetType="Button">
      <Setter Property="Background" Value="#0E7C86"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextBlock.Foreground="{TemplateBinding Foreground}"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#0D3A40"/></Trigger></ControlTemplate.Triggers>
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
      <Run Text="Installed: "/><Run Text="$l" FontWeight="SemiBold"/><Run Text="    Available: "/><Run Text="$r" FontWeight="SemiBold" Foreground="#0E7C86"/>
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

function Invoke-NsUpdateCheck {
    if ($SkipUpdateCheck -or -not $script:_manifestUrl) { return }
    $self = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    if (-not $self) { return }
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
        # 1. Fetch the tiny manifest and find this collector's entry.
        $mresp = Invoke-WebRequest -Uri $script:_manifestUrl -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        $manifest = "$($mresp.Content)" | ConvertFrom-Json
        $entry = @($manifest.files) | Where-Object { $_.name -eq $script:_selfName } | Select-Object -First 1
        if (-not $entry -or -not $entry.sha256) { Write-Verbose "Update check: no manifest entry for $($script:_selfName)"; return }
        $wantHash = "$($entry.sha256)".ToUpperInvariant()
        # 2. Compare my own bytes to the manifest. Same hash -> nothing to do.
        $myHash = (Get-FileHash -LiteralPath $self -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($myHash -eq $wantHash) { Write-Verbose 'Update check: up to date (hash matches manifest)'; return }
        # Never downgrade.
        $rv = ConvertTo-CollectorVersion "$($entry.version)"; $lv = ConvertTo-CollectorVersion $script:CollectorVersion
        if ($rv -and $lv -and $rv -lt $lv) { Write-Verbose "Update check: manifest v$($entry.version) older than local - skipping"; return }
        if (-not (Show-UpdatePrompt $script:CollectorVersion "$($entry.version)")) { return }
        # 3. Download the published script BYTE-EXACT (preserves any signature).
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("NsCollector-$([guid]::NewGuid().ToString('N')).ps1")
        Invoke-WebRequest -Uri "$($script:_updateRawBase)/$($script:_selfName)" -UseBasicParsing -TimeoutSec 30 -OutFile $tmp -ErrorAction Stop | Out-Null
        # 4. Verify BEFORE replacing: hash matches the manifest, it parses, and - when signed - its signature is valid.
        $why = ''
        $dlHash = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($dlHash -ne $wantHash) { $why = 'hash mismatch after download' }
        if (-not $why) {
            $tk = $null; $perr = $null
            [System.Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$tk, [ref]$perr) | Out-Null
            if ($perr -and $perr.Count) { $why = 'parse errors' }
        }
        if (-not $why -and $entry.signed) {
            $sig = Get-AuthenticodeSignature -LiteralPath $tmp
            if ($sig.Status -ne 'Valid') { $why = "signature is $($sig.Status)" }
        }
        if ($why) {
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            Show-MsgBox "The downloaded update did not validate ($why); keeping the current version." -Icon Warning; return
        }
        # 5. Back up, replace BYTE-EXACT (Copy-Item, not Set-Content, so a signature survives), relaunch.
        try {
            Copy-Item -LiteralPath $self -Destination "$self.bak" -Force -ErrorAction SilentlyContinue
            Copy-Item -LiteralPath $tmp -Destination $self -Force
        } catch {
            $alt = Join-Path (Split-Path $self -Parent) 'Get-NetScalerData.NEW.ps1'
            try { Copy-Item -LiteralPath $tmp -Destination $alt -Force } catch {}
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            Show-MsgBox "Couldn't replace the running script (permissions?). The new version was saved as:`n$alt`n`nReplace the old script with it and re-run." -Icon Warning; return
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        Show-MsgBox "Updated to version $($entry.version).`n`nThe collector will now relaunch." -Icon Info
        try { Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $self + '"') } catch {}
        exit 0
    } catch {
        Write-Verbose "Update check skipped: $(("$($_.Exception.Message)" -replace '\s+', ' '))"
    }
}

#endregion

#region -- Splash screen -------------------------------------------------------

# Brand logo for the splash, embedded so this collector stays a single standalone file (the same
# Trustmarque-Ultima-Logo-Small.jpg the report generators load from their themes\ folder).
$script:_splashLogoB64 = @'
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
'@

[xml]$splashXaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="NetScaler Data Collector" Height="170" Width="440"
    ResizeMode="NoResize" WindowStartupLocation="CenterScreen"
    Background="Transparent" FontFamily="Segoe UI"
    WindowStyle="None" AllowsTransparency="True" Topmost="True">
  <Border x:Name="SplashBorder" CornerRadius="6" Background="White"
          BorderBrush="#DDE1E7" BorderThickness="1">
    <Border.Effect>
      <DropShadowEffect BlurRadius="24" ShadowDepth="3" Opacity="0.12" Color="#000000"/>
    </Border.Effect>
    <StackPanel VerticalAlignment="Center" Margin="32,24">
      <Image x:Name="Logo" Height="34" HorizontalAlignment="Center" Stretch="Uniform" Margin="0,0,0,12"/>
      <TextBlock Text="Citrix NetScaler - Data Collector"
                 FontSize="15" FontWeight="Bold" Foreground="#0E7C86"
                 HorizontalAlignment="Center" Margin="0,0,0,6"/>
      <TextBlock x:Name="SplashStatus" Text="Starting..."
                 FontSize="12" Foreground="#555"
                 HorizontalAlignment="Center" Margin="0,0,0,18"/>
      <ProgressBar x:Name="SplashProgress" IsIndeterminate="False"
                   Minimum="0" Maximum="100" Value="0"
                   Height="3" Background="#E8EAED" Foreground="#0E7C86"
                   BorderThickness="0"/>
      <TextBlock x:Name="SplashSub" Text=""
                 FontSize="10" Foreground="#888"
                 HorizontalAlignment="Center" Margin="0,8,0,0"/>
    </StackPanel>
  </Border>
</Window>
'@

$splashReader           = [System.Xml.XmlNodeReader]::new($splashXaml)
$script:_splash         = [Windows.Markup.XamlReader]::Load($splashReader)
try {
    $_lb = [Convert]::FromBase64String($script:_splashLogoB64)
    $_lbi = New-Object System.Windows.Media.Imaging.BitmapImage
    $_lbi.BeginInit(); $_lbi.CacheOption = 'OnLoad'
    $_lbi.StreamSource = [System.IO.MemoryStream]::new($_lb)
    $_lbi.EndInit(); $_lbi.Freeze()
    $_lg = $script:_splash.FindName('Logo'); if ($_lg) { $_lg.Source = $_lbi }
} catch {}
$script:_splashStatus   = $script:_splash.FindName('SplashStatus')
$script:_splashProgress = $script:_splash.FindName('SplashProgress')
$script:_splashSub      = $script:_splash.FindName('SplashSub')

function Set-CollectStatus {
    param([string]$Text, [int]$Progress = -1, [string]$Sub = '')
    $script:_splash.Dispatcher.Invoke([Action]{
        $script:_splashStatus.Text = $Text
        if ($Progress -ge 0) { $script:_splashProgress.Value = $Progress }
        $script:_splashSub.Text = $Sub
    }, [System.Windows.Threading.DispatcherPriority]::Render)
}

# Offer to self-update from GitHub before doing anything (interactive; fail-safe / optional).
Invoke-NsUpdateCheck

$script:_splash.Show()
$script:_splash.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)

#endregion

#region -- NITRO helpers -------------------------------------------------------

Set-CollectStatus 'Initialising...' -Progress 10

# Bypass self-signed cert validation on NetScaler management interface.
# Scoped to this process only — not a system-wide change.
Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class NsDataCertBypass {
    public static void Install() {
        ServicePointManager.ServerCertificateValidationCallback =
            (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) => true;
    }
}
'@ -ErrorAction SilentlyContinue
try { [NsDataCertBypass]::Install() } catch {}

function Connect-Nitro {
    param([string]$ApplianceHost, [string]$Username, [System.Security.SecureString]$Password)
    # ConvertFrom-SecureStringPlain frees the BSTR; unwrapping inline here used to leak it, leaving
    # the plaintext password in unmanaged memory for the life of the process.
    $plainPwd = ConvertFrom-SecureStringPlain $Password
    $body = '{"login":{"username":"' + $Username + '","password":"' + ($plainPwd -replace '\\','\\' -replace '"','\"') + '"}}'
    $session = $null
    try {
        $resp = Invoke-WebRequest -Uri "https://$ApplianceHost/nitro/v1/config/login" `
            -Method POST -Body $body -ContentType 'application/json' `
            -SessionVariable 'session' -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $data = $resp.Content | ConvertFrom-Json
        if ($data.errorcode -ne 0) {
            throw "NITRO login failed (errorcode $($data.errorcode)): $($data.message)"
        }
        return $session
    } catch {
        throw "Cannot connect to $ApplianceHost`: $_"
    } finally {
        if ($plainPwd) { $plainPwd = $null }
    }
}

function Disconnect-Nitro {
    param([Microsoft.PowerShell.Commands.WebRequestSession]$Session, [string]$ApplianceHost)
    try {
        Invoke-WebRequest -Uri "https://$ApplianceHost/nitro/v1/config/logout" `
            -Method POST -Body '{"logout":{}}' -ContentType 'application/json' `
            -WebSession $Session -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue | Out-Null
    } catch {}
}

function Invoke-NitroGet {
    param(
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$BaseUri,
        [string]$Resource,
        [switch]$Stat,
        [string]$QueryArgs = ''
    )
    $ns = if ($Stat) { 'stat' } else { 'config' }
    $url = "$BaseUri/nitro/v1/$ns/$Resource"
    if ($QueryArgs) { $url += "?$QueryArgs" }
    $resp = Invoke-WebRequest -Uri $url -Method GET -WebSession $Session `
        -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    $data = $resp.Content | ConvertFrom-Json
    # NITRO errorcode 258 is "No such resource exists" - the standard response when a resource type
    # is genuinely configured with zero entries, not a failure. Every other non-zero errorcode is a
    # real failure (auth/permission/malformed request/etc.) and must propagate so the caller's
    # try/catch records it in CollectionErrors, instead of being indistinguishable from "none present".
    if ($data.errorcode -eq 258) { return @() }
    if ($data.errorcode -ne 0 -and $data.errorcode -ne $null) {
        throw "NITRO error $($data.errorcode) for '$Resource': $($data.message)"
    }
    if ($data.PSObject.Properties.Name -contains $Resource) {
        $raw = $data.$Resource
        if ($raw -eq $null) { return @() }
        if ($raw -is [array]) { return $raw }
        return @($raw)
    }
    return @()
}

function Invoke-NitroGetSingle {
    param(
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$BaseUri,
        [string]$Resource
    )
    $url = "$BaseUri/nitro/v1/config/$Resource"
    $resp = Invoke-WebRequest -Uri $url -Method GET -WebSession $Session `
        -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    $data = $resp.Content | ConvertFrom-Json
    # See Invoke-NitroGet above - 258 is the normal "nothing configured" response, not a failure.
    if ($data.errorcode -eq 258) { return $null }
    if ($data.errorcode -ne 0 -and $data.errorcode -ne $null) {
        throw "NITRO error $($data.errorcode) for '$Resource': $($data.message)"
    }
    if ($data.PSObject.Properties.Name -contains $Resource) { return $data.$Resource }
    return $null
}

function Get-NitroProp {
    # NITRO omits optional fields entirely rather than returning them as null,
    # so plain dot-notation throws under Set-StrictMode when a field wasn't set.
    param($Obj, [string]$Name)
    if ($Obj -and ($Obj.PSObject.Properties.Name -contains $Name)) { return $Obj.$Name }
    return $null
}

#endregion

#region -- Config helpers ------------------------------------------------------

# Where this script lives. Inside an EXE wrapper none of the automatic variables that normally reveal it
# are populated, which is why -ScriptDir exists: the EXE tells us. Most reliable source first.
# This only RESOLVES the path - deliberately no Set-Location, because changing the process working
# directory would alter how a relative -OutputPath resolves and would persist after the script exits.
$script:_scriptDir =
    if ($ScriptDir) {
        if (-not (Test-Path -LiteralPath $ScriptDir)) { throw "-ScriptDir '$ScriptDir' does not exist." }
        (Resolve-Path -LiteralPath $ScriptDir).Path
    }
    elseif ($PSScriptRoot)                { $PSScriptRoot }
    elseif ($PSCommandPath)               { Split-Path -Parent $PSCommandPath }
    elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
    else { throw 'Cannot determine the script directory (running from an EXE?). Pass -ScriptDir <path>.' }

$script:_configDir = Join-Path $script:_scriptDir 'configs'

function Read-CollectConfig {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $null }
    try { return (Get-Content $Path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Save-CollectConfig {
    param($Config, [string]$CustomerName)
    try {
        if (-not (Test-Path $script:_configDir)) {
            New-Item -ItemType Directory -Path $script:_configDir -Force | Out-Null
        }
        $safeName = if ($CustomerName) { ($CustomerName -replace '[^A-Za-z0-9\-_\s]', '_').Trim() } else { 'Default' }
        $path = Join-Path $script:_configDir "$safeName.config.json"
        $Config | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
        return $path
    } catch { return $null }
}

#endregion

#region -- Add Appliance dialog ------------------------------------------------

function Show-AddApplianceDialog {
    param([string]$DefaultName = '', [string]$DefaultHost = '')

    $win = New-ThemedWindow @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Add Appliance" Width="380" SizeToContent="Height"
        WindowStartupLocation="CenterOwner" ResizeMode="NoResize"
        FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources>
    <Style x:Key="BlueBtn" TargetType="Button">
      <Setter Property="Background" Value="#0E7C86"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                            TextBlock.Foreground="{TemplateBinding Foreground}"/>
        </Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#0D3A40"/></Trigger>
        </ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="GreyBtn" TargetType="Button">
      <Setter Property="Background" Value="#E1E4EA"/><Setter Property="Foreground" Value="#1F2937"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Cursor" Value="Hand"/>
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
  <StackPanel Margin="20,18,20,16">
    <TextBlock Text="Name" FontSize="11" Foreground="#555" Margin="0,0,0,4"/>
    <TextBox x:Name="TxtName" Text="$DefaultName" Padding="8,6" Margin="0,0,0,12"
             Background="White" BorderBrush="#CDD0D6" BorderThickness="1"
             FontSize="13"/>
    <TextBlock Text="Host / IP Address" FontSize="11" Foreground="#555" Margin="0,0,0,4"/>
    <TextBox x:Name="TxtHost" Text="$DefaultHost" Padding="8,6" Margin="0,0,0,16"
             Background="White" BorderBrush="#CDD0D6" BorderThickness="1"
             FontSize="13"/>
    <TextBlock x:Name="TxtError" Text="" Foreground="#D83B01" FontSize="11"
               Margin="0,0,0,10" Visibility="Collapsed"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="BtnOk"     Content="Add"    Width="80" Padding="0,7"
              Style="{StaticResource BlueBtn}" Margin="0,0,8,0"/>
      <Button x:Name="BtnCancel" Content="Cancel" Width="80" Padding="0,7"
              Style="{StaticResource GreyBtn}"/>
    </StackPanel>
  </StackPanel>
</Window>
"@

    $txtName   = $win.FindName('TxtName')
    $txtHost   = $win.FindName('TxtHost')
    $txtError  = $win.FindName('TxtError')
    $btnOk     = $win.FindName('BtnOk')
    $btnCancel = $win.FindName('BtnCancel')

    $btnCancel.Add_Click({ $win.DialogResult = $false; $win.Close() })
    $btnOk.Add_Click({
        $n = $txtName.Text.Trim()
        $h = $txtHost.Text.Trim()
        if (-not $n -or -not $h) {
            $txtError.Text = 'Both Name and Host are required.'
            $txtError.Visibility = 'Visible'
            return
        }
        $win.DialogResult = $true
        $win.Close()
    })

    $script:_addResult = $null
    if ($win.ShowDialog()) {
        $script:_addResult = [ordered]@{
            Name = $txtName.Text.Trim()
            Host = $txtHost.Text.Trim()
        }
    }
    return $script:_addResult
}

#endregion

#region -- Main collection dialog ----------------------------------------------

function Show-CollectorDialog {

    $win = New-ThemedWindow @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NetScaler Data Collector" Width="580" SizeToContent="Height"
        WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        FontFamily="Segoe UI" FontSize="13" Background="#F4F6F9">
  <Window.Resources>
    <Style x:Key="BlueBtn" TargetType="Button">
      <Setter Property="Background" Value="#0E7C86"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="FontSize" Value="12"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                            TextBlock.Foreground="{TemplateBinding Foreground}"/>
        </Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#0D3A40"/></Trigger>
          <Trigger Property="IsPressed"   Value="True"><Setter TargetName="bd" Property="Background" Value="#082A2E"/></Trigger>
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

    <!-- Header -->
    <DockPanel Margin="0,0,0,18">
      <TextBlock Text="&#x1F5A7;" FontSize="28" Foreground="#0E7C86" DockPanel.Dock="Left"
                 VerticalAlignment="Center" Margin="0,0,14,0"/>
      <StackPanel>
        <TextBlock Text="Citrix NetScaler" FontSize="18" FontWeight="Bold" Foreground="#1F2937"/>
        <TextBlock Text="Data Collection" FontSize="12" Foreground="#555"/>
      </StackPanel>
    </DockPanel>

    <!-- Customer -->
    <TextBlock Text="Customer Name" FontSize="11" Foreground="#555" Margin="0,0,0,4"/>
    <TextBox x:Name="TxtCustomer" Padding="8,6" Margin="0,0,0,16"
             Background="White" BorderBrush="#CDD0D6" BorderThickness="1"/>

    <!-- Appliances -->
    <DockPanel Margin="0,0,0,6">
      <TextBlock Text="Appliances" FontSize="11" Foreground="#555"
                 VerticalAlignment="Center" DockPanel.Dock="Left"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="BtnAddAppliance" Content="+ Add Single Appliance" Padding="10,5"
                Style="{StaticResource GreyBtn}" Margin="0,0,6,0"/>
        <Button x:Name="BtnLoadConfig"   Content="&#x1F4C2; Load Config"   Padding="10,5"
                Style="{StaticResource GreyBtn}"/>
      </StackPanel>
    </DockPanel>
    <Border Background="White" BorderBrush="#CDD0D6" BorderThickness="1" CornerRadius="4"
            Margin="0,0,0,4" MinHeight="80">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <!-- Column headers -->
        <Grid Grid.Row="0" Background="#F0F2F5" Margin="0">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="26"/>
          </Grid.ColumnDefinitions>
          <TextBlock Grid.Column="0" Text="Name" FontSize="11" FontWeight="SemiBold"
                     Foreground="#555" Margin="10,5,0,5"/>
          <TextBlock Grid.Column="1" Text="Host / IP" FontSize="11" FontWeight="SemiBold"
                     Foreground="#555" Margin="10,5,0,5"/>
        </Grid>
        <ListBox x:Name="LstAppliances" Grid.Row="1" Background="Transparent"
                 BorderThickness="0" ScrollViewer.HorizontalScrollBarVisibility="Disabled"
                 MaxHeight="160">
          <ListBox.ItemContainerStyle>
            <Style TargetType="ListBoxItem">
              <Setter Property="HorizontalContentAlignment" Value="Stretch"/>
              <Setter Property="Padding" Value="0"/>
            </Style>
          </ListBox.ItemContainerStyle>
        </ListBox>
      </Grid>
    </Border>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,0,0,16">
      <Button x:Name="BtnRemoveAppliance" Content="Remove Selected" Padding="8,4"
              Style="{StaticResource GreyBtn}" FontSize="11"/>
    </StackPanel>

    <!-- Credentials -->
    <Grid Margin="0,0,0,16">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="16"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <StackPanel Grid.Column="0">
        <TextBlock Text="Username" FontSize="11" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox x:Name="TxtUsername" Text="nsroot" Padding="8,6"
                 Background="White" BorderBrush="#CDD0D6" BorderThickness="1"/>
      </StackPanel>
      <StackPanel Grid.Column="2">
        <TextBlock Text="Password" FontSize="11" Foreground="#555" Margin="0,0,0,4"/>
        <PasswordBox x:Name="PwdPassword" Padding="8,6"
                     Background="White" BorderBrush="#CDD0D6" BorderThickness="1"/>
      </StackPanel>
    </Grid>

    <!-- Output folder -->
    <TextBlock Text="Output Folder" FontSize="11" Foreground="#555" Margin="0,0,0,4"/>
    <Grid Margin="0,0,0,16">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="8"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="TxtOutput" Padding="8,6"
               Background="White" BorderBrush="#CDD0D6" BorderThickness="1"/>
      <Button x:Name="BtnBrowse" Grid.Column="2" Content="Browse..." Padding="10,6"
              Style="{StaticResource GreyBtn}"/>
    </Grid>

    <!-- Data-file protection is automatic (certificate) - there is nothing to ask the operator. -->
    <TextBlock Text="The collected data file is encrypted automatically with the EUC Reports data-protection certificate (.cdenc)."
               FontSize="10" Foreground="#8a8f98" TextWrapping="Wrap" Margin="0,0,0,16"/>

    <!-- Error text -->
    <TextBlock x:Name="TxtError" Text="" Foreground="#D83B01" FontSize="11"
               Margin="0,0,0,10" Visibility="Collapsed" TextWrapping="Wrap"/>

    <!-- Action buttons -->
    <DockPanel>
      <Button x:Name="BtnSaveConfig" Content="Save Config" Padding="14,8"
              Style="{StaticResource GreyBtn}" DockPanel.Dock="Left"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="BtnCollect" Content="Collect Data" Padding="18,8"
                Style="{StaticResource BlueBtn}" Margin="0,0,8,0"/>
        <Button x:Name="BtnCancel" Content="Cancel" Padding="14,8"
                Style="{StaticResource GreyBtn}"/>
      </StackPanel>
    </DockPanel>

  </StackPanel>
</Window>
'@

    $txtCustomer      = $win.FindName('TxtCustomer')
    $lstAppliances    = $win.FindName('LstAppliances')
    $txtUsername      = $win.FindName('TxtUsername')
    $pwdPassword      = $win.FindName('PwdPassword')
    $txtOutput        = $win.FindName('TxtOutput')
    $txtError         = $win.FindName('TxtError')
    $btnAddAppliance  = $win.FindName('BtnAddAppliance')
    $btnLoadConfig    = $win.FindName('BtnLoadConfig')
    $btnRemove        = $win.FindName('BtnRemoveAppliance')
    $btnBrowse        = $win.FindName('BtnBrowse')
    $btnSaveConfig    = $win.FindName('BtnSaveConfig')
    $btnCollect       = $win.FindName('BtnCollect')
    $btnCancel        = $win.FindName('BtnCancel')

    $txtOutput.Text = $OutputPath

    $script:_applianceList = [System.Collections.Generic.List[hashtable]]::new()

    function Add-ApplianceRow {
        param([string]$Name, [string]$ApplianceHost)
        $row = [ordered]@{ Name = $Name; Host = $ApplianceHost }
        $script:_applianceList.Add($row)
        $grid = [System.Windows.Controls.Grid]::new()
        $col0 = [System.Windows.Controls.ColumnDefinition]::new(); $col0.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
        $col1 = [System.Windows.Controls.ColumnDefinition]::new(); $col1.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
        $col2 = [System.Windows.Controls.ColumnDefinition]::new(); $col2.Width = [System.Windows.GridLength]::new(26)
        $grid.ColumnDefinitions.Add($col0); $grid.ColumnDefinitions.Add($col1); $grid.ColumnDefinitions.Add($col2)
        $tb0 = [System.Windows.Controls.TextBlock]::new(); $tb0.Text = $Name; $tb0.Margin = [System.Windows.Thickness]::new(10,6,0,6); $tb0.VerticalAlignment = 'Center'
        $tb1 = [System.Windows.Controls.TextBlock]::new(); $tb1.Text = $ApplianceHost; $tb1.Margin = [System.Windows.Thickness]::new(10,6,0,6); $tb1.Foreground = [System.Windows.Media.Brushes]::Gray; $tb1.VerticalAlignment = 'Center'
        [System.Windows.Controls.Grid]::SetColumn($tb0, 0); [System.Windows.Controls.Grid]::SetColumn($tb1, 1)
        $grid.Children.Add($tb0) | Out-Null; $grid.Children.Add($tb1) | Out-Null
        $item = [System.Windows.Controls.ListBoxItem]::new(); $item.Content = $grid; $item.Tag = $row
        $lstAppliances.Items.Add($item) | Out-Null
    }

    $btnAddAppliance.Add_Click({
        $result = Show-AddApplianceDialog
        if ($result) { Add-ApplianceRow -Name $result.Name -ApplianceHost $result.Host }
    })

    $btnRemove.Add_Click({
        $sel = $lstAppliances.SelectedItem
        if ($sel) {
            $tag = $sel.Tag
            $script:_applianceList.Remove($tag) | Out-Null
            $lstAppliances.Items.Remove($sel)
        }
    })

    $btnLoadConfig.Add_Click({
        $ofd = [Microsoft.Win32.OpenFileDialog]::new()
        $ofd.Filter = 'Config files (*.config.json)|*.config.json|All files (*.*)|*.*'
        $ofd.InitialDirectory = $script:_configDir
        if ($ofd.ShowDialog()) {
            $cfg = Read-CollectConfig -Path $ofd.FileName
            if ($cfg) {
                if ($cfg.CustomerName) { $txtCustomer.Text = $cfg.CustomerName }
                if ($cfg.OutputPath)   { $txtOutput.Text   = $cfg.OutputPath }
                if ($cfg.Username)     { $txtUsername.Text  = $cfg.Username }
                $lstAppliances.Items.Clear()
                $script:_applianceList.Clear()
                foreach ($a in @($cfg.Appliances)) {
                    if ($a) { Add-ApplianceRow -Name $a.Name -ApplianceHost $a.Host }
                }
            }
        }
    })

    $btnBrowse.Add_Click({
        $fbd = [System.Windows.Forms.FolderBrowserDialog]::new()
        $fbd.SelectedPath = $txtOutput.Text
        if ($fbd.ShowDialog() -eq 'OK') { $txtOutput.Text = $fbd.SelectedPath }
    })

    $btnSaveConfig.Add_Click({
        $cfg = [ordered]@{
            CustomerName = $txtCustomer.Text.Trim()
            OutputPath   = $txtOutput.Text.Trim()
            Username     = $txtUsername.Text.Trim()
            Appliances   = @($script:_applianceList | ForEach-Object { [ordered]@{ Name = $_['Name']; Host = $_['Host'] } })
        }
        $saved = Save-CollectConfig -Config $cfg -CustomerName $cfg.CustomerName
        if ($saved) {
            Show-MsgBox "Config saved to:`n$saved"
        } else {
            Show-MsgBox 'Failed to save config.' -Icon 'Error'
        }
    })

    $btnCancel.Add_Click({ $win.DialogResult = $false; $win.Close() })

    $script:_dialogResult = $null
    $btnCollect.Add_Click({
        $txtError.Visibility = 'Collapsed'
        $errs = [System.Collections.Generic.List[string]]::new()
        if (-not $txtCustomer.Text.Trim())    { $errs.Add('Customer name is required.') }
        if ($script:_applianceList.Count -eq 0) { $errs.Add('Add at least one appliance.') }
        if (-not $txtUsername.Text.Trim())    { $errs.Add('Username is required.') }
        if (-not $pwdPassword.Password)       { $errs.Add('Password is required.') }
        if (-not $txtOutput.Text.Trim())      { $errs.Add('Output folder is required.') }
        if ($errs.Count -gt 0) {
            $txtError.Text = $errs -join '  '
            $txtError.Visibility = 'Visible'
            return
        }
        $secPwd = $pwdPassword.SecurePassword
        $script:_dialogResult = [ordered]@{
            CustomerName    = $txtCustomer.Text.Trim()
            Appliances      = @($script:_applianceList | ForEach-Object { [ordered]@{ Name = $_['Name']; Host = $_['Host'] } })
            Username        = $txtUsername.Text.Trim()
            Password        = $secPwd
            OutputPath      = $txtOutput.Text.Trim()
        }
        $win.DialogResult = $true
        $win.Close()
    })

    $null = $win.ShowDialog()
    return $script:_dialogResult
}

#endregion

#region -- Show dialog ---------------------------------------------------------

Set-CollectStatus 'Ready' -Progress 30

# Headless when host/username/password are all supplied - skips the WPF dialog entirely (scripted/
# CI collection), mirroring the report script's -DataFile headless bypass. Multi-appliance runs still
# need the dialog (Lab.config.json-style appliance list); this path is single-appliance only.
$script:_headless = [bool]($ApplianceHost -and $Username -and $Password)

if (-not $script:_headless) {
    # Hide splash while dialog is open so it doesn't sit on top (Topmost=True)
    $script:_splash.Dispatcher.Invoke([Action]{ $script:_splash.Hide() }, [System.Windows.Threading.DispatcherPriority]::Render)

    $dialogResult = Show-CollectorDialog
    if (-not $dialogResult) {
        $script:_splash.Close()
        exit 0
    }

    # Re-show splash for collection progress
    $script:_splash.Dispatcher.Invoke([Action]{ $script:_splash.Show() }, [System.Windows.Threading.DispatcherPriority]::Render)
    $script:_splash.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)

    $customerName  = $dialogResult['CustomerName']
    $applianceDefs = @($dialogResult['Appliances'])
    $username      = $dialogResult['Username']
    $password      = $dialogResult['Password']
    $outPath       = $dialogResult['OutputPath']
} else {
    # Splash stays open (already shown earlier) and keeps receiving Set-CollectStatus progress
    # updates exactly as in interactive mode - only the credential dialog itself is skipped. It's
    # closed at the very end of the script either way.
    $customerName  = $CustomerName
    $applianceDefs = @(@{ Name = $(if ($ApplianceName) { $ApplianceName } else { $ApplianceHost }); Host = $ApplianceHost })
    $username      = $Username
    $password      = $Password
    $outPath       = $OutputPath
}

if (-not (Test-Path $outPath)) {
    New-Item -ItemType Directory -Path $outPath -Force | Out-Null
}

#endregion

#region -- Data collection -----------------------------------------------------

$report = [ordered]@{
    GeneratedAt      = (Get-Date).ToString('o')
    CollectorVersion = $script:CollectorVersion
    CustomerName     = $customerName
    Appliances       = [System.Collections.Generic.List[object]]::new()
}

$totalAppliances = $applianceDefs.Count
$progressBase    = 35
$progressPerApp  = if ($totalAppliances -gt 0) { [int]((90 - $progressBase) / $totalAppliances) } else { 55 }

for ($ai = 0; $ai -lt $applianceDefs.Count; $ai++) {
    $appDef  = $applianceDefs[$ai]
    $appName = $appDef['Name']
    $appHost = $appDef['Host']
    $appBase = $progressBase + ($ai * $progressPerApp)

    Set-CollectStatus "Connecting to $appName..." -Progress $appBase -Sub $appHost

    $appData = [ordered]@{
        Name             = $appName
        Host             = $appHost
        FirmwareVersion  = ''
        Model            = ''
        SerialNumber     = ''
        SystemSettings   = [ordered]@{}
        HaNode           = $null
        Features         = [ordered]@{}
        Modes            = [ordered]@{}
        License          = [ordered]@{}
        Interfaces       = @()
        Vlans            = @()
        Routes           = @()
        GslbSites         = @()
        GslbServices      = @()
        GslbServiceGroups = @()
        GslbVservers      = @()
        NsIps            = @()
        NtpServers       = @()
        SnmpCommunities  = @()
        SyslogActions    = @()
        SystemStats      = [ordered]@{}
        LbVservers       = @()
        ServiceGroups    = @()
        Servers          = @()
        Monitors         = @()
        CsVservers       = @()
        CsPolicies       = @()
        CsActions        = @()
        SslCertKeys      = @()
        SslVservers      = @()
        SslProfiles      = @()
        SslServiceGroups = @()
        SslCipherGroups  = @()
        VpnVservers      = @()
        AuthVservers     = @()
        VpnSessionPolicies = @()
        VpnParameters    = $null
        AaaParameters    = $null
        AuthLdapActions  = @()
        AuthSamlActions  = @()
        AuthRadiusActions = @()
        AuthnProfiles    = @()
        AuthPolicies     = @()
        AuthPolicyLabels = @()
        NFactorChains    = [ordered]@{}
        AppFwProfiles    = @()
        AppFwPolicies    = @()
        ResponderPolicies = @()
        HttpProfiles     = @()
        TcpProfiles      = @()
        SystemUsers      = @()
        SystemParameters = $null
        SystemExternalAuthBindings = @()
        CollectionErrors = [ordered]@{}
    }

    $session = $null
    try {
        $session = Connect-Nitro -ApplianceHost $appHost -Username $username -Password $password
    } catch {
        $appData['CollectionErrors']['Login'] = $_.ToString()
        $report['Appliances'].Add($appData)
        Set-CollectStatus "Login failed for $appName" -Sub $_.ToString()
        continue
    }

    $baseUri = "https://$appHost"

    function Collect {
        param([string]$Resource, [string]$Label, [switch]$Stat, [string]$QueryArgs = '')
        Set-CollectStatus "[$appName] $Label..." -Sub $appHost
        try {
            return Invoke-NitroGet -Session $session -BaseUri $baseUri -Resource $Resource -Stat:$Stat -QueryArgs $QueryArgs
        } catch {
            $appData['CollectionErrors'][$Resource] = $_.ToString()
            return @()
        }
    }

    # -- System ---
    Set-CollectStatus "[$appName] System info..." -Progress ($appBase + 2) -Sub $appHost
    try {
        $ver = Invoke-NitroGetSingle -Session $session -BaseUri $baseUri -Resource 'nsversion'
        if ($ver -and $ver.PSObject.Properties.Name -contains 'version') {
            $appData['FirmwareVersion'] = $ver.version
        }
    } catch { $appData['CollectionErrors']['nsversion'] = $_.ToString() }

    try {
        $hw = Invoke-NitroGetSingle -Session $session -BaseUri $baseUri -Resource 'nshardware'
        if ($hw) {
            if ($hw.PSObject.Properties.Name -contains 'hwdescription') { $appData['Model']        = $hw.hwdescription }
            if ($hw.PSObject.Properties.Name -contains 'serialno')      { $appData['SerialNumber'] = $hw.serialno }
        }
    } catch { $appData['CollectionErrors']['nshardware'] = $_.ToString() }

    try {
        $ss = Invoke-NitroGetSingle -Session $session -BaseUri $baseUri -Resource 'nsconfig'
        if ($ss) { $appData['SystemSettings'] = $ss }
    } catch { $appData['CollectionErrors']['nsconfig'] = $_.ToString() }

    try {
        $feat = Invoke-NitroGetSingle -Session $session -BaseUri $baseUri -Resource 'nsfeature'
        if ($feat) { $appData['Features'] = $feat }
    } catch { $appData['CollectionErrors']['nsfeature'] = $_.ToString() }

    try {
        $modes = Invoke-NitroGetSingle -Session $session -BaseUri $baseUri -Resource 'nsmode'
        if ($modes) { $appData['Modes'] = $modes }
    } catch { $appData['CollectionErrors']['nsmode'] = $_.ToString() }

    $appData['NsIps']           = @(Collect 'nsip'          'IP addresses')
    $appData['NtpServers']      = @(Collect 'ntpserver'      'NTP servers')
    $appData['SnmpCommunities'] = @(Collect 'snmpcommunity'  'SNMP communities')
    $appData['SyslogActions']   = @(Collect 'syslogaction'   'Syslog actions')

    try {
        $stats = Invoke-NitroGet -Session $session -BaseUri $baseUri -Resource 'system' -Stat
        if ($stats -and $stats.Count -gt 0) { $appData['SystemStats'] = $stats[0] }
    } catch { $appData['CollectionErrors']['stat/system'] = $_.ToString() }

    try {
        $ha = Invoke-NitroGet -Session $session -BaseUri $baseUri -Resource 'hanode'
        if ($ha -and $ha.Count -gt 0) { $appData['HaNode'] = $ha[0] }
    } catch { $appData['CollectionErrors']['hanode'] = $_.ToString() }

    try {
        $lic = Invoke-NitroGetSingle -Session $session -BaseUri $baseUri -Resource 'nslicense'
        if ($lic) { $appData['License'] = $lic }
    } catch { $appData['CollectionErrors']['nslicense'] = $_.ToString() }

    # -- Network --
    $appData['Interfaces'] = @(Collect 'interface' 'Interfaces')
    $appData['Routes']     = @(Collect 'route'     'Static routes')
    $appData['Vlans']      = @(Collect 'vlan'       'VLANs')

    foreach ($vlan in $appData['Vlans']) {
        $vlanId = $vlan.id
        $bindings = [System.Collections.Generic.List[object]]::new()
        try {
            $ifBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'vlan_interface_binding' `
                -QueryArgs "args=id:$([uri]::EscapeDataString("$vlanId"))"
            foreach ($b in $ifBindings) { [void]$bindings.Add([pscustomobject]@{ Type = 'Interface'; Value = $b.ifnum }) }
        } catch {}
        try {
            $ipBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'vlan_nsip_binding' `
                -QueryArgs "args=id:$([uri]::EscapeDataString("$vlanId"))"
            foreach ($b in $ipBindings) { [void]$bindings.Add([pscustomobject]@{ Type = 'IPAddress'; Value = $b.ipaddress }) }
        } catch {}
        $vlan | Add-Member -NotePropertyName 'Bindings' -NotePropertyValue @($bindings) -Force
    }

    # -- Load Balancing ---
    Set-CollectStatus "[$appName] Load balancing..." -Progress ($appBase + 6) -Sub $appHost
    $appData['LbVservers']  = @(Collect 'lbvserver'   'LB vservers')
    $appData['ServiceGroups'] = @(Collect 'servicegroup' 'Service groups')
    $appData['Servers']     = @(Collect 'server'       'Servers')
    $appData['Monitors']    = @(Collect 'lbmonitor'    'Monitors')

    # Attach service group members to each service group
    foreach ($sg in $appData['ServiceGroups']) {
        $sgName = $sg.servicegroupname
        try {
            $members = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'servicegroup_servicegroupmember_binding' `
                -QueryArgs "args=servicegroupname:$([uri]::EscapeDataString($sgName))"
            $sg | Add-Member -NotePropertyName 'Members' -NotePropertyValue @($members) -Force
        } catch {
            $sg | Add-Member -NotePropertyName 'Members' -NotePropertyValue @() -Force
        }
    }

    # Attach service group bindings to each LB vserver
    foreach ($lb in $appData['LbVservers']) {
        $lbName = $lb.name
        try {
            $bindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'lbvserver_servicegroup_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($lbName))"
            $lb | Add-Member -NotePropertyName 'ServiceGroupBindings' -NotePropertyValue @($bindings) -Force
        } catch {
            $lb | Add-Member -NotePropertyName 'ServiceGroupBindings' -NotePropertyValue @() -Force
        }
        # WAF policy bindings on LB vserver
        try {
            $wafBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'lbvserver_appfwpolicy_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($lbName))"
            $lb | Add-Member -NotePropertyName 'AppFwPolicyBindings' -NotePropertyValue @($wafBindings) -Force
        } catch {
            $lb | Add-Member -NotePropertyName 'AppFwPolicyBindings' -NotePropertyValue @() -Force
        }
        # Responder policy bindings on LB vserver
        try {
            $responderBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'lbvserver_responderpolicy_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($lbName))"
            $lb | Add-Member -NotePropertyName 'ResponderPolicyBindings' -NotePropertyValue @($responderBindings) -Force
        } catch {
            $lb | Add-Member -NotePropertyName 'ResponderPolicyBindings' -NotePropertyValue @() -Force
        }
    }

    # -- GSLB ---
    Set-CollectStatus "[$appName] GSLB..." -Progress ($appBase + 8) -Sub $appHost
    $appData['GslbSites']         = @(Collect 'gslbsite'         'GSLB sites')
    $appData['GslbServices']      = @(Collect 'gslbservice'      'GSLB services')
    $appData['GslbServiceGroups'] = @(Collect 'gslbservicegroup' 'GSLB service groups')
    $appData['GslbVservers']      = @(Collect 'gslbvserver'      'GSLB vservers')

    # Attach members to each GSLB service group
    foreach ($gsg in $appData['GslbServiceGroups']) {
        $gsgName = $gsg.servicegroupname
        try {
            $members = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'gslbservicegroup_gslbservicegroupmember_binding' `
                -QueryArgs "args=servicegroupname:$([uri]::EscapeDataString($gsgName))"
            $gsg | Add-Member -NotePropertyName 'Members' -NotePropertyValue @($members) -Force
        } catch {
            $gsg | Add-Member -NotePropertyName 'Members' -NotePropertyValue @() -Force
        }
    }

    # Attach bound services and bound domains to each GSLB vserver
    foreach ($gvs in $appData['GslbVservers']) {
        $gvsName = $gvs.name
        try {
            $svcBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'gslbvserver_gslbservice_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($gvsName))"
            $gvs | Add-Member -NotePropertyName 'BoundServices' -NotePropertyValue @($svcBindings) -Force
        } catch {
            $gvs | Add-Member -NotePropertyName 'BoundServices' -NotePropertyValue @() -Force
        }
        try {
            $domBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'gslbvserver_domain_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($gvsName))"
            $gvs | Add-Member -NotePropertyName 'BoundDomains' -NotePropertyValue @($domBindings) -Force
        } catch {
            $gvs | Add-Member -NotePropertyName 'BoundDomains' -NotePropertyValue @() -Force
        }
    }

    # -- Content Switching ---
    Set-CollectStatus "[$appName] Content switching..." -Progress ($appBase + 10) -Sub $appHost
    $appData['CsVservers'] = @(Collect 'csvserver'  'CS vservers')
    $appData['CsPolicies'] = @(Collect 'cspolicy'   'CS policies')
    $appData['CsActions']  = @(Collect 'csaction'   'CS actions')

    foreach ($cs in $appData['CsVservers']) {
        $csName = $cs.name
        try {
            $bindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'csvserver_cspolicy_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($csName))"
            $cs | Add-Member -NotePropertyName 'PolicyBindings' -NotePropertyValue @($bindings) -Force
        } catch {
            $cs | Add-Member -NotePropertyName 'PolicyBindings' -NotePropertyValue @() -Force
        }
        try {
            $wafBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'csvserver_appfwpolicy_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($csName))"
            $cs | Add-Member -NotePropertyName 'AppFwPolicyBindings' -NotePropertyValue @($wafBindings) -Force
        } catch {
            $cs | Add-Member -NotePropertyName 'AppFwPolicyBindings' -NotePropertyValue @() -Force
        }
        try {
            $responderBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'csvserver_responderpolicy_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($csName))"
            $cs | Add-Member -NotePropertyName 'ResponderPolicyBindings' -NotePropertyValue @($responderBindings) -Force
        } catch {
            $cs | Add-Member -NotePropertyName 'ResponderPolicyBindings' -NotePropertyValue @() -Force
        }
    }

    # -- SSL ---
    Set-CollectStatus "[$appName] SSL certificates..." -Progress ($appBase + 14) -Sub $appHost
    $appData['SslCertKeys'] = @(Collect 'sslcertkey'  'SSL certificates')
    # NITRO's bulk (unscoped) sslvserver GET returns only a reduced summary field set;
    # the SSL protocol/HSTS/OCSP attributes are omitted unless explicitly requested.
    $sslVserverAttrs = 'vservername,cleartextport,service,quicflag,sslprofile,' +
        'ssl2,ssl3,tls1,tls11,tls12,tls13,hsts,ocspstapling,denySSLReneg'
    $appData['SslVservers'] = @(Collect 'sslvserver'  'SSL vservers' -QueryArgs "attrs=$sslVserverAttrs")
    $appData['SslProfiles'] = @(Collect 'sslprofile'  'SSL profiles')

    # Attach cert and cipher suite bindings to each SSL vserver.
    # NITRO's *_binding resources require the parent key in the query — an unscoped
    # bulk GET returns an empty (but "successful") result set, not an error, so this
    # must be queried per-vserver rather than fetched once for all vservers.
    foreach ($sv in $appData['SslVservers']) {
        $vn = $sv.vservername
        try {
            $certBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'sslvserver_sslcertkey_binding' `
                -QueryArgs "args=vservername:$([uri]::EscapeDataString($vn))"
            $sv | Add-Member -NotePropertyName 'CertKeyBindings' -NotePropertyValue @($certBindings) -Force
        } catch {
            $sv | Add-Member -NotePropertyName 'CertKeyBindings' -NotePropertyValue @() -Force
        }
        try {
            # 'sslvserver_sslciphersuite_binding' is a valid resource name but never returns bound
            # ciphers (confirmed live) — the real per-vserver cipher/cipher-group binding lives
            # under 'sslvserver_sslcipher_binding', field 'cipheraliasname'.
            $cipherBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'sslvserver_sslcipher_binding' `
                -QueryArgs "args=vservername:$([uri]::EscapeDataString($vn))"
            $sv | Add-Member -NotePropertyName 'CipherBindings' -NotePropertyValue @($cipherBindings | ForEach-Object { Get-NitroProp $_ 'cipheraliasname' }) -Force
        } catch {
            $sv | Add-Member -NotePropertyName 'CipherBindings' -NotePropertyValue @() -Force
        }
    }

    # Attach cipher suite bindings to each SSL profile (same per-parent constraint as above)
    foreach ($sp in $appData['SslProfiles']) {
        $pn = $sp.name
        try {
            # Same mismatch as the vserver binding above — 'sslprofile_sslciphersuite_binding'
            # always returns empty; 'sslprofile_sslcipher_binding' (field 'cipheraliasname') is
            # the resource that actually reflects a profile's bound cipher/cipher group.
            $profCipherBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'sslprofile_sslcipher_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($pn))"
            $sp | Add-Member -NotePropertyName 'CipherBindings' -NotePropertyValue @($profCipherBindings | ForEach-Object { Get-NitroProp $_ 'cipheraliasname' }) -Force
        } catch {
            $sp | Add-Member -NotePropertyName 'CipherBindings' -NotePropertyValue @() -Force
        }
    }

    # Backend (service group) SSL/TLS parameters — NetScaler-to-server communication. Collected here,
    # before the cipher-groups block below, because that block needs SslServiceGroups' sslprofile
    # field already populated to know which profiles are actually in use (a profile referenced only by
    # a service group, never a vserver, still counts as used) - it used to run after, which meant
    # every service-group-only profile binding looked orphaned and its cipher group got dropped.
    $appData['SslServiceGroups'] = @(Collect 'sslservicegroup' 'Backend SSL service groups')

    # Cipher groups — an unscoped GET also returns NetScaler's built-in groups (ALL, DEFAULT,
    # HIGH, ...) and every user-defined group, whether or not it's actually in use. Only report a
    # group that's actually bound to a vserver/service-group, OR bound to a profile that is itself
    # attached to at least one vserver/service-group - confirmed live that several built-in profiles
    # (ns_default_ssl_profile_quic_frontend/backend, ns_default_ssl_profile_secure_frontend[_cloud])
    # have a cipher group bound in firmware defaults despite nothing on the appliance ever using the
    # profile itself; a group only reachable through one of those is just as dead as an unbound one.
    $allCipherGroups  = @(Collect 'sslcipher' 'SSL cipher groups')
    $usedProfileNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($sv in $appData['SslVservers'])      { if ($sv.sslprofile) { [void]$usedProfileNames.Add($sv.sslprofile) } }
    foreach ($sg in $appData['SslServiceGroups']) { if ($sg.sslprofile) { [void]$usedProfileNames.Add($sg.sslprofile) } }
    $boundCipherNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($sv in $appData['SslVservers']) {
        # Snapshot of what was literally bound, before the recommended-cipher expansion below
        # overwrites CipherBindings - the "Bound Vservers" column needs the real group name (an exact
        # match), not a "do all of this group's members appear in the expanded list" guess, which
        # gives false positives whenever one group's members happen to be a subset of another's (e.g.
        # a 3-cipher TLS 1.3-only group vs. a 6-cipher group that includes those same 3 TLS 1.3 suites).
        $sv | Add-Member -NotePropertyName 'BoundCipherNames' -NotePropertyValue @($sv.CipherBindings) -Force
        foreach ($c in @($sv.CipherBindings)) { [void]$boundCipherNames.Add($c) }
    }
    foreach ($sp in $appData['SslProfiles']) {
        $sp | Add-Member -NotePropertyName 'BoundCipherNames' -NotePropertyValue @($sp.CipherBindings) -Force
        if ($usedProfileNames.Contains($sp.name)) {
            foreach ($c in @($sp.CipherBindings)) { [void]$boundCipherNames.Add($c) }
        }
    }
    $appData['SslCipherGroups'] = @($allCipherGroups | Where-Object {
        $boundCipherNames.Contains((Get-NitroProp $_ 'ciphergroupname'))
    })
    foreach ($cg in $appData['SslCipherGroups']) {
        $cgName = Get-NitroProp $cg 'ciphergroupname'
        try {
            # Both the bare 'sslcipher' resource (scoped by name or by args=) return only the
            # group's single highest-priority member (confirmed live) — the full member list
            # lives nested under 'sslcipher_binding's 'sslcipher_sslciphersuite_binding' array.
            $bindingWrapper = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'sslcipher_binding' `
                -QueryArgs "args=ciphergroupname:$([uri]::EscapeDataString($cgName))"
            $members = if (@($bindingWrapper).Count -gt 0) { @(Get-NitroProp $bindingWrapper[0] 'sslcipher_sslciphersuite_binding') } else { @() }
            $cg | Add-Member -NotePropertyName 'MemberCiphers' -NotePropertyValue @($members | ForEach-Object { Get-NitroProp $_ 'ciphername' }) -Force
        } catch {
            $cg | Add-Member -NotePropertyName 'MemberCiphers' -NotePropertyValue @() -Force
        }
    }

    # A vserver/profile that binds a named cipher GROUP (rather than individual suites) gets that
    # binding back from NITRO as one entry whose 'cipheraliasname' is the group's own name, not its
    # member suites - so a health check comparing CipherBindings against a suite-name allow-list would
    # flag the group's name itself as "not recommended" even when its members are exactly right.
    # ConvertFrom-NsConfig already expands group bindings into their member suites when parsing a
    # static ns.conf export (see its 'bind ssl vserver/profile' cases); mirror that here so both paths
    # converge on the same CipherBindings semantics - always real suite names, never a group alias.
    # Scoped to user-defined groups only (not the broader SslCipherGroups display list above) -
    # expanding a built-in group's dozens of members into the SSL-013/014 recommended-cipher
    # comparison would just be noise for every environment still on its default profile ciphers.
    $cipherGroupMembers = [System.Collections.Generic.Dictionary[string,string[]]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($cg in $appData['SslCipherGroups'] | Where-Object { (Get-NitroProp $_ 'description') -eq 'User Defined Cipher Group' }) {
        $cipherGroupMembers[(Get-NitroProp $cg 'ciphergroupname')] = @($cg.MemberCiphers)
    }
    if ($cipherGroupMembers.Count -gt 0) {
        foreach ($holder in (@($appData['SslVservers']) + @($appData['SslProfiles']))) {
            $expanded = [System.Collections.Generic.List[string]]::new()
            foreach ($c in @($holder.CipherBindings)) {
                if ($cipherGroupMembers.ContainsKey($c)) { foreach ($m in $cipherGroupMembers[$c]) { [void]$expanded.Add($m) } }
                else { [void]$expanded.Add($c) }
            }
            $holder.CipherBindings = @($expanded)
        }
    }

    # -- Citrix Gateway ---
    Set-CollectStatus "[$appName] Citrix Gateway..." -Progress ($appBase + 18) -Sub $appHost
    $appData['VpnVservers']       = @(Collect 'vpnvserver'               'VPN vservers')
    $appData['AuthVservers']      = @(Collect 'authenticationvserver'    'Authentication (AAA) vservers')
    $appData['VpnSessionPolicies'] = @(Collect 'vpnsessionpolicy'         'VPN session policies')
    $appData['AuthLdapActions']   = @(Collect 'authenticationldapaction'  'LDAP actions')
    $appData['AuthSamlActions']   = @(Collect 'authenticationsamlaction'  'SAML actions')
    $appData['AuthRadiusActions'] = @(Collect 'authenticationradiusaction' 'RADIUS actions')

    try {
        $vpnParam = Invoke-NitroGetSingle -Session $session -BaseUri $baseUri -Resource 'vpnparameter'
        if ($vpnParam) { $appData['VpnParameters'] = $vpnParam }
    } catch { $appData['CollectionErrors']['vpnparameter'] = $_.ToString() }

    try {
        $aaaParam = Invoke-NitroGetSingle -Session $session -BaseUri $baseUri -Resource 'aaaparameter'
        if ($aaaParam) { $appData['AaaParameters'] = $aaaParam }
    } catch { $appData['CollectionErrors']['aaaparameter'] = $_.ToString() }

    foreach ($vpn in $appData['VpnVservers']) {
        $vpnName = $vpn.name
        try {
            $ldapBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'vpnvserver_authenticationldappolicy_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($vpnName))"
            $vpn | Add-Member -NotePropertyName 'LdapPolicyBindings' -NotePropertyValue @($ldapBindings) -Force
        } catch {
            $vpn | Add-Member -NotePropertyName 'LdapPolicyBindings' -NotePropertyValue @() -Force
        }
        try {
            $samlBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'vpnvserver_authenticationsamlpolicy_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($vpnName))"
            $vpn | Add-Member -NotePropertyName 'SamlPolicyBindings' -NotePropertyValue @($samlBindings) -Force
        } catch {
            $vpn | Add-Member -NotePropertyName 'SamlPolicyBindings' -NotePropertyValue @() -Force
        }
        try {
            $radiusBindings = Invoke-NitroGet -Session $session -BaseUri $baseUri `
                -Resource 'vpnvserver_authenticationradiuspolicy_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($vpnName))"
            $vpn | Add-Member -NotePropertyName 'RadiusPolicyBindings' -NotePropertyValue @($radiusBindings) -Force
        } catch {
            $vpn | Add-Member -NotePropertyName 'RadiusPolicyBindings' -NotePropertyValue @() -Force
        }
    }

    # -- nFactor authentication policy chains ---
    # An authnProfile on a gateway vserver points to an AAA (authentication) vserver, whose
    # entry-level policy binding can chain into further "next factor" policy labels, each
    # binding more policies (which may themselves chain further). Walk that graph so the
    # report can show the real auth methods (LDAP/RADIUS/cert/etc.) used at each factor,
    # not just the opaque authnProfile name.
    $appData['AuthnProfiles']     = @(Collect 'authenticationauthnprofile' 'Authentication profiles (nFactor)')
    $appData['AuthPolicies']      = @(Collect 'authenticationpolicy'       'Authentication policies (nFactor)')
    $appData['AuthPolicyLabels']  = @(Collect 'authenticationpolicylabel'  'Authentication policy labels (nFactor)')

    $authnProfileLookup = @{}
    foreach ($ap in $appData['AuthnProfiles']) {
        $apName = Get-NitroProp $ap 'name'
        if ($apName) { $authnProfileLookup[$apName] = Get-NitroProp $ap 'authnvsname' }
    }
    $authPolicyLookup = @{}
    foreach ($pol in $appData['AuthPolicies']) {
        $polName = Get-NitroProp $pol 'name'
        if ($polName) { $authPolicyLookup[$polName] = $pol }
    }
    $authPolicyLabelLookup = @{}
    foreach ($lbl in $appData['AuthPolicyLabels']) {
        $lblName = Get-NitroProp $lbl 'labelname'
        if ($lblName) { $authPolicyLabelLookup[$lblName] = Get-NitroProp $lbl 'loginschema' }
    }

    function Get-NFactorSteps {
        param(
            [string]$Resource,
            [string]$QueryArgs,
            [string]$PolicyField,
            [System.Collections.Generic.HashSet[string]]$AncestorPath,
            [int]$Depth = 0
        )
        $steps = [System.Collections.Generic.List[object]]::new()
        if ($Depth -gt 25) { return @($steps) }
        try {
            $bindings = Invoke-NitroGet -Session $session -BaseUri $baseUri -Resource $Resource -QueryArgs $QueryArgs
            foreach ($b in $bindings) {
                $polName   = Get-NitroProp $b $PolicyField
                $nextLabel = Get-NitroProp $b 'nextfactor'
                $polDetail = if ($polName -and $authPolicyLookup.ContainsKey($polName)) { $authPolicyLookup[$polName] } else { $null }
                $children  = @()
                if ($nextLabel -and $AncestorPath.Add("LBL:$nextLabel")) {
                    $children = @(Get-NFactorSteps -Resource 'authenticationpolicylabel_authenticationpolicy_binding' `
                        -QueryArgs "args=labelname:$([uri]::EscapeDataString($nextLabel))" -PolicyField 'policyname' `
                        -AncestorPath $AncestorPath -Depth ($Depth + 1))
                    [void]$AncestorPath.Remove("LBL:$nextLabel")
                }
                $steps.Add([ordered]@{
                    Policy           = $polName
                    Priority         = Get-NitroProp $b 'priority'
                    PolicyType       = if ($polDetail) { Get-NitroProp $polDetail 'policysubtype' } else { '' }
                    Action           = if ($polDetail) { Get-NitroProp $polDetail 'action' } else { '' }
                    Expression       = if ($polDetail) { Get-NitroProp $polDetail 'rule' } else { '' }
                    NextFactor       = if ($nextLabel) { $nextLabel } else { '' }
                    NextFactorSchema = if ($nextLabel -and $authPolicyLabelLookup.ContainsKey($nextLabel)) { $authPolicyLabelLookup[$nextLabel] } else { '' }
                    Steps            = $children
                })
            }
        } catch { }
        return @($steps)
    }

    $appData['NFactorChains'] = [ordered]@{}
    foreach ($vpn in $appData['VpnVservers']) {
        $apName = Get-NitroProp $vpn 'authnprofile'
        if ($apName -and -not $appData['NFactorChains'].Contains($apName)) {
            $vsName = if ($authnProfileLookup.ContainsKey($apName)) { $authnProfileLookup[$apName] } else { $apName }
            $ancestorPath = [System.Collections.Generic.HashSet[string]]::new()
            [void]$ancestorPath.Add("VS:$vsName")
            $appData['NFactorChains'][$apName] = @(Get-NFactorSteps -Resource 'authenticationvserver_authenticationpolicy_binding' `
                -QueryArgs "args=name:$([uri]::EscapeDataString($vsName))" -PolicyField 'policy' `
                -AncestorPath $ancestorPath -Depth 0)
        }
    }

    # -- WAF ---
    Set-CollectStatus "[$appName] Web Application Firewall..." -Progress ($appBase + 22) -Sub $appHost
    $appData['AppFwProfiles'] = @(Collect 'appfwprofile' 'WAF profiles')
    $appData['AppFwPolicies'] = @(Collect 'appfwpolicy'  'WAF policies')

    # -- Responder / AppExpert ---
    Set-CollectStatus "[$appName] Responder policies..." -Progress ($appBase + 24) -Sub $appHost
    $appData['ResponderPolicies'] = @(Collect 'responderpolicy' 'Responder policies')

    # -- HTTP / TCP profiles ---
    Set-CollectStatus "[$appName] HTTP/TCP profiles..." -Progress ($appBase + 25) -Sub $appHost
    $appData['HttpProfiles'] = @(Collect 'nshttpprofile' 'HTTP profiles')
    $appData['TcpProfiles']  = @(Collect 'nstcpprofile'  'TCP profiles')

    # -- System accounts / external authentication ---
    Set-CollectStatus "[$appName] System accounts..." -Progress ($appBase + 26) -Sub $appHost
    $appData['SystemUsers'] = @(Collect 'systemuser' 'System accounts')
    try {
        $sysParam = Invoke-NitroGetSingle -Session $session -BaseUri $baseUri -Resource 'systemparameter'
        if ($sysParam) { $appData['SystemParameters'] = $sysParam }
    } catch { $appData['CollectionErrors']['systemparameter'] = $_.ToString() }

    $externalAuthBindings = [System.Collections.Generic.List[object]]::new()
    foreach ($sysAuthResource in @('systemglobal_authenticationldappolicy_binding', 'systemglobal_authenticationradiuspolicy_binding', 'systemglobal_authenticationtacacspolicy_binding')) {
        try {
            $b = Invoke-NitroGet -Session $session -BaseUri $baseUri -Resource $sysAuthResource
            foreach ($item in $b) { $externalAuthBindings.Add($item) }
        } catch { $appData['CollectionErrors'][$sysAuthResource] = $_.ToString() }
    }
    $appData['SystemExternalAuthBindings'] = @($externalAuthBindings)

    Disconnect-Nitro -Session $session -ApplianceHost $appHost
    $report['Appliances'].Add($appData)
    Set-CollectStatus "Collected $appName" -Progress ($appBase + $progressPerApp) -Sub ''
}

#endregion

#region -- Save JSON -----------------------------------------------------------

Set-CollectStatus 'Saving data...' -Progress 92

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$safeName  = if ($customerName) { ($customerName -replace '[^A-Za-z0-9\-_]', '_').Trim('_') } else { 'NetScaler' }
# Protected output is .cdenc, -NoProtect is .json - so only the stem is known here. The full path is
# built AFTER Protect-CollectorOutput reports the extension: it used to be built up front and only
# $fileName was corrected afterwards, so the write still went to the stale .json path and every
# encrypted file shipped with a .json extension.
$fileStem = "$safeName-NetScaler-Data-$timestamp"

$payload  = $report | ConvertTo-Json -Depth 20
$prot     = Protect-CollectorOutput $payload
$payload  = $prot.Json
$fileName = "$fileStem.$($prot.Ext)"
$filePath = Join-Path $outPath $fileName
$payload | Set-Content -Path $filePath -Encoding UTF8

Set-CollectStatus 'Complete' -Progress 100 -Sub $filePath
Start-Sleep -Milliseconds 800

$script:_splash.Dispatcher.Invoke([Action]{ $script:_splash.Close() }, [System.Windows.Threading.DispatcherPriority]::Normal)

Show-MsgBox "Data collection complete.`n`nSaved to:`n$filePath"

#endregion

#Requires -Version 5.1
# Version: 2026-07-10   (keep in lock-step with $script:_version below and the published .version file)
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
    [System.Security.SecureString]$EncryptPassword,
    [switch]$NoSplash,
    [switch]$SkipUpdateCheck
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

$script:_version = '2026-07-10'
# Self-update source (public euc-reports-collectors repo): the launch check reads a TINY .version file
# and downloads the full script only when a newer version exists AND the user accepts. Keep the
# '# Version:' header, this $script:_version, and the published .version file in lock-step per release.
$script:_updateVersionUrl = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/Get-VsphereData.version'
$script:_updateScriptUrl  = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/Get-VsphereData.ps1'

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
    try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}
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
    if ($SkipUpdateCheck -or $script:_noSplash -or -not $script:_updateVersionUrl) { return }
    $self = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    if (-not $self) { return }
    try {
        $vresp = Invoke-WebRequest -Uri $script:_updateVersionUrl -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        $remoteVer = (("$($vresp.Content)" -split "`r?`n") | Where-Object { "$_".Trim() } | Select-Object -First 1); $remoteVer = "$remoteVer".Trim()
        $rv = ConvertTo-CollectorVersion $remoteVer; $lv = ConvertTo-CollectorVersion $script:_version
        if (-not $rv) { Write-Log "Update check: unrecognised remote version '$remoteVer'" 'WARN'; return }
        if (-not $lv -or $rv -le $lv) { Write-Log "Update check: up to date (local $($script:_version), remote $remoteVer)"; return }
        if (-not (Show-UpdatePrompt $script:_version $remoteVer)) { return }
        $resp = Invoke-WebRequest -Uri $script:_updateScriptUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $content = "$($resp.Content)"
        if ($content.Length -lt 20000 -or $content -notmatch 'Get-VsphereData' -or $content -notmatch "\`$script:_version\s*=\s*'([^']+)'") {
            Show-MsgBox 'Could not download a valid update; keeping the current version.' -Icon Warning; Write-Log 'Update: download not recognised' 'WARN'; return
        }
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("VsphereCollector-$([guid]::NewGuid().ToString('N')).ps1")
        Set-Content -Path $tmp -Value $content -Encoding UTF8
        $tk = $null; $perr = $null; [System.Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$tk, [ref]$perr) | Out-Null; Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        if ($perr -and $perr.Count) { Show-MsgBox 'The downloaded update did not validate (parse errors). Keeping the current version.' -Icon Warning; return }
        try { Copy-Item -LiteralPath $self -Destination "$self.bak" -Force -ErrorAction SilentlyContinue; Set-Content -Path $self -Value $content -Encoding UTF8 }
        catch { $alt = Join-Path (Split-Path $self -Parent) 'Get-VsphereData.NEW.ps1'; try { Set-Content -Path $alt -Value $content -Encoding UTF8 } catch {}; Show-MsgBox "Couldn't replace the running script (permissions?). Saved as:`n$alt" -Icon Warning; return }
        Show-MsgBox "Updated to version $remoteVer.`n`nThe collector will now relaunch." -Icon Info
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
        $r = Invoke-WebRequest -Uri $script:_sdk -Method Post -Body $body -ContentType 'text/xml; charset=utf-8' -Headers @{ SOAPAction = 'urn:vim25' } -WebSession $script:_ws -TimeoutSec 90 @script:_iwrExtra
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
    $r = Invoke-WebRequest -Uri $script:_sdk -Method Post -Body $rsc -ContentType 'text/xml; charset=utf-8' -Headers @{ SOAPAction = 'urn:vim25' } -SessionVariable ws -TimeoutSec 30 @script:_iwrExtra
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
#endregion

#region -- Collection ---------------------------------------------------------
$script:_hostPaths = @('name','parent','summary.hardware.numCpuCores','summary.hardware.numCpuThreads','summary.hardware.cpuMhz','summary.hardware.numCpuPkgs','summary.hardware.memorySize','summary.hardware.vendor','summary.hardware.model','summary.quickStats.overallCpuUsage','summary.quickStats.overallMemoryUsage','summary.quickStats.uptime','runtime.connectionState','runtime.powerState','vm')
$script:_vmPaths   = @('name','runtime.host','runtime.powerState','config.hardware.numCPU','config.hardware.memoryMB','summary.quickStats.overallCpuUsage','summary.quickStats.hostMemoryUsage','summary.quickStats.guestMemoryUsage','config.guestFullName')

function Get-MoRefName ([string]$Type, [string]$MoRef) {
    if (-not $MoRef) { return '' }
    $o = @(Get-ObjectsByMoRef $Type @($MoRef) @('name')) | Select-Object -First 1
    if ($o) { return (Get-Prop $o 'name') } ; ''
}

function Collect-VsphereData {
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

    # CPU Ready for powered-on VMs (one QueryPerf across all)
    Set-SplashStatus 'Querying CPU Ready (performance counters)...'
    $counterId = Get-CpuReadyCounterId
    $onVmMo = @($vmObjs | Where-Object { (Get-Prop $_ 'runtime.powerState') -eq 'poweredOn' } | ForEach-Object { "$($_.obj.'#text')" })
    $readyMs = Get-CpuReadyMs $onVmMo $counterId $ReadySamples

    # collect VM metadata; associate to hosts by Where-Object (avoids a PS quirk indexing List-valued hashtables)
    $vmMeta = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($vmObjs)) {
        $mo = "$($v.obj.'#text')"
        $numCpu = [int](Get-Prop $v 'config.hardware.numCPU')
        $on = (Get-Prop $v 'runtime.powerState') -eq 'poweredOn'
        $rMs = if ($readyMs.ContainsKey($mo)) { [double]$readyMs[$mo] } else { $null }
        $readyPct = if ($null -ne $rMs) { [math]::Round($rMs / 20000 * 100, 2) } else { $null }              # total across vCPUs
        $readyPerV = if ($null -ne $rMs -and $numCpu -gt 0) { [math]::Round($rMs / 20000 * 100 / $numCpu, 2) } else { $null }
        $rec = [ordered]@{
            Name         = "$(Get-Prop $v 'name')"
            PowerState   = "$(Get-Prop $v 'runtime.powerState')"
            NumCpu       = $numCpu
            MemoryMB     = [int](Get-Prop $v 'config.hardware.memoryMB')
            CpuUsageMhz  = [int](Get-Prop $v 'summary.quickStats.overallCpuUsage')
            MemActiveMB  = [int](Get-Prop $v 'summary.quickStats.guestMemoryUsage')
            MemConsumedMB= [int](Get-Prop $v 'summary.quickStats.hostMemoryUsage')
            CpuReadyPct  = $readyPct
            CpuReadyPerVcpuPct = $readyPerV
            GuestOs      = "$(Get-Prop $v 'config.guestFullName')"
        }
        $vmMeta.Add([pscustomobject]@{ Mo = $mo; HostMo = "$(Get-Prop $v 'runtime.host')"; On = $on; NumCpu = $numCpu; Record = $rec })
    }

    # build host records
    $hostList = New-Object System.Collections.Generic.List[object]
    foreach ($h in @($hostObjs)) {
        $hMo = "$($h.obj.'#text')"
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
        $hostList.Add([ordered]@{
            Name            = "$(Get-Prop $h 'name')"
            Cluster         = $clusterName
            ConnectionState = "$(Get-Prop $h 'runtime.connectionState')"
            PowerState      = "$(Get-Prop $h 'runtime.powerState')"
            Vendor          = "$(Get-Prop $h 'summary.hardware.vendor')"
            Model           = "$(Get-Prop $h 'summary.hardware.model')"
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
        })
    }

    $hostArr = $hostList.ToArray()   # never wrap a List[object] in @() - throws "Argument types do not match" on this PS
    $totCores = (@($hostArr) | ForEach-Object { [int]$_.Cores } | Measure-Object -Sum).Sum
    $totVcpu  = (@($hostArr) | ForEach-Object { [int]$_.VcpuAllocated } | Measure-Object -Sum).Sum
    $totVms   = (@($hostArr) | ForEach-Object { [int]$_.VmCount } | Measure-Object -Sum).Sum
    $totOn    = (@($hostArr) | ForEach-Object { [int]$_.PoweredOnVmCount } | Measure-Object -Sum).Sum
    $avgCpu   = if (@($hostArr).Count) { [math]::Round((@($hostArr) | ForEach-Object { [double]$_.CpuUsagePct } | Measure-Object -Average).Average, 1) } else { 0 }
    $avgMem   = if (@($hostArr).Count) { [math]::Round((@($hostArr) | ForEach-Object { [double]$_.MemoryUsagePct } | Measure-Object -Average).Average, 1) } else { 0 }

    [ordered]@{
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
        Summary        = [ordered]@{
            HostCount = @($hostArr).Count; VmCount = [int]$totVms; PoweredOnVmCount = [int]$totOn
            TotalCores = [int]$totCores; TotalVcpuAllocated = [int]$totVcpu
            ClusterOvercommit = if ($totCores) { [math]::Round($totVcpu / $totCores, 2) } else { 0 }
            AvgCpuUsagePct = $avgCpu; AvgMemUsagePct = $avgMem
        }
        Hosts          = @($hostArr)
    }
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
  <Border CornerRadius="6" Background="White" BorderBrush="#DDE1E7" BorderThickness="1"><StackPanel Margin="26,22">
    <TextBlock Text="vSphere Data Collector" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
    <TextBlock Text="Host + VM utilisation, CPU Ready and overcommit from a vCenter (VCSA)" FontSize="12" Foreground="#555" Margin="0,2,0,16"/>
    <TextBlock Text="vCenter (VCSA) address" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
    <TextBox x:Name="VcBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,12"/>
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
    <Grid><TextBlock x:Name="VersionText" Text="" FontSize="10" Foreground="#8a8f98" VerticalAlignment="Center" HorizontalAlignment="Left"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button x:Name="CancelBtn" Content="Cancel" Width="80" Padding="0,7" Style="{StaticResource GreyBtn}" Margin="0,0,8,0"/><Button x:Name="OkBtn" Content="Collect" Width="100" Padding="0,7" Style="{StaticResource BlueBtn}"/></StackPanel></Grid>
  </StackPanel></Border>
</Window>
'@
    $win = New-ThemedWindow $xaml
    $win.FindName('VersionText').Text = "v$($script:_version)"
    $vcBox = $win.FindName('VcBox'); $userBox = $win.FindName('UserBox'); $pwBox = $win.FindName('PwBox')
    $rbCluster = $win.FindName('RbCluster'); $scopeBox = $win.FindName('ScopeBox'); $custBox = $win.FindName('CustBox'); $encBox = $win.FindName('EncBox')
    if ($VCenter) { $vcBox.Text = $VCenter }; if ($Username) { $userBox.Text = $Username }; if ($Cluster) { $scopeBox.Text = $Cluster }; if ($VMHost) { $win.FindName('RbHost').IsChecked = $true; $scopeBox.Text = $VMHost }
    $result = @{ Action = 'Cancel' }
    $win.FindName('OkBtn').Add_Click({
        if (-not $vcBox.Text.Trim() -or -not $userBox.Text.Trim() -or -not $scopeBox.Text.Trim() -or -not $pwBox.Password) { [System.Windows.MessageBox]::Show('Enter the vCenter, username, password and scope.', 'vSphere', 'OK', 'Warning') | Out-Null; return }
        $result.Action = 'OK'; $result.VCenter = $vcBox.Text.Trim(); $result.Username = $userBox.Text.Trim()
        $result.Password = ConvertTo-SecureString $pwBox.Password -AsPlainText -Force
        $result.ScopeType = if ($rbCluster.IsChecked) { 'Cluster' } else { 'Host' }; $result.Scope = $scopeBox.Text.Trim(); $result.Customer = $custBox.Text.Trim()
        $result.Encrypt = if ($encBox.Password) { ConvertTo-SecureString $encBox.Password -AsPlainText -Force } else { $null }
        $win.Close()
    })
    $win.FindName('CancelBtn').Add_Click({ $win.Close() })
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
}
if (-not $VCenter -or -not $Username -or -not $Password -or (-not $Cluster -and -not $VMHost)) { throw 'Missing -VCenter / -Username / -Password / scope (-Cluster or -VMHost).' }

Show-Splash
$data = $null
try {
    Set-SplashStatus "Connecting to $VCenter..."
    $pwPlain = ConvertFrom-SecureStringPlain $Password
    $null = Connect-Vsphere $VCenter $Username $pwPlain
    $pwPlain = $null
    Write-Log "Connected to $VCenter as $Username"
    $data = Collect-VsphereData
} catch {
    Close-Splash
    Write-Log "Collection failed: $($_.Exception.Message)" 'ERROR'
    Write-Log "Stack: $($_.ScriptStackTrace -replace '\s+',' ')" 'ERROR'
    Show-MsgBox "vSphere collection failed:`n`n$($_.Exception.Message)" -Icon Error
    Disconnect-Vsphere
    exit 1
}
Disconnect-Vsphere

# Write output
$encrypt = ($EncryptPassword -and $EncryptPassword.Length -gt 0)
$json = $data | ConvertTo-Json -Depth 12
$safeCustomer = if ($Customer) { ($Customer -replace '[^\w\-. ]', '_').Trim() } else { '' }
$outDir = if ($safeCustomer) { Join-Path $script:_outputDir $safeCustomer } else { $script:_outputDir }
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$base = if ($safeCustomer) { "$safeCustomer-Vsphere-Data-$stamp" } else { "Vsphere-Data-$stamp" }
$ext = if ($encrypt) { '.cdenc' } else { '.json' }
$outFile = Join-Path $outDir "$base$ext"
try {
    if ($encrypt) { Set-Content -Path $outFile -Value (Protect-ReportData $json $EncryptPassword) -Encoding UTF8 }
    else { Set-Content -Path $outFile -Value $json -Encoding UTF8 }
    Write-Log "Output written: $outFile ($([math]::Round((Get-Item $outFile).Length/1KB,1)) KB)$(if ($encrypt) { ' [encrypted]' })"
} catch { Write-Log "Failed to write output: $_" 'ERROR'; Show-MsgBox "Failed to write output:`n$($_.Exception.Message)" -Icon Error; exit 1 }

Close-Splash
$hc = @($data.Hosts).Count; $vc = [int]$data.Summary.VmCount; $oc = $data.Summary.ClusterOvercommit
Show-MsgBox "vSphere collection complete.`n`nScope: $($data.Scope.Type) '$($data.Scope.Name)'`nHosts: $hc   VMs: $vc   Overcommit: ${oc}:1`n`nOutput:`n$outFile" -Icon Info
if ($script:_noSplash) { Write-Host "Output: $outFile" }
#endregion

#Requires -Version 5.1

<#
.SYNOPSIS
    Collects on-premises Citrix component data (Cloud Connectors, StoreFront, FAS)
    for the Citrix-DaaS-Report Performance section.

.DESCRIPTION
    For each target server (local or remote via WinRM) the collector gathers:
      - Machine specification (OS, CPU, RAM, disks)
      - Installed key Citrix component versions (Cloud Connector / StoreFront / FAS)
      - A performance sample every 30 seconds for a chosen duration
        (CPU %, RAM %, disk queue length, disk throughput MB/s, network Mbps)
    Each server is written to its own JSON file the report consumes via -OnPremFiles.

    Run with no parameters for the WPF prompt, or pass -Servers / -DurationMinutes
    for non-interactive use.

.PARAMETER Servers
    One or more server names. Empty, 'localhost', '.' or the local hostname = local.

.PARAMETER DurationMinutes
    How long to monitor performance (a sample is taken every 30 seconds).

.PARAMETER Credential
    Optional alternate credentials for WinRM to remote servers. Defaults to the
    current user.

.PARAMETER OutputPath
    Override the output folder (default: .\Outputs).

.PARAMETER NoPerf
    Skip performance sampling entirely (collect spec, versions, event errors, FAS and
    StoreFront config only). Useful for a quick config-only run with no monitoring window.

.PARAMETER NoSplash
    Run headless: suppress the WPF splash and the completion/warning message boxes (status
    still goes to the console and OnPremComponentsData-Debug.log). Intended for command-line / scripted use.

.EXAMPLE
    .\Get-OnPremComponentsData.ps1
    # Interactive - shows the prompt

.EXAMPLE
    .\Get-OnPremComponentsData.ps1 -Servers CTXCC01,CTXSF01 -DurationMinutes 30

.EXAMPLE
    .\Get-OnPremComponentsData.ps1 -Servers CTXSF01 -NoPerf -NoSplash
    # Headless, config-only (no perf sampling, no pop-ups)
#>

[CmdletBinding()]
param(
    [string[]]$Servers,
    [int]$DurationMinutes = 30,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputPath,
    [string]$Customer,
    [switch]$NoPerf,
    [switch]$NoSplash,
    [switch]$LiveView,
    # Optional: encrypt each server's output file with this password (writes OnPrem-*.cdenc instead
    # of .json). OFF by default - omit it and output stays plaintext .json exactly as before.
    [System.Security.SecureString]$EncryptPassword,
    # Skip the "newer version available?" check against GitHub on launch (also skipped with -NoSplash).
    [switch]$SkipUpdateCheck
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

#region ── Assemblies & Script-Scope Globals ──────────────────────────────────

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

#region ── Data-file encryption (opt-in, self-contained) ──────────────────────
# Portable password-based encryption for the output data files. OFF unless -EncryptPassword is given.
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

# Version: 'YYYY-MM-DD' or 'YYYY-MM-DD.rev' (rev distinguishes multiple releases in a day).
# IMPORTANT: bump this on EVERY release; the published .version file is derived from it.
$script:_version      = '2026-07-09.2'
# Self-update: the launch check reads a TINY version file (a few bytes) - efficient - and only
# downloads the full script if a newer version is actually available.
$script:_updateVersionUrl = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/Get-OnPremComponentsData.version'
$script:_updateScriptUrl  = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/Get-OnPremComponentsData.ps1'
$script:_encryptPassword = $null   # set from -EncryptPassword or the launch dialog; $null = plaintext
$script:_scriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:_outputDir    = if ($OutputPath) { $OutputPath } else { Join-Path $script:_scriptDir 'Outputs' }
$script:_debugLogPath = Join-Path $script:_scriptDir 'OnPremComponentsData-Debug.log'
$script:_splash       = $null
$script:_noSplash     = [bool]$NoSplash   # headless: suppress splash + message boxes
$script:_splashStatus = $null

# True when this process holds an elevated (local-administrator) token. Local collection of IIS
# bindings / SSL certificate and the StoreFront / FAS / PVS admin cmdlets needs it; remote (WinRM)
# targets instead use the supplied credential's rights on the target.
function Test-IsElevated {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
# Single source for the "not elevated" warning shown by both the launch-dialog banner and the
# console path, so the two can't drift.
$script:_adminWarnText = 'Not running as administrator. Local collection for this machine (IIS bindings / SSL certificate and StoreFront / FAS / PVS admin config) will be incomplete - re-run elevated ("Run as administrator") for full local collection. Remote servers are unaffected; they use the supplied credentials on the target.'

if (-not (Test-Path $script:_outputDir)) { New-Item -ItemType Directory -Path $script:_outputDir -Force | Out-Null }

# DWM P/Invoke for square corners on Windows 11
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class OnPremDwm {
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
            [void][OnPremDwm]::DwmSetWindowAttribute($h, $script:_dwmAttr, [ref]$script:_dwmSquare, 4)
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
        "Citrix On-Premises Data Collector  v$($script:_version)"
        "Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        "User    : $env:USERDOMAIN\$env:USERNAME"
        "Machine : $env:COMPUTERNAME"
        '=' * 70
    ) -join "`n") -ErrorAction SilentlyContinue
    Write-Log 'On-premises collector starting'
}

#endregion

#region ── WPF Helpers ───────────────────────────────────────────────────────

function Show-MsgBox {
    param(
        [string]$Message,
        [string]$Title = 'Citrix On-Premises Collector',
        [ValidateSet('Info','Warning','Error')][string]$Icon = 'Info'
    )
    if ($script:_noSplash) { Write-Host "[$Icon] $Message"; Write-Log $Message; return }
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
# On launch (interactive only), check euc-reports-collectors for a newer version of THIS script and
# offer to update in place. Fully optional and fail-safe: short timeout, silent on any failure (many
# customer servers have no/limited internet), skipped with -SkipUpdateCheck or -NoSplash.

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
    if ($script:_noSplash) { return $false }
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

function Invoke-OnPremUpdateCheck {
    if ($SkipUpdateCheck -or $script:_noSplash -or -not $script:_updateVersionUrl) { return }
    $self = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    if (-not $self) { return }
    try {
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
        # Step 1 (lightweight): read just the tiny version file - a few bytes.
        $vresp = Invoke-WebRequest -Uri $script:_updateVersionUrl -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        $remoteVer = (("$($vresp.Content)" -split "`r?`n") | Where-Object { "$_".Trim() } | Select-Object -First 1)
        $remoteVer = "$remoteVer".Trim()
        $rv = ConvertTo-CollectorVersion $remoteVer; $lv = ConvertTo-CollectorVersion $script:_version
        if (-not $rv) { Write-Log "Update check: unrecognised remote version '$remoteVer' - skipping" 'WARN'; return }
        if (-not $lv -or $rv -le $lv) { Write-Log "Update check: up to date (local $($script:_version), remote $remoteVer)"; return }
        Write-Log "Update check: newer version available - local $($script:_version), remote $remoteVer"
        if (-not (Show-UpdatePrompt $script:_version $remoteVer)) { Write-Log 'Update check: user chose Not now'; return }
        # Step 2 (only when updating): download the full script.
        $resp = Invoke-WebRequest -Uri $script:_updateScriptUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $content = "$($resp.Content)"
        # Sanity: recognisably our collector, and carries a version line.
        if ($content.Length -lt 20000 -or $content -notmatch 'Get-OnPremComponentsData' -or $content -notmatch "\`$script:_version\s*=\s*'([^']+)'") {
            Show-MsgBox 'Could not download a valid update; keeping the current version.' -Icon Warning
            Write-Log 'Update check: downloaded script not recognised - aborting' 'WARN'; return
        }
        # Validate the download parses before replacing anything.
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("OnPremCollector-$([guid]::NewGuid().ToString('N')).ps1")
        Set-Content -Path $tmp -Value $content -Encoding UTF8
        $tk = $null; $perr = $null
        [System.Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$tk, [ref]$perr) | Out-Null
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        if ($perr -and $perr.Count) { Show-MsgBox 'The downloaded update did not validate (parse errors). Keeping the current version.' -Icon Warning; Write-Log 'Update check: downloaded content failed to parse - aborting' 'WARN'; return }
        try {
            Copy-Item -LiteralPath $self -Destination "$self.bak" -Force -ErrorAction SilentlyContinue
            Set-Content -Path $self -Value $content -Encoding UTF8
        } catch {
            $alt = Join-Path (Split-Path $self -Parent) 'Get-OnPremComponentsData.NEW.ps1'
            try { Set-Content -Path $alt -Value $content -Encoding UTF8 } catch {}
            Show-MsgBox "Couldn't replace the running script (permissions?). The new version was saved as:`n$alt`n`nReplace the old script with it and re-run." -Icon Warning
            Write-Log "Update check: could not overwrite $self - saved new version to $alt" 'WARN'; return
        }
        Write-Log "Update check: updated $self to $remoteVer - relaunching"
        Show-MsgBox "Updated to version $remoteVer.`n`nThe collector will now relaunch." -Icon Info
        try { Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $self + '"') } catch { Write-Log "Relaunch failed: $($_.Exception.Message)" 'WARN' }
        exit 0
    } catch {
        Write-Log "Update check skipped: $(("$($_.Exception.Message)" -replace '\s+', ' '))"
    }
}

#endregion

#region ── WPF Splash Screen ─────────────────────────────────────────────────

function Show-Splash {
    if ($script:_noSplash) { Write-Log 'Headless (-NoSplash): splash suppressed'; return }
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Citrix On-Premises Collector" Height="170" Width="460"
        WindowStartupLocation="CenterScreen" WindowStyle="None"
        AllowsTransparency="True" Background="Transparent" Topmost="True"
        ShowInTaskbar="True" FontFamily="Segoe UI">
    <Border CornerRadius="6" Background="White" BorderBrush="#DDE1E7" BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect BlurRadius="24" ShadowDepth="3" Opacity="0.12" Color="#000000"/>
        </Border.Effect>
        <StackPanel VerticalAlignment="Center" Margin="32,24">
            <TextBlock Text="Citrix On-Premises - Data Collector"
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
    $script:_splash.Show()
    [void]$script:_splash.Activate()    # bring to the foreground on launch (void: Activate() returns a bool)
    $script:_splash.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    # Shown on top initially, but then drop to normal z-order so it doesn't stay above
    # other apps during the (potentially long) run - it can be re-summoned from the taskbar.
    $script:_splash.Topmost = $false
    Write-Log 'Splash shown'
}

function Set-SplashStatus ([string]$Message) {
    Write-Log $Message
    if ($script:_splash -and $script:_splashStatus) {
        $script:_splash.Dispatcher.Invoke([Action]{ $script:_splashStatus.Text = $Message },
            [System.Windows.Threading.DispatcherPriority]::Send)
        # Setting Text alone does not repaint when the caller then blocks the thread (e.g. the
        # inter-sample sleep). Pump the dispatcher at Background priority to force a render pass.
        $script:_splash.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    }
}

# Sleep that keeps the WPF splash responsive: sleeps in short slices, pumping the
# dispatcher each slice so the window repaints / the progress bar animates and the OS
# does not flag it "Not Responding" during the long inter-sample waits.
function Start-SleepResponsive ([int]$Seconds) {
    $sliceMs = 250
    $slices  = [math]::Max(1, [int][math]::Round(($Seconds * 1000) / $sliceMs))
    for ($n = 0; $n -lt $slices; $n++) {
        Start-Sleep -Milliseconds $sliceMs
        $w = if ($script:_liveWin) { $script:_liveWin } else { $script:_splash }
        if ($w) {
            try { $w.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background) } catch {}
        }
    }
}

function Close-Splash {
    if ($script:_splash) {
        try { $script:_splash.Close() } catch {}
        $script:_splash = $null
    }
}

#endregion

#region ── WPF Live Collection View ──────────────────────────────────────────

$script:_liveWin     = $null
$script:_liveStatus  = $null
$script:_liveBar     = $null
$script:_liveRows    = @{}     # server -> @{ Root; BadgeBorder; BadgeText; RoleText; Metrics=@{ Id -> @{Poly;Canvas;Label;Vals;Max;Unit} } }
$script:_liveClosed  = $false
# Metric columns for each server row (matches the report's five perf charts).
$script:_liveMetrics = @(
    @{ Key = 'CpuPct';       Id = 'Cpu'; Cap = 'CPU %';      Color = '#2563eb'; Max = 100; Unit = '%' }
    @{ Key = 'RamPct';       Id = 'Ram'; Cap = 'RAM %';      Color = '#16a34a'; Max = 100; Unit = '%' }
    @{ Key = 'DiskQueueLen'; Id = 'Dq';  Cap = 'Disk Queue'; Color = '#CA5010'; Max = 0;   Unit = '' }
    @{ Key = 'DiskMBps';     Id = 'Dm';  Cap = 'Disk MB/s';  Color = '#9333ea'; Max = 0;   Unit = '' }
    @{ Key = 'NetMbps';      Id = 'Net'; Cap = 'Net Mbps';   Color = '#0891b2'; Max = 0;   Unit = '' }
    @{ Key = 'Sessions';     Id = 'Sess'; Cap = 'Sessions';  Color = '#7c3aed'; Max = 0;   Unit = ''; VdaOnly = $true }
)

# Frozen-brush cache: badge colours repeat constantly, so create each SolidColorBrush once and Freeze it
# (frozen Freezables skip change-notification and render faster) instead of allocating a converter per call.
$script:_brushCache = @{}
function Get-LiveBrush ([string]$Hex) {
    $b = $script:_brushCache[$Hex]
    if (-not $b) {
        $b = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($Hex))
        $b.Freeze()
        $script:_brushCache[$Hex] = $b
    }
    $b
}

function Show-LiveView ([string[]]$Servers) {
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Citrix On-Premises - Live Collection" Height="620" Width="980"
        WindowStartupLocation="CenterScreen" Background="#F4F6F9" FontFamily="Segoe UI">
    <DockPanel Margin="16">
        <StackPanel DockPanel.Dock="Top" Margin="0,0,0,12">
            <TextBlock Text="Citrix On-Premises - Live Collection" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
            <TextBlock x:Name="StatusText" Text="Starting..." FontSize="12" Foreground="#555" Margin="0,3,0,8"/>
            <ProgressBar x:Name="Bar" IsIndeterminate="True" Height="3" Background="#E8EAED" Foreground="#0078D4" BorderThickness="0"/>
        </StackPanel>
        <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel x:Name="RowsPanel"/></ScrollViewer>
    </DockPanel>
</Window>
'@
    $win = New-ThemedWindow $xaml
    $script:_liveWin    = $win
    $script:_liveStatus = $win.FindName('StatusText')
    $script:_liveBar    = $win.FindName('Bar')
    $script:_liveClosed = $false
    $script:_liveRows   = @{}
    $rowsPanel = $win.FindName('RowsPanel')

    foreach ($srv in $Servers) {
        if ($script:_liveRows.ContainsKey("$srv")) { continue }   # don't create an orphan row for a repeated server
        $nameEsc = [System.Security.SecurityElement]::Escape("$srv")
        $boxes = ''
        foreach ($m in $script:_liveMetrics) {
            # VDA-only metrics (Sessions) start hidden and are revealed when data first arrives.
            $vis = if ($m.VdaOnly) { 'Collapsed' } else { 'Visible' }
            $boxes += @"
<StackPanel x:Name="$($m.Id)Box" Visibility="$vis" Margin="0,0,10,0">
  <TextBlock Text="$($m.Cap)" FontSize="10" Foreground="#888"/>
  <TextBlock x:Name="$($m.Id)Val" Text="-" FontSize="12" FontWeight="SemiBold" Foreground="#1F2937"/>
  <Border Background="#F7F8FA" BorderBrush="#E8EAED" BorderThickness="1" CornerRadius="3" Margin="0,2,0,0">
    <Canvas x:Name="$($m.Id)Canvas" Width="150" Height="40"><Polyline x:Name="$($m.Id)Poly" Stroke="$($m.Color)" StrokeThickness="1.5"/></Canvas>
  </Border>
</StackPanel>
"@
        }
        $rowXaml = @"
<Border xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Background="White" BorderBrush="#DDE1E7" BorderThickness="1" CornerRadius="6" Margin="0,0,0,8" Padding="12,10">
  <Grid>
    <Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
    <StackPanel Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0">
      <TextBlock Text="$nameEsc" FontWeight="Bold" FontSize="13" Foreground="#1F2937" TextTrimming="CharacterEllipsis"/>
      <TextBlock x:Name="RoleText" Text="" FontSize="11" Foreground="#888" TextWrapping="Wrap"/>
      <Border x:Name="Badge" Background="#888" CornerRadius="3" Padding="6,2" HorizontalAlignment="Left" Margin="0,4,0,0">
        <TextBlock x:Name="BadgeText" Text="Pending" FontSize="10" FontWeight="SemiBold" Foreground="White"/>
      </Border>
      <TextBlock x:Name="StepText" Text="" FontSize="10" Foreground="#6B7280" TextWrapping="Wrap" Margin="0,4,0,0"/>
    </StackPanel>
    <StackPanel Grid.Column="1" Orientation="Horizontal">$boxes</StackPanel>
  </Grid>
</Border>
"@
        $row = [System.Windows.Markup.XamlReader]::Parse($rowXaml)
        $entry = @{ Root = $row; BadgeBorder = $row.FindName('Badge'); BadgeText = $row.FindName('BadgeText'); RoleText = $row.FindName('RoleText'); StepText = $row.FindName('StepText'); Metrics = @{} }
        foreach ($m in $script:_liveMetrics) {
            $entry.Metrics[$m.Id] = @{
                Poly   = $row.FindName("$($m.Id)Poly")
                Canvas = $row.FindName("$($m.Id)Canvas")
                Label  = $row.FindName("$($m.Id)Val")
                Box    = $row.FindName("$($m.Id)Box")
                Vals   = [System.Collections.Generic.Queue[double]]::new()
                Max    = [double]$m.Max
                Unit   = "$($m.Unit)"
            }
        }
        $script:_liveRows["$srv"] = $entry
        [void]$rowsPanel.Children.Add($row)
    }

    $win.Add_Closed({ $script:_liveClosed = $true })
    $win.Show()
    [void]$win.Activate()
    $win.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    $win.Topmost = $false
    Write-Log "Live view shown ($($Servers.Count) server(s))"
}

function Set-LiveStatus ([string]$Text) {
    Write-Log $Text
    if ($script:_liveWin -and $script:_liveStatus) {
        # Single Background-priority invoke: sets the text and flushes the queue (repaints) in one pass.
        $script:_liveWin.Dispatcher.Invoke([Action]{ $script:_liveStatus.Text = $Text }, [System.Windows.Threading.DispatcherPriority]::Background)
    }
}

# Update a server's status badge (and optionally its role line).
function Set-LiveServerState ([string]$Server, [string]$Text, [string]$Color = '#888', [string]$Role) {
    if (-not $script:_liveWin) { return }
    $row = $script:_liveRows["$Server"]; if (-not $row) { return }
    $script:_liveWin.Dispatcher.Invoke([Action]{
        $row.BadgeText.Text = $Text
        $row.BadgeBorder.Background = Get-LiveBrush $Color
        if ($PSBoundParameters.ContainsKey('Role')) { $row.RoleText.Text = $Role }
    }, [System.Windows.Threading.DispatcherPriority]::Render)
}

# Update a server's fine-grained step line (what is being attempted right now) so a hang is
# visible against the exact operation. Also logged, so the debug log carries the same trail.
function Set-LiveServerStep ([string]$Server, [string]$Text) {
    Write-Log "[$Server] $Text"
    if (-not $script:_liveWin) { return }
    $row = $script:_liveRows["$Server"]; if (-not $row -or -not $row.StepText) { return }
    $script:_liveWin.Dispatcher.Invoke([Action]{ $row.StepText.Text = $Text }, [System.Windows.Threading.DispatcherPriority]::Render)
}

# Append one tick's sample to a server's sparklines + value labels. $Sessions >= 0 (VDA only)
# reveals + feeds the Sessions box; -1 leaves it hidden.
function Update-LiveSample ([string]$Server, [double]$Cpu, [double]$Ram, [double]$Dq, [double]$Dm, [double]$Net, [int]$Sessions = -1) {
    if (-not $script:_liveWin) { return }
    $row = $script:_liveRows["$Server"]; if (-not $row) { return }
    $vals = @{ Cpu = $Cpu; Ram = $Ram; Dq = $Dq; Dm = $Dm; Net = $Net }
    if ($Sessions -ge 0) { $vals['Sess'] = $Sessions }
    $script:_liveWin.Dispatcher.Invoke([Action]{
        if ($Sessions -ge 0 -and $row.Metrics['Sess'].Box) { $row.Metrics['Sess'].Box.Visibility = 'Visible' }
        foreach ($id in $vals.Keys) {
            $e = $row.Metrics[$id]; if (-not $e) { continue }
            $v = [double]$vals[$id]
            # O(1) ring buffer (Queue) capped at 60 - a 150px sparkline can't show more, and this avoids the
            # O(n) List.RemoveAt(0) shift every tick.
            $q = $e.Vals; $q.Enqueue($v); while ($q.Count -gt 60) { [void]$q.Dequeue() }
            $arr = $q.ToArray(); $n = $arr.Length
            $w = 150.0; $h = 40.0
            # Fixed scale (CPU/RAM) uses Max; auto-scale metrics take a cheap manual max (no Measure-Object).
            if ($e.Max -gt 0) { $top = [double]$e.Max }
            else { $top = 0.0; for ($k = 0; $k -lt $n; $k++) { if ($arr[$k] -gt $top) { $top = $arr[$k] } }; if ($top -le 0) { $top = 1.0 } }
            $pts = New-Object System.Windows.Media.PointCollection
            for ($i = 0; $i -lt $n; $i++) {
                $x = if ($n -le 1) { 0.0 } else { $w * $i / ($n - 1) }
                $cv = [math]::Min($arr[$i], $top)
                $y = $h - ($h * ($cv / $top))
                [void]$pts.Add([System.Windows.Point]::new($x, $y))
            }
            if ($n -le 1) { [void]$pts.Add([System.Windows.Point]::new($w, $pts[0].Y)) }
            $pts.Freeze()   # frozen point collection renders without per-point change notifications
            $e.Poly.Points = $pts
            $e.Label.Text = if ($e.Max -eq 100) { '{0:N0}{1}' -f $v, $e.Unit } else { '{0:N1}' -f $v }
        }
    }, [System.Windows.Threading.DispatcherPriority]::Render)
}

function Close-LiveView {
    if ($script:_liveWin) {
        try { $script:_liveWin.Close() } catch {}
        $script:_liveWin = $null
    }
}

#endregion

#region ── WPF Launch Dialog ─────────────────────────────────────────────────

function Show-OnPremDialog {
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Citrix On-Premises Collector" Width="480" SizeToContent="Height"
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
                <TextBlock Text="Citrix On-Premises Collector" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
                <TextBlock Text="Cloud Connector / StoreFront / FAS spec + performance" FontSize="12" Foreground="#555" Margin="0,2,0,0"/>
            </StackPanel>
        </DockPanel>

        <Border x:Name="AdminWarn" Background="#FFF4CE" BorderBrush="#E6C200" BorderThickness="1" CornerRadius="3" Padding="10,8" Margin="0,0,0,14" Visibility="Collapsed">
            <!-- Text set from $script:_adminWarnText when shown (single source with the console warning). -->
            <TextBlock x:Name="AdminWarnText" TextWrapping="Wrap" FontSize="11" Foreground="#7A5C00"/>
        </Border>

        <TextBlock Text="Customer (groups output files under Outputs\&lt;Customer&gt;)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox x:Name="CustomerBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,14"/>

        <TextBlock Text="Servers (one per line; blank or 'localhost' = this machine)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox x:Name="ServersBox" AcceptsReturn="True" TextWrapping="Wrap" Height="92" VerticalScrollBarVisibility="Auto"
                 Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,14"/>

        <Grid Margin="0,0,0,14">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="16"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <StackPanel Grid.Column="0">
                <TextBlock Text="Monitor duration (minutes)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
                <TextBox x:Name="DurationBox" Text="30" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12"/>
            </StackPanel>
            <StackPanel Grid.Column="2">
                <TextBlock Text="Sample interval" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
                <TextBox Text="Every 30 seconds (fixed)" IsEnabled="False" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="#EEF0F3" FontSize="12" Foreground="#888"/>
            </StackPanel>
        </Grid>

        <Rectangle Height="1" Fill="#DDE1E7" Margin="0,0,0,12"/>
        <TextBlock Text="Remote credentials (optional - blank uses the current user; remote needs WinRM)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,6"/>
        <Grid Margin="0,0,0,16">
            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="16"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <TextBox x:Name="UserBox" Grid.Column="0" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12"/>
            <PasswordBox x:Name="PassBox" Grid.Column="2" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12"/>
        </Grid>

        <TextBlock Text="Encrypt output (optional - leave blank for plaintext .json; a password writes .cdenc)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,6"/>
        <PasswordBox x:Name="EncryptBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,16"/>

        <CheckBox x:Name="PerfChk" Content="Collect performance samples (every 30 seconds)" IsChecked="True"
                  Foreground="#1F2937" FontSize="12" Margin="0,0,0,10"/>
        <CheckBox x:Name="LiveViewChk" Content="Show live performance view during collection"
                  Foreground="#1F2937" FontSize="12" Margin="0,0,0,16"/>

        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="CancelBtn" Content="Cancel" Width="80" Padding="0,7" Style="{StaticResource GreyBtn}" Margin="0,0,8,0"/>
            <Button x:Name="OkBtn" Content="Start" Width="100" Padding="0,7" Style="{StaticResource BlueBtn}"/>
        </StackPanel>
        <TextBlock x:Name="VersionText" HorizontalAlignment="Right" Margin="0,12,0,0" FontSize="10" Foreground="#9aa4b2"/>
    </StackPanel>
</Window>
'@
    $win = New-ThemedWindow $xaml
    $win.FindName('VersionText').Text = "Version $($script:_version)"
    $customerBox = $win.FindName('CustomerBox')
    $serversBox = $win.FindName('ServersBox')
    $durationBox = $win.FindName('DurationBox')
    $userBox = $win.FindName('UserBox')
    $passBox = $win.FindName('PassBox')
    $okBtn = $win.FindName('OkBtn')
    $cancel = $win.FindName('CancelBtn')
    $liveViewChk = $win.FindName('LiveViewChk')
    $perfChk = $win.FindName('PerfChk')
    $encryptBox = $win.FindName('EncryptBox')

    # Show the "not running as administrator" banner when this process lacks a local-admin token -
    # local collection (IIS/cert/StoreFront/FAS/PVS admin) would come back incomplete.
    $adminWarn = $win.FindName('AdminWarn')
    if (-not (Test-IsElevated)) {
        $win.FindName('AdminWarnText').Text = $script:_adminWarnText
        $adminWarn.Visibility = 'Visible'
    }

    # Live view + monitor duration only apply when performance sampling is on; grey them out otherwise.
    $syncPerf = {
        $on = [bool]$perfChk.IsChecked
        $durationBox.IsEnabled = $on
        $liveViewChk.IsEnabled = $on
        if (-not $on) { $liveViewChk.IsChecked = $false }
    }
    $perfChk.Add_Checked($syncPerf); $perfChk.Add_Unchecked($syncPerf)

    $result = [ordered]@{ Action = 'Cancel'; Servers = @(); DurationMinutes = 30; Credential = $null; Customer = ''; LiveView = $false; NoPerf = $false; EncryptPassword = $null }

    $okBtn.Add_Click({
        $lines = @($serversBox.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($lines.Count -eq 0) { $lines = @('localhost') }   # blank = local
        $dur = 30; [void][int]::TryParse($durationBox.Text.Trim(), [ref]$dur)
        if ($dur -lt 1) { $dur = 1 }
        $cred = $null
        if ($userBox.Text.Trim() -and $passBox.Password) {
            $sec = ConvertTo-SecureString $passBox.Password -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential($userBox.Text.Trim(), $sec)
        }
        $result['Action'] = 'Run'
        $result['Servers'] = $lines
        $result['DurationMinutes'] = $dur
        $result['Credential'] = $cred
        $result['Customer'] = $customerBox.Text.Trim()
        $result['NoPerf'] = -not [bool]$perfChk.IsChecked
        $result['LiveView'] = [bool]$liveViewChk.IsChecked -and -not $result['NoPerf']
        if ($encryptBox.Password) { $result['EncryptPassword'] = ConvertTo-SecureString $encryptBox.Password -AsPlainText -Force }
        $win.Close()
    })
    $cancel.Add_Click({ $result['Action'] = 'Cancel'; $win.Close() })
    $null = $win.ShowDialog()
    return $result
}

#endregion

#region ── Collection ────────────────────────────────────────────────────────

# True when the target name refers to this machine (so we skip remoting).
function Test-IsLocalTarget ([string]$Name) {
    if (-not $Name) { return $true }
    $n = $Name.Trim().ToLower()
    if ($n -in @('localhost', '.', '127.0.0.1', '::1')) { return $true }
    $local = @("$env:COMPUTERNAME".ToLower())
    try { $local += ([System.Net.Dns]::GetHostName()).ToLower() } catch {}
    try { $local += ([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName.ToLower() } catch {}
    return ($local -contains $n) -or ($n.Split('.')[0] -eq "$env:COMPUTERNAME".ToLower())
}

# Run a scriptblock locally (no session) or on a remote PSSession.
function Invoke-OnTarget ($Session, [scriptblock]$Block) {
    if ($Session) { Invoke-Command -Session $Session -ScriptBlock $Block -ErrorAction Stop }
    else          { & $Block }
}

# --- Scriptblocks that run on the target (local or remote) ---

$script:_specBlock = {
    $os    = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs    = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $cpus  = @(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue)
    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)
    [pscustomobject]@{
        OSCaption   = "$($os.Caption)".Trim()
        OSVersion   = "$($os.Version)"
        CpuModel    = "$(($cpus | Select-Object -First 1).Name)".Trim()
        Sockets     = $cpus.Count
        Cores       = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
        Logical     = ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        MaxClockMHz = ($cpus | Select-Object -First 1).MaxClockSpeed
        RamGB       = if ($cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } else { $null }
        Disks       = @($disks | ForEach-Object {
            [pscustomobject]@{
                Drive  = $_.DeviceID
                SizeGB = if ($_.Size) { [math]::Round($_.Size / 1GB, 1) } else { 0 }
                FreeGB = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 1) } else { 0 }
                UsedPct = if ($_.Size) { [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 1) } else { 0 }
            }
        })
    }
}

$script:_versionBlock = {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = foreach ($p in $paths) { Get-ItemProperty $p -ErrorAction SilentlyContinue }
    # For each component: the plain entry gives the component's own version, and the
    # "Citrix Virtual Apps and Desktops 7 <YYMM> - <component>" entry (when present)
    # names the CVAD release directly (e.g. DisplayName "...7 2407 - StoreFront",
    # DisplayVersion "2407.0.100.16") - the authoritative CVAD match, no guessing.
    $targets = @(
        @{ Name = 'Cloud Connector'; Match = 'Citrix Cloud Connector'; CvadLabel = $null }
        @{ Name = 'StoreFront';      Match = 'Citrix StoreFront';       CvadLabel = 'StoreFront' }
        @{ Name = 'FAS';             Match = 'Citrix Federated Authentication Service'; CvadLabel = 'Federated Authentication Service' }
        @{ Name = 'VDA';             Match = 'Citrix Virtual Delivery Agent'; CvadLabel = 'Virtual Delivery Agent' }
        # PVS server product name varies by release/branding - "Citrix Provisioning Server <YYMM>"
        # (CR), "Citrix <YYMM> LTSR CU<x> - Provisioning Server x64" (LTSR), and older "Citrix
        # Provisioning Services x64". The reliable common token is "Provisioning Server/Services";
        # match it anywhere, excluding the Console / Target Device (a VDA with the PVS target must not
        # be mistaken for a PVS server).
        @{ Name = 'Provisioning Server'; MatchRegex = '(?i)Provisioning (Server|Services)'; ExcludeRegex = '(?i)Console|Target|Client|Device'; CvadLabel = $null }
    )
    $out = @()
    foreach ($t in $targets) {
        if ($t.MatchRegex) {
            $m = $apps | Where-Object { "$($_.DisplayName)" -match $t.MatchRegex -and ($null -eq $t.ExcludeRegex -or "$($_.DisplayName)" -notmatch $t.ExcludeRegex) } | Select-Object -First 1
        } else {
            $m = $apps | Where-Object { "$($_.DisplayName)" -eq $t.Match } | Select-Object -First 1
            if (-not $m) { $m = $apps | Where-Object { "$($_.DisplayName)" -like "*$($t.Match)*" } | Select-Object -First 1 }
        }
        $cvadRelease = ''; $cvadVersion = ''
        if ($t.CvadLabel) {
            $cv = $apps | Where-Object { "$($_.DisplayName)" -match "Citrix Virtual Apps and Desktops.*-\s*$([regex]::Escape($t.CvadLabel))$" } | Select-Object -First 1
            if ($cv) {
                $cvadVersion = "$($cv.DisplayVersion)"
                if     ("$($cv.DisplayVersion)" -match '^(\d{4})\.') { $cvadRelease = $matches[1] }
                elseif ("$($cv.DisplayName)"    -match '\b(\d{4})\b') { $cvadRelease = $matches[1] }
                if (-not $m) { $m = $cv }   # only the CVAD-named entry exists on some installs
            }
        }
        if ($m -or $cvadRelease) {
            $out += [pscustomobject]@{
                Name        = $t.Name
                Product     = if ($m) { "$($m.DisplayName)" } else { '' }
                Version     = if ($m) { "$($m.DisplayVersion)" } else { $cvadVersion }
                CvadRelease = $cvadRelease   # YYMM (e.g. '2407'); '' when not a CVAD-bundled component
            }
        }
    }
    # Emit the objects (no unary comma: with local '& $block' + @() wrapping it would
    # otherwise inject a phantom empty element when nothing matched).
    $out
}

# Windows security-patch currency. Get-HotFix wraps Win32_QuickFixEngineering; InstalledOn is null
# on a few entries, so filter. The most recent install date is "last patched".
$script:_patchBlock = {
    $hf = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    [pscustomobject]@{
        LastPatch   = if ($hf.Count) { ([datetime]$hf[0].InstalledOn).ToString('o') } else { '' }
        HotfixCount = $hf.Count
        Recent      = @($hf | Select-Object -First 15 | ForEach-Object {
            [pscustomobject]@{ Id = "$($_.HotFixID)"; Description = "$($_.Description)"; InstalledOn = ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') }
        })
    }
}

# All co-installed Citrix products from the uninstall registry - the "what's on this VDA" inventory.
$script:_vdaComponentsBlock = {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = foreach ($p in $paths) { Get-ItemProperty $p -ErrorAction SilentlyContinue }
    @($apps | Where-Object { "$($_.DisplayName)" -like 'Citrix*' } |
        Sort-Object DisplayName -Unique |
        ForEach-Object { [pscustomobject]@{ Name = "$($_.DisplayName)"; Version = "$($_.DisplayVersion)" } })
}

# VDA logged-on session count via quser (ICA / RDP / console user sessions). Counts by state
# without strict column parsing (quser's disconnected rows shift columns). 0 sessions -> quser
# writes to stderr, hence the try/catch.
$script:_sessionBlock = {
    $users = @()
    $raw = @()
    try { $raw = @(quser 2>$null) } catch {}
    foreach ($line in ($raw | Select-Object -Skip 1)) {
        $t = ($line -replace '^\s*>', ' ').TrimEnd()
        if (-not $t.Trim()) { continue }
        $name  = (($t.Trim()) -split '\s+')[0]
        $state = if ($t -match '\bActive\b') { 'Active' } elseif ($t -match '\bDisc\b') { 'Disconnected' } else { 'Other' }
        $users += [pscustomobject]@{ User = $name; State = $state }
    }
    [pscustomobject]@{
        Total        = $users.Count
        Active       = @($users | Where-Object { $_.State -eq 'Active' }).Count
        Disconnected = @($users | Where-Object { $_.State -eq 'Disconnected' }).Count
        Users        = @($users | ForEach-Object { "$($_.User) ($($_.State))" })
    }
}

# Counts Citrix-specific Error + Critical events (levels 1-2) over the last 7 days and last 24h on the
# target. "Citrix only": every Citrix-named operational log (e.g. 'Citrix Delivery Services' for
# StoreFront) plus Application-log events whose provider is Citrix* (FAS
# 'Citrix.Authentication.FederatedAuthenticationService' and 'Citrix.Fas.PkiCore'; Cloud Connector
# 'Citrix.CloudServices.*'). The 7-day window is queried once and the 24h count derived from it; events
# surfacing in two logs are de-duplicated. Get-WinEvent throws "No events were found" on an empty
# filter - benign.
$script:_eventBlock = {
    $now    = Get-Date
    $since7 = $now.AddDays(-7)
    $cut24  = $now.AddHours(-24)
    $events  = @()
    $scanned = @()
    # (a) Citrix-named operational logs that actually have records.
    $citrixLogs = @()
    try { $citrixLogs = @(Get-WinEvent -ListLog 'Citrix*' -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 } | ForEach-Object { "$($_.LogName)" }) } catch {}
    foreach ($ln in $citrixLogs) {
        try {
            $e = @(Get-WinEvent -FilterHashtable @{ LogName = $ln; Level = 1, 2; StartTime = $since7 } -ErrorAction Stop)
            if ($e.Count -gt 0) { $events += $e; $scanned += $ln }
        } catch {}
    }
    # (b) Application log, Citrix providers only.
    try {
        $appCitrix = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2; StartTime = $since7 } -ErrorAction Stop | Where-Object { "$($_.ProviderName)" -like 'Citrix*' })
        if ($appCitrix.Count -gt 0) { $events += $appCitrix; $scanned += 'Application (Citrix providers)' }
    } catch {}
    $uniq    = @($events | Sort-Object ProviderName, Id, TimeCreated -Unique)
    $count7  = $uniq.Count
    $count24 = @($uniq | Where-Object { $_.TimeCreated -ge $cut24 }).Count

    # Local Host Cache activation (Cloud Connector only): the 'Citrix High Availability Service'
    # provider logs 3502 = outage/LHC active, 3507 = active status update, 3503/3508 = resolved.
    # Non-CC servers have no such provider (the filter throws/returns nothing - benign).
    $lhcActivated = $false; $lhcCount = 0; $lhcLast = ''; $lhcInOutage = $false
    $haEvents = @()
    try { $haEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Citrix High Availability Service'; StartTime = $since7 } -ErrorAction Stop) } catch {}
    if ($haEvents.Count -gt 0) {
        $starts = @($haEvents | Where-Object { $_.Id -eq 3502 } | Sort-Object TimeCreated -Descending)
        $lhcCount     = $starts.Count
        $lhcActivated = $lhcCount -gt 0
        if ($lhcActivated) { $lhcLast = $starts[0].TimeCreated.ToString('o') }
        # Currently in outage if the most-recent HA event is an active one (3502/3507) with no resolve after.
        $latest = $haEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($latest -and ($latest.Id -eq 3502 -or $latest.Id -eq 3507)) { $lhcInOutage = $true }
    }

    [pscustomobject]@{
        Count24h    = $count24
        Count7d     = $count7
        WindowHours = 24
        WindowDays  = 7
        LogsScanned = @($scanned)
        LhcActivated = $lhcActivated
        LhcCount     = $lhcCount
        LhcLast      = $lhcLast
        LhcInOutage  = $lhcInOutage
    }
}

# Runs ON a StoreFront server (locally, or via the WinRM/remote-PowerShell session) using the
# StoreFront PowerShell modules (Get-STF* cmdlets) to capture the deployment: server-group members,
# deployment base URL, stores + their delivery-controller farms, Receiver for Web sites +
# auth methods, roaming gateways, and internal/external beacons. (Export-STFConfiguration is
# NOT used - it prompts and cannot run in a non-interactive remote session.)
$script:_storeFrontBlock = {
    $sf = [ordered]@{
        ModulesAvailable   = $false
        HostBaseUrl        = ''
        ServerGroupMembers = @()
        PropagationStatus  = ''
        Stores             = @()
        WebReceivers       = @()
        Gateways           = @()
        BeaconInternal     = ''
        BeaconsExternal    = @()
        SslCertificate     = $null
        IisHardening       = $null
        SecurityHeaders    = $null
        TlsProtocols       = @()
        IisCleanup         = $null
        IcaSigning         = $null
        Messages           = @()
    }
    $imp = 'C:\Program Files\Citrix\Receiver StoreFront\Scripts\ImportModules.ps1'
    if (-not (Test-Path $imp)) { $sf['Messages'] += 'StoreFront PowerShell modules (ImportModules.ps1) not found.'; return [pscustomobject]$sf }
    try { & $imp *>$null; $sf['ModulesAvailable'] = $true } catch { $sf['Messages'] += "Module import failed: $($_.Exception.Message)"; return [pscustomobject]$sf }

    try { $dep = Get-STFDeployment -ErrorAction Stop; $sf['HostBaseUrl'] = "$($dep.HostbaseUrl)" } catch { $sf['Messages'] += "Deployment: $($_.Exception.Message)" }
    try {
        $sg = Get-STFServerGroup -ErrorAction Stop
        # ClusterMembers may be member objects (use .Name/.Server) or a single value that
        # stringifies to a comma-joined list (e.g. a standalone server -> "ctxsf1, CTXSF1");
        # flatten, split on commas, then dedupe case-insensitively.
        $names = @(@($sg.ClusterMembers) | ForEach-Object {
            if ($_ -and $_.PSObject.Properties['Name'])   { "$($_.Name)" }
            elseif ($_ -and $_.PSObject.Properties['Server']) { "$($_.Server)" }
            else { "$_" }
        } | ForEach-Object { $_ -split '\s*,\s*' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $sf['ServerGroupMembers'] = @($names | Sort-Object -Unique)
    } catch { $sf['Messages'] += "ServerGroup: $($_.Exception.Message)" }

    try {
        $sf['Stores'] = @(@(Get-STFStoreService -ErrorAction Stop) | ForEach-Object {
            $st = $_
            $farms = @()
            try {
                $fc = Get-STFStoreFarmConfiguration -StoreService $st -ErrorAction Stop
                $farms = @(@($fc.Farms) | ForEach-Object { [ordered]@{
                    Name          = "$($_.FarmName)"
                    FarmType      = "$($_.FarmType)"
                    Servers       = @(@($_.Servers) | ForEach-Object { "$_" })
                    Port          = [int]$_.Port
                    SSLRelayPort  = [int]$_.SSLRelayPort
                    TransportType = "$($_.TransportType)"
                    LoadBalance   = [bool]$_.LoadBalance
                } })
            } catch {}
            [ordered]@{
                Name            = "$($st.FriendlyName)"
                VirtualPath     = "$($st.VirtualPath)"
                AuthVirtualPath = "$($st.AuthenticationServiceVirtualPath)"
                Farms           = $farms
            }
        })
    } catch { $sf['Messages'] += "Stores: $($_.Exception.Message)" }

    try {
        $sf['WebReceivers'] = @(@(Get-STFWebReceiverService -ErrorAction Stop) | ForEach-Object {
            $wr = $_
            $methods = @()
            try { $methods = @((Get-STFWebReceiverAuthenticationMethods -WebReceiverService $wr -ErrorAction Stop).Methods | ForEach-Object { "$_" }) } catch {}
            [ordered]@{
                Name             = "$($wr.FriendlyName)"
                VirtualPath      = "$($wr.VirtualPath)"
                StoreVirtualPath = "$($wr.StoreServiceVirtualPath)"
                DefaultIISSite   = [bool]$wr.DefaultIISSite
                AuthMethods      = $methods
            }
        })
    } catch { $sf['Messages'] += "WebReceiver: $($_.Exception.Message)" }

    try {
        $sf['Gateways'] = @(@(Get-STFRoamingGateway -ErrorAction Stop) | ForEach-Object { [ordered]@{
            Name        = "$($_.Name)"
            Url         = "$($_.Location)"
            Version     = "$($_.Version)"
            CallbackUrl = "$($_.CallbackUrl)"
            Subnet      = "$($_.SubnetIPAddress)"
            LogonType   = "$($_.LogonType)"
        } })
    } catch {}

    try { $bi = Get-STFRoamingBeacon -Internal -ErrorAction Stop; $sf['BeaconInternal'] = "$bi" } catch {}
    try { $sf['BeaconsExternal'] = @(Get-STFRoamingBeacon -External -ErrorAction Stop | ForEach-Object { "$_" } | Where-Object { $_ }) } catch {}

    # SSL certificate on the IIS HTTPS binding (for the SAN / expiry check). Read the bound
    # cert's thumbprint from the first https binding, then inspect the cert in LocalMachine.
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $bind = @(Get-WebBinding | Where-Object { $_.protocol -eq 'https' }) | Select-Object -First 1
        if ($bind -and "$($bind.certificateHash)") {
            $store = if ("$($bind.certificateStoreName)") { "$($bind.certificateStoreName)" } else { 'MY' }
            $cert  = Get-Item ("Cert:\LocalMachine\{0}\{1}" -f $store, "$($bind.certificateHash)") -ErrorAction Stop
            $sanExt = @($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' })
            $sf['SslCertificate'] = [ordered]@{
                Subject    = "$($cert.Subject)"
                Issuer     = "$($cert.Issuer)"
                NotAfter   = $cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                Thumbprint = "$($cert.Thumbprint)"
                HasSan     = ($sanExt.Count -gt 0)
                SanList    = (@($cert.DnsNameList | ForEach-Object { "$_" } | Where-Object { $_ }) -join '; ')
            }
        }
    } catch { $sf['Messages'] += "SSL cert: $($_.Exception.Message)" }

    # Optional IIS hardening state (headers + request filtering) for the StoreFront site.
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $site = 'IIS:\Sites\Default Web Site'
        $rf = Get-WebConfiguration -PSPath $site -Filter 'system.webServer/security/requestFiltering' -ErrorAction Stop
        $allowExt = $true; $allowVerb = $true; $srvHeader = $true
        if ($rf) {
            if ($rf.fileExtensions -and $null -ne $rf.fileExtensions.allowUnlisted) { $allowExt  = [bool]$rf.fileExtensions.allowUnlisted }
            if ($rf.verbs          -and $null -ne $rf.verbs.allowUnlisted)          { $allowVerb = [bool]$rf.verbs.allowUnlisted }
            if ($null -ne $rf.removeServerHeader)                                    { $srvHeader = -not [bool]$rf.removeServerHeader }  # IIS 10+
        }
        # requestFiltering hardening: non-ASCII (high-bit) and double-escaped URLs (hardened = both false)
        $highBit = $true; $dblEsc = $true
        if ($rf) {
            if ($null -ne $rf.allowHighBitCharacters) { $highBit = [bool]$rf.allowHighBitCharacters }
            if ($null -ne $rf.allowDoubleEscaping)    { $dblEsc  = [bool]$rf.allowDoubleEscaping }
        }
        $xpb = $false
        try {
            $hdrs = @(Get-WebConfiguration -PSPath $site -Filter 'system.webServer/httpProtocol/customHeaders/add' -ErrorAction Stop)
            $xpb  = [bool](@($hdrs) | Where-Object { "$($_.name)" -match '(?i)^X-Powered-By$' })
        } catch {}
        # OS-shell MIME types still mapped (Citrix says remove .exe/.dll/.com/.bat/.csh)
        $osShellMime = $false
        try {
            $mimes = @(Get-WebConfiguration -PSPath $site -Filter 'system.webServer/staticContent/mimeMap' -ErrorAction Stop)
            $osShellMime = [bool](@($mimes) | Where-Object { "$($_.fileExtension)" -in '.exe', '.dll', '.com', '.bat', '.csh' })
        } catch {}
        # IIS handler mappings (effective/merged list). Citrix says StoreFront needs only
        # ExtensionlessUrlHandler-Integrated-4.0, PageHandlerFactory-Integrated-4.0 and StaticFile;
        # capture the raw name list so the report can flag any extras.
        $handlers = @()
        try { $handlers = @(@(Get-WebConfiguration -PSPath $site -Filter 'system.webServer/handlers/add' -ErrorAction Stop) | ForEach-Object { "$($_.name)" } | Where-Object { $_ }) } catch {}
        # .NET "Retail mode" (machine.config <system.web><deployment retail="true"/>) - hardened = true.
        # Prefer the 64-bit framework config, fall back to 32-bit. Raw fact: $true/$false/$null (unknown).
        $retail = $null
        try {
            $mc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\Config\machine.config'
            if (-not (Test-Path $mc)) { $mc = Join-Path $env:windir 'Microsoft.NET\Framework\v4.0.30319\Config\machine.config' }
            if (Test-Path $mc) {
                [xml]$mx = Get-Content -LiteralPath $mc -Raw
                $dep = $mx.configuration.'system.web'.deployment
                $retail = if ($dep -and "$($dep.retail)") { ("$($dep.retail)" -eq 'true') } else { $false }
            }
        } catch {}
        $sf['IisHardening'] = [ordered]@{
            AllowUnlistedFileExtensions = $allowExt
            AllowUnlistedVerbs          = $allowVerb
            XPoweredByPresent           = $xpb
            ServerHeaderPresent         = $srvHeader
            OsShellMimeTypesPresent     = $osShellMime
            AllowHighBitCharacters      = $highBit
            AllowDoubleEscaping         = $dblEsc
            HandlerMappings             = $handlers
            DotNetRetailMode            = $retail
        }
    } catch { $sf['Messages'] += "IIS hardening: $($_.Exception.Message)" }

    # TLS protocol state (SCHANNEL registry) - RAW facts only: whether the Server sub-key exists and
    # its Enabled / DisabledByDefault values. The report decides what's a problem (report knows the
    # OS defaults / severity), so no interpretation happens here.
    try {
        $sf['TlsProtocols'] = @(foreach ($proto in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2') {
            $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
            $present = Test-Path $key
            $enabled = $null; $disabledDefault = $null
            if ($present) {
                $rp = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($rp.PSObject.Properties['Enabled'])          { $enabled = [int]$rp.Enabled }
                if ($rp.PSObject.Properties['DisabledByDefault']) { $disabledDefault = [int]$rp.DisabledByDefault }
            }
            [ordered]@{ Name = $proto; Present = [bool]$present; Enabled = $enabled; DisabledByDefault = $disabledDefault }
        })
    } catch { $sf['Messages'] += "TLS protocols: $($_.Exception.Message)" }

    # IIS cleanup: ISAPI filters (StoreFront needs none) + default IIS landing page under wwwroot.
    try {
        $isapi = @()
        try { $isapi = @(@(Get-WebConfiguration -PSPath 'IIS:\Sites\Default Web Site' -Filter 'system.webServer/isapiFilters/filter' -ErrorAction Stop) | ForEach-Object { "$($_.name)" } | Where-Object { $_ }) } catch {}
        $landing = (Test-Path 'C:\inetpub\wwwroot\iisstart.htm') -or (Test-Path 'C:\inetpub\wwwroot\welcome.png')
        $sf['IisCleanup'] = [ordered]@{ IsapiFilters = $isapi; DefaultLandingPage = [bool]$landing }
    } catch { $sf['Messages'] += "IIS cleanup: $($_.Exception.Message)" }

    # Security response headers - RAW facts: whether HSTS is configured in IIS, and the actual header
    # values returned by a best-effort HEAD probe of the store URL (StoreFront sets CSP/XCTO/XFO at
    # runtime, so a static config read would miss them). The report evaluates the values.
    try {
        $hstsConfigured = $false
        try { $h = Get-WebConfiguration -PSPath 'IIS:\Sites\Default Web Site' -Filter 'system.webServer/hsts' -ErrorAction Stop; if ($h -and $null -ne $h.enabled) { $hstsConfigured = [bool]$h.enabled } } catch {}
        if (-not $hstsConfigured) {
            try { $ch = @(Get-WebConfiguration -PSPath 'IIS:\Sites\Default Web Site' -Filter 'system.webServer/httpProtocol/customHeaders/add' -ErrorAction Stop); if (@($ch) | Where-Object { "$($_.name)" -match '(?i)^Strict-Transport-Security$' }) { $hstsConfigured = $true } } catch {}
        }
        $csp = ''; $xcto = ''; $xfo = ''; $sts = ''; $probeErr = ''
        $url = "$($sf['HostBaseUrl'])"
        if ($url -match '^(?i)https://') {
            $probe = ($url.TrimEnd('/')) + '/Citrix/StoreWeb'   # a Receiver-for-Web path returns the security headers
            $prevCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
            $prevProto = [System.Net.ServicePointManager]::SecurityProtocol
            try {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }   # internal cert
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
                $resp = Invoke-WebRequest -Uri $probe -Method Head -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
                $hk = $resp.Headers
                $csp  = "$($hk['Content-Security-Policy'])"
                $xcto = "$($hk['X-Content-Type-Options'])"
                $xfo  = "$($hk['X-Frame-Options'])"
                $sts  = "$($hk['Strict-Transport-Security'])"
            } catch { $probeErr = ("$($_.Exception.Message)" -replace '\s+', ' ') }
            finally {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCb
                [System.Net.ServicePointManager]::SecurityProtocol = $prevProto
            }
        } else { $probeErr = 'base URL is not HTTPS - header probe skipped' }
        $sf['SecurityHeaders'] = [ordered]@{ HstsConfigured = [bool]$hstsConfigured; Csp = $csp; XContentTypeOptions = $xcto; XFrameOptions = $xfo; StrictTransportSecurity = $sts; ProbeError = $probeErr }
    } catch { $sf['Messages'] += "Security headers: $($_.Exception.Message)" }

    # ICA file signing (best-effort). Try the StoreFront store-launch cmdlet; else leave unknown.
    try {
        $icaEnabled = $null; $icaSource = 'not determined'
        try {
            $svc = @(Get-STFStoreService -ErrorAction Stop) | Select-Object -First 1
            if ($svc) {
                $lo = Get-STFStoreLaunchOptions -StoreService $svc -ErrorAction Stop
                foreach ($pn in 'SignIcaFile', 'RequireLaunchReference', 'IcaFileSigning') {
                    if ($lo.PSObject.Properties[$pn]) { $icaEnabled = [bool]$lo.$pn; $icaSource = "Get-STFStoreLaunchOptions.$pn"; break }
                }
            }
        } catch { $icaSource = "cmdlet unavailable: $(("$($_.Exception.Message)" -replace '\s+',' '))" }
        $sf['IcaSigning'] = [ordered]@{ Enabled = $icaEnabled; Source = $icaSource }
    } catch { $sf['Messages'] += "ICA signing: $($_.Exception.Message)" }

    [pscustomobject]$sf
}

# Runs ON a Provisioning Services server (local or via the WinRM session) using the PVS PowerShell
# snap-in (Citrix.PVS.SnapIn) to capture farm essentials: name/description, license server + edition,
# member servers (the farm "server group"), and the license-available state. The runtime "license
# available" state isn't a reliable SDK field, so it's derived from PVS licensing events in the Windows
# Application log (the console's "No license is currently available for this farm" warning).
$script:_pvsBlock = {
    $pvs = [ordered]@{
        SdkAvailable      = $false
        FarmName          = ''
        Description       = ''
        LicenseServerName = ''
        LicenseServerPort = 0
        Edition           = ''
        DefaultSiteName   = ''
        AutoAddEnabled    = $false
        AuditingEnabled   = $false
        OfflineDbSupport  = $false
        EntitledState     = ''
        EntitlementExpiry = ''
        Servers           = @()
        Sites             = @()
        Stores            = @()
        Disks             = @()
        Collections       = @()
        DeviceCount       = 0
        ServerVersion     = ''
        ConsoleVersion    = ''
        LicenseOk         = $true
        LicenseMessage    = ''
        Messages          = @()
    }
    # PVS Server + Console product versions (should match) from the uninstall registry - captured
    # independently of the snap-in so a version mismatch is reported even if the SDK isn't loadable.
    try {
        $pvsApps = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue }
        $srvApp = $pvsApps | Where-Object { "$($_.DisplayName)" -match '(?i)Provisioning Server' -and "$($_.DisplayName)" -notmatch '(?i)Console|Target|Client|Device' } | Select-Object -First 1
        $conApp = $pvsApps | Where-Object { "$($_.DisplayName)" -match '(?i)Provisioning Console' } | Select-Object -First 1
        if ($srvApp) { $pvs['ServerVersion']  = "$($srvApp.DisplayVersion)" }
        if ($conApp) { $pvs['ConsoleVersion'] = "$($conApp.DisplayVersion)" }
    } catch {}
    # Load the PVS snap-in (registered by the PVS console install); fall back to the console DLL.
    $loaded = $false
    try { Add-PSSnapin Citrix.PVS.SnapIn -ErrorAction Stop; $loaded = $true } catch {}
    if (-not $loaded) {
        $dll = 'C:\Program Files\Citrix\Provisioning Services Console\Citrix.PVS.SnapIn.dll'
        if (Test-Path $dll) { try { Import-Module $dll -ErrorAction Stop; $loaded = $true } catch { $pvs['Messages'] += "Snap-in import failed: $($_.Exception.Message)" } }
    }
    if (-not $loaded) { $pvs['Messages'] += 'PVS PowerShell snap-in (Citrix.PVS.SnapIn) not available.'; return [pscustomobject]$pvs }
    $pvs['SdkAvailable'] = $true

    try {
        $farm = Get-PvsFarm -ErrorAction Stop | Select-Object -First 1
        if ($farm) {
            $pvs['FarmName']          = "$($farm.FarmName)"
            $pvs['Description']       = "$($farm.Description)"
            $pvs['LicenseServerName'] = "$($farm.LicenseServer)"           # property is 'LicenseServer'
            $pvs['LicenseServerPort'] = [int]$farm.LicenseServerPort
            $pvs['DefaultSiteName']   = "$($farm.DefaultSiteName)"
            $pvs['AutoAddEnabled']    = [bool]$farm.AutoAddEnabled
            $pvs['AuditingEnabled']   = [bool]$farm.AuditingEnabled
            $pvs['OfflineDbSupport']  = [bool]$farm.OfflineDatabaseSupportEnabled
            $pvs['Edition']           = if ([bool]$farm.CloudSetupActive) { 'Citrix Cloud' } else { 'On-premises' }
            # Licence availability: EntitledState 0 with no expiry = farm not entitled to a licence -> the
            # console's "No license is currently available for this farm" warning (verified on a live
            # unlicensed Cloud-setup farm: EntitledState=0, EntitlementExpirationDate empty).
            $es  = "$($farm.EntitledState)"
            $exp = "$($farm.EntitlementExpirationDate)"
            $pvs['EntitledState']     = $es
            $pvs['EntitlementExpiry'] = $exp
            if ($es -in @('0', '') -and -not $exp) {
                $pvs['LicenseOk']      = $false
                $pvs['LicenseMessage'] = 'Farm is not entitled to a license (no valid license available) - streamed devices will eventually be shut down.'
            }
            if (-not "$($farm.LicenseServer)") {
                $pvs['LicenseOk'] = $false
                if (-not $pvs['LicenseMessage']) { $pvs['LicenseMessage'] = 'No license server is configured for the farm.' }
            }
        }
    } catch { $pvs['Messages'] += "Get-PvsFarm: $($_.Exception.Message)" }

    try { $pvs['Servers'] = @(@(Get-PvsServer -ErrorAction Stop) | ForEach-Object { "$($_.Name)" } | Where-Object { $_ } | Sort-Object -Unique) }
    catch { $pvs['Messages'] += "Get-PvsServer: $($_.Exception.Message)" }

    # Farm inventory: sites, stores, vDisks (disk locators), collections, target-device count.
    try { $pvs['Sites'] = @(@(Get-PvsSite -ErrorAction Stop) | ForEach-Object { [ordered]@{ Name = "$($_.SiteName)"; DefaultCollection = "$($_.DefaultCollectionName)" } }) }
    catch { $pvs['Messages'] += "Get-PvsSite: $($_.Exception.Message)" }

    try {
        $pvs['Stores'] = @(@(Get-PvsStore -ErrorAction Stop) | ForEach-Object { [ordered]@{
            Name        = "$($_.StoreName)"
            Path        = "$($_.Path)"
            CachePath   = (@($_.CachePath) | Where-Object { $_ }) -join '; '
            Site        = "$($_.SiteName)"
            Description = "$($_.Description)"
        } })
    } catch { $pvs['Messages'] += "Get-PvsStore: $($_.Exception.Message)" }

    try {
        $pvs['Disks'] = @(@(Get-PvsDiskLocator -ErrorAction Stop) | ForEach-Object { [ordered]@{
            Name  = "$($_.DiskLocatorName)"
            Store = "$($_.StoreName)"
            Site  = "$($_.SiteName)"
        } })
    } catch { $pvs['Messages'] += "Get-PvsDiskLocator: $($_.Exception.Message)" }

    try {
        $cols = @(Get-PvsCollection -ErrorAction Stop)
        $pvs['Collections'] = @($cols | ForEach-Object { [ordered]@{ Name = "$($_.CollectionName)"; Site = "$($_.SiteName)"; DeviceCount = [int]$_.DeviceCount } })
        $pvs['DeviceCount'] = ([int](@($cols | ForEach-Object { [int]$_.DeviceCount }) | Measure-Object -Sum).Sum)
    } catch { $pvs['Messages'] += "Get-PvsCollection: $($_.Exception.Message)" }

    # License-available state from PVS licensing events in the Application log (last 7 days). PVS logs the
    # licence-check failure periodically, so a recent licensing Error/Warning => "not available".
    try {
        $since = (Get-Date).AddDays(-7)
        $licEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = @('StreamProcess', 'soapserver', 'StreamService'); StartTime = $since } -ErrorAction SilentlyContinue |
            Where-Object { "$($_.Message)" -match '(?i)licens' })
        $bad = @($licEvents | Where-Object { $_.LevelDisplayName -in @('Error', 'Warning') -or "$($_.Message)" -match '(?i)no license|not available|shut down|grace' } | Sort-Object TimeCreated -Descending)
        if ($bad.Count -gt 0) {
            $pvs['LicenseOk']      = $false
            $pvs['LicenseMessage'] = ("$($bad[0].Message)" -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1)
        }
    } catch { $pvs['Messages'] += "License events: $($_.Exception.Message)" }

    [pscustomobject]$pvs
}

# Runs ON a FAS server (local or via the WinRM session) to capture the FAS baseline that
# needs NO FAS admin SDK: service state, install/config presence, and the applied FAS GPO
# address list. The GPO state is itself a key health signal - a FAS server absent from the
# applied "Federated Authentication Service" GPO is not advertised to StoreFront/VDAs
# (the console's "not available for use" warning). Deep health (RA cert / rules / cert
# definitions) is gathered separately by Get-FasData using the FAS snap-in.
$script:_fasBlock = {
    $fqdn = try { [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName } catch { "$env:COMPUTERNAME" }
    $r = [ordered]@{
        Fqdn                   = $fqdn
        ServiceRunning         = $false
        ServiceStartType       = ''
        Installed              = $false
        InstallDir             = ''
        CheckAddressAgainstGpo = $null
        DefaultToLocalhost     = $null
        GpoApplied             = $false
        GpoAddresses           = @()
        InGpo                  = $false
        RaCertificates         = @()
    }
    $svc = Get-Service -Name 'CitrixFederatedAuthenticationService' -ErrorAction SilentlyContinue
    if (-not $svc) { $svc = Get-Service -DisplayName '*Federated Authentication*' -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if ($svc) { $r.ServiceRunning = ($svc.Status -eq 'Running'); $r.ServiceStartType = "$($svc.StartType)" }

    $cfg = 'HKLM:\SOFTWARE\Citrix\Authentication\UserCredentialService'
    if (Test-Path $cfg) {
        $p = Get-ItemProperty $cfg -ErrorAction SilentlyContinue
        $r.Installed  = ("$($p.installed)" -eq '1') -or [bool]$p.InstallDir
        $r.InstallDir = "$($p.InstallDir)"
        $adm = Get-ItemProperty "$cfg\Admin" -ErrorAction SilentlyContinue
        if ($adm) {
            if ($null -ne $adm.CheckAddressAgainstGpo) { $r.CheckAddressAgainstGpo = [bool]$adm.CheckAddressAgainstGpo }
            if ($null -ne $adm.DefaultToLocalhost)     { $r.DefaultToLocalhost     = [bool]$adm.DefaultToLocalhost }
        }
    }

    # Applied FAS GPO advertised-address list. Absent key (or this server's FQDN missing
    # from it) => the server is not advertised to consumers via the GPO.
    $gpo = 'HKLM:\SOFTWARE\Policies\Citrix\Authentication\UserCredentialService\Addresses'
    if (Test-Path $gpo) {
        $r.GpoApplied = $true
        $gp = Get-ItemProperty $gpo -ErrorAction SilentlyContinue
        $addrs = @($gp.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "$($_.Value)" } | Where-Object { $_ })
        $r.GpoAddresses = $addrs
        $short = ($fqdn -split '\.')[0]
        $r.InGpo = [bool](@($addrs | Where-Object { $_ -match [regex]::Escape($fqdn) -or $_ -match "(^|//)$([regex]::Escape($short))(\.|:|/|$)" }).Count)
    }

    # RA certificate validity from the FAS PkiCore event log. FAS logs EVERY installed
    # certificate (provider Citrix.Fas.PkiCore, event ID 1) - that is the long-lived
    # RA/authorization certificate AND a short-lived per-logon USER certificate for every
    # session. We only want the RA cert, so we read each cert's validity window and KEEP ONLY
    # long-lived certs: a user logon cert lasts days/weeks, the RA cert lasts 1-2 years. This
    # filters the per-session user certificates out. Deduped by serial (newest kept). Keyed by
    # TrustArea so the report can match it to the active authorization cert. WinRM-readable.
    $minRaValidityDays = 180
    $parseFasDate = {
        param($s)
        if (-not $s) { return $null }
        try { return [datetime]::Parse($s, [Globalization.CultureInfo]::GetCultureInfo('en-US')) } catch {}
        try { return [datetime]$s } catch {}
        return $null
    }
    $raBySerial = [ordered]@{}
    try {
        foreach ($e in @(Get-WinEvent -FilterHashtable @{ ProviderName = 'Citrix.Fas.PkiCore'; Id = 1 } -MaxEvents 1000 -ErrorAction Stop)) {
            $m = "$($e.Message)"
            if ($m -notmatch 'Installed certificate') { continue }
            $ta  = if ($m -match 'TrustArea:\s*([0-9a-fA-F-]{36})')            { $matches[1] } else { '' }
            $sub = if ($m -match '\[Subject\]\s*(.+?)\s*\[Issuer\]')           { $matches[1].Trim() } else { '' }
            $iss = if ($m -match '\[Issuer\]\s*(.+?)\s*\[Serial Number\]')     { $matches[1].Trim() } else { '' }
            $ser = if ($m -match '\[Serial Number\]\s*([0-9A-Fa-f]+)')         { $matches[1] } else { '' }
            $nbR = if ($m -match '\[Not Before\]\s*([\d/]+ [\d:]+ [AP]M)')     { $matches[1] }
                   elseif ($m -match '\[Not Before\]\s*([\d/]+ [\d:]+)')       { $matches[1] } else { '' }
            $naR = if ($m -match '\[Not After\]\s*([\d/]+ [\d:]+ [AP]M)')      { $matches[1] }
                   elseif ($m -match '\[Not After\]\s*([\d/]+ [\d:]+)')        { $matches[1] } else { '' }
            $nbD = & $parseFasDate $nbR
            $naD = & $parseFasDate $naR
            if (-not $naD) { continue }
            # Validity span discriminates RA (long) from user (short) certs. Skip short-lived.
            $validityDays = if ($nbD) { [int][math]::Round(($naD - $nbD).TotalDays) } else { $null }
            if ($null -ne $validityDays -and $validityDays -lt $minRaValidityDays) { continue }
            # No Not Before to measure the span: fall back to time-remaining at install - a real
            # RA cert still has a long run left when logged; a user cert does not.
            if ($null -eq $validityDays -and (($naD - $e.TimeCreated).TotalDays -lt $minRaValidityDays)) { continue }
            $key = if ($ser) { $ser } else { "$sub|$naR" }
            # Newest-first stream, so the first sighting of a serial is the one to keep.
            if (-not $raBySerial.Contains($key)) {
                $raBySerial[$key] = [pscustomobject]@{
                    TrustArea    = $ta; Subject = $sub; Issuer = $iss; Serial = $ser
                    NotBefore    = $(if ($nbD) { $nbD.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
                    NotAfter     = $naD.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    ValidityDays = $validityDays
                    Logged       = $e.TimeCreated.ToUniversalTime().ToString('o')
                }
            }
        }
    } catch { }
    $r.RaCertificates = @($raBySerial.Values)

    [pscustomobject]$r
}

$script:_sampleBlock = {
    $cs = Get-Counter -Counter @(
        '\Processor(_Total)\% Processor Time'
        '\PhysicalDisk(_Total)\Current Disk Queue Length'
        '\PhysicalDisk(_Total)\Disk Bytes/sec'
        '\Network Interface(*)\Bytes Total/sec'
    ) -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
    $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $ramPct = if ($os.TotalVisibleMemorySize) {
        [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 1)
    } else { $null }
    $s   = $cs.CounterSamples
    $cpu = ($s | Where-Object { $_.Path -like '*% processor time*' } | Select-Object -First 1).CookedValue
    $dq  = ($s | Where-Object { $_.Path -like '*current disk queue length*' } | Select-Object -First 1).CookedValue
    $db  = ($s | Where-Object { $_.Path -like '*disk bytes/sec*' } | Select-Object -First 1).CookedValue
    $net = ($s | Where-Object { $_.Path -like '*bytes total/sec*' } | Measure-Object -Property CookedValue -Sum).Sum
    [pscustomobject]@{
        CpuPct       = [math]::Round([double]$cpu, 1)
        RamPct       = $ramPct
        DiskQueueLen = [math]::Round([double]$dq, 2)
        DiskMBps     = [math]::Round([double]$db / 1MB, 2)
        NetMbps      = [math]::Round(([double]$net * 8) / 1e6, 2)
    }
}

# Flatten an object's scalar properties to a name->string ordered map (skips blobs/objects).
function Get-FasFlat ($o) {
    $h = [ordered]@{}
    foreach ($p in $o.PSObject.Properties) {
        $v = $p.Value; if ($null -eq $v) { continue }
        if ($v -is [string] -or $v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [datetime]) {
            $h[$p.Name] = if ($v -is [datetime]) { $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { "$v" }
        }
    }
    $h
}
# FAS user (smartcard-logon) certificate template subject-name policy, for the KB5014754 / strong
# certificate binding check (CTX695393). FACTUAL ONLY - no guessing: the template FAS uses is the one
# named by the FAS certificate definition (from the FAS admin channel, Get-FasCertificateDefinition).
# When the admin channel is not readable we return nothing and the report shows the template as "not
# checked" (never "assumed"). The template's msPKI-Certificate-Name-Flag - read from AD in the
# collector's own domain-authenticated session (any authenticated user can read a template) - tells us
# whether the subject is built from AD (SID-capable, correct) or supplied in the request (weak).
function Get-FasCertTemplateInfo {
    param([object[]]$CertDefinitions = @(), [bool]$AdminReadable)
    $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    if (-not $AdminReadable) { return @() }   # no admin channel -> template unknown, do NOT guess
    $result = @()
    try {
        # The exact template name(s) FAS is configured to use, from its certificate definition(s).
        # NB: the collector builds cert definitions as ordered HASHTABLES (Get-FasFlat), so iterate
        # dictionary Keys - .PSObject.Properties on a dictionary returns the dictionary's own members
        # (Keys/Values/Count), not the entries, and would miss 'MsTemplate'.
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($cd in @($CertDefinitions)) {
            if ($null -eq $cd) { continue }
            if ($cd -is [System.Collections.IDictionary]) {
                foreach ($k in @($cd.Keys)) { if ("$k" -match '(?i)template' -and "$($cd[$k])") { [void]$names.Add("$($cd[$k])") } }
            } else {
                foreach ($p in $cd.PSObject.Properties) { if ($p.Name -match '(?i)template' -and "$($p.Value)") { [void]$names.Add("$($p.Value)") } }
            }
        }
        if ($names.Count -eq 0) { return @() }

        $configNC = "$(([ADSI]'LDAP://RootDSE').configurationNamingContext)"
        if (-not $configNC) { return @() }
        $tplRoot = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

        $seen = @{}
        foreach ($nm in $names) {
            $key = $nm.ToLower(); if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
            $rec = [ordered]@{ Name = $nm; DisplayName = ''; NameFlag = $null; SuppliesSubjectInRequest = $null; BuildFromAd = $null; TemplateSource = 'FAS cert definition'; AdLookup = '' }
            try {
                $ds2 = New-Object System.DirectoryServices.DirectorySearcher($tplRoot, "(cn=$nm)")
                foreach ($pp in 'cn','displayName','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag') { [void]$ds2.PropertiesToLoad.Add($pp) }
                $r = $ds2.FindOne()
                if ($r) {
                    if ($r.Properties['cn'].Count) { $rec['Name'] = "$($r.Properties['cn'][0])" }
                    $rec['DisplayName'] = "$(if ($r.Properties['displayname'].Count) { $r.Properties['displayname'][0] })"
                    $nameFlag = 0; if ($r.Properties['mspki-certificate-name-flag'].Count) { $nameFlag = [int64]$r.Properties['mspki-certificate-name-flag'][0] }
                    $supplies = (($nameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0)
                    $rec['NameFlag'] = $nameFlag; $rec['SuppliesSubjectInRequest'] = $supplies; $rec['BuildFromAd'] = (-not $supplies); $rec['AdLookup'] = 'ok'
                } else {
                    $rec['AdLookup'] = 'template named by FAS was not found in AD'
                }
            } catch { $rec['AdLookup'] = "AD read failed: $(("$_" -replace '\s+',' '))" }
            $result += [pscustomobject]$rec
        }
    } catch { return @() }
    return $result
}
# Best-effort certificate expiry from a FAS object. The RA cert's NotAfter is not a plain
# scalar on Get-FasAuthorizationCertificate, so: (1) try named date fields, (2) parse a
# certificate held as an X509 object / byte[] / base64 string, (3) fall back to any
# DateTime property whose name looks like an expiry. Returns ISO-8601 UTC or ''.
function Get-FasExpiry ($o) {
    $iso = { param($d) ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    foreach ($pn in 'NotAfter','ExpiryDate','CertificateExpiryDate','Expiry','ExpiresAt','ExpiresOn','ValidTo','ExpiryTime','CertificateExpiry','ExpirationDate') {
        $pp = $o.PSObject.Properties[$pn]
        if ($pp -and $pp.Value) { try { return (& $iso $pp.Value) } catch { } }
    }
    foreach ($pn in 'Certificate','RaCertificate','CertificateRequest','RawCertificate','X509Certificate') {
        $pp = $o.PSObject.Properties[$pn]; if (-not $pp -or -not $pp.Value) { continue }
        $v = $pp.Value
        try {
            if ($v -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) { return (& $iso $v.NotAfter) }
            if ($v -is [byte[]]) { return (& $iso ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($v)).NotAfter) }
            if ($v -is [string]) { return (& $iso ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($v))).NotAfter) }
        } catch { }
    }
    # Heuristic: an expiry-looking DateTime property under any name.
    $cand = @($o.PSObject.Properties | Where-Object { $_.Value -is [datetime] -and $_.Name -match 'exp|valid|after|renew' } | Sort-Object { $_.Value })
    if ($cand.Count -gt 0) { try { return (& $iso $cand[0].Value) } catch { } }
    ''
}

# Deep FAS health via the FAS PowerShell snap-in, run in the COLLECTOR's own session
# (not via WinRM-into-the-server, which the FAS admin pipe rejects). Works when the
# snap-in is present: locally on the FAS server (queries localhost, like the console) or
# on a collector that has the FAS SDK installed (queries -Address for GPO-listed servers).
# Returns RA cert / rules / cert definitions / CAs, or a clear status when unavailable.
# Field names are captured defensively (refined from the first reachable-snap-in run).
function Get-FasData ([string]$Address, [bool]$IsLocal, [string[]]$ExtraAddresses = @()) {
    $r = [ordered]@{
        SdkAvailable = $false; AdminReadable = $false
        AuthCerts = @(); RaMonitor = @(); Rules = @(); CertDefinitions = @(); CertAuthorities = @(); Messages = @()
    }
    if ($null -eq $script:_fasSnapin) {
        $script:_fasSnapin = 'missing'
        try { Add-PSSnapin Citrix.Authentication.FederatedAuthenticationService.V1 -ErrorAction Stop; $script:_fasSnapin = 'ok' } catch { }
        if ($script:_fasSnapin -ne 'ok') { try { Import-Module Citrix.Authentication.FederatedAuthenticationService.PowerShell -ErrorAction Stop; $script:_fasSnapin = 'ok' } catch { } }
    }
    $r.SdkAvailable = ($script:_fasSnapin -eq 'ok')
    if (-not $r.SdkAvailable) { $r.Messages = @('FAS PowerShell snap-in not available on the collector - run the collector on the FAS server for RA cert / rules / cert definitions.'); return [pscustomobject]$r }

    # Candidate -Address values. FAS validates the address against its configured/GPO list, which
    # holds FQDNs - a bare short name is rejected ("Unknown server"). Locally: try localhost (admin
    # pipe, bypasses the address check), then this machine's FQDN, then any GPO-listed address that
    # matches this machine's short name. Remotely: the supplied address as-is.
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($IsLocal) {
        [void]$candidates.Add('localhost')
        $short = "$env:COMPUTERNAME"
        try { $fqdn = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName; if ($fqdn) { [void]$candidates.Add($fqdn) } } catch {}
        foreach ($ea in @($ExtraAddresses)) {
            # GPO entries may be bare FQDNs or URLs - reduce to the host part.
            $hostPart = "$ea" -replace '^[a-z]+://', '' -replace '[:/].*$', ''
            if ($hostPart -and $hostPart -match "^(?i)$([regex]::Escape($short))\." ) { [void]$candidates.Add($hostPart) }
        }
    } else {
        [void]$candidates.Add($Address)
    }
    $candidates = @($candidates | Select-Object -Unique)
    $accessDeniedSeen = $false
    foreach ($addr in $candidates) {
        $ok = $false
        try {
            $ac = @(Get-FasAuthorizationCertificate -Address $addr -ErrorAction Stop)
            $r.AuthCerts = @($ac | ForEach-Object { $f = Get-FasFlat $_; $f['Expiry'] = Get-FasExpiry $_; [pscustomobject]$f })
            $ok = $true
        } catch {
            $m = "$_"; $r.Messages += ("AuthCert@${addr}: " + ($m -replace '\s+', ' ')).Substring(0, [Math]::Min(160, ("AuthCert@${addr}: " + $m).Length))
            # FAS authorises the PROCESS TOKEN: a non-elevated session presents a UAC-filtered token
            # and is denied even for local admins. Record the actionable guidance once.
            if (-not $accessDeniedSeen -and $m -match 'Access Denied|FederatedAuthenticationServerFault') {
                $accessDeniedSeen = $true
                $r.Messages += "FAS administration returned Access Denied (collector elevated: $(Test-IsElevated)) - run the collector from an ELEVATED PowerShell on the FAS server with an account authorised to administer FAS (default: the server's local Administrators; check the FAS console if the ACL was customised)."
            }
            continue
        }
        if ($ok) {
            $r.AdminReadable = $true
            # RA certificate monitor - purpose-built for RA cert expiry/renewal tracking.
            try { $r.RaMonitor = @(@(Get-FasRaCertificateMonitor -Address $addr -ErrorAction Stop) | ForEach-Object { $f = Get-FasFlat $_; $f['Expiry'] = Get-FasExpiry $_; [pscustomobject]$f }) } catch { $r.Messages += "RaMonitor: $(("$_" -replace '\s+',' '))" }
            try { $r.Rules           = @(@(Get-FasRule -Address $addr -ErrorAction Stop)                  | ForEach-Object { Get-FasFlat $_ }) } catch { $r.Messages += "Rule: $(("$_" -replace '\s+',' '))" }
            # Cert definition also carries its CertificateAuthorities list (a non-scalar prop
            # that Get-FasFlat drops). Capture the CA count/list explicitly - this is the
            # reliable "how many CAs" signal (Get-FasMsCertificateAuthority can read 0). Used
            # by the FAS-008 certificate-authority-resiliency check.
            try { $r.CertDefinitions = @(@(Get-FasCertificateDefinition -Address $addr -ErrorAction Stop) | ForEach-Object {
                $f = Get-FasFlat $_
                $caList = @($_.CertificateAuthorities | Where-Object { "$_" })
                $f['CaCount'] = $caList.Count
                if ($caList.Count) { $f['CaList'] = ($caList -join '; ') }
                $f
            }) } catch { $r.Messages += "CertDef: $(("$_" -replace '\s+',' '))" }
            try { $r.CertAuthorities = @(@(Get-FasMsCertificateAuthority -Address $addr -ErrorAction Stop)| ForEach-Object { Get-FasFlat $_ }) } catch { $r.Messages += "CA: $(("$_" -replace '\s+',' '))" }
            break
        }
    }
    if (-not $r.AdminReadable -and $r.Messages.Count -eq 0) { $r.Messages = @('FAS admin channel not reachable.') }
    return [pscustomobject]$r
}

# Fast TCP reachability probe for the WinRM HTTP port (5985) with an explicit timeout, so a
# filtered/blocked port fails in a few seconds with a clear reason instead of New-PSSession
# blocking on the default WS-Man open. Uses BeginConnect + a bounded wait (deterministic).
function Test-WinRmPort ([string]$ComputerName, [int]$Port = 5985, [int]$TimeoutMs = 5000) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }   # timed out
        $client.EndConnect($iar)                                               # throws if refused
        return $true
    } catch { return $false } finally { $client.Close() }
}

# Run a scriptblock with a HARD wall-clock timeout in a background runspace, so a call that
# ignores its own timeout (e.g. Test-WSMan, which can sit on a stalled auth handshake even when
# the port is open) cannot hang the collector. Returns @{ TimedOut; Error; Result }.
function Invoke-WithTimeout ([scriptblock]$Script, [int]$TimeoutSec = 15, [object[]]$ArgumentList = @()) {
    $ps = [powershell]::Create()
    try {
        [void]$ps.AddScript($Script)
        foreach ($a in @($ArgumentList)) { [void]$ps.AddArgument($a) }
        $async = $ps.BeginInvoke()
        if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSec))) {
            try { [void]$ps.BeginStop($null, $null) } catch {}   # abandon the stuck call
            return @{ TimedOut = $true; Error = "no response within ${TimeoutSec}s"; Result = $null }
        }
        $res = $ps.EndInvoke($async)
        $err = if ($ps.Streams.Error.Count) { "$($ps.Streams.Error[0])" } else { $null }
        return @{ TimedOut = $false; Error = $err; Result = $res }
    } catch {
        return @{ TimedOut = $false; Error = "$($_.Exception.Message)"; Result = $null }
    } finally {
        # Dispose only if the call actually finished; a timed-out runspace is left to abort.
        if ($async -and $async.IsCompleted) { try { $ps.Dispose() } catch {} }
    }
}

function Invoke-OnPremCollection ([string[]]$ServerList, [int]$DurationMin, [System.Management.Automation.PSCredential]$Cred, [switch]$NoPerf) {
    $files = [System.Collections.Generic.List[string]]::new()
    $intervalSec  = 30
    $sampleCount  = if ($NoPerf) { 0 } else { [math]::Max(1, [int][math]::Round(($DurationMin * 60) / $intervalSec)) }
    $runStamp     = (Get-Date).ToString('yyyyMMdd-HHmmss')   # one stable file name per server per run
    # Explicit open timeout so an unreachable / half-open target fails fast (20s) instead of the
    # collector hanging on New-PSSession's default WS-Man open behaviour.
    # OpenTimeout bounds the connect; OperationTimeout bounds each WS-Man operation (incl. the
    # shell creation during New-PSSession, and every later Invoke-Command). 60s is well above any
    # legitimate single operation here (perf samples are instantaneous; config reads take seconds)
    # but stops a half-hung target from blocking the run for the 3-minute WinRM default.
    $psSessionOption = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000

    # ── Phase 1: connect to every server and collect the static data (spec/versions)
    # once. Each reachable server gets a context whose JSON is then rewritten after every
    # sample tick. Unreachable servers are written out immediately and skipped.
    $contexts = [System.Collections.Generic.List[object]]::new()
    foreach ($server in $ServerList) {
        $isLocal = Test-IsLocalTarget $server
        $display = if ($isLocal) { "$env:COMPUTERNAME (local)" } else { $server }
        $name    = if ($isLocal) { "$env:COMPUTERNAME" } else { $server }
        Set-SplashStatus "Connecting to $display..."
        Set-LiveServerState $server 'Connecting' '#0078D4'

        $swConn = [System.Diagnostics.Stopwatch]::StartNew()   # per-server connect timing (logged)
        $session = $null
        $reached = 'Local'
        if (-not $isLocal) {
            # Staged connect so a failure names the exact step (and can't hang):
            #   1. TCP probe of WinRM port 5985, 2. WS-Man/auth handshake, 3. timed session open.
            $connectFail = $null

            Set-LiveServerStep $server 'Testing WinRM port (TCP 5985)...'
            if (-not (Test-WinRmPort $server)) {
                $connectFail = 'WinRM port 5985 not reachable (TCP connect failed/timed out) - check the WinRM service is running and that the firewall allows the collector (run Enable-WinRMForCollector.ps1 on the target).'
            }

            if (-not $connectFail) {
                Set-LiveServerStep $server 'Testing WinRM service (WS-Man handshake)...'
                # Hard-bounded: Test-WSMan can sit on a stalled auth handshake even when 5985 is
                # open, so run it in a runspace with a wall-clock timeout.
                $wsman = Invoke-WithTimeout -TimeoutSec 15 -ArgumentList @($server, $Cred) -Script {
                    param($s, $c)
                    $p = @{ ComputerName = $s; ErrorAction = 'Stop' }
                    if ($c) { $p['Credential'] = $c }
                    Test-WSMan @p | Out-Null
                }
                if ($wsman.TimedOut) {
                    $connectFail = 'WS-Man did not respond within 15s - port 5985 is open but the auth handshake is not completing (check Kerberos/SPN, DNS name resolution, or the WinRM service health on the target).'
                } elseif ($wsman.Error) {
                    $connectFail = "WS-Man handshake failed: $(($wsman.Error -replace '\s+',' '))"
                }
            }

            if (-not $connectFail) {
                Set-LiveServerStep $server 'Opening remote PowerShell session...'
                # IMPORTANT: create the session in THIS runspace so it stays Open for the whole
                # collection. (A session opened inside a child runspace is Closed when that
                # runspace is disposed - "the session state is Closed".) The wall-clock bound is
                # provided by the session option's Open/Operation timeouts above, not a runspace.
                try {
                    $params = @{ ComputerName = $server; ErrorAction = 'Stop'; SessionOption = $psSessionOption }
                    if ($Cred) { $params['Credential'] = $Cred }
                    $session = New-PSSession @params
                    $reached = 'WinRM'
                } catch { $connectFail = "Session open failed: $(("$($_.Exception.Message)" -replace '\s+',' '))" }
            }

            if ($connectFail) {
                Write-Log "[$server] UNREACHABLE after $([math]::Round($swConn.Elapsed.TotalSeconds,1))s - $connectFail" 'WARN'
                Set-LiveServerStep  $server $connectFail
                Set-LiveServerState $server 'Unreachable' '#D83B01'
                $safe = $name -replace '[^\w\-]', '_'
                Write-OnPremJson -Server $server -ReachedVia 'Unreachable' -Spec $null -Components @() -Roles @() -Samples @() -DurationMin $DurationMin -Files $files -OutFile (Join-Path $script:_outputDir "OnPrem-$safe-$runStamp.json") -Events $null -StoreFront $null -Patch $null -VdaComponents $null -Sessions $null
                continue
            }
        }
        if ($reached -eq 'WinRM') { Write-Log "[$server] WinRM session opened in $([math]::Round($swConn.Elapsed.TotalSeconds,1))s" }

        try {
            Set-LiveServerStep $server 'Reading server spec & Citrix versions...'
            Set-SplashStatus "Collecting spec + versions on $display..."
            $spec  = Invoke-OnTarget $session $script:_specBlock
            $comps = @(Invoke-OnTarget $session $script:_versionBlock)
            $roles = @($comps | ForEach-Object { "$($_.Name)" })
            $safe  = $name -replace '[^\w\-]', '_'
            $roleLabel = if ($roles.Count) { $roles -join ', ' } else { 'No Citrix role detected' }
            if ($NoPerf) { Set-LiveServerState $server 'Collected' '#107C10' -Role $roleLabel }
            else         { Set-LiveServerState $server 'Sampling'  '#0078D4' -Role $roleLabel }

            Set-LiveServerStep $server 'Counting Citrix event-log errors...'
            Set-SplashStatus "Counting Citrix event errors on $display..."
            $events = $null
            try { $events = Invoke-OnTarget $session $script:_eventBlock } catch { Write-Log "Event-log query failed on ${display}: $_" 'WARN' }

            # Windows security-patch currency (all servers).
            Set-LiveServerStep $server 'Checking Windows patch history...'
            $patch = $null
            try { $patch = Invoke-OnTarget $session $script:_patchBlock } catch { Write-Log "Patch query failed on ${display}: $_" 'WARN' }

            # FAS: WinRM baseline (service/config/GPO) + best-effort snap-in deep health.
            $fas = $null
            if ($roles -contains 'FAS') {
                Set-LiveServerStep $server 'Collecting FAS configuration (rules / CAs / RA cert)...'
                Set-SplashStatus "Collecting FAS configuration on $display..."
                $fb = Invoke-OnTarget $session $script:_fasBlock
                $fd = Get-FasData -Address $name -IsLocal $isLocal -ExtraAddresses @($fb.GpoAddresses)
                $fas = [ordered]@{
                    ServiceRunning         = [bool]$fb.ServiceRunning
                    ServiceStartType       = "$($fb.ServiceStartType)"
                    Installed              = [bool]$fb.Installed
                    InstallDir             = "$($fb.InstallDir)"
                    CheckAddressAgainstGpo = $fb.CheckAddressAgainstGpo
                    DefaultToLocalhost     = $fb.DefaultToLocalhost
                    GpoApplied             = [bool]$fb.GpoApplied
                    GpoAddresses           = @($fb.GpoAddresses)
                    InGpo                  = [bool]$fb.InGpo
                    SdkAvailable           = [bool]$fd.SdkAvailable
                    AdminReadable          = [bool]$fd.AdminReadable
                    AuthCerts              = @($fd.AuthCerts)
                    RaMonitor              = @($fd.RaMonitor)
                    RaCertificates         = @($fb.RaCertificates)
                    Rules                  = @($fd.Rules)
                    CertDefinitions        = @($fd.CertDefinitions)
                    CertAuthorities        = @($fd.CertAuthorities)
                    Messages               = @(@($fd.Messages) | Where-Object { $_ })
                }
                # Anchor the RA cert on the LIVE authorization certificate: match the event-log RA
                # cert to it by Serial (preferred) or TrustArea, so the authorization cert shows its
                # real expiry (the cmdlets expose none) and ONLY the current RA cert is kept - any
                # stray RA-class cert in the log that doesn't match the live auth cert is dropped.
                $acSerialOf = {
                    param($o)
                    foreach ($p in $o.PSObject.Properties) { if ($p.Name -match '(?i)serial' -and $p.Value) { return (("$($p.Value)" -replace '[^0-9A-Fa-f]', '').ToUpper()) } }
                    ''
                }
                $normSer = { param($s) ("$s" -replace '[^0-9A-Fa-f]', '').ToUpper() }
                foreach ($ac in @($fas['AuthCerts'])) {
                    $acSer = & $acSerialOf $ac; $acTa = "$($ac.TrustArea)"; $hit = $null
                    if ($acSer) { $hit = @(@($fas['RaCertificates']) | Where-Object { (& $normSer $_.Serial) -eq $acSer } | Sort-Object Logged -Descending | Select-Object -First 1) }
                    if (-not $hit -or -not $hit.Count) { if ($acTa) { $hit = @(@($fas['RaCertificates']) | Where-Object { "$($_.TrustArea)" -and "$($_.TrustArea)" -eq $acTa } | Sort-Object Logged -Descending | Select-Object -First 1) } }
                    if ($hit -and $hit.Count) {
                        if (-not "$($ac.Expiry)" -and "$($hit[0].NotAfter)") { $ac.Expiry = "$($hit[0].NotAfter)" }
                        $ac | Add-Member -NotePropertyName NotAfter  -NotePropertyValue "$($hit[0].NotAfter)"  -Force
                        $ac | Add-Member -NotePropertyName NotBefore -NotePropertyValue "$($hit[0].NotBefore)" -Force
                    }
                }
                # When the live auth cert is known, keep only the event-log RA cert(s) that match it.
                # Safe fallback: if nothing matches (field-name mismatch etc.), keep the set as-is.
                if (@($fas['AuthCerts']).Count -gt 0 -and @($fas['RaCertificates']).Count -gt 0) {
                    $acSers = @(@($fas['AuthCerts']) | ForEach-Object { & $acSerialOf $_ } | Where-Object { $_ })
                    $acTas  = @(@($fas['AuthCerts']) | ForEach-Object { "$($_.TrustArea)" } | Where-Object { $_ })
                    $matched = @(@($fas['RaCertificates']) | Where-Object {
                        $s = & $normSer $_.Serial
                        ($s -and $acSers -contains $s) -or ("$($_.TrustArea)" -and $acTas -contains "$($_.TrustArea)")
                    })
                    if ($matched.Count -gt 0) { $fas['RaCertificates'] = @($matched) }
                }
                # Cert template subject-name policy (KB5014754 / strong certificate binding). Read from
                # AD in the collector's own domain-authenticated session (any authenticated user can
                # read a template; only the WinRM double-hop, not rights, would block it).
                $fas['CertTemplates'] = @(Get-FasCertTemplateInfo -CertDefinitions @($fas['CertDefinitions']) -AdminReadable ([bool]$fas['AdminReadable']))
                if (-not $fas['SdkAvailable']) { $script:_fasSdkMissing = $true }
                Write-Log "FAS ${display}: svc=$($fas['ServiceRunning']) installed=$($fas['Installed']) inGpo=$($fas['InGpo']) sdk=$($fas['SdkAvailable']) adminReadable=$($fas['AdminReadable']) authCerts=$($fas['AuthCerts'].Count) rules=$($fas['Rules'].Count) certDefs=$($fas['CertDefinitions'].Count) certTemplates=$($fas['CertTemplates'].Count)"
                # Raw dump of the deep data so SDK-populated field names can be finalised.
                if ($fas['AdminReadable']) { try { Write-Log ("FAS ${display} raw: " + (@{ AuthCerts = $fas['AuthCerts']; Rules = $fas['Rules']; CertDefinitions = $fas['CertDefinitions']; CertAuthorities = $fas['CertAuthorities'] } | ConvertTo-Json -Depth 6 -Compress)) } catch { } }
                if ($fas['Messages'].Count) { Write-Log ("FAS ${display} messages: " + ($fas['Messages'] -join ' || ')) }
            }

            # StoreFront: deployment, server group, stores, web receiver, gateways, beacons (StoreFront PS modules on the SF server).
            $storeFront = $null
            if ($roles -contains 'StoreFront') {
                Set-LiveServerStep $server 'Collecting StoreFront configuration (stores / SSL / IIS)...'
                Set-SplashStatus "Collecting StoreFront configuration on $display..."
                try {
                    $storeFront = Invoke-OnTarget $session $script:_storeFrontBlock
                    Write-Log "StoreFront ${display}: modules=$($storeFront.ModulesAvailable) baseUrl=$($storeFront.HostBaseUrl) groupMembers=$(@($storeFront.ServerGroupMembers).Count) stores=$(@($storeFront.Stores).Count) webReceivers=$(@($storeFront.WebReceivers).Count) gateways=$(@($storeFront.Gateways).Count)"
                    if (@($storeFront.Messages).Count) { Write-Log ("StoreFront ${display} messages: " + (@($storeFront.Messages) -join ' || ')) }
                } catch { Write-Log "StoreFront collection failed on ${display}: $_" 'WARN' }
            }

            # VDA: inventory of co-installed Citrix products.
            $vdaComponents = $null
            $sessions = $null
            if ($roles -contains 'VDA') {
                Set-LiveServerStep $server 'Collecting VDA components & sessions...'
                Set-SplashStatus "Collecting VDA components on $display..."
                try { $vdaComponents = @(Invoke-OnTarget $session $script:_vdaComponentsBlock) } catch { Write-Log "VDA component query failed on ${display}: $_" 'WARN' }
                try { $sessions = Invoke-OnTarget $session $script:_sessionBlock } catch { Write-Log "VDA session query failed on ${display}: $_" 'WARN' }
                Write-Log "VDA ${display}: citrixProducts=$(@($vdaComponents).Count) sessions=$($sessions.Total)"
            }

            # PVS: farm config (name/description, license server + status, member servers) via the PVS snap-in.
            $pvs = $null
            if ($roles -contains 'Provisioning Server') {
                Set-LiveServerStep $server 'Collecting PVS farm configuration...'
                Set-SplashStatus "Collecting PVS farm configuration on $display..."
                try {
                    $pvs = Invoke-OnTarget $session $script:_pvsBlock
                    Write-Log "PVS ${display}: sdk=$($pvs.SdkAvailable) farm='$($pvs.FarmName)' licSrv=$($pvs.LicenseServerName) licOk=$($pvs.LicenseOk) servers=$(@($pvs.Servers).Count)"
                    if (@($pvs.Messages).Count) { Write-Log ("PVS ${display} messages: " + (@($pvs.Messages) -join ' || ')) }
                } catch { Write-Log "PVS collection failed on ${display}: $_" 'WARN' }
            }

            $ctx = [ordered]@{
                Server        = $server
                Display       = $display
                Session       = $session
                Reached       = $reached
                Spec          = $spec
                Comps         = $comps
                Roles         = $roles
                Fas           = $fas
                Events        = $events
                StoreFront    = $storeFront
                Pvs           = $pvs
                Patch         = $patch
                VdaComponents = $vdaComponents
                Sessions      = $sessions
                OutFile       = Join-Path $script:_outputDir "OnPrem-$safe-$runStamp.json"
                Samples       = [System.Collections.Generic.List[object]]::new()
            }
            # Write an initial file (0 samples) so it exists straight away.
            Write-OnPremJson -Server $server -ReachedVia $reached -Spec $spec -Components $comps -Roles $roles -Samples $ctx['Samples'] -DurationMin $DurationMin -Files $files -OutFile $ctx['OutFile'] -Fas $fas -Events $events -StoreFront $storeFront -Pvs $pvs -Patch $patch -VdaComponents $vdaComponents -Sessions $sessions
            [void]$contexts.Add($ctx)
            Set-LiveServerStep $server $(if ($NoPerf) { 'Static data collected.' } else { "Static data collected - sampling performance every ${intervalSec}s..." })
        } catch {
            Write-Log "Setup failed on ${display}: $_" 'ERROR'
            Set-LiveServerStep  $server "Setup failed: $(("$($_.Exception.Message)" -replace '\s+',' '))"
            Set-LiveServerState $server 'Error' '#D83B01'
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        }
    }

    # ── Phase 2: interleaved sampling - one sample from EVERY server per tick, so all
    # servers are measured over the same window. Each server's JSON is rewritten as it
    # goes, so the file on disk is always valid and current even if the run is interrupted.
    if ($contexts.Count -gt 0) {
        for ($i = 0; $i -lt $sampleCount; $i++) {
            Set-SplashStatus "Sampling all servers (tick $($i + 1) of $sampleCount)..."
            Set-LiveStatus "Sampling - tick $($i + 1) of $sampleCount (every ${intervalSec}s)..."
            foreach ($ctx in $contexts) {
                try {
                    $smp = Invoke-OnTarget $ctx['Session'] $script:_sampleBlock
                    $entry = [ordered]@{
                        Timestamp    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                        CpuPct       = $smp.CpuPct
                        RamPct       = $smp.RamPct
                        DiskQueueLen = $smp.DiskQueueLen
                        DiskMBps     = $smp.DiskMBps
                        NetMbps      = $smp.NetMbps
                    }
                    # VDA only: sample the live session count into the perf series.
                    $sessCount = -1
                    if ($ctx['Roles'] -contains 'VDA') {
                        try { $ss = Invoke-OnTarget $ctx['Session'] $script:_sessionBlock; $sessCount = [int]$ss.Total; $entry['Sessions'] = $sessCount } catch {}
                    }
                    [void]$ctx['Samples'].Add($entry)
                    Update-LiveSample $ctx['Server'] $smp.CpuPct $smp.RamPct $smp.DiskQueueLen $smp.DiskMBps $smp.NetMbps $sessCount
                    Write-OnPremJson -Server $ctx['Server'] -ReachedVia $ctx['Reached'] -Spec $ctx['Spec'] -Components $ctx['Comps'] -Roles $ctx['Roles'] -Samples $ctx['Samples'] -DurationMin $DurationMin -Files $files -OutFile $ctx['OutFile'] -Fas $ctx['Fas'] -Events $ctx['Events'] -StoreFront $ctx['StoreFront'] -Pvs $ctx['Pvs'] -Patch $ctx['Patch'] -VdaComponents $ctx['VdaComponents'] -Sessions $ctx['Sessions']
                } catch { Write-Log "Sample $($i + 1) failed on $($ctx['Display']): $_" 'WARN' }
            }
            if ($i -lt ($sampleCount - 1)) { Start-SleepResponsive ($intervalSec - 1) }   # -1 for the Get-Counter second
        }
    }

    # ── Phase 3: files are already final (last tick wrote them); just close sessions.
    foreach ($ctx in $contexts) {
        Set-LiveServerState $ctx['Server'] 'Done' '#107C10'
        if ($ctx['Session']) { Remove-PSSession $ctx['Session'] -ErrorAction SilentlyContinue }
    }
    return $files
}

# Build the per-server output object and write it to a JSON file. $OutFile is a stable
# path computed once per server, so repeated calls (one per sample tick) overwrite the
# same file in place rather than creating a new timestamped file each time.
function Write-OnPremJson ($Server, [string]$ReachedVia, $Spec, $Components, $Roles, $Samples, [int]$DurationMin, $Files, [string]$OutFile, $Fas, $Events, $StoreFront, $Pvs, $Patch, $VdaComponents, $Sessions) {
    $name = if (Test-IsLocalTarget $Server) { "$env:COMPUTERNAME" } else { $Server }
    $disks = @(if ($Spec) { $Spec.Disks } )

    $now = Get-Date
    $output = [ordered]@{
        SchemaType       = 'OnPrem'
        GeneratedAt      = $now.ToString('o')
        CollectorVersion = $script:_version
        ComputerName     = $name
        ReachedVia       = $ReachedVia
        OS = [ordered]@{
            Caption = if ($Spec) { "$($Spec.OSCaption)" } else { '' }
            Version = if ($Spec) { "$($Spec.OSVersion)" } else { '' }
        }
        Spec = [ordered]@{
            CpuModel    = if ($Spec) { "$($Spec.CpuModel)" } else { '' }
            Sockets     = if ($Spec) { [int]$Spec.Sockets } else { 0 }
            Cores       = if ($Spec) { [int]$Spec.Cores } else { 0 }
            Logical     = if ($Spec) { [int]$Spec.Logical } else { 0 }
            MaxClockMHz = if ($Spec) { [int]$Spec.MaxClockMHz } else { 0 }
            RamGB       = if ($Spec -and $null -ne $Spec.RamGB) { [double]$Spec.RamGB } else { 0 }
            Disks       = @($disks | ForEach-Object {
                [ordered]@{ Drive = "$($_.Drive)"; SizeGB = [double]$_.SizeGB; FreeGB = [double]$_.FreeGB; UsedPct = [double]$_.UsedPct }
            })
        }
        Roles = @($Roles | Where-Object { $_ })
        CitrixComponents = @(@($Components) | Where-Object { $_ -and "$($_.Name)" } | ForEach-Object {
            [ordered]@{ Name = "$($_.Name)"; Product = "$($_.Product)"; Version = "$($_.Version)"; CvadRelease = "$($_.CvadRelease)" }
        })
        Monitoring = [ordered]@{
            IntervalSeconds = 30
            DurationMinutes = $DurationMin
            SampleCount     = @($Samples).Count
            StartTime       = if (@($Samples).Count -gt 0) { "$(@($Samples)[0]['Timestamp'])" } else { '' }
            EndTime         = if (@($Samples).Count -gt 0) { "$(@($Samples)[-1]['Timestamp'])" } else { '' }
        }
        PerfSamples = @($Samples)
    }
    if ($Events) {
        $output['EventErrors'] = [ordered]@{
            Count24h    = [int]$Events.Count24h
            Count7d     = [int]$Events.Count7d
            WindowHours = [int]$Events.WindowHours
            WindowDays  = [int]$Events.WindowDays
            LogsScanned = @($Events.LogsScanned | Where-Object { $_ })
        }
        # Local Host Cache activation is only meaningful on a Cloud Connector.
        if (@($Roles) -contains 'Cloud Connector') {
            $output['LocalHostCache'] = [ordered]@{
                Activated       = [bool]$Events.LhcActivated
                ActivationCount = [int]$Events.LhcCount
                LastActivation  = "$($Events.LhcLast)"
                InOutageNow     = [bool]$Events.LhcInOutage
                WindowDays      = [int]$Events.WindowDays
            }
        }
    }
    if ($Patch) {
        $output['Patching'] = [ordered]@{
            LastPatch   = "$($Patch.LastPatch)"
            HotfixCount = [int]$Patch.HotfixCount
            Recent      = @(@($Patch.Recent) | ForEach-Object { [ordered]@{ Id = "$($_.Id)"; Description = "$($_.Description)"; InstalledOn = "$($_.InstalledOn)" } })
        }
    }
    if ($VdaComponents) {
        $output['VdaComponents'] = @(@($VdaComponents) | Where-Object { "$($_.Name)" } | ForEach-Object { [ordered]@{ Name = "$($_.Name)"; Version = "$($_.Version)" } })
    }
    if ($Sessions) {
        $output['Sessions'] = [ordered]@{
            Total        = [int]$Sessions.Total
            Active       = [int]$Sessions.Active
            Disconnected = [int]$Sessions.Disconnected
            Users        = @($Sessions.Users | Where-Object { $_ })
        }
    }
    if ($Fas) { $output['Fas'] = $Fas }
    if ($StoreFront) { $output['StoreFront'] = $StoreFront }
    if ($Pvs) { $output['Pvs'] = $Pvs }

    if ($OutFile) {
        $outFile = $OutFile
    } else {
        $safeName = $name -replace '[^\w\-]', '_'
        $outFile  = Join-Path $script:_outputDir "OnPrem-$safeName-$($now.ToString('yyyyMMdd-HHmmss')).json"
    }
    # Opt-in encryption: swap the extension to .cdenc and wrap the JSON with the run password.
    $encrypt = ($script:_encryptPassword -and $script:_encryptPassword.Length -gt 0)
    if ($encrypt) { $outFile = [System.IO.Path]::ChangeExtension($outFile, 'cdenc') }
    try {
        $json = $output | ConvertTo-Json -Depth 12
        if ($encrypt) { $json = Protect-CitrixData $json $script:_encryptPassword }
        Set-Content -Path $outFile -Value $json -Encoding UTF8
        # Each server's file is rewritten every tick; record it in $Files only once.
        if (-not $Files.Contains($outFile)) {
            Write-Log "Output written: $outFile (reached=$ReachedVia, samples=$(@($Samples).Count))"
            [void]$Files.Add($outFile)
        }
    } catch {
        Write-Log "Failed to write JSON for ${name}: $_" 'ERROR'
    }
}

#endregion

#region ── Entry Point ────────────────────────────────────────────────────────

Start-DebugLog

# Offer to self-update from GitHub before doing anything (interactive only; fail-safe / optional).
Invoke-OnPremUpdateCheck

$targets  = $Servers
$duration = $DurationMinutes
$cred     = $Credential
$customer = $Customer

$liveView = [bool]$LiveView
$noPerf   = [bool]$NoPerf
$script:_encryptPassword = $EncryptPassword   # CLI param; the dialog can also set it below
if (-not $targets) {
    $sel = Show-OnPremDialog
    if ($sel['Action'] -eq 'Cancel') { Write-Log 'User cancelled at launch dialog'; exit 0 }
    $targets  = $sel['Servers']
    $duration = $sel['DurationMinutes']
    $cred     = $sel['Credential']
    if (-not $customer) { $customer = $sel['Customer'] }
    $liveView = [bool]$sel['LiveView']
    $noPerf   = [bool]$sel['NoPerf']
    if ($sel['EncryptPassword']) { $script:_encryptPassword = $sel['EncryptPassword'] }
} else {
    $targets = @($targets | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($targets.Count -eq 0) { $targets = @('localhost') }
}
Write-Log "Output encryption: $(if ($script:_encryptPassword -and $script:_encryptPassword.Length -gt 0) { 'on (.cdenc)' } else { 'off (plaintext .json)' })"

# De-duplicate the target list (case-insensitive, order-preserving) so a server entered twice
# doesn't double-collect or create an orphan "Pending" row in the live view.
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$targets = @($targets | ForEach-Object { "$_".Trim() } | Where-Object { $_ -and $seen.Add($_) })

# Elevation check. Reading IIS bindings / the SSL certificate and the StoreFront / FAS / PVS admin
# cmdlets needs an elevated (local-administrator) token. For a LOCAL target that means running THIS
# script elevated; remote (WinRM) targets instead use the supplied credential's rights on the target,
# so local elevation does not gate those. Warn (don't block) when a local target would be collected
# without admin, since that data would silently come back incomplete.
$isElevated = Test-IsElevated
$localNames = @('localhost', '127.0.0.1', '::1', '.', "$env:COMPUTERNAME")
$hasLocalTarget = @($targets | Where-Object { $_ -in $localNames -or "$_" -like "$env:COMPUTERNAME.*" }).Count -gt 0
Write-Log "Elevated=$isElevated; localTarget=$hasLocalTarget"
if (-not $isElevated) {
    if ($hasLocalTarget) {
        Write-Log $script:_adminWarnText 'WARN'
        Write-Host "`n  ! $script:_adminWarnText`n" -ForegroundColor Yellow
    } else {
        Write-Log 'Not elevated, but all targets are remote - remote collection uses the supplied credential''s rights on each target (a local admin there gets the full token over WinRM).'
    }
}

# Group outputs in a per-customer subfolder (when a customer is supplied).
$safeCustomer = ("$customer" -replace '[^\w\-. ]', '_').Trim().TrimEnd('.')
if ($safeCustomer) { $script:_outputDir = Join-Path $script:_outputDir $safeCustomer }
if (-not (Test-Path $script:_outputDir)) { New-Item -ItemType Directory -Path $script:_outputDir -Force | Out-Null }

# Live dashboard (opt-in, GUI only) runs collection in a background runspace so the window stays
# responsive; the plain splash / headless paths run synchronously on this thread.
$useLive = $liveView -and -not $noPerf -and -not $script:_noSplash
Write-Log "Targets: $($targets -join ', '); duration=$(if ($noPerf) { 'n/a (NoPerf)' } else { "${duration}m" }); cred=$([bool]$cred); noSplash=$([bool]$NoSplash); liveView=$useLive"
if ($useLive) { Show-LiveView -Servers $targets } else { Show-Splash }
$files = Invoke-OnPremCollection -ServerList $targets -DurationMin $duration -Cred $cred -NoPerf:$noPerf
if (-not $useLive) { Close-Splash }

# FAS server(s) found but the FAS PowerShell SDK isn't on this collector machine: the
# WinRM baseline (service / GPO / config) was still captured, but deep cert health needs
# the snap-in. Prompt once (install the SDK here, or run the collector on the FAS server).
if ($script:_fasSdkMissing) {
    Show-MsgBox ("A FAS server was found, but the Citrix FAS PowerShell SDK is not installed on this machine.`n`n" +
        "Service state, GPO/config and version were still collected over WinRM. To also capture the RA certificate, rules and certificate definitions, either install the FAS PowerShell SDK on this machine, or run the collector on the FAS server itself.") -Icon Warning
}

$fileCount = @($files).Count
if ($fileCount -gt 0) {
    $msg  = "On-premises collection complete.`n`n$fileCount file(s) written to:`n$script:_outputDir`n`nUse the report's -OnPremFiles parameter (or the dialog picker) to include them."
    $icon = 'Info'
} else {
    $msg  = 'No data files were written. See OnPremComponentsData-Debug.log for details.'
    $icon = 'Warning'
}
if ($useLive -and $script:_liveWin) {
    # Leave the live window up for review; block (pumping) until the user closes it.
    Set-LiveStatus "Collection complete - $fileCount file(s) in $script:_outputDir. Close this window when done."
    # Stop the indeterminate progress animation now that collection has finished.
    if ($script:_liveBar) { $script:_liveWin.Dispatcher.Invoke([Action]{ $script:_liveBar.IsIndeterminate = $false; $script:_liveBar.Value = 100 }, [System.Windows.Threading.DispatcherPriority]::Render) }
    while (-not $script:_liveClosed) {
        try { if (-not $script:_liveWin.IsVisible) { break }; $script:_liveWin.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background) } catch { break }
        Start-Sleep -Milliseconds 150
    }
    Close-LiveView
} else {
    Show-MsgBox $msg -Icon $icon
}
Write-Log 'On-premises collector finished'

#endregion


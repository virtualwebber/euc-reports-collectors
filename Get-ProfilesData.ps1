#Requires -Version 5.1
# Version: 2026-07-09.2   (keep in lock-step with $script:_version below and the published .version file)
<#
.SYNOPSIS
    Collects raw data about user-profile storage shares (FSLogix / Citrix Profile Management) for
    health-check reporting. Supports Azure Files shares and traditional on-premises SMB shares.

.DESCRIPTION
    For each share this collector records FACTS ONLY (analysis happens in the report):
      - Share permissions (best-effort): SMB share ACL via CIM on the file server (needs admin
        there); for Azure Files, the RBAC role assignments on the storage account plus share
        properties (quota, usage, identity-based-auth settings) via the ARM REST API.
      - Root NTFS permissions: owner + SDDL + access rules (Get-Acl over SMB; for Azure Files with
        no SMB reachability, the root SDDL is fetched over the File REST API).
      - Folder inventory: every top-level folder with its RECURSIVE total size / file count, its
        immediate files and subfolders with sizes, and (with -FullInventory) every file recursively.
      - Product evidence: raw hints (VHD/VHDX counts, SID-pattern folder names, UPM_* markers) that
        indicate FSLogix or Citrix Profile Management.

    Azure access uses REST APIs authenticated with Az.Accounts only (Get-AzAccessToken), the same
    pattern as the AVD collector. Azure Files data access requires the caller to hold a Storage File
    Data role (e.g. Storage File Data SMB Share Reader for SMB, or Storage File Data Privileged
    Reader for the REST fallback) and ARM read on the storage account for RBAC/share properties.
    On-premises share ACLs require admin rights on the file server; NTFS reads require at least
    read access on the share. Every failure is recorded per-share and never aborts the run.

.PARAMETER Shares
    One or more share paths (UNC or local). An optional product hint can be appended after a pipe,
    e.g. '\\filesrv1\Profiles|CPM' or '\\acct.file.core.windows.net\fslogix|FSLogix'.
    Omit to use the launch dialog.

.PARAMETER Customer
    Customer name; groups the output under Outputs\<Customer> and prefixes the file name.

.PARAMETER OutputPath
    Override the output folder (default: Outputs\ next to this script).

.PARAMETER FullInventory
    List EVERY file recursively (relative path + size) per top-level folder, instead of only the
    immediate files/subfolders. Can be slow and produce large JSON on big CPM shares.

.PARAMETER EncryptPassword
    Optional: encrypt the output with this password (writes <name>.cdenc instead of .json).
    OFF by default - omit it and the output stays plaintext .json.

.PARAMETER NoSplash
    Headless - suppress the WPF splash and message boxes (status still goes to the console and
    ProfilesData-Debug.log). For command-line / scripted use.

.EXAMPLE
    .\Get-ProfilesData.ps1
    # Interactive - shows the launch dialog

.EXAMPLE
    .\Get-ProfilesData.ps1 -Shares '\\filesrv1\Profiles$|CPM','\\stacct.file.core.windows.net\fslogix|FSLogix' -Customer 'Contoso' -NoSplash
#>

[CmdletBinding()]
param(
    [string[]]$Shares,
    [string]$Customer,
    [string]$OutputPath,
    [switch]$FullInventory,
    # Optional: encrypt the collected data file with this password (writes <name>.cdenc instead of
    # .json). OFF by default - omit it and output stays plaintext .json.
    [System.Security.SecureString]$EncryptPassword,
    [switch]$NoSplash,
    # Skip the launch-time GitHub self-update check (also skipped automatically with -NoSplash).
    [switch]$SkipUpdateCheck
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

#region ── Assemblies & Script-Scope Globals ──────────────────────────────────

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

$script:_version      = '2026-07-09.2'
# Self-update source (public euc-reports-collectors repo): the launch check reads a TINY .version file
# (a few bytes); the full script downloads only when a newer version exists AND the user accepts. Keep
# the '# Version:' header, this $script:_version, and the published .version file in lock-step per release.
$script:_updateVersionUrl = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/Get-ProfilesData.version'
$script:_updateScriptUrl  = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/Get-ProfilesData.ps1'
$script:_scriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:_outputDir    = if ($OutputPath) { $OutputPath } else { Join-Path $script:_scriptDir 'Outputs' }
$script:_debugLogPath = Join-Path $script:_scriptDir 'ProfilesData-Debug.log'
$script:_splash       = $null
$script:_noSplash     = [bool]$NoSplash
$script:_splashStatus = $null
$script:_encryptPassword = $null   # set from -EncryptPassword or the launch dialog; $null = plaintext

if (-not (Test-Path $script:_outputDir)) { New-Item -ItemType Directory -Path $script:_outputDir -Force | Out-Null }

# DWM P/Invoke for square corners on Windows 11
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class ProfilesDwm {
    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
}
'@
} catch {}

$script:_dwmAttr   = 33
$script:_dwmSquare = 1

# GetDiskFreeSpaceEx P/Invoke: read a path's hosting-volume capacity + free space. Works on UNC shares
# over SMB with only read access (no admin/remoting on the file server) and on local paths.
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ProfilesDisk {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetDiskFreeSpaceEx(string lpDirectoryName, out ulong lpFreeBytesAvailable, out ulong lpTotalNumberOfBytes, out ulong lpTotalNumberOfFreeBytes);
}
'@
} catch {}

# Returns @{ CapacityBytes; FreeBytes } for the volume hosting $Path, or $null if it can't be read.
function Get-PathCapacity ([string]$Path) {
    if (-not $Path) { return $null }
    $dir = if ($Path.EndsWith('\')) { $Path } else { "$Path\" }
    try {
        $free = [uint64]0; $total = [uint64]0; $totalFree = [uint64]0
        if ([ProfilesDisk]::GetDiskFreeSpaceEx($dir, [ref]$free, [ref]$total, [ref]$totalFree)) {
            return @{ CapacityBytes = [long]$total; FreeBytes = [long]$totalFree }
        }
    } catch {}
    return $null
}

function Set-SquareCorners ([System.Windows.Window]$Window) {
    $Window.Add_SourceInitialized({
        param($s, $e)
        try {
            $h = (New-Object System.Windows.Interop.WindowInteropHelper($s)).Handle
            [void][ProfilesDwm]::DwmSetWindowAttribute($h, $script:_dwmAttr, [ref]$script:_dwmSquare, 4)
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

function Invoke-ProfilesUpdateCheck {
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
        if ($content.Length -lt 20000 -or $content -notmatch 'Get-ProfilesData' -or $content -notmatch "\`$script:_version\s*=\s*'([^']+)'") {
            Show-MsgBox 'Could not download a valid update; keeping the current version.' -Icon Warning
            Write-Log 'Update check: downloaded script not recognised - aborting' 'WARN'; return
        }
        # Validate the download parses before replacing anything.
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ProfilesCollector-$([guid]::NewGuid().ToString('N')).ps1")
        Set-Content -Path $tmp -Value $content -Encoding UTF8
        $tk = $null; $perr = $null
        [System.Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$tk, [ref]$perr) | Out-Null
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        if ($perr -and $perr.Count) { Show-MsgBox 'The downloaded update did not validate (parse errors). Keeping the current version.' -Icon Warning; Write-Log 'Update check: downloaded content failed to parse - aborting' 'WARN'; return }
        try {
            Copy-Item -LiteralPath $self -Destination "$self.bak" -Force -ErrorAction SilentlyContinue
            Set-Content -Path $self -Value $content -Encoding UTF8
        } catch {
            $alt = Join-Path (Split-Path $self -Parent) 'Get-ProfilesData.NEW.ps1'
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

#region ── Data-file encryption (opt-in, self-contained) ──────────────────────
# Portable password-based encryption for the output data file. OFF unless -EncryptPassword is given.
# AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC); PBKDF2 (Rfc2898DeriveBytes 3-arg SHA1 form - identical
# on .NET Framework 5.1 and .NET Core 7, so a .cdenc file decrypts on the report/app service). Shared
# .cdenc format with the other EUC reports. The password is never written to the file or a log.
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
        "User Profiles Data Collector  v$($script:_version)"
        "Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        "User    : $env:USERDOMAIN\$env:USERNAME"
        "Machine : $env:COMPUTERNAME"
        '=' * 70
    ) -join "`n") -ErrorAction SilentlyContinue
    Write-Log 'Profiles collector starting'
}

#endregion

#region ── WPF Helpers (message box + splash) ─────────────────────────────────

function Show-MsgBox {
    param(
        [string]$Message,
        [string]$Title = 'User Profiles Collector',
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

function Show-Splash {
    if ($script:_noSplash) { Write-Log 'Headless (-NoSplash): splash suppressed'; return }
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="User Profiles Collector" Height="170" Width="460"
        WindowStartupLocation="CenterScreen" WindowStyle="None"
        AllowsTransparency="True" Background="Transparent" Topmost="True"
        ShowInTaskbar="True" FontFamily="Segoe UI">
    <Border CornerRadius="6" Background="White" BorderBrush="#DDE1E7" BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect BlurRadius="24" ShadowDepth="3" Opacity="0.12" Color="#000000"/>
        </Border.Effect>
        <StackPanel VerticalAlignment="Center" Margin="32,24">
            <TextBlock Text="User Profiles - Data Collector"
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
    [void]$script:_splash.Activate()
    $script:_splash.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    $script:_splash.Topmost = $false
    Write-Log 'Splash shown'
}

function Set-SplashStatus ([string]$Message) {
    Write-Log $Message
    if ($script:_splash -and $script:_splashStatus) {
        $script:_splash.Dispatcher.Invoke([Action]{ $script:_splashStatus.Text = $Message },
            [System.Windows.Threading.DispatcherPriority]::Send)
        $script:_splash.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    }
}

function Close-Splash {
    if ($script:_splash) {
        try { $script:_splash.Close() } catch {}
        $script:_splash = $null
    }
}

#endregion

#region ── Azure REST helpers (Az.Accounts auth only - same pattern as the AVD collector) ──

$script:ApiVersions = @{
    Subscriptions = '2022-12-01'
    Storage       = '2023-01-01'
    Authorization = '2022-04-01'
    FileData      = '2022-11-02'   # x-ms-version for the File service data plane
}
$script:_armTokenCache = @{}

# True when Az.Accounts is importable AND an authenticated context exists.
function Test-AzContextAvailable {
    try {
        if (-not (Get-Module -ListAvailable -Name Az.Accounts)) { return $false }
        Import-Module Az.Accounts -ErrorAction Stop | Out-Null
        return [bool](Get-AzContext -ErrorAction SilentlyContinue)
    } catch { return $false }
}

function Get-ArmToken {
    param([string]$ResourceUrl = 'https://management.azure.com/')
    $cached = $script:_armTokenCache[$ResourceUrl]
    if ($cached -and $cached['ExpiresOn'] -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) { return $cached['Token'] }
    $tok = $null
    try   { $tok = Get-AzAccessToken -ResourceUrl $ResourceUrl -AsSecureString -ErrorAction Stop }
    catch { $tok = Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop }
    $plain = if ($tok.PSObject.Properties['Token'] -and $tok.Token -is [securestring]) {
        [System.Net.NetworkCredential]::new('', $tok.Token).Password
    } elseif ($tok.PSObject.Properties['Token']) { [string]$tok.Token } else { [string]$tok }
    $expiry = if ($tok.PSObject.Properties['ExpiresOn']) { $tok.ExpiresOn } else { [DateTimeOffset]::UtcNow.AddHours(1) }
    $script:_armTokenCache[$ResourceUrl] = @{ Token = $plain; ExpiresOn = $expiry }
    return $plain
}

function Invoke-ArmRestMethod {
    param(
        [string]$Method = 'GET', [string]$Path, [string]$Token, [object]$Body,
        [string]$ApiVersion, [switch]$FullResponse, [int]$MaxRetries = 3,
        [string]$BaseUri = 'https://management.azure.com'
    )
    $uri = if ($Path.StartsWith('https://')) { $Path } else { "$BaseUri$Path" }
    if ($ApiVersion -and $uri -notmatch 'api-version=') {
        $sep = if ($uri.Contains('?')) { '&' } else { '?' }
        $uri = "$uri${sep}api-version=$ApiVersion"
    }
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    $all = [System.Collections.Generic.List[object]]::new()
    $cur = $uri
    do {
        $resp = $null
        for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
            try {
                $irm = @{ Method = $Method; Uri = $cur; Headers = $headers; ErrorAction = 'Stop'; TimeoutSec = 30 }
                if ($Body) { $irm['Body'] = if ($Body -is [string]) { $Body } else { ConvertTo-Json $Body -Depth 10 -Compress } }
                $resp = Invoke-RestMethod @irm; break
            } catch {
                $sc = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
                if (($sc -eq 429 -or ($sc -ge 500 -and $sc -lt 600)) -and $attempt -lt $MaxRetries) {
                    Start-Sleep -Seconds ([Math]::Pow(2, $attempt)); continue
                }
                throw
            }
        }
        if ($FullResponse -or $Method -ne 'GET') { return $resp }
        $hasValue    = $resp -and $resp.PSObject.Properties['value']
        $hasNextLink = $resp -and $resp.PSObject.Properties['nextLink']
        if ($hasValue) { foreach ($item in $resp.value) { $all.Add($item) } }
        elseif ($resp -and -not $hasNextLink) { return $resp }
        $cur = if ($hasNextLink -and $resp.nextLink) { $resp.nextLink } else { $null }
    } while ($cur)
    return $all.ToArray()
}

# Find the storage account resource (id/subscription/resourceGroup/properties) by ACCOUNT NAME across
# all subscriptions the signed-in context can see. Returns $null when not found/visible.
function Find-ArmStorageAccount ([string]$AccountName, [string]$Token) {
    $subs = @(Invoke-ArmRestMethod -Path '/subscriptions' -Token $Token -ApiVersion $script:ApiVersions.Subscriptions)
    foreach ($sub in $subs) {
        try {
            $accts = @(Invoke-ArmRestMethod -Path "/subscriptions/$($sub.subscriptionId)/providers/Microsoft.Storage/storageAccounts" -Token $Token -ApiVersion $script:ApiVersions.Storage)
            $hit = $accts | Where-Object { "$($_.name)" -ieq $AccountName } | Select-Object -First 1
            if ($hit) { return $hit }
        } catch { Write-Log "Storage lookup in sub $($sub.subscriptionId) failed: $($_.Exception.Message)" 'WARN' }
    }
    return $null
}

function Get-ArmRoleAssignments { param([string]$ResourceId, [string]$Token)
    @(Invoke-ArmRestMethod -Path "$ResourceId/providers/Microsoft.Authorization/roleAssignments?`$filter=atScope()" -Token $Token -ApiVersion $script:ApiVersions.Authorization)
}
function Get-ArmRoleDefinitions { param([string]$SubscriptionId, [string]$Token)
    $defs = @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions" -Token $Token -ApiVersion $script:ApiVersions.Authorization)
    $map = @{}; foreach ($d in $defs) { $map[$d.name] = $d.properties.roleName }; return $map
}
function Get-ArmFileShareProps { param([string]$AccountId, [string]$ShareName, [string]$Token)
    try { Invoke-ArmRestMethod -Path "$AccountId/fileServices/default/shares/$ShareName`?`$expand=stats" -Token $Token -ApiVersion $script:ApiVersions.Storage } catch { $null }
}
function Get-ArmStorageAccountKey { param([string]$AccountId, [string]$Token)
    try { $r = Invoke-ArmRestMethod -Method POST -Path "$AccountId/listKeys" -Token $Token -ApiVersion $script:ApiVersions.Storage -FullResponse; $r.keys[0].value } catch { $null }
}

# Best-effort: resolve principal ids to display names/types via Microsoft Graph (getByIds).
function Resolve-GraphPrincipals ([string[]]$Ids) {
    $out = @{}
    if (-not $Ids -or $Ids.Count -eq 0) { return $out }
    try {
        $gtok = Get-ArmToken -ResourceUrl 'https://graph.microsoft.com/'
        $body = @{ ids = @($Ids | Select-Object -Unique) } | ConvertTo-Json
        $resp = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' `
                    -Headers @{ Authorization = "Bearer $gtok"; 'Content-Type' = 'application/json' } -Body $body -ErrorAction Stop
        foreach ($o in @($resp.value)) {
            $t = "$($o.'@odata.type')" -replace '^#microsoft\.graph\.', ''
            $out["$($o.id)"] = @{ Name = "$($o.displayName)"; Type = $t }
        }
    } catch { Write-Log "Graph principal resolution failed: $($_.Exception.Message)" 'WARN' }
    return $out
}

# Shared Key authorization header for the File service data plane (fallback when no data-plane RBAC).
function New-StorageSharedKeyAuth {
    param([string]$AccountName, [string]$AccountKey, [string]$Method, [string]$Uri, [hashtable]$XmsHeaders)
    $date    = [DateTime]::UtcNow.ToString('R')
    $allXms  = $XmsHeaders.Clone()
    $allXms['x-ms-date'] = $date
    $uriObj    = [Uri]$Uri
    $canonHdrs = (($allXms.Keys | Where-Object { $_ -like 'x-ms-*' } | Sort-Object) |
                  ForEach-Object { "$($_):$($allXms[$_])" }) -join "`n"
    $canonRes  = "/$AccountName$($uriObj.AbsolutePath)"
    if ($uriObj.Query) {
        $qs = $uriObj.Query.TrimStart('?') -split '&' |
              ForEach-Object { $p = $_ -split '=',2; [pscustomobject]@{k=$p[0];v=if($p.Count -gt 1){[uri]::UnescapeDataString($p[1])}else{''}} } |
              Sort-Object k
        $canonRes += "`n" + (($qs | ForEach-Object { "$($_.k):$($_.v)" }) -join "`n")
    }
    $sts  = "$Method`n`n`n`n`n`n`n`n`n`n`n`n$canonHdrs`n$canonRes"
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($AccountKey))
    $sig  = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($sts)))
    return @{ Authorization = "SharedKey ${AccountName}:${sig}"; 'x-ms-date' = $date }
}

# Build headers for a File data-plane request in a SPECIFIC mode ('oauth' = bearer + backup intent,
# needs a Storage File Data role; 'key' = Shared Key signature from the account key).
function New-FileDataHeaders ([string]$Mode, [string]$AccountName, [string]$StorageToken, [string]$AccountKey, [string]$Method, [string]$Uri, [hashtable]$ExtraXms) {
    if ($Mode -eq 'oauth') {
        $h = @{ Authorization = "Bearer $StorageToken"; 'x-ms-file-request-intent' = 'backup'; 'x-ms-version' = $script:ApiVersions.FileData }
        if ($ExtraXms) { foreach ($k in $ExtraXms.Keys) { $h[$k] = $ExtraXms[$k] } }
        return $h
    }
    $xms = @{ 'x-ms-version' = $script:ApiVersions.FileData }
    if ($ExtraXms) { foreach ($k in $ExtraXms.Keys) { $xms[$k] = $ExtraXms[$k] } }
    $auth = New-StorageSharedKeyAuth -AccountName $AccountName -AccountKey $AccountKey -Method $Method -Uri $Uri -XmsHeaders $xms
    $h = @{ Authorization = $auth.Authorization; 'x-ms-date' = $auth.'x-ms-date' }
    foreach ($k in $xms.Keys) { $h[$k] = $xms[$k] }
    return $h
}

# Credential modes to attempt, in order: OAuth (backup intent) first, Shared Key fallback. A caller
# with Owner but no Storage File Data role gets 403 on OAuth - the key (via ARM listKeys) still works.
function Get-FileDataModes ([string]$StorageToken, [string]$AccountKey) {
    $modes = @()
    if ($StorageToken) { $modes += 'oauth' }
    if ($AccountKey)   { $modes += 'key' }
    return $modes
}

# Root SDDL of an Azure Files share over REST (no SMB mount needed). Tries OAuth backup-intent
# (Storage File Data Privileged Reader) then Shared Key. Returns $null on failure.
function Get-AzureFilesRootSddl ([string]$AccountName, [string]$ShareName, [string]$StorageToken, [string]$AccountKey) {
    $baseUri = "https://$AccountName.file.core.windows.net"
    $dirUri  = "$baseUri/$ShareName/?restype=directory"
    foreach ($mode in (Get-FileDataModes $StorageToken $AccountKey)) {
        try {
            $h = New-FileDataHeaders $mode $AccountName $StorageToken $AccountKey 'GET' $dirUri
            $dirResp = Invoke-WebRequest -Uri $dirUri -Method Get -Headers $h -UseBasicParsing -ErrorAction Stop
            $permKey = $dirResp.Headers['x-ms-file-permission-key']
            if (-not $permKey) { return $null }
            $permUri = "$baseUri/$ShareName`?restype=share&comp=filepermission"
            $ph = New-FileDataHeaders $mode $AccountName $StorageToken $AccountKey 'GET' $permUri @{ 'x-ms-file-permission-key' = "$permKey" }
            $permResp = Invoke-RestMethod -Uri $permUri -Method Get -Headers $ph -ErrorAction Stop
            if ($permResp -is [string]) { return $permResp } else { return $permResp.permission }
        } catch { Write-Log "Azure Files root SDDL ($AccountName/$ShareName) [$mode]: $($_.Exception.Message)" 'WARN' }
    }
    return $null
}

# List one directory of an Azure Files share over REST. Returns @{ Files=@(@{Name;Bytes}); Dirs=@(names) }.
# Tries OAuth (backup intent) then Shared Key; remembers the first mode that works for the session.
$script:_fileDataMode = ''
function Get-AzureFilesDirList ([string]$AccountName, [string]$ShareName, [string]$DirPath, [string]$StorageToken, [string]$AccountKey) {
    $baseUri = "https://$AccountName.file.core.windows.net"
    $dirSeg  = if ($DirPath) { '/' + (($DirPath -split '/|\\' | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/') } else { '' }
    $modes = @(Get-FileDataModes $StorageToken $AccountKey)
    if ($modes.Count -eq 0) { throw 'No Azure Files data-plane credential (needs a Storage File Data role or the account key).' }
    if ($script:_fileDataMode -and $modes -contains $script:_fileDataMode) { $modes = @($script:_fileDataMode) + @($modes | Where-Object { $_ -ne $script:_fileDataMode }) }
    $lastErr = $null
    foreach ($mode in $modes) {
        $files = [System.Collections.Generic.List[object]]::new()
        $dirs  = [System.Collections.Generic.List[string]]::new()
        try {
            $marker = ''
            do {
                $uri = "$baseUri/$ShareName$dirSeg`?restype=directory&comp=list&maxresults=5000" + $(if ($marker) { "&marker=$([uri]::EscapeDataString($marker))" })
                $h = New-FileDataHeaders $mode $AccountName $StorageToken $AccountKey 'GET' $uri
                $raw = Invoke-WebRequest -Uri $uri -Method Get -Headers $h -UseBasicParsing -ErrorAction Stop
                # Response is XML with a BOM-ish prefix sometimes; parse defensively.
                $txt = "$($raw.Content)"; $ix = $txt.IndexOf('<'); if ($ix -gt 0) { $txt = $txt.Substring($ix) }
                [xml]$x = $txt
                foreach ($f in @($x.EnumerationResults.Entries.File)) {
                    if ($null -eq $f) { continue }
                    [void]$files.Add([ordered]@{ Name = "$($f.Name)"; Bytes = [long]$f.Properties.'Content-Length' })
                }
                foreach ($d in @($x.EnumerationResults.Entries.Directory)) {
                    if ($null -eq $d) { continue }
                    [void]$dirs.Add("$($d.Name)")
                }
                $marker = "$($x.EnumerationResults.NextMarker)"
            } while ($marker)
            $script:_fileDataMode = $mode
            return @{ Files = $files.ToArray(); Dirs = $dirs.ToArray() }
        } catch { $lastErr = $_ }
    }
    throw $lastErr
}

#endregion

#region ── Share permissions + NTFS ACL helpers ───────────────────────────────

# SMB share ACL via CIM on the file server (needs admin there). Best-effort with method recorded.
function Get-SmbShareAcl ([string]$Server, [string]$ShareName) {
    $result = [ordered]@{ Collected = $false; Method = ''; Aces = @(); Error = '' }
    $cim = $null
    try {
        $cim = New-CimSession -ComputerName $Server -OperationTimeoutSec 20 -ErrorAction Stop
        try {
            $aces = @(Get-SmbShareAccess -CimSession $cim -Name $ShareName -ErrorAction Stop)
            $result['Aces'] = @($aces | ForEach-Object { [ordered]@{ Account = "$($_.AccountName)"; Right = "$($_.AccessRight)"; Type = "$($_.AccessControlType)" } })
            $result['Collected'] = $true; $result['Method'] = 'Get-SmbShareAccess (CIM)'
            return $result
        } catch {
            # Fallback: legacy Win32 share security descriptor.
            $sec = Get-CimInstance -CimSession $cim -ClassName Win32_LogicalShareSecuritySetting -Filter "Name='$ShareName'" -ErrorAction Stop
            $sd  = ($sec | Invoke-CimMethod -MethodName GetSecurityDescriptor -ErrorAction Stop).Descriptor
            $result['Aces'] = @(@($sd.DACL) | ForEach-Object {
                [ordered]@{
                    Account = "$($_.Trustee.Domain)\$($_.Trustee.Name)".Trim('\')
                    Right   = "0x{0:X}" -f $_.AccessMask
                    Type    = if ($_.AceType -eq 0) { 'Allow' } elseif ($_.AceType -eq 1) { 'Deny' } else { "$($_.AceType)" }
                }
            })
            $result['Collected'] = $true; $result['Method'] = 'Win32_LogicalShareSecuritySetting (CIM)'
            return $result
        }
    } catch {
        $result['Error'] = "Share ACL not collected: $($_.Exception.Message) (reading the share ACL needs admin rights on $Server)"
        return $result
    } finally {
        if ($cim) { try { Remove-CimSession $cim } catch {} }
    }
}

# Root NTFS ACL via Get-Acl (works over SMB, incl. mounted Azure Files). Raw facts.
function Get-RootNtfsAcl ([string]$Path) {
    $result = [ordered]@{ Collected = $false; Owner = ''; Sddl = ''; Aces = @(); Error = '' }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $result['Owner'] = "$($acl.Owner)"
        $result['Sddl']  = "$($acl.Sddl)"
        $result['Aces']  = @($acl.Access | ForEach-Object {
            [ordered]@{
                Identity    = "$($_.IdentityReference)"
                Rights      = "$($_.FileSystemRights)"
                Type        = "$($_.AccessControlType)"
                Inherited   = [bool]$_.IsInherited
                Inheritance = "$($_.InheritanceFlags)"
                Propagation = "$($_.PropagationFlags)"
            }
        })
        $result['Collected'] = $true
    } catch { $result['Error'] = "Root NTFS ACL not collected: $($_.Exception.Message)" }
    return $result
}

#endregion

#region ── Folder inventory (filesystem + Azure Files REST walkers) ───────────

# Recursively measure a directory using a manual stack so one access-denied branch doesn't kill the
# walk. Optionally records every file (relative path + size) into $AllFiles for -FullInventory.
function Measure-FolderRecursive ([string]$Root, [System.Collections.Generic.List[string]]$Errors, $AllFiles, [string]$RelBase) {
    $bytes = [long]0; $files = [long]0; $dirs = [long]0
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        try { foreach ($d in [System.IO.Directory]::EnumerateDirectories($cur)) { $dirs++; $stack.Push($d) } }
        catch { [void]$Errors.Add("dirs: $cur - $($_.Exception.Message)") }
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($cur)) {
                try {
                    $fi = [System.IO.FileInfo]::new($f)
                    $bytes += $fi.Length; $files++
                    if ($null -ne $AllFiles) {
                        [void]$AllFiles.Add([ordered]@{
                            Path = $f.Substring($RelBase.Length).TrimStart('\','/')
                            Bytes = [long]$fi.Length
                            LastWriteUtc = $fi.LastWriteTimeUtc.ToString('o')
                        })
                    }
                } catch { [void]$Errors.Add("file: $f - $($_.Exception.Message)") }
            }
        } catch { [void]$Errors.Add("files: $cur - $($_.Exception.Message)") }
    }
    return @{ Bytes = $bytes; Files = $files; Dirs = $dirs }
}

# Inventory a share root over the FILESYSTEM (UNC or local): top-level folders with recursive totals,
# immediate files/subfolders, root loose files. $Full = every file recursively per folder.
function Get-ShareInventoryFs ([string]$Root, [bool]$Full, [string]$ShareLabel) {
    $folders = [System.Collections.Generic.List[object]]::new()
    $rootFiles = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $totBytes = [long]0; $totFiles = [long]0

    try {
        foreach ($f in [System.IO.Directory]::EnumerateFiles($Root)) {
            try { $fi = [System.IO.FileInfo]::new($f); [void]$rootFiles.Add([ordered]@{ Name = $fi.Name; Bytes = [long]$fi.Length; Extension = $fi.Extension.ToLower(); LastWriteUtc = $fi.LastWriteTimeUtc.ToString('o') }); $totBytes += $fi.Length; $totFiles++ } catch { [void]$errors.Add("root file: $f - $($_.Exception.Message)") }
        }
    } catch { [void]$errors.Add("root files: $($_.Exception.Message)") }

    $topDirs = @()
    try { $topDirs = @([System.IO.Directory]::EnumerateDirectories($Root)) } catch { [void]$errors.Add("root dirs: $($_.Exception.Message)") }

    $idx = 0
    foreach ($dirPath in $topDirs) {
        $idx++
        $di = [System.IO.DirectoryInfo]::new($dirPath)
        if ($idx % 25 -eq 0 -or $idx -eq 1) { Set-SplashStatus "$ShareLabel - sizing folder $idx of $($topDirs.Count)..." }
        $fErrors = [System.Collections.Generic.List[string]]::new()
        # NB: direct assignment, not `= if (...) { ::new() }` - an empty collection returned through
        # an if-expression is pipeline-unrolled to AutomationNull, which silently disables the adds.
        $allFiles = $null
        if ($Full) { $allFiles = [System.Collections.Generic.List[object]]::new() }

        # Immediate files
        $imFiles = [System.Collections.Generic.List[object]]::new()
        $imBytes = [long]0; $imCount = [long]0
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($dirPath)) {
                try {
                    $fi = [System.IO.FileInfo]::new($f)
                    [void]$imFiles.Add([ordered]@{ Name = $fi.Name; Bytes = [long]$fi.Length; Extension = $fi.Extension.ToLower(); LastWriteUtc = $fi.LastWriteTimeUtc.ToString('o') })
                    $imBytes += $fi.Length; $imCount++
                    if ($null -ne $allFiles) { [void]$allFiles.Add([ordered]@{ Path = $fi.Name; Bytes = [long]$fi.Length; LastWriteUtc = $fi.LastWriteTimeUtc.ToString('o') }) }
                } catch { [void]$fErrors.Add("file: $f - $($_.Exception.Message)") }
            }
        } catch { [void]$fErrors.Add("files: $dirPath - $($_.Exception.Message)") }

        # Immediate subfolders, each with its own recursive totals
        $subs = [System.Collections.Generic.List[object]]::new()
        $subBytes = [long]0; $subFiles = [long]0; $subDirs = [long]0
        try {
            foreach ($sd in [System.IO.Directory]::EnumerateDirectories($dirPath)) {
                $m = Measure-FolderRecursive $sd $fErrors $allFiles $dirPath
                $sdi = [System.IO.DirectoryInfo]::new($sd)
                [void]$subs.Add([ordered]@{ Name = $sdi.Name; TotalBytes = [long]$m.Bytes; FileCount = [long]$m.Files; DirCount = [long]$m.Dirs })
                $subBytes += $m.Bytes; $subFiles += $m.Files; $subDirs += ([long]$m.Dirs + 1)
            }
        } catch { [void]$fErrors.Add("subdirs: $dirPath - $($_.Exception.Message)") }

        $entry = [ordered]@{
            Name         = $di.Name
            TotalBytes   = [long]($imBytes + $subBytes)
            FileCount    = [long]($imCount + $subFiles)
            DirCount     = [long]$subDirs
            LastWriteUtc = $(try { $di.LastWriteTimeUtc.ToString('o') } catch { '' })
            Files        = @($imFiles)
            Subfolders   = @($subs)
            Errors       = @($fErrors)
        }
        if ($Full) { $entry['AllFiles'] = @($allFiles) }
        [void]$folders.Add($entry)
        $totBytes += $entry['TotalBytes']; $totFiles += $entry['FileCount']
    }

    return [ordered]@{
        Folders    = @($folders)
        RootFiles  = @($rootFiles)
        TotalBytes = [long]$totBytes
        TotalFiles = [long]$totFiles
        Errors     = @($errors)
        Method     = 'Filesystem (SMB)'
    }
}

# Same inventory over the Azure Files REST data plane (used when SMB/445 is unreachable).
function Get-ShareInventoryRest ([string]$AccountName, [string]$ShareName, [string]$SubPath, [bool]$Full, [string]$StorageToken, [string]$AccountKey, [string]$ShareLabel) {
    $folders = [System.Collections.Generic.List[object]]::new()
    $errors  = [System.Collections.Generic.List[string]]::new()
    $totBytes = [long]0; $totFiles = [long]0

    function Measure-RestRecursive ([string]$Dir, [System.Collections.Generic.List[string]]$Errs, $AllFiles, [string]$RelBase) {
        $bytes = [long]0; $files = [long]0; $dirs = [long]0
        $stack = [System.Collections.Generic.Stack[string]]::new(); $stack.Push($Dir)
        while ($stack.Count -gt 0) {
            $cur = $stack.Pop()
            try {
                $l = Get-AzureFilesDirList $AccountName $ShareName $cur $StorageToken $AccountKey
                foreach ($f in $l.Files) {
                    $bytes += [long]$f.Bytes; $files++
                    if ($null -ne $AllFiles) { [void]$AllFiles.Add([ordered]@{ Path = ("$cur/$($f.Name)").Substring($RelBase.Length).TrimStart('/'); Bytes = [long]$f.Bytes }) }
                }
                foreach ($d in $l.Dirs) { $dirs++; $stack.Push("$cur/$d") }
            } catch { [void]$Errs.Add("list: $cur - $($_.Exception.Message)") }
        }
        return @{ Bytes = $bytes; Files = $files; Dirs = $dirs }
    }

    $rootList = Get-AzureFilesDirList $AccountName $ShareName $SubPath $StorageToken $AccountKey
    $rootFiles = @($rootList.Files | ForEach-Object { [ordered]@{ Name = $_.Name; Bytes = [long]$_.Bytes; Extension = [System.IO.Path]::GetExtension($_.Name).ToLower() } })
    foreach ($rf in $rootFiles) { $totBytes += [long]$rf.Bytes; $totFiles++ }

    $idx = 0
    foreach ($dirName in @($rootList.Dirs)) {
        $idx++
        if ($idx % 10 -eq 0 -or $idx -eq 1) { Set-SplashStatus "$ShareLabel - sizing folder $idx of $(@($rootList.Dirs).Count) (REST)..." }
        $dirPath = if ($SubPath) { "$SubPath/$dirName" } else { $dirName }
        $fErrors = [System.Collections.Generic.List[string]]::new()
        # Direct assignment (see the FS walker note): an if-expression would unroll the empty list.
        $allFiles = $null
        if ($Full) { $allFiles = [System.Collections.Generic.List[object]]::new() }

        $imFiles = [System.Collections.Generic.List[object]]::new(); $imBytes = [long]0; $imCount = [long]0
        $subs = [System.Collections.Generic.List[object]]::new(); $subBytes = [long]0; $subFiles = [long]0; $subDirs = [long]0
        try {
            $l = Get-AzureFilesDirList $AccountName $ShareName $dirPath $StorageToken $AccountKey
            foreach ($f in $l.Files) {
                [void]$imFiles.Add([ordered]@{ Name = $f.Name; Bytes = [long]$f.Bytes; Extension = [System.IO.Path]::GetExtension($f.Name).ToLower() })
                $imBytes += [long]$f.Bytes; $imCount++
                if ($null -ne $allFiles) { [void]$allFiles.Add([ordered]@{ Path = $f.Name; Bytes = [long]$f.Bytes }) }
            }
            foreach ($sd in $l.Dirs) {
                $m = Measure-RestRecursive "$dirPath/$sd" $fErrors $allFiles $dirPath
                [void]$subs.Add([ordered]@{ Name = $sd; TotalBytes = [long]$m.Bytes; FileCount = [long]$m.Files; DirCount = [long]$m.Dirs })
                $subBytes += $m.Bytes; $subFiles += $m.Files; $subDirs += ([long]$m.Dirs + 1)
            }
        } catch { [void]$fErrors.Add("list: $dirPath - $($_.Exception.Message)") }

        $entry = [ordered]@{
            Name = $dirName; TotalBytes = [long]($imBytes + $subBytes); FileCount = [long]($imCount + $subFiles); DirCount = [long]$subDirs
            LastWriteUtc = ''; Files = @($imFiles); Subfolders = @($subs); Errors = @($fErrors)
        }
        if ($Full) { $entry['AllFiles'] = @($allFiles) }
        [void]$folders.Add($entry)
        $totBytes += $entry['TotalBytes']; $totFiles += $entry['FileCount']
    }

    return [ordered]@{
        Folders = @($folders); RootFiles = @($rootFiles); TotalBytes = [long]$totBytes; TotalFiles = [long]$totFiles
        Errors = @($errors); Method = 'Azure Files REST'
    }
}

#endregion

#region ── Product evidence (raw hints only - the report does the analysis) ───

function Get-ProductEvidence ($Inventory) {
    $vhdCount = 0; $sidFolders = 0; $upmMarkers = 0
    $sidRx = [regex]'(?i)S-1-5-21-[\d\-]+'
    foreach ($rf in @($Inventory['RootFiles'])) { if ("$($rf['Extension'])" -in '.vhd', '.vhdx') { $vhdCount++ } }
    foreach ($fld in @($Inventory['Folders'])) {
        if ($sidRx.IsMatch("$($fld['Name'])")) { $sidFolders++ }
        foreach ($f in @($fld['Files'])) { if ("$($f['Extension'])" -in '.vhd', '.vhdx') { $vhdCount++ } }
        foreach ($s in @($fld['Subfolders'])) {
            if ("$($s['Name'])" -match '(?i)^(UPM_Profile|UPM_Data|Pending)$') { $upmMarkers++ }
        }
        if ("$($fld['Name'])" -match '(?i)^(UPM_Profile|UPM_Data|Pending)$') { $upmMarkers++ }
    }
    $detected = if ($vhdCount -gt 0 -and $upmMarkers -gt 0) { 'Mixed' }
                elseif ($vhdCount -gt 0) { 'FSLogix' }
                elseif ($upmMarkers -gt 0) { 'CPM' }
                else { 'Unknown' }
    return [ordered]@{
        DetectedProduct  = $detected
        VhdVhdxFileCount = $vhdCount
        SidPatternFolders = $sidFolders
        UpmMarkerCount   = $upmMarkers
    }
}

#endregion

#region ── Launch dialog ──────────────────────────────────────────────────────

function Show-ProfilesDialog {
    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="User Profiles Collector" SizeToContent="Height" Width="560"
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
    <StackPanel Margin="24,20,24,20">
        <DockPanel Margin="0,0,0,16">
            <TextBlock Text="&#x1F4C2;" FontSize="26" Foreground="#0078D4" DockPanel.Dock="Left"
                       VerticalAlignment="Center" Margin="0,0,12,0"/>
            <StackPanel>
                <TextBlock Text="User Profiles Collector" FontSize="16" FontWeight="Bold" Foreground="#0078D4"/>
                <TextBlock Text="FSLogix / Citrix Profile Management share inventory + permissions" FontSize="12" Foreground="#555" Margin="0,2,0,0"/>
            </StackPanel>
        </DockPanel>

        <TextBlock Text="Customer (groups output files under Outputs\&lt;Customer&gt;)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox x:Name="CustomerBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,14"/>

        <TextBlock Text="Profile shares (one per line; optional |FSLogix or |CPM hint after the path)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,4"/>
        <TextBox x:Name="SharesBox" AcceptsReturn="True" TextWrapping="Wrap" Height="92" VerticalScrollBarVisibility="Auto"
                 Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,6"/>
        <TextBlock Text="e.g.  \\filesrv1\Profiles$|CPM     \\acct.file.core.windows.net\fslogix|FSLogix" FontSize="10" Foreground="#8a8f98" Margin="0,0,0,10"/>
        <TextBlock TextWrapping="Wrap" FontSize="10" Foreground="#8a8f98" Margin="0,0,0,14"
                   Text="Azure Files: sign in first with Connect-AzAccount for RBAC + share stats (ARM read on the storage account); data access needs a Storage File Data role (or SMB reachability). On-prem: reading the share ACL needs admin on the file server; NTFS/folder reads need read access on the share."/>

        <CheckBox x:Name="FullChk" Content="Full file inventory (every file recursively - slower, larger output)"
                  Foreground="#1F2937" FontSize="12" Margin="0,0,0,12"/>

        <TextBlock Text="Encrypt output (optional - leave blank for plaintext .json; a password writes .cdenc)" FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,6"/>
        <PasswordBox x:Name="EncryptBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" Background="White" FontSize="12" Margin="0,0,0,16"/>

        <Grid>
            <TextBlock x:Name="VersionText" Text="" FontSize="10" Foreground="#8a8f98" VerticalAlignment="Center" HorizontalAlignment="Left"/>
            <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                <Button x:Name="CancelBtn" Content="Cancel" Width="80" Padding="0,7" Style="{StaticResource GreyBtn}" Margin="0,0,8,0"/>
                <Button x:Name="OkBtn" Content="Start" Width="100" Padding="0,7" Style="{StaticResource BlueBtn}"/>
            </StackPanel>
        </Grid>
    </StackPanel>
</Window>
'@
    $win = New-ThemedWindow $xaml
    $win.FindName('VersionText').Text = "v$($script:_version)"
    $customerBox = $win.FindName('CustomerBox')
    $sharesBox   = $win.FindName('SharesBox')
    $fullChk     = $win.FindName('FullChk')
    $encryptBox  = $win.FindName('EncryptBox')
    $okBtn       = $win.FindName('OkBtn')
    $cancel      = $win.FindName('CancelBtn')

    $result = [ordered]@{ Action = 'Cancel'; Shares = @(); Customer = ''; FullInventory = $false; EncryptPassword = $null }

    $okBtn.Add_Click({
        $lines = @($sharesBox.Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($lines.Count -eq 0) {
            Show-MsgBox 'Enter at least one share path.' -Icon Warning
            return
        }
        $result['Action']  = 'Run'
        $result['Shares']  = $lines
        $result['Customer'] = $customerBox.Text.Trim()
        $result['FullInventory'] = [bool]$fullChk.IsChecked
        if ($encryptBox.Password) { $result['EncryptPassword'] = ConvertTo-SecureString $encryptBox.Password -AsPlainText -Force }
        $win.Close()
    })
    $cancel.Add_Click({ $result['Action'] = 'Cancel'; $win.Close() })
    $null = $win.ShowDialog()
    return $result
}

#endregion

#region ── Per-share collection ───────────────────────────────────────────────

# Parse '\\host\share\sub' -> @{ Host; Share; Sub }; $null for non-UNC.
function Split-UncPath ([string]$Path) {
    $m = [regex]::Match($Path, '^\\\\([^\\]+)\\([^\\]+)(?:\\(.*))?$')
    if (-not $m.Success) { return $null }
    return @{ Host = $m.Groups[1].Value; Share = $m.Groups[2].Value; Sub = $m.Groups[3].Value }
}

function Invoke-ShareCollection ([string]$Entry, [bool]$Full, [bool]$AzAvailable) {
    # Optional product hint after a pipe: '\\server\share|CPM'
    $parts = $Entry -split '\|', 2
    $path  = $parts[0].Trim().TrimEnd('\')
    $hint  = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }

    $unc  = Split-UncPath $path
    $isAzure = $unc -and ($unc.Host -match '(?i)\.file\.core\.windows\.net$')
    $kind = if ($isAzure) { 'AzureFiles' } elseif ($unc) { 'SMB' } else { 'Local' }

    $share = [ordered]@{
        Path            = $path
        Kind            = $kind
        TypeHint        = $hint
        Reachable       = $false
        InventoryMethod = ''
        SharePermissions = $null
        AzureShare      = $null
        RootAcl         = $null
        ProductEvidence = $null
        Folders         = @()
        RootFiles       = @()
        TotalBytes      = [long]0
        TotalFiles      = [long]0
        CapacityBytes   = $null
        FreeBytes       = $null
        FolderCount     = 0
        Errors          = @()
        DurationSec     = 0
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $errs = [System.Collections.Generic.List[string]]::new()
    Set-SplashStatus "Collecting $path ..."
    Write-Log "=== Share: $path (kind=$kind hint='$hint') ==="

    # ── Azure control plane (RBAC + share properties) ──
    $storageToken = $null; $accountKey = $null
    if ($isAzure) {
        $acctName = ($unc.Host -split '\.')[0]
        if ($AzAvailable) {
            try {
                $armTok = Get-ArmToken
                $acct = Find-ArmStorageAccount $acctName $armTok
                if ($acct) {
                    $subId = ($acct.id -split '/')[2]
                    $roleMap = Get-ArmRoleDefinitions $subId $armTok
                    $ras = @(Get-ArmRoleAssignments $acct.id $armTok)
                    $principals = Resolve-GraphPrincipals @($ras | ForEach-Object { "$($_.properties.principalId)" })
                    $rbac = @($ras | ForEach-Object {
                        $p = $_.properties
                        $roleId = ("$($p.roleDefinitionId)" -split '/')[-1]
                        $pr = $principals["$($p.principalId)"]
                        [ordered]@{
                            Role          = if ($roleMap.ContainsKey($roleId)) { $roleMap[$roleId] } else { $roleId }
                            PrincipalId   = "$($p.principalId)"
                            PrincipalName = if ($pr) { $pr.Name } else { '' }
                            PrincipalType = if ($pr) { $pr.Type } else { "$($p.principalType)" }
                            Scope         = "$($p.scope)"
                        }
                    })
                    $props = Get-ArmFileShareProps $acct.id $unc.Share $armTok
                    $idAuth = $null
                    try { $idAuth = $acct.properties.azureFilesIdentityBasedAuthentication } catch {}
                    # Network posture (raw): explains a data-plane 403 (private-endpoint-only accounts
                    # reject clients outside the VNet regardless of credentials).
                    $netInfo = [ordered]@{
                        PublicNetworkAccess = $(try { "$($acct.properties.publicNetworkAccess)" } catch { '' })
                        DefaultAction       = $(try { "$($acct.properties.networkAcls.defaultAction)" } catch { '' })
                        IpRules             = $(try { @($acct.properties.networkAcls.ipRules).Count } catch { 0 })
                        VnetRules           = $(try { @($acct.properties.networkAcls.virtualNetworkRules).Count } catch { 0 })
                        PrivateEndpoints    = $(try { @($acct.properties.privateEndpointConnections).Count } catch { 0 })
                    }
                    $share['AzureShare'] = [ordered]@{
                        StorageAccount = "$($acct.name)"
                        ResourceId     = "$($acct.id)"
                        SubscriptionId = $subId
                        ShareName      = "$($unc.Share)"
                        QuotaGiB       = $(try { [long]$props.properties.shareQuota } catch { $null })
                        UsageBytes     = $(try { [long]$props.properties.shareUsageBytes } catch { $null })
                        EnabledProtocols = $(try { "$($props.properties.enabledProtocols)" } catch { '' })
                        IdentityAuth   = $(if ($idAuth) { [ordered]@{ DirectoryServiceOptions = "$($idAuth.directoryServiceOptions)"; DefaultSharePermission = "$($idAuth.defaultSharePermission)" } } else { $null })
                        NetworkAccess  = $netInfo
                    }
                    $share['SharePermissions'] = [ordered]@{ Collected = $true; Method = 'ARM RBAC role assignments (storage-account scope)'; Rbac = $rbac; Error = '' }
                    # Data-plane credentials for the REST fallback paths.
                    try { $storageToken = Get-ArmToken -ResourceUrl 'https://storage.azure.com/' } catch { Write-Log "Storage data-plane token: $($_.Exception.Message)" 'WARN' }
                    $accountKey = Get-ArmStorageAccountKey $acct.id $armTok
                } else {
                    [void]$errs.Add("Azure: storage account '$acctName' not found in any visible subscription - RBAC/share stats not collected.")
                    $share['SharePermissions'] = [ordered]@{ Collected = $false; Method = ''; Rbac = @(); Error = "Storage account '$acctName' not visible to the signed-in Azure context." }
                }
            } catch {
                [void]$errs.Add("Azure control plane: $($_.Exception.Message)")
                $share['SharePermissions'] = [ordered]@{ Collected = $false; Method = ''; Rbac = @(); Error = "$($_.Exception.Message)" }
            }
        } else {
            $share['SharePermissions'] = [ordered]@{ Collected = $false; Method = ''; Rbac = @(); Error = 'Not collected - no Azure context (run Connect-AzAccount before collecting for RBAC + share stats).' }
        }
    } elseif ($kind -eq 'SMB') {
        $share['SharePermissions'] = Get-SmbShareAcl $unc.Host $unc.Share
    } else {
        $share['SharePermissions'] = [ordered]@{ Collected = $false; Method = ''; Aces = @(); Error = 'Local path - no share ACL (share permissions apply to UNC shares only).' }
    }

    # ── Reachability + root NTFS ACL ──
    $smbReachable = $false
    try { $smbReachable = Test-Path -LiteralPath $path -ErrorAction Stop } catch { $smbReachable = $false }

    # Share capacity ("max size"). Azure: derived from the share quota; on-prem/local: the hosting volume.
    if ($share['AzureShare'] -and $share['AzureShare'].QuotaGiB) {
        $share['CapacityBytes'] = [long]$share['AzureShare'].QuotaGiB * 1GB
        if ($null -ne $share['AzureShare'].UsageBytes) { $share['FreeBytes'] = [long]$share['CapacityBytes'] - [long]$share['AzureShare'].UsageBytes }
    } elseif ($smbReachable) {
        $cap = Get-PathCapacity $path
        if ($cap) { $share['CapacityBytes'] = $cap.CapacityBytes; $share['FreeBytes'] = $cap.FreeBytes }
    }
    $share['Reachable'] = [bool]$smbReachable
    if ($smbReachable) {
        $share['RootAcl'] = Get-RootNtfsAcl $path
    } elseif ($isAzure) {
        $sddl = Get-AzureFilesRootSddl (($unc.Host -split '\.')[0]) $unc.Share $storageToken $accountKey
        $share['RootAcl'] = [ordered]@{
            Collected = [bool]$sddl; Owner = ''; Sddl = "$sddl"; Aces = @()
            Error = $(if ($sddl) { '' } else { 'Root SDDL not collected - SMB (445) unreachable and the REST fallback failed (needs Storage File Data Privileged Reader or the account key via ARM).' })
        }
        if ($sddl) { Write-Log 'Root SDDL collected via Azure Files REST.' }
    } else {
        $share['RootAcl'] = [ordered]@{ Collected = $false; Owner = ''; Sddl = ''; Aces = @(); Error = "Path not reachable: $path" }
    }

    # ── Folder inventory ──
    $inv = $null
    # A private-endpoint-only / firewalled account rejects the data plane from outside its network
    # regardless of credentials - name that in the error so the report can advise where to run from.
    $netHint = ''
    if ($isAzure -and $share['AzureShare'] -and $share['AzureShare']['NetworkAccess']) {
        $na = $share['AzureShare']['NetworkAccess']
        if ("$($na['PublicNetworkAccess'])" -eq 'Disabled' -or "$($na['DefaultAction'])" -eq 'Deny') {
            $netHint = " The storage account restricts network access (publicNetworkAccess=$($na['PublicNetworkAccess']); defaultAction=$($na['DefaultAction']); privateEndpoints=$($na['PrivateEndpoints'])) - run the collector from a host with line-of-sight (VNet / private endpoint / allowed IP)."
        }
    }
    if ($smbReachable) {
        try { $inv = Get-ShareInventoryFs $path $Full $path } catch { [void]$errs.Add("inventory: $($_.Exception.Message)") }
    } elseif ($isAzure -and ($storageToken -or $accountKey)) {
        try { $inv = Get-ShareInventoryRest (($unc.Host -split '\.')[0]) $unc.Share "$($unc.Sub)" $Full $storageToken $accountKey $path } catch { [void]$errs.Add("inventory (REST): $($_.Exception.Message)$netHint") }
    } else {
        [void]$errs.Add("Inventory not collected - path unreachable$(if ($isAzure) { ' and no Azure Files data-plane credential (Storage File Data role or account key)' } ).$netHint")
    }
    if ($inv) {
        $share['InventoryMethod'] = "$($inv['Method'])"
        $share['Folders']     = @($inv['Folders'])
        $share['RootFiles']   = @($inv['RootFiles'])
        $share['TotalBytes']  = [long]$inv['TotalBytes']
        $share['TotalFiles']  = [long]$inv['TotalFiles']
        $share['FolderCount'] = @($inv['Folders']).Count
        foreach ($e in @($inv['Errors'])) { [void]$errs.Add($e) }
        $share['ProductEvidence'] = Get-ProductEvidence $inv
    }

    $sw.Stop()
    $share['DurationSec'] = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $share['Errors'] = @($errs)
    Write-Log "Share done: $path - folders=$($share['FolderCount']) bytes=$($share['TotalBytes']) errors=$(@($errs).Count) ($($share['DurationSec'])s)"
    return $share
}

#endregion

#region ── Entry Point ────────────────────────────────────────────────────────

# Allow dot-sourcing (for tests) without auto-running the collection.
if ($MyInvocation.InvocationName -eq '.') { return }

Start-DebugLog

# Offer to self-update from GitHub before anything else (interactive only; fail-safe / optional).
Invoke-ProfilesUpdateCheck

$targets  = @($Shares | Where-Object { "$_".Trim() })
$customer = $Customer
$full     = [bool]$FullInventory
$script:_encryptPassword = $EncryptPassword

if ($targets.Count -eq 0) {
    $sel = Show-ProfilesDialog
    if ($sel['Action'] -eq 'Cancel') { Write-Log 'User cancelled at launch dialog'; exit 0 }
    $targets = @($sel['Shares'])
    if (-not $customer) { $customer = $sel['Customer'] }
    $full = [bool]$sel['FullInventory']
    if ($sel['EncryptPassword']) { $script:_encryptPassword = $sel['EncryptPassword'] }
}
Write-Log "Targets: $($targets -join ', '); full=$full; encrypt=$(if ($script:_encryptPassword -and $script:_encryptPassword.Length -gt 0) { 'on (.cdenc)' } else { 'off (plaintext .json)' })"

# Group outputs in a per-customer subfolder (when a customer is supplied).
$safeCustomer = ("$customer" -replace '[^\w\-. ]', '_').Trim().TrimEnd('.')
if ($safeCustomer) { $script:_outputDir = Join-Path $script:_outputDir $safeCustomer }
if (-not (Test-Path $script:_outputDir)) { New-Item -ItemType Directory -Path $script:_outputDir -Force | Out-Null }

# Azure context (needed only for Azure Files shares; best-effort).
$azAvailable = $false
if (@($targets | Where-Object { $_ -match '(?i)\.file\.core\.windows\.net' }).Count -gt 0) {
    $azAvailable = Test-AzContextAvailable
    Write-Log "Azure Files share(s) present; Az context available: $azAvailable"
    if (-not $azAvailable) {
        Show-MsgBox 'One or more Azure Files shares were supplied but no Azure sign-in is available (Az.Accounts + Connect-AzAccount). RBAC, share stats and the REST fallback will be skipped - NTFS/folder data is still collected if the share is SMB-reachable.' -Icon Warning
    }
}
$azCtx = $null
if ($azAvailable) { try { $c = Get-AzContext; $azCtx = [ordered]@{ Account = "$($c.Account.Id)"; Tenant = "$($c.Tenant.Id)" } } catch {} }

Show-Splash

$shareResults = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($t in $targets) {
    $i++
    Set-SplashStatus "Share $i of $($targets.Count): $t"
    try { [void]$shareResults.Add((Invoke-ShareCollection $t $full $azAvailable)) }
    catch {
        Write-Log "Share '$t' failed: $($_.Exception.Message)" 'ERROR'
        [void]$shareResults.Add([ordered]@{ Path = "$t"; Kind = 'Unknown'; Reachable = $false; Errors = @("$($_.Exception.Message)") })
    }
}

$output = [ordered]@{
    SchemaType       = 'ProfileShares'
    GeneratedAt      = (Get-Date).ToString('o')
    CollectorVersion = $script:_version
    CustomerName     = "$customer"
    CollectedBy      = "$env:USERDOMAIN\$env:USERNAME"
    CollectedFrom    = "$env:COMPUTERNAME"
    FullInventory    = $full
    AzureContext     = $(if ($azCtx) { $azCtx } else { [ordered]@{ Account = ''; Tenant = '' } })
    Shares           = @($shareResults)
}

Set-SplashStatus 'Writing output file...'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$prefix    = if ($safeCustomer) { $safeCustomer } else { 'Profiles' }
$encrypt   = ($script:_encryptPassword -and $script:_encryptPassword.Length -gt 0)
$outFile   = Join-Path $script:_outputDir ("$prefix-Profiles-Data-$timestamp." + $(if ($encrypt) { 'cdenc' } else { 'json' }))
try {
    $json = $output | ConvertTo-Json -Depth 12
    if ($encrypt) { $json = Protect-ReportData $json $script:_encryptPassword }
    Set-Content -Path $outFile -Value $json -Encoding UTF8
    Write-Log "Output written: $outFile ($([Math]::Round((Get-Item $outFile).Length / 1KB, 1)) KB)$(if ($encrypt) { ' [encrypted]' })"
} catch {
    Write-Log "Failed to write output: $_" 'ERROR'
}

Close-Splash
$totErr = (@($shareResults | ForEach-Object { @($_['Errors']).Count }) | Measure-Object -Sum).Sum
Show-MsgBox "Profile share collection complete.`n`nShares: $($shareResults.Count)   Issues recorded: $totErr`n`nOutput:`n$outFile" -Icon $(if ($totErr -gt 0) { 'Warning' } else { 'Info' })

#endregion


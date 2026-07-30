#Requires -Version 5.1
# Version: 2026-07-30   (keep in lock-step with $script:CollectorVersion below and the published .version file)
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

.EXAMPLE
    .\Get-NetScalerData.ps1

.EXAMPLE
    .\Get-NetScalerData.ps1 -OutputPath "C:\NetScalerData"

.EXAMPLE
    .\Get-NetScalerData.ps1 -SkipUpdateCheck
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter()]
    [switch]$SkipUpdateCheck
)

$script:CollectorVersion = '2026-07-30'

# Self-update source - the public euc-reports-collectors repo (same feed as the other collectors).
$script:_manifestUrl   = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/update-manifest.json'
$script:_updateRawBase = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main'
$script:_selfName      = 'Get-NetScalerData.ps1'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# PS 5.1 defaults to TLS 1.0 — NetScaler management interfaces require TLS 1.2+.
# -bor rather than a flat assignment so an environment that already enabled TLS 1.3 keeps it.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

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
    $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
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
    try {
        $resp = Invoke-WebRequest -Uri $url -Method GET -WebSession $Session `
            -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $data = $resp.Content | ConvertFrom-Json
        if ($data.errorcode -ne 0 -and $data.errorcode -ne $null) {
            return @()
        }
        if ($data.PSObject.Properties.Name -contains $Resource) {
            $raw = $data.$Resource
            if ($raw -eq $null) { return @() }
            if ($raw -is [array]) { return $raw }
            return @($raw)
        }
        return @()
    } catch {
        return @()
    }
}

function Invoke-NitroGetSingle {
    param(
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$BaseUri,
        [string]$Resource
    )
    $url = "$BaseUri/nitro/v1/config/$Resource"
    try {
        $resp = Invoke-WebRequest -Uri $url -Method GET -WebSession $Session `
            -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $data = $resp.Content | ConvertFrom-Json
        if ($data.errorcode -ne 0 -and $data.errorcode -ne $null) { return $null }
        if ($data.PSObject.Properties.Name -contains $Resource) { return $data.$Resource }
        return $null
    } catch {
        return $null
    }
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

$script:_configDir = Join-Path $PSScriptRoot 'configs'

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
            CustomerName = $txtCustomer.Text.Trim()
            Appliances   = @($script:_applianceList | ForEach-Object { [ordered]@{ Name = $_['Name']; Host = $_['Host'] } })
            Username     = $txtUsername.Text.Trim()
            Password     = $secPwd
            OutputPath   = $txtOutput.Text.Trim()
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
        SslCertKeys      = @()
        SslVservers      = @()
        SslProfiles      = @()
        SslServiceGroups = @()
        SslCipherGroups  = @()
        VpnVservers      = @()
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

    # -- Content Switching ---
    Set-CollectStatus "[$appName] Content switching..." -Progress ($appBase + 10) -Sub $appHost
    $appData['CsVservers'] = @(Collect 'csvserver'  'CS vservers')
    $appData['CsPolicies'] = @(Collect 'cspolicy'   'CS policies')

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

    # Cipher groups — an unscoped GET also returns NetScaler's built-in groups (ALL, DEFAULT,
    # HIGH, ...); only entries with this description are ones an admin actually configured
    # (matches what 'add ssl cipher' lines in ns.conf would show).
    $allCipherGroups = @(Collect 'sslcipher' 'SSL cipher groups')
    $appData['SslCipherGroups'] = @($allCipherGroups | Where-Object { (Get-NitroProp $_ 'description') -eq 'User Defined Cipher Group' })
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

    # Backend (service group) SSL/TLS parameters — NetScaler-to-server communication
    $appData['SslServiceGroups'] = @(Collect 'sslservicegroup' 'Backend SSL service groups')

    # -- Citrix Gateway ---
    Set-CollectStatus "[$appName] Citrix Gateway..." -Progress ($appBase + 18) -Sub $appHost
    $appData['VpnVservers']       = @(Collect 'vpnvserver'               'VPN vservers')
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
$fileName  = "$safeName-NetScaler-Data-$timestamp.json"
$filePath  = Join-Path $outPath $fileName

$report | ConvertTo-Json -Depth 20 | Set-Content -Path $filePath -Encoding UTF8

Set-CollectStatus 'Complete' -Progress 100 -Sub $filePath
Start-Sleep -Milliseconds 800

$script:_splash.Dispatcher.Invoke([Action]{ $script:_splash.Close() }, [System.Windows.Threading.DispatcherPriority]::Normal)

Show-MsgBox "Data collection complete.`n`nSaved to:`n$filePath"

#endregion

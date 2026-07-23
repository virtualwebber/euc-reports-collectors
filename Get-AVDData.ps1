#Requires -Version 5.1
# Version: 2026-07-23.1   (keep in lock-step with $script:CollectorVersion below and the published .version file)
<#
.SYNOPSIS
    Collects Azure Virtual Desktop data across subscriptions and saves it as JSON.

.DESCRIPTION
    Authenticates to Azure, queries all AVD objects (host pools, session hosts,
    application groups, workspaces, scaling plans, storage accounts, RBAC) across
    selected subscriptions, and saves the collected data to a JSON file.

    Run Get-AVDReport.ps1 (in the Report\ folder) against the resulting JSON file
    to generate HTML and/or Word reports without requiring Azure access.

.PARAMETER OutputPath
    Directory where the JSON data file will be saved. Defaults to the current directory.

.EXAMPLE
    .\Get-AVDData.ps1

.EXAMPLE
    .\Get-AVDData.ps1 -OutputPath "C:\AVDData"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,
    # Optional: encrypt the collected data file with this password (writes <name>.cdenc instead of
    # .json). OFF by default - omit it and output stays plaintext .json exactly as before.
    [Parameter()]
    [System.Security.SecureString]$EncryptPassword,
    # Skip the launch-time GitHub self-update check.
    [Parameter()]
    [switch]$SkipUpdateCheck
)

$script:CollectorVersion = '2026-07-23.1'
# Self-update source (public euc-reports-collectors repo): the launch check reads a TINY .version file
# (a few bytes); the full script downloads only when a newer version exists AND the user accepts. Keep
# the '# Version:' header, this $script:CollectorVersion, and the published .version file in lock-step.
# Self-update: fetch update-manifest.json, compare this file's SHA-256 to its manifest entry, and if they
# differ download the published .ps1 BYTE-EXACT (Invoke-WebRequest -OutFile), verify its hash (and signature
# when the manifest marks it signed) before replacing itself.
$script:_manifestUrl    = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main/update-manifest.json'
$script:_updateRawBase  = 'https://raw.githubusercontent.com/virtualwebber/euc-reports-collectors/refs/heads/main'
$script:_selfName       = 'Get-AVDData.ps1'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region -- Data-file encryption (opt-in, self-contained) ----------------------
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

#region -- WPF / DWM setup ----------------------------------------------------

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class AvdDataDwm {
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
            [void][AvdDataDwm]::DwmSetWindowAttribute($h, $script:DwmCornerAttr, [ref]$script:DwmCornerSquare, 4)
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
    param([string]$Message, [string]$Title = 'AVD Data Collector', [string]$Icon = 'Info')
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

#region -- Splash screen -------------------------------------------------------

[xml]$splashXaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="AVD Data Collector" Height="220" Width="440"
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
      <TextBlock Text="Azure Virtual Desktop - Data Collector"
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

$script:_splash         = $null
$script:_splashStatus   = $null
$script:_splashProgress = $null
$script:_splashSub      = $null
$script:_splashSync     = $null   # synchronized hashtable bridging to the dedicated splash UI thread
$script:_splashPs = $null; $script:_splashRs = $null; $script:_splashHandle = $null
$script:_splashLogoB64 = @'
/9j/4AAQSkZJRgABAQEAYABgAAD/4QAiRXhpZgAATU0AKgAAAAgAAQESAAMAAAABAAEAAAAAAAD/2wBDAAIBAQIBAQICAgICAgICAwUDAwMDAwYEBAMFBwYHBwcGBwcICQsJCAgKCAcHCg0KCgsMDAwMBwkODw0MDgsMDAz/2wBDAQICAgMDAwYDAwYMCAcIDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAz/wAARCAAlAQoDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD9/M5or8wf+Ci/7RXjx/2mtd8PHXNX0PR9EMcdjZ2dw9ssqFA3nEqQXLEnnOBjFfOPjz4++OPDvgvVL608WeJ3uraAtEP7UnYA5A3Y3duv4V7WV5HVx2JpYWlJKVSUYq+15NJXfbU+DwvHEMVnVPJMNRvOdSNJSlJRXNKSjd6Oyu/u6H7mZxQDmv56/wBnr/gpV8Wf2Z/iKnimPxZr3iiygDTalpGq373FvqcKqSyDeT5b4HysuMHHbNYn/BZX/gs741/aj+KHhdfhT468Q+FvhfPoFrqMNvpV09jdTXz5NxHdOhDF4XATYDt/i53Zr63jnw1xvDOMpYXEVY1FUjzKSutnZpp9V+K+4/X/ABF4bq8I1qdHFzVTnjePLddbPfs/66H9F+aK/F//AIIR/wDBeO/8R+IrD4MfHfxE97fX8gh8LeK9QkAedzwtjdycAsf+Wcp6/dPODX7Pg1+e1qMqUuWR8jgsbTxNP2lP/hhaM1gfFL4h23wn+Hmr+JLyy1fUbXRrdrmW20uze8vJ1H8MUKfM7ew5r5u8B/8ABYf4a/Ej4iz+FdM8J/GJ9bsbm3tdRgk8EXif2S04zG1ySP3Klfmy3G0E1EYSkrpG060INKTtc+sM0V8sfDH/AILEfBj4peKNF0+C48YaNZ+JNTbRtI1rWPDd1Z6PqV4JGiEEd2y+UWZ1KrlgGPAr2f4L/tLeFvj3qXje08Oz3k0/w912bw5rAntmiEV5EiO6oT99cOvzDg03Tkt0EK9OfwyTPQMj1ozXzLqH/BWf4RxfDDwX4m09/F3iE/EFb2XQ9H0fQLi+1e8hs5nhuZ/s0YLLFG6EF2wORjOcVm/Er/gsV8I/hf4D03xZd2HxG1DwlqWnJqY1yw8I3k1hao0pi8uaQqPKlWRSrIwBBI9RT9lPaxDxVFauS+8+rKK+fPhp/wAFKvh18Q/E/hjR7q18Z+DdQ8aajLpOhxeKdAn0g6ncxweeUj80DdlPunuRgc16T8T/ANo/wf8AB/x94K8L67q0dr4g+IWoPpuhWCrvmvJEjaSRto5CIq5ZjwMgd6lwknZo0VaDV0zuqK4C6/ac8F2v7Slt8I31qBfH13oL+JItNP3mslmERfPruP3euAT0FeRfFr/grV8KPgv8WPFnhDWLfx5Pd+BGhXxDf6d4Xu77TtHEsYlV5p4lYKuw7iewz6UKEnshSr04q8pLsfTlGea8S+N3/BQn4W/Azwd4T1a81248QSePYhP4Z03w7ZyarqOvxFQ/mW8EILMgVgS5wozyc1g+FP8AgqV8I/Ffwj8e+Lf7R1zSj8MLJtQ8UaFqmkTWWu6TAASJHs5AHKsAdrLlTjGc01Tna9hPEU0+VyVz6LozXmnxT/ax8HfBr4SeG/G2uXN9FoPiu903T9PeK1aSR5b90S2DIOVBLrkn7vevJtU/4K1/Dm1+IHiTw7p3hj4teI7rwnrEmg6ldaL4Nu76zhvIyA8YmQFTt3Ak+lCpyeyHKvTi7SZ9SUZqO0uBdW0cgDqJFDgMMMARnBHY151+1P4x1XwX8L3n0l5IJJ50hluI/vQIc5IPbPTPvXjZ9nFLKsurZjWTcaUXJpbu3Y9DAYOWLxEMNB2c2lrtqek5FHSvmTwr+1HqGi/BHV7DTNOv9T8U6TpN5d28zt5ySMiM6s3c89vavzi+FH7aHxX074zaPrtv4x8Qatq1/qESyWc1y0sF9vkAaEw/dwQSAABj8K+g8McPS43ymebZZViowsmne6ny8zi3ZbXs3sfN8a5wuGsdTwOMpybnqmrfDe1/O/Y/bjNFfkb8TPi74ti/4O1Ph94VXxJ4ht/DFz8PTczaGuoyjT2lNpdEs0Abyy2QDkjOVFfX3/BdfxZqvgb/AIJHfHbVtE1PUNG1Wx8NSSW17Y3D29xbt5kfzJIhDKcZ5B71ynso+tKK/n6+BX7SXjOx/ac/4Jfzap468WHSNX+Hl3qXiJZdWuHi1IRNds8tyu4+cQqdWDHCivc/2cf+Dq74deIv2+vi/o3xD8deGtI+BekxRr4E1W20O8+1aq+5Q5lIVmHBb7yKOKAP2Sor8z9V8T6Tp3/Bd2DxnN+1TrCaMPh43iH/AIVX9gvDbnT/ALIX+0bwPs/l4Hn9PO3DHSu98U/8HMX7F/hXQNE1F/jBa3sWuuyxRWelXc09qFbaXnjEe6Jc9NwBIGQCKAPvOivjP4+/8HAf7JP7Oeg+GtQ1v4v6LqMXi2zTUNOj0WGbU5WtnJCyyLEpMQyCMSbW4PHFe7fDf9uH4SfFr9mpvjDoPj/w3efDSO2kup9fa6EVraJH/rBKXwY3U8FGAbOBjkUAerUV8PfCb/g42/Y9+NHxit/BGjfFyyj1a9uVs7Oe+0+5s7G8lZtqok8kYT5iQAWIByK+4A4IyOQe4FAHF/E/9nXwR8aLiCbxV4Y0nW57VdkU1xF+9Rf7u4YOPbNfNf8AwUD/AGS/hx8Kv2Wte1rw94Q0nStVt5IFjuIlbeoaQBhySMEEivsmvKv20/g5qPx5/Zt8R+G9IMf9q3MSzWiOwVZZI2DhCe2cYz6kVvQqyjOLTtZnz2fZTRrYOvOlSi6rjKz5VzXtpZ737H4DftAfCT/hE9L1PVdNjJ0uS1nMsY/5dGMbf+OHt6V8HaNqSQ2RtblTJZT4Y4GWhfHEi+/qO4r94/2df2A/HPxI+L+n6b4p8F31h4Ygnxrn9qQ7Lee3xh4Rz+8Lg4+X1zmviT/gqZ/wQG+JH7LXxju9T+EXhTX/AB98Mtblaawj02I3d9oLMebWaMfOyDPySAEEYBwRX6Pn/G2IzunhqOPlzToxcea+sk2mr/3l1fXfe9/KxnGGf8UZThJZ1TbqYVSp87vzTi7NOSa3jazl13et2/z01PTZNNuRFIytkCWKWNuJF6q6nr1/EEV+6H/BAb/gt4fjNbaV8Dfi9qw/4TK1jFv4Y166fH9vRKPltZmP/LyoGFP/AC0A/vDnyf8AZW/4Ny/FXxm/4Jp63D4+s08FfF651aTWfCEdyQZdPh8pVNpebc4SdlyV6xna3XIr5C/Zy/4IzftM+Iv2svDvhqb4a+JvCVxoutW1ze69eJ5WnadHFMrtPHcA7ZOFO0JktkcV8jWnRrxlFvVHPg6ONwdSFSEXaXT9H2Z/UMPmFfH/AOyZpF/af8FEf2v7mezvYrW8l8P/AGaaSFliudumMDsYjDYPBxnFfXtpGYbaNGcyMihWc9XIHX8aeRmvBjKyfmfczp8zi+3+Vj8YPhD8G/iV4e/Yi+BniDx/rHiHxB+z3pHjSTUfE3g/TtAFtqugCPVJns7l5ADNcWkdxseVAA21gQSAa+kPgx+1D4f/AOCefxs/aN0f4lWPiizm8eeMZ/GfhGew0O6v4PFNpdWsISK1eFGUzrJGUMbFSCQenNfofijYOOBx046Vs8RzX5kcdPAeztyS1Vt9elu/4dD8lNG+FOgfs2/smfs/2HxRv/in8D/if4e0LU9S0Px/oOlSXtvoj3t7JcPo16kayLIWWSNmglTaxUgMGFelftEfEz4mftJf8EAvFmteOvD11B4y1OGONYrXS5LWbVrdNVhEN59j5eEzRKspjP3d3pX6QFAwIPI6880u2k692m1re41gLRcVLRq34Wuz4C/4Kufs4237U3x1/ZQ8H6tba2uk3+rat59/p3mJNo066UXt7pZF/wBXJHMqspbgkY5zXmnir9kf4g/Bn9sv9nH4n/GXxTJ8QviLJ4ov9OvNW020lXTND0O10y4MSpCBhHmK+dK55aR9o4Ar9SNtBXNEa7S5ehVTAQnJz6tp/db/AC/E/GDWNR+MutapeftZwfA3xnJ4jt/Gy+LrHWzqFsrr4NijNodL+xEi5+e1LzFNuTIQccV3/j34YfHH4z/Fn9sXxD8FPFN1olhrq6HdDRZdDQy+LLWXSUMqW11MP3E/kl41wCBIQGxX6wYo28ccVX1l9jJZb0c337a2avp6n5f/AAJ8a+Dv2Q/jn8N/jNB4b8XH4B6t8LLLwHo+pz6VcXd/8PbqzuGaW2v4FQyxCYkhpVTBePB4INY/7Qmq2f8AwVp/aV+Ks3wXjla38H/B7VvC2oXt3A2nz+Jr3USstlbJDKFleBPKZhMyhA0mAetfqu0YYEEAg9Rjg14v+0h+wP4B/aX8X6Z4p1Bdc8NeONFhNtY+KPDOpSaVq0EJOTC0sfEkWedkgZQegFEK65uZ7hUwUuTkTut7bfc/+B5XPjb4oftK6V+2z8AvgV8F/BeheMj8RtP8S+GrnxJpN9oN1ZnwnDpkkcl5JeSyII1C+UVXazbyy7etcf8As2fGLwh+z/8AtU/GS+8bfF/4r+ApLf4s6pqUfhSx0W5m0fWLdvLCyuUtZCyycg7ZB90V+mXwL+EUnwS+H0Ggy+KvFfjKSGV5TqniO9F5fy7jna0gVcqvQDHArsMe9L2yV4paDWCk2qkn7yt+HoyKwvo9SsYLmFi8NwgljYgglWGRweRwe9cl+0H8TdD+EHwg1zX/ABCsU2m2NuxaCQA/anPCRAHqWbA/XtXZbc968q/ar/ZQ0z9rHwzpmlatrOsaVa6Zcm6C2TKFnbbgbwwIOOcema8HPPrf9n1VgIKdVxaipWSbemt9LLe3XY+oyGOClmFFZlNwo8y53FXdlq7JdXt5XueAfsAftoaZ4v8ADvjC31rSNK0/xDpkcmpW62UAjF5adox1JKEgH1Bz2rD+H+ueHvBnxgg8Xp4I8H29/JdebNNb6cqyxhjy0fOFfnqBk16X8Kf+CVHhP4TfEPS/EVn4m8TXE2mSFvIkaJY7hSpVo3wuSpB5Fej6H+xl4a0TxPBqH2rULmK2m85LWVlMXByFPGSB/SjwhljMoyOeX59TUKiulyNWlF66qNkndtPvoz6LxHnw5js4eMyVc1KSTtKL9yWzUea7s7J+V7bH5c/taeNbD4I/8Hb/AME/FHiWVNK0Dxl4Ij03Tb65byoZJpIbuFVLHgHzCq892X1r66/4OSfjBoPwo/4I5/GGLWr+3s7jxRpyaJpkLuBJeXM0ybURerEKGY46BSa9P/4KZ/8ABJr4Uf8ABVH4a6bonxCtL+y1fw9I02h+IdKkEGpaQ7Y3BGIIZG2qSjAjKgjBGa+SPht/waqfD2b4k6DrPxf+M3xc+OOj+GHWTTtA8R6h/oK7TkK43MxXgAqpUMODkcV6x8OfGnwN8LXXh39tX/gk5pWrWbQTN8OpRPbTp1jla5YBlPUMjDg9jXs3/BLv9l74a+MP+Dhr9tXwzqvw98E6l4d0OC2fTdLudFt5bTTyZIcmGJkKx5zyVA61+jPx3/4JX+DPjr+3J8GfjnPrOtaNq/wSsnsdH0ewSFNPnibfhXBXcAofACkDAFeI/ty/8G8/hD9rL9qvVfjF4S+K3xK+C/jHxRZiw8Ry+FbpYk1mPYqEt0ZGKqoOCQSAcZ5oA+Wf2vLOHTv+Dl7xZb28UcEEH7PmpxxxxqFSNRYTAKAOAAOMVp/8Gw/7BHwe+Ln/AARq1fW/FXw98LeI9Z8calq1nq19qWnx3NxJDEfKjjR3BaNVGSNhHzEnrX2Vp3/BEbwXZ/tQ6V8Vrjx1451PX9L+Gv8AwrMi9lhm+12v2Zrf7XK5Te1wVYknOCe1eo/8E3/+Cdfhr/gmp+yRa/CDwvrut6/o1rd3d4L3U/LFyWuW3MP3aquAenFAH5k/8GnH7C/wl8f/ALJHxd1zxL4D8NeKdUvfGF34ee41jT4r10sYokCwp5gOwHexO3BJPXgV83fsZ/GH4Wfse/8ABMP9uLRviT4Hl+Inw30f4uJoGheEjeyW0ctyzzLAPNU7o1QQI5YZP7odSa/bn/gmP/wTP8L/APBLv4Q+IfB3hXxBr3iKy8Ra/Pr80+qiISxSyhQUXy1UbQFHUZrxnw1/wbx/Buz+Avx0+Heu6v4q8S6F8dPE3/CWXz3MkUVxol8ryPHJasiDGxpD98NkcHIJoA/Ir/gsf8O/jR4d/wCCZHhjVPHf7Nn7Nnwc8EJeacfDN34ZvQfEtiJELJCpDEy7o+ZCxY8bjzzX9Ev7J+q3Oqfss/DS5uZ5J7i48K6XLLK53NI7WkRLE9ySSa/NvVP+DSXwB8Q/h23h/wAffHr42+OItMijt/DTX+oIYfDcStysULBkJZcKcgAAcAV+pnww+HNr8Lfhr4e8MWk9xcWvhzTLbS4ZZSPMlSCJYlZscZIUE470AdDRiiigBMcUY4oooAXFJt+tFFAC4xRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAFFFFABRRRQAUUUUAf//Z
'@

# Run the splash on its OWN dedicated STA thread so it stays live - the progress bar + status render and the
# window stays draggable - even while the MAIN thread is blocked for a long time on Azure API calls. If the
# dedicated thread can't start we fall back to the inline splash, so collection is never affected either way.
function Show-Splash {
    $sync = [hashtable]::Synchronized(@{ Xaml = $splashXaml.OuterXml; Dispatcher = $null; Status = $null; Progress = $null; Sub = $null; Win = $null; Ready = $false; Err = $null; Logo = $script:_splashLogoB64 })
    $script:_splashSync = $sync
    try {
        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = 'STA'; $rs.ThreadOptions = 'ReuseThread'; $rs.Open()
        $rs.SessionStateProxy.SetVariable('sync', $sync)
        $ps = [powershell]::Create(); $ps.Runspace = $rs
        [void]$ps.AddScript({
            try {
                Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
                $w = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new([xml]$sync.Xaml))
                $sync.Win = $w; $sync.Dispatcher = $w.Dispatcher
                $sync.Status = $w.FindName('SplashStatus'); $sync.Progress = $w.FindName('SplashProgress'); $sync.Sub = $w.FindName('SplashSub')
                try { $lb=[Convert]::FromBase64String($sync.Logo); $lbi=New-Object System.Windows.Media.Imaging.BitmapImage; $lbi.BeginInit(); $lbi.CacheOption='OnLoad'; $lbi.StreamSource=(New-Object System.IO.MemoryStream(,$lb)); $lbi.EndInit(); $lbi.Freeze(); $lg=$w.FindName('Logo'); if($lg){$lg.Source=$lbi} } catch {}
                $w.Add_SourceInitialized({ $sync.Ready = $true })
                # Borderless window - let the user drag it anywhere during collection.
                $w.Add_MouseLeftButtonDown({ try { $this.DragMove() } catch {} })
                # Apply status/progress/sub updates ON the splash thread via a timer that reads the synced
                # hashtable - the main thread only writes $sync.Msg/$sync.Prog/$sync.SubText, so no scriptblock
                # is marshaled across the runspace/thread boundary.
                $t = New-Object System.Windows.Threading.DispatcherTimer
                $t.Interval = [TimeSpan]::FromMilliseconds(120)
                $t.Add_Tick({ try {
                    if ("$($sync.Msg)" -ne "$($sync.Shown)") { $sync.Status.Text = "$($sync.Msg)"; $sync.Shown = "$($sync.Msg)" }
                    if ($null -ne $sync.Prog -and "$($sync.Prog)" -ne "$($sync.ProgShown)") { $sync.Progress.Value = [double]$sync.Prog; $sync.ProgShown = "$($sync.Prog)" }
                    if ("$($sync.SubText)" -ne "$($sync.SubShown)") { $sync.Sub.Text = "$($sync.SubText)"; $sync.SubShown = "$($sync.SubText)" }
                } catch {} })
                $sync.Timer = $t; $t.Start()
                $w.Show()
                [System.Windows.Threading.Dispatcher]::Run()
            } catch { $sync.Err = "$($_.Exception.Message)" }
        })
        $script:_splashPs = $ps; $script:_splashRs = $rs; $script:_splashHandle = $ps.BeginInvoke()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $sync.Ready -and -not $sync.Err -and $sw.ElapsedMilliseconds -lt 4000) { Start-Sleep -Milliseconds 25 }
        if ($sync.Dispatcher) {
            $script:_splash = $sync.Win; $script:_splashStatus = $sync.Status
            $script:_splashProgress = $sync.Progress; $script:_splashSub = $sync.Sub
            return
        }
    } catch {}
    $script:_splashSync = $null

    # Fallback: inline (same-thread) splash.
    $script:_splash         = [Windows.Markup.XamlReader]::Load([System.Xml.XmlNodeReader]::new($splashXaml))
    $script:_splashStatus   = $script:_splash.FindName('SplashStatus')
    $script:_splashProgress = $script:_splash.FindName('SplashProgress')
    $script:_splashSub      = $script:_splash.FindName('SplashSub')
    $script:_splash.Add_MouseLeftButtonDown({ try { $this.DragMove() } catch {} })
    $script:_splash.Show()
    $script:_splash.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
}

function Set-ReportStatus {
    param([string]$Text, [int]$Progress = -1, [string]$Sub = '')
    $sync = $script:_splashSync
    if ($sync -and $sync.Dispatcher) {
        # Hand the values to the splash thread via the synchronized hashtable; the DispatcherTimer set up in
        # Show-Splash (running ON the splash thread) applies them. No cross-thread/runspace scriptblock.
        $sync.Msg = $Text
        if ($Progress -ge 0) { $sync.Prog = $Progress }
        $sync.SubText = $Sub
        return
    }
    if ($script:_splash -and $script:_splashStatus) {
        try { $script:_splash.Dispatcher.Invoke([Action]{
            $script:_splashStatus.Text = $Text
            if ($Progress -ge 0) { $script:_splashProgress.Value = $Progress }
            $script:_splashSub.Text = $Sub
        }, [System.Windows.Threading.DispatcherPriority]::Render) } catch {}
    }
}

function Close-Splash {
    $sync = $script:_splashSync
    if ($sync -and $sync.Dispatcher) {
        try { $sync.Dispatcher.Invoke([Action]{ try { $sync.Win.Close() } catch {} }) } catch {}
        try { $sync.Dispatcher.InvokeShutdown() } catch {}
        try { if ($script:_splashPs -and $script:_splashHandle) { [void]$script:_splashPs.EndInvoke($script:_splashHandle) } } catch {}
        try { if ($script:_splashRs) { $script:_splashRs.Close() } } catch {}
        $script:_splashSync = $null; $script:_splash = $null
        return
    }
    if ($script:_splash) { try { $script:_splash.Close() } catch {} ; $script:_splash = $null }
}

# -- Self-update check (GitHub) ------------------------------------------------
# On launch, check euc-reports-collectors for a newer version of THIS script and offer to update in
# place. Optional and fail-safe: short timeout, silent on any failure; skip with -SkipUpdateCheck.
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

function Invoke-AvdUpdateCheck {
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
        # Never downgrade (a same-version, different-hash entry is the unsigned->signed migration, kept).
        $rv = ConvertTo-CollectorVersion "$($entry.version)"; $lv = ConvertTo-CollectorVersion $script:CollectorVersion
        if ($rv -and $lv -and $rv -lt $lv) { Write-Verbose "Update check: manifest v$($entry.version) older than local - skipping"; return }
        if (-not (Show-UpdatePrompt $script:CollectorVersion "$($entry.version)")) { return }
        # 3. Download the published script BYTE-EXACT (preserves any signature).
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("AvdCollector-$([guid]::NewGuid().ToString('N')).ps1")
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
            $alt = Join-Path (Split-Path $self -Parent) 'Get-AVDData.NEW.ps1'
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

# Offer to self-update from GitHub before doing anything (interactive; fail-safe / optional).
Invoke-AvdUpdateCheck

Show-Splash

#endregion

#region -- Prerequisites -------------------------------------------------------

function Assert-Module {
    param([string]$Name, [int]$Progress)
    Set-ReportStatus "Loading module: $Name" -Progress $Progress
    $mod = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $mod) {
        Set-ReportStatus "Installing: $Name" -Progress $Progress
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    }
    Import-Module $Name -Force -ErrorAction Stop
}

Set-ReportStatus 'Loading Az.Accounts...' -Progress 15
Assert-Module -Name 'Az.Accounts' -Progress 15

Set-ReportStatus 'Initialising...' -Progress 30

#region -- ARM REST Helpers ----------------------------------------------------

$script:ApiVersions = @{
    DesktopVirtualization = '2025-10-10'
    Authorization         = '2022-04-01'
    DiagnosticSettings    = '2021-05-01-preview'
    Network               = '2025-05-01'
    Storage               = '2025-06-01'
    Resources             = '2024-03-01'
    Subscriptions         = '2022-12-01'
    LogAnalytics          = '2022-10-01'
    KeyVault              = '2023-07-01'
    PrivateLinkScope      = '2021-07-01-preview'
    Compute               = '2024-07-01'
    ComputeGalleries      = '2026-03-03'
    VirtualMachineImages  = '2025-10-01'
    DataCollection        = '2022-06-01'
}

$script:_armTokenCache = @{}
$script:_vmSizeCache   = @{}   # keyed "subId:location" -> hashtable of vmSizeName -> {numberOfCores, memoryInMB}


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
        $hasOdata    = $resp -and $resp.PSObject.Properties['@odata.nextLink']
        if ($hasValue) { foreach ($item in $resp.value) { $all.Add($item) } }
        elseif ($resp -and -not $hasNextLink -and -not $hasOdata) { return $resp }
        $cur = if ($hasNextLink -and $resp.nextLink) { $resp.nextLink }
               elseif ($hasOdata -and $resp.'@odata.nextLink') { $resp.'@odata.nextLink' }
               else { $null }
    } while ($cur)
    return $all.ToArray()
}

function Get-LogAnalyticsToken {
    $cached = $script:_armTokenCache['OperationalInsights']
    if ($cached -and $cached['ExpiresOn'] -gt [DateTimeOffset]::UtcNow.AddMinutes(5)) { return $cached['Token'] }
    $tok = $null
    # Try named resource type first (most reliable), fall back to resource URL
    try   { $tok = Get-AzAccessToken -ResourceTypeName 'OperationalInsights' -AsSecureString -ErrorAction Stop }
    catch { try { $tok = Get-AzAccessToken -ResourceTypeName 'OperationalInsights' -ErrorAction Stop } catch {} }
    if (-not $tok) {
        try   { $tok = Get-AzAccessToken -ResourceUrl 'https://api.loganalytics.azure.com/' -AsSecureString -ErrorAction Stop }
        catch { $tok = Get-AzAccessToken -ResourceUrl 'https://api.loganalytics.azure.com/' -ErrorAction Stop }
    }
    $plain = if ($tok.PSObject.Properties['Token'] -and $tok.Token -is [securestring]) {
        [System.Net.NetworkCredential]::new('', $tok.Token).Password
    } elseif ($tok.PSObject.Properties['Token']) { [string]$tok.Token } else { [string]$tok }
    $expiry = if ($tok.PSObject.Properties['ExpiresOn']) { $tok.ExpiresOn } else { [DateTimeOffset]::UtcNow.AddHours(1) }
    # Log token audience for diagnostics
    try {
        $payload = $plain.Split('.')[1]
        $pad = 4 - ($payload.Length % 4); if ($pad -lt 4) { $payload += '=' * $pad }
        $claims = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json
        Write-DebugLog "  LA token audience: $($claims.aud)"
    } catch {}
    $script:_armTokenCache['OperationalInsights'] = @{ Token = $plain; ExpiresOn = $expiry }
    return $plain
}

function Invoke-LogAnalyticsQuery {
    param([string]$WorkspaceResourceId, [string]$WorkspaceName, [string]$Token, [string]$Query)
    if (-not $WorkspaceResourceId) { return @() }
    $resp = $null
    # Primary: ARM management-plane proxy ( /api/query , api-version 2020-08-01 ).
    # Goes via management.azure.com and is not subject to the Log Analytics data-plane
    # private-link rejection that blocks api.loganalytics.azure.com in some networks.
    try {
        $body = @{ query = $Query } | ConvertTo-Json -Depth 5 -Compress
        $resp = Invoke-ArmRestMethod -Method POST -Path "$WorkspaceResourceId/api/query" -Token $Token -ApiVersion '2020-08-01' -Body $body -FullResponse
    } catch {
        Write-DebugLog "  LA ARM query failed for ${WorkspaceName} (trying direct): $_"
        # Fallback: direct LA data-plane API on api.loganalytics.azure.com, by resource id.
        try {
            $laTok   = Get-LogAnalyticsToken
            $uri     = "https://api.loganalytics.azure.com/v1$WorkspaceResourceId/query"
            $body    = @{ query = $Query } | ConvertTo-Json -Depth 5 -Compress
            $headers = @{ Authorization = "Bearer $laTok"; 'Content-Type' = 'application/json' }
            $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -TimeoutSec 90 -ErrorAction Stop
        } catch {
            Write-DebugLog "  LA direct query also failed for ${WorkspaceName}: $_"
            return @()
        }
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    if ($resp -and ($resp.PSObject.Properties['tables']) -and $resp.tables -and @($resp.tables).Count -gt 0) {
        $tbl  = @($resp.tables)[0]
        $cols = @($tbl.columns | ForEach-Object {
            if ($_.PSObject.Properties['name'])            { $_.name }
            elseif ($_.PSObject.Properties['ColumnName'])  { $_.ColumnName }
            else                                           { "$_" }
        })
        foreach ($r in $tbl.rows) {
            $o = [ordered]@{}
            for ($i = 0; $i -lt $cols.Count; $i++) { $o[$cols[$i]] = $r[$i] }
            $rows.Add($o)
        }
    }
    return $rows.ToArray()
}

function Get-ArmHostPools          { param([string]$SubscriptionId,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.DesktopVirtualization/hostPools" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) }
function Get-ArmSessionHosts       { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$HostPool,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.DesktopVirtualization/hostPools/$HostPool/sessionHosts" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) }
function Get-ArmUserSessions       { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$HostPool,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.DesktopVirtualization/hostPools/$HostPool/userSessions" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) }
function Get-ArmApplicationGroups  { param([string]$SubscriptionId,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.DesktopVirtualization/applicationGroups" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) }
function Get-ArmApplications       { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$AppGroupName,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.DesktopVirtualization/applicationGroups/$AppGroupName/applications" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) }
function Get-ArmDesktops           { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$AppGroupName,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.DesktopVirtualization/applicationGroups/$AppGroupName/desktops" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) }
function Get-ArmWorkspaces         { param([string]$SubscriptionId,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.DesktopVirtualization/workspaces" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) }
function Get-ArmScalingPlans       { param([string]$SubscriptionId,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.DesktopVirtualization/scalingPlans" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) }
function Get-ArmScalingPlanSchedules { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$ScalingPlanName,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.DesktopVirtualization/scalingPlans/$ScalingPlanName/pooledSchedules" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) }
function Get-ArmSessionHostConfiguration { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$HostPoolName,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.DesktopVirtualization/hostPools/$HostPoolName/sessionHostConfigurations" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) | Select-Object -First 1 } catch { $null } }
function Get-ArmImageTemplates    { param([string]$SubscriptionId,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.VirtualMachineImages/imageTemplates" -Token $Token -ApiVersion $script:ApiVersions.VirtualMachineImages) } catch { @() } }
function Get-ArmAppAttachPackages { param([string]$SubscriptionId,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.DesktopVirtualization/appAttachPackages" -Token $Token -ApiVersion $script:ApiVersions.DesktopVirtualization) } catch { @() } }
function Get-ArmRoleAssignments    { param([string]$ResourceId,[string]$Token) @(Invoke-ArmRestMethod -Path "$ResourceId/providers/Microsoft.Authorization/roleAssignments?`$filter=atScope()" -Token $Token -ApiVersion $script:ApiVersions.Authorization) }
function Get-ArmRoleDefinitions    { param([string]$SubscriptionId,[string]$Token) $defs = @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions" -Token $Token -ApiVersion $script:ApiVersions.Authorization); $map = @{}; foreach ($d in $defs) { $map[$d.name] = $d.properties.roleName }; return $map }
function Get-ArmDiagnosticSettings {
    param([string]$ResourceId, [string]$Token)
    try {
        $r = Invoke-ArmRestMethod -Path "$ResourceId/providers/microsoft.insights/diagnosticSettings" -Token $Token -ApiVersion $script:ApiVersions.DiagnosticSettings
        return @($r | ForEach-Object {
            $p = $_.properties
            $dest = [System.Collections.Generic.List[string]]::new()
            $lawResourceId = $null
            if ($p.PSObject.Properties['workspaceId']                 -and $p.workspaceId)                 { [void]$dest.Add('LogAnalytics:' + ($p.workspaceId -split '/')[-1]); $lawResourceId = $p.workspaceId }
            if ($p.PSObject.Properties['storageAccountId']            -and $p.storageAccountId)            { [void]$dest.Add('Storage:'      + ($p.storageAccountId -split '/')[-1]) }
            if ($p.PSObject.Properties['eventHubAuthorizationRuleId'] -and $p.eventHubAuthorizationRuleId) { [void]$dest.Add('EventHub:'     + ($p.eventHubAuthorizationRuleId -split '/')[-1]) }
            if ($p.PSObject.Properties['partnerSolutionId']           -and $p.partnerSolutionId)           { [void]$dest.Add('Partner:'      + ($p.partnerSolutionId -split '/')[-1]) }
            $enabledLogs = @()
            if ($p.PSObject.Properties['logs']) {
                $enabledLogs = @($p.logs | Where-Object { $_.enabled } | ForEach-Object { $_.category })
            }
            $allLogsEnabled = $false
            if ($p.PSObject.Properties['categoryGroups']) {
                $allLogsEnabled = @($p.categoryGroups) -contains 'allLogs'
            }
            [ordered]@{
                Name              = $_.name
                Destinations      = @($dest)
                WorkspaceId       = $lawResourceId
                EnabledLogs       = $enabledLogs
                AllLogs           = $allLogsEnabled
            }
        })
    } catch {
        return @()
    }
}
function Get-ArmStorageAccounts    { param([string]$SubscriptionId,[string]$Token,[string]$ResourceGroup='') $path = if ($ResourceGroup) { "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Storage/storageAccounts" } else { "/subscriptions/$SubscriptionId/providers/Microsoft.Storage/storageAccounts" }; @(Invoke-ArmRestMethod -Path $path -Token $Token -ApiVersion $script:ApiVersions.Storage) }
function Get-ArmBlobContainers     { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$AccountName,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Storage/storageAccounts/$AccountName/blobServices/default/containers" -Token $Token -ApiVersion $script:ApiVersions.Storage) } catch { @() } }
function Get-ArmFileShares         { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$AccountName,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Storage/storageAccounts/$AccountName/fileServices/default/shares" -Token $Token -ApiVersion $script:ApiVersions.Storage) } catch { @() } }
function Get-ArmFileShareStats     { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$AccountName,[string]$ShareName,[string]$Token) try { Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Storage/storageAccounts/$AccountName/fileServices/default/shares/$ShareName`?`$expand=stats" -Token $Token -ApiVersion $script:ApiVersions.Storage } catch { $null } }
function Get-ArmStorageAccountKey  { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$AccountName,[string]$Token) try { $r = Invoke-ArmRestMethod -Method POST -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Storage/storageAccounts/$AccountName/listKeys" -Token $Token -ApiVersion $script:ApiVersions.Storage -FullResponse; $r.keys[0].value } catch { $null } }
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
              ForEach-Object { $p = $_ -split '=',2; [pscustomobject]@{k=$p[0];v=if($p.Count -gt 1){$p[1]}else{''}} } |
              Sort-Object k
        $canonRes += "`n" + (($qs | ForEach-Object { "$($_.k):$($_.v)" }) -join "`n")
    }
    $sts  = "$Method`n`n`n`n`n`n`n`n`n`n`n`n$canonHdrs`n$canonRes"
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($AccountKey))
    $sig  = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($sts)))
    return @{ Authorization = "SharedKey ${AccountName}:${sig}"; 'x-ms-date' = $date }
}
function Get-AzureFilesShareAcl {
    param([string]$AccountName, [string]$ShareName, [string]$StorageToken, [string]$AccountKey)

    $sddl = $null
    Write-DebugLog "  ACL [$AccountName/$ShareName] starting - token=$(if($StorageToken){'yes'}else{'no'}) key=$(if($AccountKey){'yes'}else{'no'})"

    $baseUri    = "https://$AccountName.file.core.windows.net"
    $apiVersion = '2022-11-02'

    # Step 1: REST API with OAuth token + x-ms-file-request-intent: backup header.
    # Requires Storage File Data Privileged Reader/Contributor role.
    if ($StorageToken) {
        Write-DebugLog "  ACL [$AccountName/$ShareName] step 1: trying REST API with OAuth token + backup intent"
        try {
            $dirHeaders = @{
                'Authorization'            = "Bearer $StorageToken"
                'x-ms-file-request-intent' = 'backup'
                'x-ms-version'             = $apiVersion
            }
            $dirResp = Invoke-WebRequest -Uri "$baseUri/$ShareName/?restype=directory" `
                           -Method Get -Headers $dirHeaders -UseBasicParsing -ErrorAction Stop
            $permKey = $dirResp.Headers['x-ms-file-permission-key']
            Write-DebugLog "  ACL [$AccountName/$ShareName] step 1: permKey=$(if($permKey){$permKey}else{'null'})"
            if ($permKey) {
                $permHeaders = $dirHeaders.Clone()
                $permHeaders['x-ms-file-permission-key'] = $permKey
                $permResp = Invoke-RestMethod -Uri "$baseUri/$ShareName`?restype=share&comp=filepermission" `
                                -Method Get -Headers $permHeaders -ErrorAction Stop
                $sddl = if ($permResp -is [string]) { $permResp } else { $permResp.permission }
                Write-DebugLog "  ACL [$AccountName/$ShareName] step 1: SDDL length=$(if($sddl){$sddl.Length}else{'null'})"
            }
        } catch {
            Write-DebugLog "  ACL [$AccountName/$ShareName] step 1: FAILED - $($_.Exception.Message)"
        }
    } else {
        Write-DebugLog "  ACL [$AccountName/$ShareName] step 1: skipped (no OAuth token available)"
    }

    # Step 2: REST API with Shared Key (storage account key).
    if (-not $sddl -and $AccountKey) {
        Write-DebugLog "  ACL [$AccountName/$ShareName] step 2: trying REST API with Shared Key auth"
        try {
            $dirUri  = "$baseUri/$ShareName/?restype=directory"
            $dirXms  = @{ 'x-ms-version' = $apiVersion }
            $dirAuth = New-StorageSharedKeyAuth -AccountName $AccountName -AccountKey $AccountKey -Method GET -Uri $dirUri -XmsHeaders $dirXms
            $dirHeaders = @{
                'Authorization' = $dirAuth.Authorization
                'x-ms-date'     = $dirAuth.'x-ms-date'
                'x-ms-version'  = $apiVersion
            }
            $dirResp = Invoke-WebRequest -Uri $dirUri -Method Get -Headers $dirHeaders -UseBasicParsing -ErrorAction Stop
            $permKey = $dirResp.Headers['x-ms-file-permission-key']
            Write-DebugLog "  ACL [$AccountName/$ShareName] step 2: permKey=$(if($permKey){$permKey}else{'null'})"
            if ($permKey) {
                $permUri  = "$baseUri/$ShareName`?restype=share&comp=filepermission"
                $permXms  = @{ 'x-ms-version' = $apiVersion; 'x-ms-file-permission-key' = $permKey }
                $permAuth = New-StorageSharedKeyAuth -AccountName $AccountName -AccountKey $AccountKey -Method GET -Uri $permUri -XmsHeaders $permXms
                $permHeaders = @{
                    'Authorization'            = $permAuth.Authorization
                    'x-ms-date'                = $permAuth.'x-ms-date'
                    'x-ms-version'             = $apiVersion
                    'x-ms-file-permission-key' = $permKey
                }
                $permResp = Invoke-RestMethod -Uri $permUri -Method Get -Headers $permHeaders -ErrorAction Stop
                $sddl = if ($permResp -is [string]) { $permResp } else { $permResp.permission }
                Write-DebugLog "  ACL [$AccountName/$ShareName] step 2: SDDL length=$(if($sddl){$sddl.Length}else{'null'})"
            }
        } catch {
            Write-DebugLog "  ACL [$AccountName/$ShareName] step 2: FAILED - $($_.Exception.Message)"
            Write-Warning "File share ACL ($AccountName/$ShareName): key-based retrieval failed: $_"
        }
    } elseif (-not $sddl) {
        Write-DebugLog "  ACL [$AccountName/$ShareName] step 2: skipped ($(if(-not $AccountKey){'no key available'}else{'SDDL already retrieved'}))"
    }

    if (-not $sddl) {
        Write-DebugLog "  ACL [$AccountName/$ShareName] FAILED - no SDDL retrieved from any method"
        if (-not $StorageToken -and -not $AccountKey) { Write-Warning "File share ACL ($AccountName/$ShareName): no credentials available, skipping" }
        else { Write-Warning "File share ACL ($AccountName/$ShareName): could not retrieve SDDL" }
        return @()
    }
    Write-DebugLog "  ACL [$AccountName/$ShareName] SDDL retrieved successfully, parsing ACEs"

    try {

        # Step 3: parse SDDL into ACE entries
        $fs    = [System.Security.AccessControl.DirectorySecurity]::new()
        $fs.SetSecurityDescriptorSddlForm($sddl)
        $rules = $fs.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
        $aces  = @()
        foreach ($rule in $rules) {
            $r     = $rule.FileSystemRights
            $flags = $rule.InheritanceFlags
            $prop  = $rule.PropagationFlags
            $ci = ($flags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0
            $oi = ($flags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0
            $io = ($prop  -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
            $appliesTo = switch ($true) {
                ($io -and $ci -and $oi) { 'Subfolders and files only'; break }
                ($ci -and $oi)          { 'This folder, subfolders and files'; break }
                ($ci)                   { 'This folder and subfolders'; break }
                ($oi)                   { 'This folder and files'; break }
                default                 { 'This folder only' }
            }
            $fc = [System.Security.AccessControl.FileSystemRights]::FullControl
            $aces += [ordered]@{
                Principal   = $rule.IdentityReference.Value
                AccessType  = $rule.AccessControlType.ToString()
                FullControl = ($r -band $fc) -eq $fc
                Modify      = ([int]$r -band 0x0301BF) -eq 0x0301BF
                ReadExecute = ([int]$r -band 0x0201A9) -eq 0x0201A9
                Read        = ([int]$r -band 0x020089) -eq 0x020089
                Write       = ([int]$r -band 0x000116) -eq 0x000116
                Inherited   = $rule.IsInherited
                AppliesTo   = $appliesTo
            }
        }
        Write-DebugLog "  ACL [$AccountName/$ShareName] parsed $($aces.Count) ACE(s): $(($aces | ForEach-Object { $_.Principal }) -join ', ')"
        return $aces
    }
    catch {
        Write-DebugLog "  ACL [$AccountName/$ShareName] SDDL parse error: $_"
        Write-Warning "File share ACL ($AccountName/$ShareName): $_"
        return @()
    }
}
function Get-ArmResourceGroups     { param([string]$SubscriptionId,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups" -Token $Token -ApiVersion $script:ApiVersions.Resources) }
function Get-ArmLogAnalyticsWorkspaces { param([string]$SubscriptionId,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.OperationalInsights/workspaces" -Token $Token -ApiVersion $script:ApiVersions.LogAnalytics) }
function Get-ArmPrivateLinkScopes       { param([string]$SubscriptionId,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/privateLinkScopes" -Token $Token -ApiVersion $script:ApiVersions.PrivateLinkScope) } catch { @() } }
function Get-ArmVmExtensions            { param([string]$ResourceId,[string]$Token) try { @(Invoke-ArmRestMethod -Path "$ResourceId/extensions" -Token $Token -ApiVersion $script:ApiVersions.Compute) } catch { @() } }
function Get-ArmVm                      { param([string]$ResourceId,[string]$Token) try { Invoke-ArmRestMethod -Path $ResourceId -Token $Token -ApiVersion $script:ApiVersions.Compute } catch { $null } }
function Get-ArmNetworkInterface        { param([string]$ResourceId,[string]$Token) try { Invoke-ArmRestMethod -Path $ResourceId -Token $Token -ApiVersion $script:ApiVersions.Network } catch { $null } }
function Get-ArmVirtualNetwork          { param([string]$ResourceId,[string]$Token) try { Invoke-ArmRestMethod -Path $ResourceId -Token $Token -ApiVersion $script:ApiVersions.Network } catch { $null } }
function Get-ArmVirtualNetworkUsages    { param([string]$ResourceId,[string]$Token) try { @(Invoke-ArmRestMethod -Path "$ResourceId/usages" -Token $Token -ApiVersion $script:ApiVersions.Network) } catch { @() } }
function Get-ArmPrivateEndpoint         { param([string]$ResourceId,[string]$Token) try { Invoke-ArmRestMethod -Path $ResourceId -Token $Token -ApiVersion $script:ApiVersions.Network } catch { $null } }
function Get-VmSizeSpec {
    param([string]$SubscriptionId, [string]$Location, [string]$VmSize, [string]$Token)
    $cacheKey = "$SubscriptionId`:$Location"
    if (-not $script:_vmSizeCache.ContainsKey($cacheKey)) {
        try {
            $raw = @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Compute/locations/$Location/vmSizes" -Token $Token -ApiVersion $script:ApiVersions.Compute)
            $map = @{}
            foreach ($s in $raw) { $map[$s.name] = $s }
            $script:_vmSizeCache[$cacheKey] = $map
            Write-DebugLog "  VM sizes cached for $Location ($($raw.Count) sizes)"
        } catch {
            $script:_vmSizeCache[$cacheKey] = @{}
            Write-DebugLog "  VM sizes lookup failed for $Location`: $_"
        }
    }
    return $script:_vmSizeCache[$cacheKey][$VmSize]
}
function Get-ArmVmsInRg                 { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/virtualMachines" -Token $Token -ApiVersion $script:ApiVersions.Compute) } catch { @() } }
function Get-ArmDataCollectionRules     { param([string]$SubscriptionId,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/dataCollectionRules" -Token $Token -ApiVersion $script:ApiVersions.DataCollection) } catch { @() } }
function Get-ArmDataCollectionEndpoints { param([string]$SubscriptionId,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/dataCollectionEndpoints" -Token $Token -ApiVersion $script:ApiVersions.DataCollection) } catch { @() } }
function Get-ArmPrivateLinkScopedResources { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$ScopeName,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/privateLinkScopes/$ScopeName/scopedResources" -Token $Token -ApiVersion $script:ApiVersions.PrivateLinkScope) } catch { @() } }
function Get-ArmKeyVaults          { param([string]$SubscriptionId,[string]$Token) @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/vaults" -Token $Token -ApiVersion $script:ApiVersions.KeyVault) }
function Get-ArmGalleries            { param([string]$SubscriptionId,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Compute/galleries" -Token $Token -ApiVersion $script:ApiVersions.ComputeGalleries) } catch { @() } }
function Get-ArmGalleryImages        { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$GalleryName,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/galleries/$GalleryName/images" -Token $Token -ApiVersion $script:ApiVersions.ComputeGalleries) } catch { @() } }
function Get-ArmGalleryImageVersions { param([string]$SubscriptionId,[string]$ResourceGroup,[string]$GalleryName,[string]$ImageName,[string]$Token) try { @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Compute/galleries/$GalleryName/images/$ImageName/versions" -Token $Token -ApiVersion $script:ApiVersions.ComputeGalleries) } catch { @() } }
function Get-ArmSubscriptions      { param([string]$Token) @(Invoke-ArmRestMethod -Path '/subscriptions' -Token $Token -ApiVersion $script:ApiVersions.Subscriptions | Where-Object { $_.state -eq 'Enabled' }) }
function Get-ArmTenants            { param([string]$Token) @(Invoke-ArmRestMethod -Path '/tenants' -Token $Token -ApiVersion $script:ApiVersions.Subscriptions) }

# Converts an ARM properties PSObject to an ordered hashtable, omitting any keys
# in the Exclude list. Used to store the full raw ARM properties alongside the
# hand-picked computed fields so the report can access any property without a
# collection-script change.
function ConvertTo-SanitisedProperties {
    param($Properties, [string[]]$Exclude = @())
    if (-not $Properties) { return [ordered]@{} }
    $out = [ordered]@{}
    foreach ($p in $Properties.PSObject.Properties) {
        if ($p.Name -in $Exclude) { continue }
        $out[$p.Name] = $p.Value
    }
    return $out
}

function Get-GraphPrincipalNames {
    param([string[]]$ObjectIds, [string]$Token)
    $map = @{}
    if (-not $ObjectIds -or $ObjectIds.Count -eq 0) { return $map }
    try {
        $unique = @($ObjectIds | Where-Object { $_ } | Sort-Object -Unique)
        $body   = @{ ids = $unique; types = @('user','group','servicePrincipal','device') } | ConvertTo-Json -Compress
        $resp   = Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' `
                    -Method POST -ContentType 'application/json' `
                    -Headers @{ Authorization = "Bearer $Token" } -Body $body
        foreach ($obj in $resp.value) {
            $name = if ($obj.displayName) { $obj.displayName } elseif ($obj.userPrincipalName) { $obj.userPrincipalName } else { $obj.id }
            $map[$obj.id] = $name
        }
    } catch {}
    return $map
}

function ConvertTo-TagHashtable {
    param($Tags)
    if (-not $Tags) { return @{} }
    $ht = @{}
    $Tags.PSObject.Properties | ForEach-Object { $ht[$_.Name] = $_.Value }
    return $ht
}

function Get-ResourceGroup {
    param([string]$ResourceId)
    $parts = $ResourceId.Split('/')
    $idx   = 0..($parts.Count - 1) | Where-Object { $parts[$_] -eq 'resourceGroups' } | Select-Object -First 1
    if ($null -ne $idx) { return $parts[$idx + 1] }
    return $ResourceId.Split('/')[4]
}

#endregion

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Hide splash while auth dialog is shown
$script:_splash.Dispatcher.Invoke([Action]{ $script:_splash.Hide() }, [System.Windows.Threading.DispatcherPriority]::Render)

#endregion

#region -- Config Helpers ------------------------------------------------------

# Consolidated per-user config folder shared by all EUC-report collectors. Each config filename is
# prefixed with its report ('avd-') so Citrix and AVD configs coexist here without colliding.
$script:_configDir    = Join-Path $env:LOCALAPPDATA 'euc-reports'
$script:_configPrefix = 'avd-'

# One-time migration: move any configs from the old in-repo <script>\configs folder into the
# consolidated folder, adding the 'avd-' prefix. (AVD is not under the read-only audit, so a plain
# Move-Item is fine.)
$script:_legacyConfigDir = Join-Path $PSScriptRoot 'configs'
try {
    if (-not (Test-Path $script:_configDir)) { New-Item -ItemType Directory -Path $script:_configDir -Force | Out-Null }
    if (Test-Path $script:_legacyConfigDir) {
        Get-ChildItem -Path $script:_legacyConfigDir -Filter '*.config.json' -ErrorAction SilentlyContinue | ForEach-Object {
            $leaf = if ($_.Name -like "$($script:_configPrefix)*") { $_.Name } else { "$($script:_configPrefix)$($_.Name)" }
            $dest = Join-Path $script:_configDir $leaf
            if (-not (Test-Path $dest)) { try { Move-Item -LiteralPath $_.FullName -Destination $dest -Force } catch {} }
        }
    }
} catch {}

function Read-CollectConfig {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $null }
    try { return (Get-Content $Path -Raw | ConvertFrom-Json) } catch { return $null }
}

function Save-CollectConfig {
    param($Config, [string]$CustomerName)
    try {
        if (-not (Test-Path $script:_configDir)) { New-Item -ItemType Directory -Path $script:_configDir -Force | Out-Null }
        $safeName = if ($CustomerName) { ($CustomerName -replace '[^A-Za-z0-9\-_\s]', '_').Trim() } else { 'Default' }
        $path = Join-Path $script:_configDir "$($script:_configPrefix)$safeName.config.json"
        $Config | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
        return $path
    } catch { return $null }
}

#endregion

#region -- Resource Group Picker -----------------------------------------------

function Show-RGPickerDialog {
    param([string[]]$SubscriptionIds, [string]$Token, [string[]]$PreSelected = @())

    $rgNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $allRGs  = [System.Collections.Generic.List[object]]::new()
    foreach ($subId in $SubscriptionIds) {
        try {
            foreach ($rg in @(Get-ArmResourceGroups -SubscriptionId $subId -Token $Token)) {
                if ($rgNames.Add($rg.name)) {
                    $allRGs.Add([ordered]@{ Name = $rg.name; Location = $rg.location })
                }
            }
        } catch {}
    }
    $sorted = @($allRGs | Sort-Object { $_['Name'] })

    $preSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $PreSelected) { [void]$preSet.Add($r) }

    $picker = New-ThemedWindow @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Select Resource Groups" Width="440" Height="520"
        WindowStartupLocation="CenterOwner" ResizeMode="CanResize"
        FontFamily="Segoe UI" FontSize="12" Background="#F4F6F9">
  <Window.Resources>
    <Style x:Key="BlueBtn" TargetType="Button">
      <Setter Property="Background" Value="#0E7C86"/><Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderThickness" Value="0"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="{TemplateBinding Padding}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextBlock.Foreground="{TemplateBinding Foreground}"/>
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
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <TextBlock Grid.Row="0" Text="Select resource groups to include in data collection. Leave all unchecked to collect from all resource groups."
               FontSize="11" Foreground="#555" TextWrapping="Wrap" Margin="0,0,0,10"/>
    <Border Grid.Row="1" Background="White" BorderBrush="#CDD0D6" BorderThickness="1" CornerRadius="4" Padding="4">
      <ScrollViewer VerticalScrollBarVisibility="Auto">
        <StackPanel x:Name="RGPanel"/>
      </ScrollViewer>
    </Border>
    <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,8,0,8">
      <Button x:Name="BtnRGAll"  Content="Select All"  Width="90" Padding="0,5" Style="{StaticResource GreyBtn}" Margin="0,0,6,0"/>
      <Button x:Name="BtnRGNone" Content="Select None" Width="90" Padding="0,5" Style="{StaticResource GreyBtn}"/>
    </StackPanel>
    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right">
      <Button x:Name="BtnRGOk"     Content="OK"     Width="80" Padding="0,7" Style="{StaticResource BlueBtn}" Margin="0,0,8,0"/>
      <Button x:Name="BtnRGCancel" Content="Cancel" Width="80" Padding="0,7" Style="{StaticResource GreyBtn}"/>
    </StackPanel>
  </Grid>
</Window>
'@

    $rgPanel   = $picker.FindName('RGPanel')
    $btnAll    = $picker.FindName('BtnRGAll')
    $btnNone   = $picker.FindName('BtnRGNone')
    $btnOk     = $picker.FindName('BtnRGOk')
    $btnCancel = $picker.FindName('BtnRGCancel')

    $cbs = [System.Collections.Generic.List[System.Windows.Controls.CheckBox]]::new()

    if ($sorted.Count -eq 0) {
        $tb = [System.Windows.Controls.TextBlock]::new()
        $tb.Text = 'No resource groups found. Load subscriptions first.'
        $tb.Foreground = [System.Windows.Media.Brushes]::Gray
        $tb.Margin = [System.Windows.Thickness]::new(6,6,6,6)
        $rgPanel.Children.Add($tb) | Out-Null
    } else {
        foreach ($rg in $sorted) {
            $cb = [System.Windows.Controls.CheckBox]::new()
            $cb.Content   = "$($rg.Name)  [$($rg.Location)]"
            $cb.Tag       = $rg.Name
            $cb.IsChecked = $preSet.Contains($rg.Name)
            $cb.Margin    = [System.Windows.Thickness]::new(6,3,6,3)
            $rgPanel.Children.Add($cb) | Out-Null
            $cbs.Add($cb)
        }
    }

    $btnAll.Add_Click({    foreach ($c in $cbs) { $c.IsChecked = $true  } })
    $btnNone.Add_Click({   foreach ($c in $cbs) { $c.IsChecked = $false } })
    $btnCancel.Add_Click({ $picker.DialogResult = $false; $picker.Close() })

    $script:_rgResult = $null
    $btnOk.Add_Click({
        $script:_rgResult = @($cbs | Where-Object { $_.IsChecked -eq $true } | ForEach-Object { $_.Tag })
        $picker.DialogResult = $true
        $picker.Close()
    })

    $null = $picker.ShowDialog()
    return $script:_rgResult
}

#endregion

#region -- WPF Auth & Subscription Dialog -------------------------------------

function Show-AzureAuthDialog {
    <#
      Shows a WPF dialog for tenant and subscription selection.
      Returns an array of selected subscription objects, or $null if cancelled.
    #>

    $existingCtx = Get-AzContext -ErrorAction SilentlyContinue
    $accountText = if ($existingCtx) { "Signed in as: $($existingCtx.Account.Id)" } else { 'Not signed in' }

    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AVD Data Collector - Azure Authentication" Width="560" SizeToContent="Height"
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
    <DockPanel Margin="0,0,0,12">
      <TextBlock Text="&#x2601;" FontSize="28" Foreground="#0E7C86" DockPanel.Dock="Left"
                 VerticalAlignment="Center" Margin="0,0,14,0"/>
      <StackPanel>
        <TextBlock Text="Azure Virtual Desktop" FontSize="16" FontWeight="Bold" Foreground="#0E7C86"/>
        <TextBlock Text="Data Collection" FontSize="12" Foreground="#555" Margin="0,2,0,0"/>
      </StackPanel>
    </DockPanel>

    <!-- Customer Name + Config -->
    <Grid Margin="0,0,0,14">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="TxtCustomer" Grid.Column="0" Padding="8,6" FontSize="12"
               BorderBrush="#CDD0D6" BorderThickness="1" Background="White"
               VerticalContentAlignment="Center" Margin="0,0,8,0"
               ToolTip="Customer name - config will be saved as CustomerName.config.json"/>
      <Button x:Name="BtnOpenConfig" Grid.Column="1" Content="Open Config..." Width="110"
              Padding="0,7" Style="{StaticResource GreyBtn}"/>
    </Grid>

    <!-- Auth status -->
    <Border Background="White" BorderBrush="#DDE1E7" BorderThickness="1" CornerRadius="4"
            Padding="12,10" Margin="0,0,0,14">
      <DockPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
          <Button x:Name="BtnSignIn" Content="Sign In" Width="80" Padding="0,6"
                  Style="{StaticResource BlueBtn}" Margin="0,0,0,0"/>
          <Button x:Name="BtnSwitch" Content="Switch Account" Width="110" Padding="0,6"
                  Style="{StaticResource GreyBtn}" Margin="8,0,0,0"/>
        </StackPanel>
        <StackPanel VerticalAlignment="Center">
          <TextBlock x:Name="TxtAccount" Text="$accountText" FontSize="12" Foreground="#1F2937" FontWeight="SemiBold"/>
          <TextBlock x:Name="TxtTenant" Text="" FontSize="11" Foreground="#888" Margin="0,2,0,0"/>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- Tenant selector -->
    <TextBlock Text="Tenant" FontSize="11" Foreground="#555" FontWeight="SemiBold"
               TextOptions.TextFormattingMode="Display" Margin="0,0,0,4"/>
    <Grid Margin="0,0,0,14">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <ComboBox x:Name="CbTenant" Grid.Column="0" Padding="8,6" BorderBrush="#CDD0D6"
                BorderThickness="1" Background="White" FontSize="12" Margin="0,0,8,0"/>
      <Button x:Name="BtnLoadSubs" Grid.Column="1" Content="Load Subscriptions" Width="140"
              Padding="0,7" Style="{StaticResource BlueBtn}"/>
    </Grid>

    <!-- Subscription list -->
    <TextBlock Text="Subscriptions" FontSize="11" Foreground="#555" FontWeight="SemiBold"
               Margin="0,0,0,4"/>
    <Border Background="White" BorderBrush="#CDD0D6" BorderThickness="1" CornerRadius="4"
            Padding="4,4" Height="200" Margin="0,0,0,4">
      <ScrollViewer VerticalScrollBarVisibility="Auto">
        <StackPanel x:Name="SubPanel"/>
      </ScrollViewer>
    </Border>
    <DockPanel Margin="0,0,0,16">
      <Button x:Name="BtnSelectAll"   Content="Select All"   Width="90" Padding="0,5"
              Style="{StaticResource GreyBtn}" DockPanel.Dock="Left" Margin="0,0,6,0"/>
      <Button x:Name="BtnSelectNone"  Content="Select None"  Width="90" Padding="0,5"
              Style="{StaticResource GreyBtn}" DockPanel.Dock="Left"/>
      <TextBlock x:Name="TxtStatus" Foreground="#888" FontSize="11" VerticalAlignment="Center"
                 HorizontalAlignment="Right" Text=""/>
    </DockPanel>

    <!-- Resource Group filter -->
    <TextBlock Text="Resource Groups" FontSize="11" Foreground="#555" FontWeight="SemiBold"
               Margin="0,0,0,4"/>
    <Grid Margin="0,0,0,14">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="TxtRGFilter" Grid.Column="0" Text="All resource groups" Padding="8,6"
               FontSize="12" BorderBrush="#CDD0D6" BorderThickness="1" Background="#F8F9FA"
               IsReadOnly="True" Foreground="#888" VerticalContentAlignment="Center"
               Margin="0,0,8,0"/>
      <Button x:Name="BtnBrowseRGs" Grid.Column="1" Content="Browse..." Width="80"
              Padding="0,7" Style="{StaticResource GreyBtn}"/>
    </Grid>

    <!-- Output path -->
    <TextBlock Text="Output Folder" FontSize="11" Foreground="#555" FontWeight="SemiBold"
               Margin="0,4,0,4"/>
    <Grid Margin="0,0,0,16">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="TxtOutputPath" Grid.Column="0" Text="" Padding="8,6"
               BorderBrush="#CDD0D6" BorderThickness="1" FontSize="12" Margin="0,0,8,0"/>
      <Button x:Name="BtnBrowse" Grid.Column="1" Content="Browse..." Width="80"
              Padding="0,7" Style="{StaticResource GreyBtn}"/>
    </Grid>

    <!-- Collection options -->
    <Separator Margin="0,4,0,12" Background="#DDE1E7"/>
    <CheckBox x:Name="ChkPerformance"
              Content="Collect performance data (30-day logon &amp; connection times from Log Analytics)"
              FontSize="11" Foreground="#555" IsChecked="False" Margin="0,0,0,8"/>
    <CheckBox x:Name="ChkSessionDetail"
              Content="Collect session detail (individual user sessions: UPN, client IP, connect time)"
              FontSize="11" Foreground="#555" IsChecked="False" Margin="0,0,0,14"/>

    <TextBlock Text="Encrypt output (optional - leave blank for plaintext .json; a password writes .cdenc)"
               FontSize="11" FontWeight="SemiBold" Foreground="#555" Margin="0,0,0,5"/>
    <PasswordBox x:Name="EncryptBox" Padding="8,6" BorderBrush="#CDD0D6" BorderThickness="1" FontSize="12" Margin="0,0,0,14"/>

    <!-- Footer buttons -->
    <DockPanel>
      <Button x:Name="BtnSaveConfig" Content="Save Config" Width="100" Padding="0,8"
              Style="{StaticResource GreyBtn}" DockPanel.Dock="Left"/>
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="BtnOk"     Content="Collect Data" Width="120" Padding="0,8"
                Style="{StaticResource BlueBtn}" Margin="0,0,8,0"/>
        <Button x:Name="BtnCancel" Content="Cancel"       Width="80"  Padding="0,8"
                Style="{StaticResource GreyBtn}"/>
      </StackPanel>
    </DockPanel>

  </StackPanel>
</Window>
"@

    $rdr = [System.Xml.XmlNodeReader]::new($xaml)
    $dlg = [Windows.Markup.XamlReader]::Load($rdr)
    Set-SquareCorners -Window $dlg

    $btnSignIn    = $dlg.FindName('BtnSignIn')
    $btnSwitch    = $dlg.FindName('BtnSwitch')
    $btnLoadSubs  = $dlg.FindName('BtnLoadSubs')
    $btnSelectAll = $dlg.FindName('BtnSelectAll')
    $btnSelNone    = $dlg.FindName('BtnSelectNone')
    $btnOk         = $dlg.FindName('BtnOk')
    $btnCancel     = $dlg.FindName('BtnCancel')
    $btnSaveConfig = $dlg.FindName('BtnSaveConfig')
    $btnBrowse     = $dlg.FindName('BtnBrowse')
    $btnBrowseRGs  = $dlg.FindName('BtnBrowseRGs')
    $btnOpenConfig = $dlg.FindName('BtnOpenConfig')
    $cbTenant      = $dlg.FindName('CbTenant')
    $subPanel      = $dlg.FindName('SubPanel')
    $chkPerformance = $dlg.FindName('ChkPerformance')
    $chkSessionDetail = $dlg.FindName('ChkSessionDetail')
    $encryptBox = $dlg.FindName('EncryptBox')
    $txtAccount    = $dlg.FindName('TxtAccount')
    $txtTenant     = $dlg.FindName('TxtTenant')
    $txtStatus     = $dlg.FindName('TxtStatus')
    $txtOutputPath = $dlg.FindName('TxtOutputPath')
    $txtCustomer   = $dlg.FindName('TxtCustomer')
    $txtRGFilter   = $dlg.FindName('TxtRGFilter')
    $script:_txtRGFilter = $txtRGFilter

    # Pre-populate output path
    $txtOutputPath.Text = $OutputPath

    $script:_authDialogResult  = $null
    $script:_tenants           = @()
    $script:_subCheckboxes     = [System.Collections.Generic.List[System.Windows.Controls.CheckBox]]::new()
    $script:_selectedRGs       = @()
    $script:_dialogInitialized = $false
    $script:_suppressRGReset   = $false

    function Import-CollectConfig {
        param($cfg)
        if (-not $cfg) { return }
        # Convert PSCustomObject to hashtable so all access is strict-mode safe
        $h = @{}
        $cfg.PSObject.Properties | ForEach-Object { $h[$_.Name] = $_.Value }
        if ($h.ContainsKey('CustomerName') -and $h['CustomerName'])  { $txtCustomer.Text   = $h['CustomerName'] }
        if ($h.ContainsKey('OutputPath')   -and $h['OutputPath'])    { $txtOutputPath.Text = $h['OutputPath'] }
        $script:_selectedRGs = if ($h.ContainsKey('SelectedResourceGroupNames') -and $h['SelectedResourceGroupNames']) {
            @($h['SelectedResourceGroupNames'] | Where-Object { $_ })
        } else { @() }
        if ($script:_selectedRGs.Count -gt 0) {
            $script:_txtRGFilter.Text       = "$($script:_selectedRGs.Count) resource group(s) selected"
            $script:_txtRGFilter.Foreground = [System.Windows.Media.Brushes]::Black
        } else {
            $script:_txtRGFilter.Text       = 'All resource groups'
            $script:_txtRGFilter.Foreground = [System.Windows.Media.Brushes]::Gray
        }
        $script:_savedSubIds = if ($h.ContainsKey('SelectedSubscriptionIds') -and $h['SelectedSubscriptionIds']) {
            @($h['SelectedSubscriptionIds'] | Where-Object { $_ })
        } else { @() }
        if ($null -ne $h['CollectPerformance']) { $chkPerformance.IsChecked = [bool]$h['CollectPerformance'] }
        if ($null -ne $h['CollectSessionDetail']) { $chkSessionDetail.IsChecked = [bool]$h['CollectSessionDetail'] }
    }
    $script:_savedSubIds = @()

    function Update-AuthStatus {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.Account) {
            $tenantId = try { if ($ctx.Tenant.PSObject.Properties['Id']) { $ctx.Tenant.Id } else { $ctx.Tenant.TenantId } } catch { '' }
            $txtAccount.Text = "Signed in as: $($ctx.Account.Id)"
            $txtTenant.Text  = "Tenant: $tenantId"
            $btnSignIn.Visibility  = 'Collapsed'
            $btnSwitch.Visibility  = 'Visible'
        }
        else {
            $txtAccount.Text = 'Not signed in'
            $txtTenant.Text  = ''
            $btnSignIn.Visibility  = 'Visible'
            $btnSwitch.Visibility  = 'Collapsed'
        }
        Update-TenantList
    }

    function Update-TenantList {
        $cbTenant.Items.Clear()
        $script:_tenants = @()
        try {
            $tok = Get-ArmToken -ErrorAction Stop
            $script:_tenants = @(Get-ArmTenants -Token $tok)
            foreach ($t in $script:_tenants) {
                $item = [System.Windows.Controls.ComboBoxItem]::new()
                $name = if ($t.displayName) { "$($t.displayName) ($($t.tenantId))" } else { $t.tenantId }
                $item.Content = $name
                $item.Tag     = $t.tenantId
                $cbTenant.Items.Add($item) | Out-Null
            }
            if ($cbTenant.Items.Count -gt 0) {
                $curCtx    = Get-AzContext -ErrorAction SilentlyContinue
                $curTenant = try { if ($curCtx -and $curCtx.Tenant) { if ($curCtx.Tenant.PSObject.Properties['Id']) { $curCtx.Tenant.Id } else { $curCtx.Tenant.TenantId } } else { $null } } catch { $null }
                $matched   = $false
                for ($i = 0; $i -lt $cbTenant.Items.Count; $i++) {
                    if ($cbTenant.Items[$i].Tag -eq $curTenant) { $cbTenant.SelectedIndex = $i; $matched = $true; break }
                }
                if (-not $matched) { $cbTenant.SelectedIndex = 0 }
            }
            $txtStatus.Text = "$($cbTenant.Items.Count) tenant(s) found"
        }
        catch { $txtStatus.Text = "Could not load tenants: $($_.Exception.Message)" }
    }

    function Update-SubscriptionList {
        $subPanel.Children.Clear()
        $script:_subCheckboxes.Clear()
        $selectedTenantId = $null
        if ($cbTenant.SelectedItem) { $selectedTenantId = $cbTenant.SelectedItem.Tag }
        try {
            $tok  = Get-ArmToken -ErrorAction Stop
            $all  = @(Get-ArmSubscriptions -Token $tok)
            $subs = if ($selectedTenantId) {
                @($all | Where-Object { $_.tenantId -eq $selectedTenantId })
            } else { $all }
            if ($subs.Count -eq 0) {
                $tb = [System.Windows.Controls.TextBlock]::new()
                $tb.Text       = 'No enabled subscriptions found in this tenant.'
                $tb.Foreground = [System.Windows.Media.Brushes]::Gray
                $tb.Margin     = [System.Windows.Thickness]::new(8,8,8,8)
                $tb.FontSize   = 12
                $subPanel.Children.Add($tb) | Out-Null
            }
            else {
                $script:_suppressRGReset = $true
                foreach ($sub in $subs | Sort-Object { $_.displayName }) {
                    $cb = [System.Windows.Controls.CheckBox]::new()
                    $cb.Content   = "$($sub.displayName)  [$($sub.subscriptionId)]"
                    $cb.Tag       = [ordered]@{ Id = $sub.subscriptionId; Name = $sub.displayName }
                    $cb.IsChecked = ($script:_savedSubIds -contains $sub.subscriptionId)
                    $cb.Add_Checked({
                        foreach ($other in $script:_subCheckboxes) { if ($other -ne $this) { $other.IsChecked = $false } }
                        if (-not $script:_suppressRGReset) {
                            $script:_selectedRGs = @()
                            $script:_txtRGFilter.Text       = 'All resource groups'
                            $script:_txtRGFilter.Foreground = [System.Windows.Media.Brushes]::Gray
                        }
                    })
                    $cb.Add_Unchecked({
                        if (-not $script:_suppressRGReset) {
                            $script:_selectedRGs = @()
                            $script:_txtRGFilter.Text       = 'All resource groups'
                            $script:_txtRGFilter.Foreground = [System.Windows.Media.Brushes]::Gray
                        }
                    })
                    $cb.Margin    = [System.Windows.Thickness]::new(6,4,6,4)
                    $cb.FontSize  = 12
                    $cb.Foreground = [System.Windows.Media.SolidColorBrush]::new(
                        [System.Windows.Media.ColorConverter]::ConvertFromString('#1F2937'))
                    $subPanel.Children.Add($cb) | Out-Null
                    $script:_subCheckboxes.Add($cb)
                }
                $script:_suppressRGReset = $false
            }
            $txtStatus.Text = "$($subs.Count) subscription(s) loaded"
        }
        catch {
            $txtStatus.Text = "Error loading subscriptions: $_"
        }
    }

    # -- Wire events ----------------------------------------------------------

    $btnSignIn.Add_Click({
        try {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $script:_armTokenCache.Clear()   # drop any tokens cached for a previous account
            $dlg.Dispatcher.Invoke({ Update-AuthStatus })
        }
        catch { $txtStatus.Text = "Sign-in failed: $_" }
    })

    $btnSwitch.Add_Click({
        try {
            Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
            Clear-AzContext -Force -ErrorAction SilentlyContinue | Out-Null
            $script:_armTokenCache.Clear()   # old account's tokens are now invalid; force fresh tokens
            Connect-AzAccount -ErrorAction Stop | Out-Null
            $script:_armTokenCache.Clear()   # clear again in case Connect populated/cached anything
            $dlg.Dispatcher.Invoke([Action]{ Update-AuthStatus }, [System.Windows.Threading.DispatcherPriority]::Background)
        }
        catch { $txtStatus.Text = "Switch account failed: $($_.Exception.Message)" }
    })

    $btnLoadSubs.Add_Click({ Update-SubscriptionList })

    $btnSelectAll.Add_Click({
        foreach ($cb in $script:_subCheckboxes) { $cb.IsChecked = $true }
    })

    $btnSelNone.Add_Click({
        foreach ($cb in $script:_subCheckboxes) { $cb.IsChecked = $false }
    })

    $btnSaveConfig.Add_Click({
        $customerName = $txtCustomer.Text.Trim()
        $outPath      = $txtOutputPath.Text.Trim()
        $cfg = [ordered]@{
            CustomerName            = $customerName
            OutputPath              = $outPath
            SelectedSubscriptionIds = @($script:_subCheckboxes | Where-Object { $_.IsChecked -eq $true } | ForEach-Object { $_.Tag['Id'] })
            CollectPerformance      = [bool]$chkPerformance.IsChecked
            CollectSessionDetail    = [bool]$chkSessionDetail.IsChecked
        }
        if ($script:_selectedRGs.Count -gt 0) { $cfg['SelectedResourceGroupNames'] = $script:_selectedRGs }
        $saved = Save-CollectConfig -Config $cfg -CustomerName $customerName
        if ($saved) { $txtStatus.Text = "Config saved: $(Split-Path $saved -Leaf)" }
        else        { $txtStatus.Text = 'Failed to save config.' }
    })

    $btnOpenConfig.Add_Click({
        try {
            $ofd = [Microsoft.Win32.OpenFileDialog]::new()
            $ofd.Title  = 'Open Configuration File'
            $ofd.Filter = 'AVD config files (avd-*.config.json)|avd-*.config.json|All config files (*.config.json)|*.config.json|All files (*.*)|*.*'
            if (Test-Path $script:_configDir) { $ofd.InitialDirectory = $script:_configDir }
            if ($ofd.ShowDialog() -eq $true) {
                $cfg = Read-CollectConfig -Path $ofd.FileName
                if ($cfg) {
                    Import-CollectConfig $cfg
                    Update-SubscriptionList
                    $txtStatus.Text = "Config loaded: $(Split-Path $ofd.FileName -Leaf)"
                }
                else { $txtStatus.Text = 'Could not read config file.' }
            }
        } catch {
            $txtStatus.Text = "Error loading config: $($_.Exception.Message)"
        }
    })

    $btnBrowseRGs.Add_Click({
        try {
            $selected = @($script:_subCheckboxes | Where-Object { $_.IsChecked -eq $true } | ForEach-Object { $_.Tag })
            if ($selected.Count -eq 0) { $txtStatus.Text = 'Select at least one subscription first.'; return }
            try { $tok = Get-ArmToken -ErrorAction Stop } catch { $txtStatus.Text = 'Not signed in.'; return }
            $result = Show-RGPickerDialog -SubscriptionIds @($selected | ForEach-Object { $_['Id'] }) -Token $tok -PreSelected $script:_selectedRGs
            if ($null -ne $result) {
                $script:_selectedRGs = @($result)
                if ($script:_selectedRGs.Count -eq 0) {
                    $txtRGFilter.Text       = 'All resource groups'
                    $txtRGFilter.Foreground = [System.Windows.Media.Brushes]::Gray
                } else {
                    $txtRGFilter.Text       = "$($script:_selectedRGs.Count) resource group(s) selected"
                    $txtRGFilter.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString('#1F2937'))
                }
            }
        } catch { $txtStatus.Text = "Error browsing resource groups: $($_.Exception.Message)" }
    })

    $btnBrowse.Add_Click({
        try {
            $browser = [System.Windows.Forms.FolderBrowserDialog]::new()
            $browser.Description = 'Select output folder for JSON data file'
            if ($txtOutputPath.Text -and (Test-Path $txtOutputPath.Text)) {
                $browser.SelectedPath = $txtOutputPath.Text
            }
            if ($browser.ShowDialog() -eq 'OK') {
                $txtOutputPath.Text = $browser.SelectedPath
            }
        } catch { $txtStatus.Text = "Error browsing folders: $($_.Exception.Message)" }
    })

    $btnOk.Add_Click({
        try {
        $selected = @($script:_subCheckboxes | Where-Object { $_.IsChecked -eq $true } | ForEach-Object { $_.Tag })
        if ($selected.Count -eq 0) {
            $txtStatus.Text = 'Please select at least one subscription.'
            return
        }
        $outPath = $txtOutputPath.Text.Trim()
        if (-not $outPath) {
            $txtStatus.Text = 'Please specify an output folder.'
            return
        }
        $customerName = $txtCustomer.Text.Trim()
        # Save config
        $cfg = [ordered]@{
            CustomerName            = $customerName
            OutputPath              = $outPath
            SelectedSubscriptionIds = @($selected | ForEach-Object { $_['Id'] })
            CollectPerformance      = [bool]$chkPerformance.IsChecked
            CollectSessionDetail    = [bool]$chkSessionDetail.IsChecked
        }
        if ($script:_selectedRGs.Count -gt 0) { $cfg['SelectedResourceGroupNames'] = $script:_selectedRGs }
        Save-CollectConfig -Config $cfg -CustomerName $customerName | Out-Null

        $script:_authDialogResult = [ordered]@{
            Subscriptions        = $selected
            OutputPath           = $outPath
            CustomerName         = $customerName
            ResourceGroupFilter  = $script:_selectedRGs
            CollectPerformance   = [bool]$chkPerformance.IsChecked
            CollectSessionDetail = [bool]$chkSessionDetail.IsChecked
            EncryptPassword      = $(if ($encryptBox.Password) { ConvertTo-SecureString $encryptBox.Password -AsPlainText -Force } else { $null })
        }
        $dlg.DialogResult = $true
        $dlg.Close()
        } catch { $txtStatus.Text = "Error: $($_.Exception.Message)" }
    })

    $btnCancel.Add_Click({
        $dlg.DialogResult = $false
        $dlg.Close()
    })

    $dlg.Add_Loaded({
        if ($script:_dialogInitialized) { return }
        $script:_dialogInitialized = $true
        Update-AuthStatus
        if ($cbTenant.Items.Count -gt 0) { Update-SubscriptionList }
    })

    $null = $dlg.ShowDialog()
    return $script:_authDialogResult
}

#endregion

#region -- Auth & Subscription Selection --------------------------------------


$dialogResult = Show-AzureAuthDialog

if (-not $dialogResult) {
    exit 0
}

$selectedSubscriptions = @($dialogResult.Subscriptions)
$OutputPath            = $dialogResult.OutputPath
$CollectCustomerName   = $dialogResult.CustomerName
# Dialog password box wins only if -EncryptPassword wasn't already passed on the command line.
if (-not $EncryptPassword -and $dialogResult['EncryptPassword']) { $EncryptPassword = $dialogResult['EncryptPassword'] }
$rgFilter              = @($dialogResult.ResourceGroupFilter | Where-Object { $_ })
$rgFilterSet           = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($rg in $rgFilter) { [void]$rgFilterSet.Add($rg) }

if ($selectedSubscriptions.Count -eq 0) {
    exit 0
}


# Re-show splash for data collection phase
$script:_splash.Dispatcher.Invoke([Action]{
    $script:_splash.Topmost = $true
    $script:_splash.Show()
}, [System.Windows.Threading.DispatcherPriority]::Render)
$script:_splash.Dispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)

#endregion

#region -- Data Collection ----------------------------------------------------

try {

Set-ReportStatus "Connecting to Azure..." -Progress 2

$_azCtx = Get-AzContext
$_tenantId = try { if ($_azCtx.Tenant) { $_azCtx.Tenant.Id } else { $_azCtx.TenantId } } catch { [string]$_azCtx.TenantId }

$report = [ordered]@{
    GeneratedAt      = (Get-Date).ToString('o')   # ISO 8601 - safe for JSON round-trip
    CollectorVersion = $script:CollectorVersion
    TenantId         = $_tenantId
    AccountName      = $_azCtx.Account.Id
    CustomerName     = $CollectCustomerName
    SessionDetailCollected = [bool]$dialogResult['CollectSessionDetail']
    Subscriptions    = [System.Collections.Generic.List[object]]::new()
}
$collectSessionDetail = [bool]$dialogResult['CollectSessionDetail']

# Progress budget: 5-95% across all subscriptions
$subCount        = $selectedSubscriptions.Count
$subBudget       = if ($subCount -gt 0) { [int](90 / $subCount) } else { 90 }
$subBaseProgress = 5

$debugLog = Join-Path $OutputPath "AVDData-Debug-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
[System.IO.File]::WriteAllText($debugLog, '', [System.Text.Encoding]::UTF8)
function Write-DebugLog { param([string]$Msg) [System.IO.File]::AppendAllText($debugLog, "$(Get-Date -Format 'HH:mm:ss') $Msg`n") }

# Queries a provider path scoped to each selected RG (when filter is set) or
# subscription-wide (when no filter). Replaces the fetch-all-then-filter pattern.
function Get-ArmResourcesScoped {
    param([string]$SubscriptionId, [string]$Token, [string]$ProviderPath, [string]$ApiVersion)
    if ($script:rgFilterSet.Count -eq 0) {
        return @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/$ProviderPath" -Token $Token -ApiVersion $ApiVersion)
    }
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($rg in $script:rgFilterSet) {
        try {
            foreach ($item in @(Invoke-ArmRestMethod -Path "/subscriptions/$SubscriptionId/resourceGroups/$rg/$ProviderPath" -Token $Token -ApiVersion $ApiVersion)) {
                $all.Add($item)
            }
        } catch { Write-DebugLog "  RG '$rg' /$ProviderPath query error: $_" }
    }
    return $all.ToArray()
}

$subIndex = 0
foreach ($sub in $selectedSubscriptions) {
    $subIndex++
    $subBase = $subBaseProgress + (($subIndex - 1) * $subBudget)
    $subId   = $sub.Id

    Write-DebugLog "Processing subscription: $($sub.Name) [$subId]"
    Set-ReportStatus "Querying subscription $subIndex of $subCount" -Progress $subBase -Sub $sub.Name

    $tok = Get-ArmToken

    # Pre-fetch role definitions once for this subscription (Id -> name lookup)
    $roleDefMap = @{}
    try { $roleDefMap = Get-ArmRoleDefinitions -SubscriptionId $subId -Token $tok } catch {}

    function Resolve-RoleAssignments {
        param([string]$ResourceId)
        $raw = @()
        try { $raw = @(Get-ArmRoleAssignments -ResourceId $ResourceId -Token $tok) } catch {}
        $direct = @($raw | Where-Object { $_.properties.scope -ieq $ResourceId })
        @($direct | ForEach-Object {
            $roleName = $roleDefMap[$_.properties.roleDefinitionId.Split('/')[-1]]
            [ordered]@{
                PrincipalId        = $_.properties.principalId
                DisplayName        = $_.properties.principalId   # resolved later via Graph batch call
                RoleDefinitionName = if ($roleName) { $roleName } else { $_.properties.roleDefinitionId.Split('/')[-1] }
                ObjectType         = $_.properties.principalType
            }
        })
    }

    $subData = [ordered]@{
        SubscriptionId              = $subId
        SubscriptionName            = $sub.Name
        HostPools                   = [System.Collections.Generic.List[object]]::new()
        Workspaces                  = [System.Collections.Generic.List[object]]::new()
        ScalingPlans                = [System.Collections.Generic.List[object]]::new()
        StorageAccounts             = [System.Collections.Generic.List[object]]::new()
        LogAnalyticsWorkspaces      = [System.Collections.Generic.List[object]]::new()
        DataCollectionRules         = [System.Collections.Generic.List[object]]::new()
        DataCollectionEndpoints     = [System.Collections.Generic.List[object]]::new()
        KeyVaults                   = [System.Collections.Generic.List[object]]::new()
        ComputeGalleries            = [System.Collections.Generic.List[object]]::new()
        ImageTemplates              = [System.Collections.Generic.List[object]]::new()
        AppAttachPackages           = [System.Collections.Generic.List[object]]::new()
        SubscriptionRoleAssignments = @(Resolve-RoleAssignments -ResourceId "/subscriptions/$subId")
    }

    # -- Scaling Plans ---------------------------------------------------------
    Set-ReportStatus "Collecting scaling plans..." -Progress ($subBase + 2) -Sub $sub.Name
    Write-DebugLog "  Collecting scaling plans..."
    try {
        $scalingPlans = @(Get-ArmResourcesScoped -SubscriptionId $subId -Token $tok -ProviderPath 'providers/Microsoft.DesktopVirtualization/scalingPlans' -ApiVersion $script:ApiVersions.DesktopVirtualization)
        foreach ($sp in $scalingPlans) {
            $spRg   = Get-ResourceGroup $sp.id
            $spName = $sp.name
            $p      = $sp.properties
            $spSchedules = @()
            try { $spSchedules = @(Get-ArmScalingPlanSchedules -SubscriptionId $subId -ResourceGroup $spRg -ScalingPlanName $spName -Token $tok) } catch {}

            $subData.ScalingPlans.Add([ordered]@{
                Name               = $spName
                ResourceGroup      = $spRg
                Location           = $sp.location
                FriendlyName       = $p.friendlyName
                Description        = $p.description
                TimeZone           = $p.timeZone
                HostPoolType       = $p.hostPoolType
                ExclusionTag       = $p.exclusionTag
                HostPoolReferenceNames = @($p.hostPoolReferences | ForEach-Object { $_.hostPoolArmPath.Split('/')[-1] })
                HostPoolReferences     = @($p.hostPoolReferences | ForEach-Object { "$($_.hostPoolArmPath.Split('/')[-1]) (Enabled:$($_.scalingPlanEnabled))" })
                Properties         = ConvertTo-SanitisedProperties $p -Exclude @('hostPoolReferences')
                Schedules          = @($spSchedules | ForEach-Object {
                    $s = $_.properties
                    function Format-SchedTime { param($t) if ($t -and $t.PSObject.Properties['hour']) { "$($t.hour):$($t.minute.ToString('D2'))" } else { '' } }
                    function Get-SchedProp    { param($o, $n) if ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
                    [ordered]@{
                        Name                           = $_.name
                        DaysOfWeek                     = if ($s.PSObject.Properties['daysOfWeek']) { $s.daysOfWeek -join ', ' } else { '' }
                        RampUpStartTime                = Format-SchedTime $s.rampUpStartTime
                        RampUpLoadBalancingAlgorithm   = Get-SchedProp $s 'rampUpLoadBalancingAlgorithm'
                        RampUpMinimumHostsPct          = Get-SchedProp $s 'rampUpMinimumHostsPct'
                        RampUpCapacityThresholdPct     = Get-SchedProp $s 'rampUpCapacityThresholdPct'
                        PeakStartTime                  = Format-SchedTime $s.peakStartTime
                        PeakLoadBalancingAlgorithm     = Get-SchedProp $s 'peakLoadBalancingAlgorithm'
                        RampDownStartTime              = Format-SchedTime $s.rampDownStartTime
                        RampDownLoadBalancingAlgorithm = Get-SchedProp $s 'rampDownLoadBalancingAlgorithm'
                        RampDownMinimumHostsPct        = Get-SchedProp $s 'rampDownMinimumHostsPct'
                        RampDownCapacityThresholdPct   = Get-SchedProp $s 'rampDownCapacityThresholdPct'
                        RampDownForceLogoffUser        = Get-SchedProp $s 'rampDownForceLogoffUser'
                        RampDownWaitTimeMinute         = Get-SchedProp $s 'rampDownWaitTimeMinutes'
                        RampDownNotificationMessage    = Get-SchedProp $s 'rampDownNotificationMessage'
                        OffPeakStartTime               = Format-SchedTime $s.offPeakStartTime
                        OffPeakLoadBalancingAlgorithm  = Get-SchedProp $s 'offPeakLoadBalancingAlgorithm'
                    }
                })
            })
        }
        Write-DebugLog "Scaling plans collected: $($scalingPlans.Count)"
        Write-DebugLog "  Found $($scalingPlans.Count) scaling plan(s)"
    }
    catch { Write-DebugLog "EXCEPTION collecting scaling plans: $_"; Write-Warning "    Could not retrieve scaling plans: $_" }

    # Build hostPool -> exclusionTag lookup for use during session host collection
    $hpExclusionTagMap = @{}
    foreach ($sp in $subData.ScalingPlans) {
        if ($sp['ExclusionTag']) {
            foreach ($hpRef in $sp['HostPoolReferenceNames']) {
                if ($hpRef) { $hpExclusionTagMap[$hpRef.ToLower()] = $sp['ExclusionTag'] }
            }
        }
    }

    # -- Workspaces ------------------------------------------------------------
    Set-ReportStatus "Collecting workspaces..." -Progress ($subBase + 8) -Sub $sub.Name
    Write-DebugLog "  Collecting workspaces..."
    try {
        $workspaces = @(Get-ArmResourcesScoped -SubscriptionId $subId -Token $tok -ProviderPath 'providers/Microsoft.DesktopVirtualization/workspaces' -ApiVersion $script:ApiVersions.DesktopVirtualization)
        foreach ($ws in $workspaces) {
            $wsRg = Get-ResourceGroup $ws.id
            $p        = $ws.properties
            $wsErrors = [ordered]@{}
            $wsRoleAssignments = @()
            try   { $wsRoleAssignments = @(Resolve-RoleAssignments -ResourceId $ws.id) }
            catch { $wsErrors['RoleAssignments'] = $_.Exception.Message; Write-DebugLog "  WS $($ws.name) role assignments error: $_" }
            $wsDiagSettings = @()
            try   { $wsDiagSettings = @(Get-ArmDiagnosticSettings -ResourceId $ws.id -Token $tok) }
            catch { $wsErrors['DiagnosticSettings'] = $_.Exception.Message; Write-DebugLog "  WS $($ws.name) diagnostic settings error: $_" }
            $subData.Workspaces.Add([ordered]@{
                Name                       = $ws.name
                ResourceGroup              = $wsRg
                Location                   = $ws.location
                FriendlyName               = $p.friendlyName
                Description                = $p.description
                ApplicationGroupReferences = @($p.applicationGroupReferences | ForEach-Object { $_.Split('/')[-1] })
                Tags                       = ConvertTo-TagHashtable $ws.tags
                RoleAssignments            = $wsRoleAssignments
                DiagnosticSettings         = $wsDiagSettings
                PrivateEndpoints           = @(if ($p.privateEndpointConnections) { $p.privateEndpointConnections | ForEach-Object { $_.name } })
                PrivateEndpointIds         = @(if ($p.privateEndpointConnections) { $p.privateEndpointConnections | Where-Object { $_.PSObject.Properties['properties'] -and $_.properties.PSObject.Properties['privateEndpoint'] } | ForEach-Object { $_.properties.privateEndpoint.id } })
                Properties                 = ConvertTo-SanitisedProperties $p -Exclude @('privateEndpointConnections','applicationGroupReferences')
                CollectionErrors           = $wsErrors
            })
        }
        Write-DebugLog "  Found $($workspaces.Count) workspace(s)"
    }
    catch { Write-Warning "    Could not retrieve workspaces: $_" }


    # -- Host Pools ------------------------------------------------------------
    Set-ReportStatus "Collecting host pools..." -Progress ($subBase + 16) -Sub $sub.Name
    Write-DebugLog "  Collecting host pools..."
    try {
        $hostPools = @(Get-ArmResourcesScoped -SubscriptionId $subId -Token $tok -ProviderPath 'providers/Microsoft.DesktopVirtualization/hostPools' -ApiVersion $script:ApiVersions.DesktopVirtualization)
        Write-DebugLog "Host pools from REST: $($hostPools.Count)"
        $hpCount = $hostPools.Count
        $hpIndex = 0

        $allAppGroups = @(Get-ArmResourcesScoped -SubscriptionId $subId -Token $tok -ProviderPath 'providers/Microsoft.DesktopVirtualization/applicationGroups' -ApiVersion $script:ApiVersions.DesktopVirtualization)

        foreach ($hp in $hostPools) {
            $hpIndex++
            $hpRg   = Get-ResourceGroup $hp.id
            $hpName = $hp.name
            $p      = $hp.properties
            $hpProgress = ($subBase + 16) + [int](($hpIndex / [Math]::Max($hpCount,1)) * ($subBudget - 18))
            Set-ReportStatus "Host pool: $hpName" -Progress $hpProgress -Sub $sub.Name
            Write-DebugLog "  Processing host pool: $hpName"
            Write-DebugLog "  Processing: $hpRg / $hpName"

            $regExpiry      = if ($p.registrationInfo -and $p.registrationInfo.expirationTime) { [datetime]$p.registrationInfo.expirationTime } else { $null }
            $regTokenExists = ($null -ne $regExpiry -and $regExpiry -gt (Get-Date))
            $hpErrors       = [ordered]@{}

            # Session Hosts
            $sessionHostData = [System.Collections.Generic.List[object]]::new()
            try {
                $sessionHosts = @(Get-ArmSessionHosts -SubscriptionId $subId -ResourceGroup $hpRg -HostPool $hpName -Token $tok)
                $allSessions  = if ($collectSessionDetail) { @(Get-ArmUserSessions -SubscriptionId $subId -ResourceGroup $hpRg -HostPool $hpName -Token $tok) } else { @() }

                foreach ($sh in $sessionHosts) {
                    $shName = $sh.name.Split('/')[-1]
                    $sp2    = $sh.properties
                    $mySessions = @($allSessions | Where-Object { $_.name -like "$hpName/$shName/*" })

                    $shAmaInstalled       = $false
                    $shDcrAssociations    = @()
                    $shVmSize             = $null
                    $shVmCpuCores         = $null
                    $shVmMemoryGB         = $null
                    $shVmTrustedLaunch      = $null
                    $shVmDiskEncryptionSet  = $false
                    $shNicId                = $null
                    $shScalingExcluded    = $null
                    $shScalingExcludeTag  = $null
                    $vmResourceId = if ($sp2.PSObject.Properties['resourceId']) { $sp2.resourceId } else { $null }
                    if ($vmResourceId) {
                        try {
                            $exts = @(Get-ArmVmExtensions -ResourceId $vmResourceId -Token $tok)
                            $amaTypes = @('AzureMonitorWindowsAgent')
                            $shAmaInstalled = @($exts | Where-Object {
                                $_.PSObject.Properties['properties'] -and
                                (
                                    $_.name -in $amaTypes -or
                                    (
                                        $_.properties.PSObject.Properties['type'] -and
                                        $_.properties.type -in $amaTypes
                                    )
                                ) -and
                                $_.properties.PSObject.Properties['provisioningState'] -and
                                $_.properties.provisioningState -eq 'Succeeded'
                            }).Count -gt 0
                        } catch { Write-DebugLog "  SH $shName AMA extension check error: $_" }
                        try {
                            $rawDcr = @(Invoke-ArmRestMethod -Path "$vmResourceId/providers/Microsoft.Insights/dataCollectionRuleAssociations" -Token $tok -ApiVersion $script:ApiVersions.DataCollection)
                            $shDcrAssociations = @($rawDcr | Where-Object {
                                $_.PSObject.Properties['properties'] -and
                                $_.properties.PSObject.Properties['dataCollectionRuleId']
                            } | ForEach-Object { $_.properties.dataCollectionRuleId.Split('/')[-1] })
                        } catch { Write-DebugLog "  SH $shName DCR association check error: $_" }
                        try {
                            $vmInfo = Get-ArmVm -ResourceId $vmResourceId -Token $tok
                            $shVmSize = if ($vmInfo -and $vmInfo.PSObject.Properties['properties'] -and $vmInfo.properties.PSObject.Properties['hardwareProfile']) { $vmInfo.properties.hardwareProfile.vmSize } else { $null }
                            if ($vmInfo -and $vmInfo.PSObject.Properties['properties']) {
                                $secProfile = if ($vmInfo.properties.PSObject.Properties['securityProfile']) { $vmInfo.properties.securityProfile } else { $null }
                                $shVmTrustedLaunch = if ($secProfile -and $secProfile.PSObject.Properties['securityType']) { $secProfile.securityType -eq 'TrustedLaunch' } else { $false }
                                if ($vmInfo.properties.PSObject.Properties['networkProfile'] -and @($vmInfo.properties.networkProfile.networkInterfaces).Count -gt 0) {
                                    $shNicId = $vmInfo.properties.networkProfile.networkInterfaces[0].id
                                }
                                $storageProfile = if ($vmInfo.properties.PSObject.Properties['storageProfile']) { $vmInfo.properties.storageProfile } else { $null }
                                if ($storageProfile -and
                                    $storageProfile.PSObject.Properties['osDisk'] -and
                                    $storageProfile.osDisk.PSObject.Properties['managedDisk'] -and
                                    $storageProfile.osDisk.managedDisk.PSObject.Properties['diskEncryptionSet'] -and
                                    $storageProfile.osDisk.managedDisk.diskEncryptionSet.PSObject.Properties['id']) {
                                    $shVmDiskEncryptionSet = [bool]$storageProfile.osDisk.managedDisk.diskEncryptionSet.id
                                }
                            }
                            if ($shVmSize -and $vmInfo.PSObject.Properties['location']) {
                                $vmLocation = $vmInfo.location
                                $szSpec = Get-VmSizeSpec -SubscriptionId $subId -Location $vmLocation -VmSize $shVmSize -Token $tok
                                $shVmCpuCores = if ($szSpec) { [int]$szSpec.numberOfCores } else { $null }
                                $shVmMemoryGB = if ($szSpec) { [math]::Round($szSpec.memoryInMB / 1024) } else { $null }
                            }
                            $excludeTag = if ($hpExclusionTagMap.ContainsKey($hpName.ToLower())) { $hpExclusionTagMap[$hpName.ToLower()] } else { $null }
                            if ($excludeTag) {
                                $shScalingExcludeTag = $excludeTag
                                $shScalingExcluded   = $vmInfo -and $vmInfo.PSObject.Properties['tags'] -and $vmInfo.tags.PSObject.Properties[$excludeTag]
                            }
                        } catch { Write-DebugLog "  SH $shName VM size/tag error: $_" }
                    }
                    $sessionHostData.Add([ordered]@{
                        Name             = $shName
                        Status           = $sp2.status
                        UpdateState      = $sp2.updateState
                        LastHeartBeat    = if ($sp2.lastHeartBeat) { ([datetime]$sp2.lastHeartBeat).ToString('o') } else { $null }
                        Sessions         = if ($null -ne $sp2.sessions) { $sp2.sessions } else { 0 }
                        AllowNewSession  = if ($null -ne $sp2.allowNewSession) { $sp2.allowNewSession } else { $true }
                        AgentVersion     = $sp2.agentVersion
                        SxSStackVersion  = $sp2.sxSStackVersion
                        OSVersion        = $sp2.osVersion
                        OSDescription    = if ($sp2.PSObject.Properties['osDescription']) { $sp2.osDescription } else { $sp2.osVersion }
                        VirtualMachineId = $sp2.virtualMachineId
                        ResourceId       = $sp2.resourceId
                        AssignedUser     = $sp2.assignedUser
                        FriendlyName     = $sp2.friendlyName
                        VmSize              = $shVmSize
                        VmCpuCores          = $shVmCpuCores
                        VmMemoryGB          = $shVmMemoryGB
                        VmTrustedLaunch        = $shVmTrustedLaunch
                        VmDiskEncryptionSet    = $shVmDiskEncryptionSet
                        NicId                  = $shNicId
                        ScalingExcludeTag   = $shScalingExcludeTag
                        ScalingExcluded     = $shScalingExcluded
                        AmaInstalled        = $shAmaInstalled
                        DcrAssociations  = $shDcrAssociations
                        Properties       = ConvertTo-SanitisedProperties $sp2
                        UserSessions     = @($mySessions | ForEach-Object {
                            $us = $_.properties
                            [ordered]@{
                                SessionId           = $_.name.Split('/')[-1]
                                UserPrincipalName   = $us.userPrincipalName
                                UserName            = $us.activeDirectoryUserName
                                State               = $us.sessionState
                                CreateTime          = $us.createTime
                                ConnectTime         = if ($us.PSObject.Properties['connectTime']) { $us.connectTime } else { $null }
                                DisconnectTime      = if ($us.PSObject.Properties['disconnectTime']) { $us.disconnectTime } else { $null }
                                IdleTime            = if ($us.PSObject.Properties['idleTime']) { $us.idleTime } else { $null }
                                ClientIPAddress     = if ($us.PSObject.Properties['clientIPAddress']) { $us.clientIPAddress } else { $null }
                                ClientOSDescription = if ($us.PSObject.Properties['clientOSDescription']) { $us.clientOSDescription } else { $null }
                                ClientVersion       = if ($us.PSObject.Properties['clientVersion']) { $us.clientVersion } else { $null }
                            }
                        })
                    })
                }
            }
            catch { $hpErrors['SessionHosts'] = $_.Exception.Message; Write-DebugLog "  Session host error for $hpName`: $_" }

            # Application Groups
            $appGroupData = [System.Collections.Generic.List[object]]::new()
            try {
                $myAppGroups = @($allAppGroups | Where-Object { $_.properties.hostPoolArmPath -eq $hp.id })
                foreach ($ag in $myAppGroups) {
                    $agRg   = Get-ResourceGroup $ag.id
                    $agName = $ag.name
                    $agp    = $ag.properties
                    $apps   = @()
                    $agFriendlyName = $agp.friendlyName
                    if ($agp.applicationGroupType -eq 'RemoteApp') {
                        try { $apps = @(Get-ArmApplications -SubscriptionId $subId -ResourceGroup $agRg -AppGroupName $agName -Token $tok) } catch {}
                    } elseif ($agp.applicationGroupType -eq 'Desktop') {
                        try {
                            $desktops = @(Get-ArmDesktops -SubscriptionId $subId -ResourceGroup $agRg -AppGroupName $agName -Token $tok)
                            if ($desktops.Count -gt 0 -and $desktops[0].properties.friendlyName) {
                                $agFriendlyName = $desktops[0].properties.friendlyName
                            }
                        } catch {}
                    }
                    $appGroupData.Add([ordered]@{
                        Name               = $agName
                        ResourceGroup      = $agRg
                        Location           = $ag.location
                        FriendlyName       = $agFriendlyName
                        Description        = $agp.description
                        Type               = $agp.applicationGroupType
                        Tags               = ConvertTo-TagHashtable $ag.tags
                        RoleAssignments    = @(Resolve-RoleAssignments -ResourceId $ag.id)
                        DiagnosticSettings = @(Get-ArmDiagnosticSettings -ResourceId $ag.id -Token $tok)
                        Properties         = ConvertTo-SanitisedProperties $agp
                        Applications       = @($apps | ForEach-Object {
                            $ap = $_.properties
                            [ordered]@{
                                Name                 = $_.name.Split('/')[-1]
                                FriendlyName         = $ap.friendlyName
                                Description          = $ap.description
                                FilePath             = $ap.filePath
                                AppAlias             = $ap.alias
                                CommandLineSetting   = $ap.commandLineSetting
                                CommandLineArguments = $ap.commandLineArgument
                                IconPath             = $ap.iconPath
                                IconIndex            = $ap.iconIndex
                                ShowInPortal         = $ap.showInPortal
                            }
                        })
                    })
                }
            }
            catch { $hpErrors['ApplicationGroups'] = $_.Exception.Message; Write-DebugLog "  App group error for $hpName`: $_" }

            # RDP properties
            $rdpProps = [ordered]@{}
            if ($p.customRdpProperty) {
                $p.customRdpProperty.Split(';') | Where-Object { $_ -match ':' } | ForEach-Object {
                    $parts = $_ -split ':', 3
                    if ($parts.Count -ge 3) { $rdpProps[$parts[0].Trim()] = $parts[2].Trim() }
                }
            }

            $hpRoleAssignments = @()
            try   { $hpRoleAssignments = @(Resolve-RoleAssignments -ResourceId $hp.id) }
            catch { $hpErrors['RoleAssignments'] = $_.Exception.Message; Write-DebugLog "  HP $hpName role assignments error: $_" }
            $hpDiagSettings = @()
            try   { $hpDiagSettings = @(Get-ArmDiagnosticSettings -ResourceId $hp.id -Token $tok) }
            catch { $hpErrors['DiagnosticSettings'] = $_.Exception.Message; Write-DebugLog "  HP $hpName diagnostic settings error: $_" }

            $subData.HostPools.Add([ordered]@{
                Name                          = $hpName
                Id                            = $hp.id
                ResourceGroup                 = $hpRg
                Location                      = $hp.location
                FriendlyName                  = $p.friendlyName
                Description                   = $p.description
                HostPoolType                  = $p.hostPoolType
                ManagementType                = if ($p.PSObject.Properties['managementType']) { $p.managementType } else { 'Standard' }
                LoadBalancerType              = $p.loadBalancerType
                MaxSessionLimit               = $p.maxSessionLimit
                ValidationEnvironment         = if ($null -ne $p.validationEnvironment) { $p.validationEnvironment } else { $false }
                StartVMOnConnect              = if ($null -ne $p.startVMOnConnect) { $p.startVMOnConnect } else { $false }
                AgentUpdate                   = $p.agentUpdate
                PreferredAppGroupType         = $p.preferredAppGroupType
                PersonalDesktopAssignmentType = $p.personalDesktopAssignmentType
                CustomRdpProperty             = $p.customRdpProperty
                RdpProperties                 = $rdpProps
                Ring                          = $p.ring
                RegistrationTokenActive       = $regTokenExists
                Tags                          = ConvertTo-TagHashtable $hp.tags
                RoleAssignments               = $hpRoleAssignments
                DiagnosticSettings            = $hpDiagSettings
                RdpShortpath                  = [ordered]@{
                    ManagedNetworks     = if ($p.PSObject.Properties['managedPrivateUdpEnabled'] -and $p.managedPrivateUdpEnabled) { $p.managedPrivateUdpEnabled } else { 'Default' }
                    ManagedNetworksStun = if ($p.PSObject.Properties['directUdpEnabled']         -and $p.directUdpEnabled)         { $p.directUdpEnabled         } else { 'Default' }
                    PublicNetworksStun  = if ($p.PSObject.Properties['publicUdpEnabled']          -and $p.publicUdpEnabled)          { $p.publicUdpEnabled          } else { 'Default' }
                    PublicNetworksTurn  = if ($p.PSObject.Properties['relayUdpEnabled']           -and $p.relayUdpEnabled)           { $p.relayUdpEnabled           } else { 'Default' }
                }
                PrivateEndpoints              = @(if ($p.privateEndpointConnections) { $p.privateEndpointConnections | ForEach-Object { $_.name } })
                PrivateEndpointIds            = @(if ($p.privateEndpointConnections) { $p.privateEndpointConnections | Where-Object { $_.PSObject.Properties['properties'] -and $_.properties.PSObject.Properties['privateEndpoint'] } | ForEach-Object { $_.properties.privateEndpoint.id } })
                Properties                    = ConvertTo-SanitisedProperties $p -Exclude @('registrationInfo','ssoClientId','ssoClientSecretKeyVaultPath','ssoSecretType','ssoadfsAuthority','privateEndpointConnections','applicationGroupReferences')
                ApplicationGroups             = $appGroupData
                SessionHosts                  = $sessionHostData
                SessionHostCount              = $sessionHostData.Count
                ActiveSessionCount            = ($sessionHostData | ForEach-Object { $_.Sessions } | Measure-Object -Sum).Sum
                SessionHostRgVmCounts         = & {
                    $shRgs = @($sessionHostData | Where-Object { $_['ResourceId'] } |
                        ForEach-Object { Get-ResourceGroup $_['ResourceId'] } | Sort-Object -Unique)
                    $counts = [ordered]@{}
                    foreach ($shRg in $shRgs) {
                        $counts[$shRg] = @(Get-ArmVmsInRg -SubscriptionId $subId -ResourceGroup $shRg -Token $tok).Count
                    }
                    $counts
                }
                SessionHostRgs                = @($sessionHostData | Where-Object { $_['ResourceId'] } |
                    ForEach-Object { Get-ResourceGroup $_['ResourceId'] } | Sort-Object -Unique)
                SessionHostConfiguration      = & {
                    $shcResult = $null
                    try {
                        $shcRaw = Get-ArmSessionHostConfiguration -SubscriptionId $subId -ResourceGroup $hpRg -HostPoolName $hpName -Token $tok
                        if ($shcRaw) {
                            $shcp = $shcRaw.properties
                            $shcResult = [ordered]@{
                                VMSizeId       = if ($shcp.PSObject.Properties['vmSizeId']) { $shcp.vmSizeId } else { '' }
                                DiskType       = if ($shcp.PSObject.Properties['diskInfo'] -and $shcp.diskInfo.PSObject.Properties['diskType']) { $shcp.diskInfo.diskType } else { '' }
                                VMNamePrefix   = if ($shcp.PSObject.Properties['vmNamePrefix']) { $shcp.vmNamePrefix } else { '' }
                                ImageType      = if ($shcp.PSObject.Properties['imageInfo'] -and $shcp.imageInfo.PSObject.Properties['type']) { $shcp.imageInfo.type } else { '' }
                                ImagePublisher = if ($shcp.PSObject.Properties['imageInfo'] -and $shcp.imageInfo.PSObject.Properties['marketplaceInfo']) { $shcp.imageInfo.marketplaceInfo.publisher } else { '' }
                                ImageOffer     = if ($shcp.PSObject.Properties['imageInfo'] -and $shcp.imageInfo.PSObject.Properties['marketplaceInfo']) { $shcp.imageInfo.marketplaceInfo.offer } else { '' }
                                ImageSku       = if ($shcp.PSObject.Properties['imageInfo'] -and $shcp.imageInfo.PSObject.Properties['marketplaceInfo']) { $shcp.imageInfo.marketplaceInfo.sku } else { '' }
                                ImageCustomId  = if ($shcp.PSObject.Properties['imageInfo'] -and $shcp.imageInfo.PSObject.Properties['customInfo']) { $shcp.imageInfo.customInfo.resourceId } else { '' }
                                SubnetId       = if ($shcp.PSObject.Properties['networkData'] -and $shcp.networkData.PSObject.Properties['subnetId']) { $shcp.networkData.subnetId } else { '' }
                                DomainType     = if ($shcp.PSObject.Properties['domainInfo'] -and $shcp.domainInfo.PSObject.Properties['joinType']) { $shcp.domainInfo.joinType } else { '' }
                                DomainName     = if ($shcp.PSObject.Properties['domainInfo'] -and $shcp.domainInfo.PSObject.Properties['activeDirectoryInfo']) { $shcp.domainInfo.activeDirectoryInfo.domainName } else { '' }
                            }
                        }
                    } catch { Write-DebugLog "  SHC collection error for ${hpName}: $_" }
                    $shcResult
                }
                CollectionErrors              = $hpErrors
            })
        }
        Write-DebugLog "  Found $($hostPools.Count) host pool(s)"
        Write-DebugLog "Host pool collection complete: $($hostPools.Count)"
    }
    catch {
        Write-DebugLog "EXCEPTION in host pool collection: $_ (line $($_.InvocationInfo.ScriptLineNumber))"
        Write-Warning "    Could not retrieve host pools: $_"
    }

    # -- Storage Accounts ------------------------------------------------------
    Set-ReportStatus "Collecting storage accounts..." -Progress ($subBase + $subBudget - 3) -Sub $sub.Name
    try {
        $sas = @(Get-ArmResourcesScoped -SubscriptionId $subId -Token $tok -ProviderPath 'providers/Microsoft.Storage/storageAccounts' -ApiVersion $script:ApiVersions.Storage)
        Write-DebugLog "Storage accounts found: $($sas.Count)"
        $saIndex = 0
        foreach ($sa in $sas) {
            $saIndex++
            Set-ReportStatus "Collecting storage accounts ($saIndex/$($sas.Count))..." -Progress ($subBase + $subBudget - 3) -Sub $sub.Name
            $saRgCheck = Get-ResourceGroup $sa.id
            Write-DebugLog "  Storage $saIndex/$($sas.Count): $($sa.name)"
            $sap     = $sa.properties
            $saRg    = Get-ResourceGroup $sa.id
            $peNames     = @(if ($sap.privateEndpointConnections) { $sap.privateEndpointConnections | ForEach-Object { $_.name } })
            $peIds       = @(if ($sap.privateEndpointConnections) { $sap.privateEndpointConnections | Where-Object { $_.PSObject.Properties['properties'] -and $_.properties.PSObject.Properties['privateEndpoint'] } | ForEach-Object { $_.properties.privateEndpoint.id } })
            $peCount     = $peNames.Count
            Write-DebugLog "  Storage $($sa.name): peCount=$peCount peNames=$($peNames.Count) rawPeConnections=$(if($sap.privateEndpointConnections){(@($sap.privateEndpointConnections)|ForEach-Object{"[$($_.GetType().Name):name=$($_.name)]"})-join','}else{'null'})"

            $saErrors = [ordered]@{}

            $blobContainers = @()
            if ($sa.kind -ne 'FileStorage') {
                try {
                    $rawContainers = @(Get-ArmBlobContainers -SubscriptionId $subId -ResourceGroup $saRg -AccountName $sa.name -Token $tok)
                    Write-DebugLog "  Storage $($sa.name): $($rawContainers.Count) blob container(s)"
                    $blobContainers = @($rawContainers | ForEach-Object {
                        $cp = $_.properties
                        [ordered]@{
                            Name         = $_.name
                            PublicAccess = if ($cp.PSObject.Properties['publicAccess']) { if ($cp.publicAccess) { $cp.publicAccess } else { 'None' } } else { 'None' }
                            LeaseStatus  = if ($cp.PSObject.Properties['leaseStatus']) { $cp.leaseStatus } else { '' }
                            LastModified = if ($cp.PSObject.Properties['lastModifiedTime']) { $cp.lastModifiedTime } else { '' }
                        }
                    })
                } catch { $saErrors['BlobContainers'] = $_.Exception.Message; Write-DebugLog "  Storage $($sa.name) blob containers error: $_" }
            } else {
                Write-DebugLog "  Storage $($sa.name): skipping blob containers (Kind=FileStorage)"
            }

            $fileShares = @()
            if ($sa.kind -in @('Storage','StorageV2','FileStorage')) {
                try {
                    $rawShares   = @(Get-ArmFileShares -SubscriptionId $subId -ResourceGroup $saRg -AccountName $sa.name -Token $tok)
                    $saAuthType  = if ($sap.PSObject.Properties['azureFilesIdentityBasedAuthentication'] -and $sap.azureFilesIdentityBasedAuthentication.PSObject.Properties['directoryServiceOptions']) { $sap.azureFilesIdentityBasedAuthentication.directoryServiceOptions } else { 'None' }
                    $isKerberos  = $saAuthType -eq 'AADKERB'
                    $storageTok  = if ($isKerberos) { try { Get-ArmToken -ResourceUrl 'https://storage.azure.com/' } catch { $null } } else { $null }
                    $storageKey  = if ($isKerberos) { Get-ArmStorageAccountKey -SubscriptionId $subId -ResourceGroup $saRg -AccountName $sa.name -Token $tok } else { $null }
                    Write-DebugLog "  Storage $($sa.name): $($rawShares.Count) file share(s), auth=$saAuthType"
                    $fileShares = @($rawShares | ForEach-Object {
                        $shareName  = $_.name.Split('/')[-1]
                        $fp         = $_.properties
                        $quotaGB    = if ($fp.PSObject.Properties['shareQuota']) { [int]$fp.shareQuota } else { $null }
                        $statsObj   = Get-ArmFileShareStats -SubscriptionId $subId -ResourceGroup $saRg -AccountName $sa.name -ShareName $shareName -Token $tok
                        $usageBytes = if ($statsObj -and $statsObj.PSObject.Properties['properties'] -and $statsObj.properties.PSObject.Properties['shareUsageBytes']) { [long]$statsObj.properties.shareUsageBytes } else { $null }
                        $aclEntries = if ($isKerberos) { @(Get-AzureFilesShareAcl -AccountName $sa.name -ShareName $shareName -StorageToken $storageTok -AccountKey $storageKey) } else { @() }
                        [ordered]@{
                            Name       = $shareName
                            QuotaGB    = $quotaGB
                            UsageGB    = if ($null -ne $usageBytes) { [math]::Round($usageBytes / 1GB, 2) } else { $null }
                            UsedPct    = if ($null -ne $usageBytes -and $null -ne $quotaGB -and $quotaGB -gt 0) { [math]::Round($usageBytes / ($quotaGB * 1GB) * 100, 1) } else { $null }
                            Protocol   = if ($fp.PSObject.Properties['enabledProtocols']) { $fp.enabledProtocols } else { 'SMB' }
                            AccessTier = if ($fp.PSObject.Properties['accessTier']) { $fp.accessTier } else { '' }
                            AclEntries = $aclEntries
                        }
                    })
                } catch { $saErrors['FileShares'] = $_.Exception.Message; Write-DebugLog "  Storage $($sa.name) file shares error: $_" }
            } else {
                Write-DebugLog "  Storage $($sa.name): skipping file shares (Kind=$($sa.kind))"
            }

            $saRoleAssignments = @()
            try   { $saRoleAssignments = @(Resolve-RoleAssignments -ResourceId $sa.id) }
            catch { $saErrors['RoleAssignments'] = $_.Exception.Message; Write-DebugLog "  Storage $($sa.name) role assignments error: $_" }

            $subData.StorageAccounts.Add([ordered]@{
                Name                  = $sa.name
                ResourceGroup         = $saRg
                Location              = $sa.location
                SkuName               = if ($sa.PSObject.Properties['sku']) { $sa.sku.name } else { '' }
                Kind                  = $sa.kind
                AzureFilesAuthType       = if ($sap.PSObject.Properties['azureFilesIdentityBasedAuthentication'] -and $sap.azureFilesIdentityBasedAuthentication.PSObject.Properties['directoryServiceOptions']) { $sap.azureFilesIdentityBasedAuthentication.directoryServiceOptions } else { 'None' }
                DefaultSharePermission   = if ($sap.PSObject.Properties['azureFilesIdentityBasedAuthentication'] -and $sap.azureFilesIdentityBasedAuthentication.PSObject.Properties['defaultSharePermission']) { $sap.azureFilesIdentityBasedAuthentication.defaultSharePermission } else { 'None' }
                MinimumTlsVersion        = if ($sap.PSObject.Properties['minimumTlsVersion']) { $sap.minimumTlsVersion } else { 'Unknown' }
                PublicNetworkAccess   = if ($sap.PSObject.Properties['publicNetworkAccess']) { $sap.publicNetworkAccess } else { 'Enabled' }
                AllowBlobPublicAccess = if ($sap.PSObject.Properties['allowBlobPublicAccess']) { $sap.allowBlobPublicAccess } else { $true }
                PrivateEndpointCount  = $peCount
                PrivateEndpoints      = $peNames
                PrivateEndpointIds    = $peIds
                Properties           = ConvertTo-SanitisedProperties $sap -Exclude @('privateEndpointConnections')
                Tags                 = ConvertTo-TagHashtable $sa.tags
                BlobContainers       = $blobContainers
                FileShares           = $fileShares
                RoleAssignments      = $saRoleAssignments
                CollectionErrors     = $saErrors
            })
        }
        Write-DebugLog "Storage accounts collected: $($subData.StorageAccounts.Count)"
    }
    catch { Write-DebugLog "Storage collection error: $_" }

    # -- AMPLS map (LAW resource ID -> scope names) --------------------------------
    # Built separately so a failure here never blocks LAW collection.
    $amplsMap   = @{}
    $amplsError = ''
    try {
        $amplsList = @(Get-ArmPrivateLinkScopes -SubscriptionId $subId -Token $tok)
        Write-DebugLog "AMPLS found: $($amplsList.Count)"
        foreach ($ampls in $amplsList) {
            try {
                $amplsRg = Get-ResourceGroup $ampls.id
                $scopedResources = @(Get-ArmPrivateLinkScopedResources -SubscriptionId $subId -ResourceGroup $amplsRg -ScopeName $ampls.name -Token $tok)
                foreach ($sr in $scopedResources) {
                    $linkedId = if ($sr.PSObject.Properties['properties'] -and $sr.properties.PSObject.Properties['linkedResourceId']) { $sr.properties.linkedResourceId } else { $null }
                    if ($linkedId) {
                        $key = $linkedId.ToLower()
                        if (-not $amplsMap.ContainsKey($key)) { $amplsMap[$key] = [System.Collections.Generic.List[string]]::new() }
                        $amplsMap[$key].Add($ampls.name)
                    }
                }
            } catch { Write-DebugLog "  AMPLS scope error ($($ampls.name)): $_" }
        }
    } catch { $amplsError = $_.Exception.Message; Write-DebugLog "AMPLS collection error: $_" }

    # -- Log Analytics Workspaces -----------------------------------------------
    Set-ReportStatus "Collecting Log Analytics workspaces..." -Progress ($subBase + $subBudget - 2) -Sub $sub.Name
    try {
        $laws = @(Get-ArmResourcesScoped -SubscriptionId $subId -Token $tok -ProviderPath 'providers/Microsoft.OperationalInsights/workspaces' -ApiVersion $script:ApiVersions.LogAnalytics)
        Write-DebugLog "Log Analytics workspaces found: $($laws.Count)"

        foreach ($law in $laws) {
            $p   = $law.properties
            $rg  = Get-ResourceGroup $law.id
            $lawErrors = [ordered]@{}
            if ($amplsError) { $lawErrors['PrivateLinkScopes'] = $amplsError }
            $lawAmpls = @()
            if ($amplsMap.ContainsKey($law.id.ToLower())) { $lawAmpls = @($amplsMap[$law.id.ToLower()]) }
            Write-DebugLog "  LAW $($law.name): $($lawAmpls.Count) AMPLS association(s)"
            $lawRoleAssignments = @()
            try   { $lawRoleAssignments = @(Resolve-RoleAssignments -ResourceId $law.id) }
            catch { $lawErrors['RoleAssignments'] = $_.Exception.Message; Write-DebugLog "  LAW $($law.name) role assignments error: $_" }
            $subData.LogAnalyticsWorkspaces.Add([ordered]@{
                Name                     = $law.name
                Id                       = $law.id
                ResourceGroup            = $rg
                Location                 = $law.location
                CustomerId               = if ($p.PSObject.Properties['customerId']) { $p.customerId } else { $null }
                SKU                      = if ($p.PSObject.Properties['sku']) { $p.sku.name } else { '' }
                RetentionDays            = if ($p.PSObject.Properties['retentionInDays']) { $p.retentionInDays } else { $null }
                DailyQuotaGB             = if ($p.PSObject.Properties['workspaceCapping'] -and $p.workspaceCapping.PSObject.Properties['dailyQuotaGb']) { $p.workspaceCapping.dailyQuotaGb } else { $null }
                PublicIngestion          = if ($p.PSObject.Properties['publicNetworkAccessForIngestion']) { $p.publicNetworkAccessForIngestion } else { 'Enabled' }
                PublicQuery              = if ($p.PSObject.Properties['publicNetworkAccessForQuery']) { $p.publicNetworkAccessForQuery } else { 'Enabled' }
                PrivateLinkScopes        = $lawAmpls
                Tags                     = ConvertTo-TagHashtable $law.tags
                Properties               = ConvertTo-SanitisedProperties $p
                RoleAssignments          = $lawRoleAssignments
                CollectionErrors         = $lawErrors
            })
        }
        Write-DebugLog "Log Analytics workspaces collected: $($subData.LogAnalyticsWorkspaces.Count)"
    }
    catch { Write-DebugLog "Log Analytics collection error: $_" }

    # -- Performance (optional): 30-day logon & connection times from Log Analytics --
    if ($dialogResult['CollectPerformance']) {
        Set-ReportStatus "Collecting performance data (Log Analytics)..." -Sub $sub.Name
        Write-DebugLog "  Collecting performance data (30d logon/connection times)..."

        # KQL: aggregate per host pool resource id (_ResourceId), last 7 days. No PII (counts/seconds only).
        # Network connect time: WVDConnections Started -> Connected.
        $connQuery = @'
let conn = WVDConnections | where TimeGenerated > ago(7d);
conn | where State == "Started" | project CorrelationId, _ResourceId, t0 = TimeGenerated
| join kind=inner (conn | where State == "Connected" | project CorrelationId, t1 = TimeGenerated) on CorrelationId
| extend sec = datetime_diff("second", t1, t0)
| where sec >= 0 and sec <= 3600
| summarize Count=count(), Avg=round(avg(sec),1), P50=round(percentile(sec,50),1), P95=round(percentile(sec,95),1), Max=max(sec) by HostPool = tolower(_ResourceId)
'@
        # Time to Connect (AVD Insights): Started -> ShellReady (desktop) / RdpShellAppExecuted (RemoteApp),
        # minus credential-entry time. Only connections that reached the host (RdpStackConnectionEstablished).
        $ttcQuery = @'
WVDConnections
| where TimeGenerated > ago(7d) | where State == "Started"
| project CorrelationId, _ResourceId, startT = TimeGenerated
| join kind=leftsemi (WVDCheckpoints | where Source == "RDStack" and Name == "RdpStackConnectionEstablished") on CorrelationId
| join kind=inner (
    WVDCheckpoints | where TimeGenerated > ago(7d) | where Name == "ShellReady" or Name == "RdpShellAppExecuted"
    | summarize shellT = min(TimeGenerated) by CorrelationId
  ) on CorrelationId
| join kind=leftouter (
    WVDCheckpoints | where Name == "OnCredentialsAcquisitionCompleted"
    | project CorrelationId, cred = todouble(Parameters.DurationMS)
  ) on CorrelationId
| extend sec = datetime_diff("second", shellT, startT) - (coalesce(cred,0.0)/1000.0)
| where sec > 0 and sec <= 1800
| summarize Count=count(), Avg=round(avg(sec),1), P50=round(percentile(sec,50),1), P95=round(percentile(sec,95),1), Max=round(max(sec),1) by HostPool = tolower(_ResourceId)
'@
        # Winlogon stages (AVD Insights): per-stage P50/P95 from the LogonDelay checkpoint, new sessions only.
        $winlogonQuery = @'
let renameStage = (stage: string) { case(
    stage =~ "frxsvc", "FSLogix",
    stage =~ "GPClient", "Group policy",
    stage =~ "WinLogon_StartShell", "Shell",
    stage =~ "AuthenticateUser", "User Auth.",
    "Others") };
WVDConnections
| where State == "Connected" | where TimeGenerated > ago(7d)
| join kind=leftsemi (WVDCheckpoints | where Source == "RDStack" and Name == "RdpStackConnectionEstablished") on CorrelationId
| join kind=leftsemi (WVDCheckpoints | where Name == "LoadBalancedNewConnection" | extend lbo = Parameters.LoadBalanceOutcome | where lbo == "NewSession") on CorrelationId
| project CorrelationId, _ResourceId
| join kind=inner (WVDCheckpoints | where Name == "LogonDelay") on CorrelationId
| extend Parameters = bag_remove_keys(Parameters, dynamic(["LogonType","WinLogonPid"]))
| mv-expand bagexpansion=array Parameters
| extend Stage = tostring(Parameters[0]), Time = toreal(Parameters[1]) / 1000.0
| where Stage != "WinLogon_Total" and Stage != "WinLogon_Logon"
| extend Stage = renameStage(trim_start("WinLogon_Logon_", Stage))
| summarize Time = sum(Time) by Stage, CorrelationId, HostPool = tolower(_ResourceId)
| summarize P50 = round(percentile(Time,50),1), P95 = round(percentile(Time,95),1), Samples = count() by HostPool, Stage
'@
        # RTT by gateway region (30d), subscription-wide (not per host pool). Requires NetworkData category.
        $rttQuery = @'
WVDConnectionNetworkData
| where TimeGenerated > ago(30d)
| where isnotnull(EstRoundTripTimeInMs) and EstRoundTripTimeInMs > 0
| join kind=inner (
    WVDConnections | where TimeGenerated > ago(30d) | where State == "Connected"
    | project CorrelationId, GatewayRegion, UserName
) on CorrelationId
| where isnotempty(GatewayRegion) and GatewayRegion != "<>"
| summarize Users=dcount(UserName), Median=round(percentile(EstRoundTripTimeInMs,50),0),
            P95=round(percentile(EstRoundTripTimeInMs,95),0),
            arg_max(EstRoundTripTimeInMs, TimeGenerated)
        by GatewayRegion
| project GatewayRegion, Users, Median, P95, Peak = round(EstRoundTripTimeInMs,0), PeakTime = TimeGenerated
| order by Users desc
'@
        # Session history per host pool, hourly bins (7d). Requires AgentHealthStatus diagnostic category.
        $sessionQuery = @'
WVDAgentHealthStatus
| where TimeGenerated > ago(7d)
| extend BinTime = bin(TimeGenerated, 1h)
| summarize arg_max(TimeGenerated, ActiveSessions, InactiveSessions) by _ResourceId, SessionHostName, BinTime
| summarize Active=sum(toint(ActiveSessions)), Disconnected=sum(toint(InactiveSessions))
        by HostPool = tolower(_ResourceId), BinTime
| extend Total = Active + Disconnected
| order by HostPool asc, BinTime asc
'@

        # Collect unique workspace resource IDs referenced by host pool diagnostic settings.
        $wsToQuery = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($hpEntry in $subData.HostPools) {
            foreach ($ds in @($hpEntry['DiagnosticSettings'])) {
                if ($ds -and $ds['WorkspaceId']) { [void]$wsToQuery.Add($ds['WorkspaceId']) }
            }
        }

        # Stage order for the winlogon breakdown (matches the AVD Insights chart).
        $wlOrder = @{ 'Others'=0; 'User Auth.'=1; 'Group policy'=2; 'Shell'=3; 'FSLogix'=4 }

        # Run queries against each target workspace. Conn/time-to-connect merge by host pool id;
        # winlogon + session accumulate per host pool; RTT is subscription-wide by gateway region.
        $connByHp = @{}; $ttcByHp = @{}; $wlByHp = @{}; $sessByHp = @{}; $rttByRegion = @{}
        foreach ($wsId in $wsToQuery) {
            $wsName = ($wsId -split '/')[-1]
            foreach ($row in (Invoke-LogAnalyticsQuery -WorkspaceResourceId $wsId -WorkspaceName $wsName -Token $tok -Query $connQuery))     { if ($row['HostPool']) { $connByHp[$row['HostPool']] = $row } }
            foreach ($row in (Invoke-LogAnalyticsQuery -WorkspaceResourceId $wsId -WorkspaceName $wsName -Token $tok -Query $ttcQuery))      { if ($row['HostPool']) { $ttcByHp[$row['HostPool']]  = $row } }
            foreach ($row in (Invoke-LogAnalyticsQuery -WorkspaceResourceId $wsId -WorkspaceName $wsName -Token $tok -Query $winlogonQuery)) { if ($row['HostPool']) { if (-not $wlByHp[$row['HostPool']])   { $wlByHp[$row['HostPool']]   = [System.Collections.Generic.List[object]]::new() }; $wlByHp[$row['HostPool']].Add($row) } }
            foreach ($row in (Invoke-LogAnalyticsQuery -WorkspaceResourceId $wsId -WorkspaceName $wsName -Token $tok -Query $sessionQuery)) { if ($row['HostPool']) { if (-not $sessByHp[$row['HostPool']]) { $sessByHp[$row['HostPool']] = [System.Collections.Generic.List[object]]::new() }; $sessByHp[$row['HostPool']].Add($row) } }
            foreach ($row in (Invoke-LogAnalyticsQuery -WorkspaceResourceId $wsId -WorkspaceName $wsName -Token $tok -Query $rttQuery)) {
                $reg = "$($row['GatewayRegion'])"
                if (-not $reg) { continue }
                $existing = $rttByRegion[$reg]
                if (-not $existing -or ([int]$row['Users'] -gt [int]$existing['Users'])) { $rttByRegion[$reg] = $row }
            }
        }

        # Subscription-wide RTT by gateway region (its own section in the report).
        $subData['RttByRegion'] = @($rttByRegion.Values | Sort-Object { -[int]$_['Users'] } | ForEach-Object {
            [ordered]@{ GatewayRegion=$_['GatewayRegion']; Users=$_['Users']; Median=$_['Median']; P95=$_['P95']; Peak=$_['Peak']; PeakTime=$_['PeakTime'] }
        })

        # Attach a Performance block to each host pool by matching resource id.
        foreach ($hpEntry in $subData.HostPools) {
            $key = if ($hpEntry['Id']) { $hpEntry['Id'].ToLowerInvariant() } else { $null }
            $c   = if ($key) { $connByHp[$key] } else { $null }
            $ttc = if ($key) { $ttcByHp[$key] }  else { $null }
            $wl  = if ($key -and $wlByHp[$key]) {
                @($wlByHp[$key] | Sort-Object { if ($wlOrder.ContainsKey("$($_['Stage'])")) { $wlOrder["$($_['Stage'])"] } else { 99 } } | ForEach-Object {
                    [ordered]@{ Stage=$_['Stage']; P50=$_['P50']; P95=$_['P95']; Samples=$_['Samples'] }
                })
            } else { @() }
            $sh  = if ($key -and $sessByHp[$key]) { @($sessByHp[$key] | ForEach-Object { [ordered]@{ Time=$_['BinTime']; Active=$_['Active']; Disconnected=$_['Disconnected']; Total=$_['Total'] } }) } else { @() }
            $hpEntry['Performance'] = [ordered]@{
                QueryWindowDays    = 7
                SessionHistoryDays = 7
                HasData            = [bool]($c -or $ttc -or $wl.Count -or $sh.Count)
                Connection         = if ($c)   { [ordered]@{ Count=$c['Count']; Avg=$c['Avg']; P50=$c['P50']; P95=$c['P95']; Max=$c['Max'] } } else { $null }
                TimeToConnect      = if ($ttc) { [ordered]@{ Count=$ttc['Count']; Avg=$ttc['Avg']; P50=$ttc['P50']; P95=$ttc['P95']; Max=$ttc['Max'] } } else { $null }
                WinlogonStages     = $wl
                SessionHistory     = $sh
            }
        }
        $withData = @($subData.HostPools | Where-Object { $_['Performance'] -and $_['Performance']['HasData'] }).Count
        $withWl   = @($subData.HostPools | Where-Object { $_['Performance'] -and @($_['Performance']['WinlogonStages']).Count -gt 0 }).Count
        $withSess = @($subData.HostPools | Where-Object { $_['Performance'] -and @($_['Performance']['SessionHistory']).Count -gt 0 }).Count
        Write-DebugLog "  Performance: $withData host pool(s) with timing data ($withWl with winlogon stages, $withSess with session history, $(@($subData['RttByRegion']).Count) gateway region(s) RTT)"
    }

    # -- Data Collection Rules --------------------------------------------------
    Set-ReportStatus "Collecting data collection rules..." -Progress ($subBase + 72) -Sub $sub.Name
    try {
        foreach ($dcr in @(Get-ArmResourcesScoped -SubscriptionId $subId -Token $tok -ProviderPath 'providers/Microsoft.Insights/dataCollectionRules' -ApiVersion $script:ApiVersions.DataCollection)) {
            $dp = $dcr.properties
            $rg = Get-ResourceGroup $dcr.id
            $dsSources = [System.Collections.Generic.List[object]]::new()
            if ($dp.PSObject.Properties['dataSources'] -and $dp.dataSources) {
                $dsTypeMap = @{
                    performanceCounters = 'Performance Counters'
                    windowsEventLogs    = 'Windows Event Logs'
                    syslog              = 'Syslog'
                    extensions          = 'Extensions'
                    logFiles            = 'Log Files'
                    iisLogs             = 'IIS Logs'
                    windowsFirewallLogs = 'Windows Firewall Logs'
                    prometheusForwarder = 'Prometheus Forwarder'
                }
                foreach ($dsProp in $dp.dataSources.PSObject.Properties) {
                    $typeName = if ($dsTypeMap.ContainsKey($dsProp.Name)) { $dsTypeMap[$dsProp.Name] } else { $dsProp.Name }
                    foreach ($src in @($dsProp.Value)) {
                        $detail = switch ($dsProp.Name) {
                            'performanceCounters' { "Interval: $($src.samplingFrequencyInSeconds)s, $(@($src.counterSpecifiers).Count) counter(s)" }
                            'windowsEventLogs'    { "$(@($src.xPathQueries).Count) XPath query/queries" }
                            'syslog'              { if ($src.PSObject.Properties['facilityNames']) { ($src.facilityNames -join ', ') } else { '' } }
                            'extensions'          { if ($src.PSObject.Properties['extensionName']) { "Extension: $($src.extensionName)" } else { '' } }
                            default               { '' }
                        }
                        $items = switch ($dsProp.Name) {
                            'performanceCounters' { if ($src.PSObject.Properties['counterSpecifiers']) { @($src.counterSpecifiers) } else { @() } }
                            'windowsEventLogs'    { if ($src.PSObject.Properties['xPathQueries'])     { @($src.xPathQueries)     } else { @() } }
                            'syslog'              { if ($src.PSObject.Properties['facilityNames'])    { @($src.facilityNames)    } else { @() } }
                            default               { @() }
                        }
                        $dsSources.Add([ordered]@{
                            Type    = $typeName
                            Name    = if ($src.PSObject.Properties['name']) { $src.name } else { '' }
                            Detail  = $detail
                            Streams = if ($src.PSObject.Properties['streams']) { @($src.streams) -join ', ' } else { '' }
                            Items   = $items
                        })
                    }
                }
            }
            $subData.DataCollectionRules.Add([ordered]@{
                Name          = $dcr.name
                ResourceGroup = $rg
                Location      = $dcr.location
                Description   = if ($dp.PSObject.Properties['description']) { $dp.description } else { $null }
                EndpointId    = if ($dp.PSObject.Properties['dataCollectionEndpointId']) { $dp.dataCollectionEndpointId.Split('/')[-1] } else { $null }
                DataSources   = $dsSources.ToArray()
                Tags          = ConvertTo-TagHashtable $(if ($dcr.PSObject.Properties['tags']) { $dcr.tags } else { $null })
                Properties    = ConvertTo-SanitisedProperties $dp
            })
        }
        Write-DebugLog "  Found $($subData.DataCollectionRules.Count) data collection rule(s)"
    } catch { Write-DebugLog "DCR collection error: $_" }

    # -- Data Collection Endpoints ----------------------------------------------
    Set-ReportStatus "Collecting data collection endpoints..." -Progress ($subBase + 74) -Sub $sub.Name
    try {
        foreach ($dce in @(Get-ArmResourcesScoped -SubscriptionId $subId -Token $tok -ProviderPath 'providers/Microsoft.Insights/dataCollectionEndpoints' -ApiVersion $script:ApiVersions.DataCollection)) {
            $ep = $dce.properties
            $rg = Get-ResourceGroup $dce.id
            $subData.DataCollectionEndpoints.Add([ordered]@{
                Name          = $dce.name
                ResourceGroup = $rg
                Location      = $dce.location
                NetworkAccess = if ($ep.PSObject.Properties['networkAcls']) { $ep.networkAcls.publicNetworkAccess } else { 'Enabled' }
                Tags          = ConvertTo-TagHashtable $(if ($dce.PSObject.Properties['tags']) { $dce.tags } else { $null })
                Properties    = ConvertTo-SanitisedProperties $ep
            })
        }
        Write-DebugLog "  Found $($subData.DataCollectionEndpoints.Count) data collection endpoint(s)"
    } catch { Write-DebugLog "DCE collection error: $_" }

    # -- Key Vaults -------------------------------------------------------------
    Set-ReportStatus "Collecting key vaults..." -Progress ($subBase + $subBudget - 1) -Sub $sub.Name
    try {
        $kvs = @(Get-ArmResourcesScoped -SubscriptionId $subId -Token $tok -ProviderPath 'providers/Microsoft.KeyVault/vaults' -ApiVersion $script:ApiVersions.KeyVault)
        Write-DebugLog "Key vaults found: $($kvs.Count)"
        foreach ($kv in $kvs) {
            $p  = $kv.properties
            $rg = Get-ResourceGroup $kv.id
            $kvPeCount = if ($p.PSObject.Properties['privateEndpointConnections']) { @($p.privateEndpointConnections).Count } else { 0 }
            $kvPeIds   = @(if ($p.PSObject.Properties['privateEndpointConnections']) { $p.privateEndpointConnections | Where-Object { $_.PSObject.Properties['properties'] -and $_.properties.PSObject.Properties['privateEndpoint'] } | ForEach-Object { $_.properties.privateEndpoint.id } })
            $kvErrors  = [ordered]@{}
            $kvRoleAssignments = @()
            try   { $kvRoleAssignments = @(Resolve-RoleAssignments -ResourceId $kv.id) }
            catch { $kvErrors['RoleAssignments'] = $_.Exception.Message; Write-DebugLog "  KV $($kv.name) role assignments error: $_" }
            $subData.KeyVaults.Add([ordered]@{
                Name                 = $kv.name
                ResourceGroup        = $rg
                Location             = $kv.location
                SKU                  = if ($p.PSObject.Properties['sku']) { $p.sku.name } else { '' }
                SoftDeleteEnabled    = if ($p.PSObject.Properties['enableSoftDelete']) { $p.enableSoftDelete } else { $false }
                PurgeProtection      = if ($p.PSObject.Properties['enablePurgeProtection']) { $p.enablePurgeProtection } else { $false }
                PublicNetworkAccess  = if ($p.PSObject.Properties['publicNetworkAccess']) { $p.publicNetworkAccess } else { 'Enabled' }
                NetworkDefaultAction = if ($p.PSObject.Properties['networkAcls'] -and $p.networkAcls.PSObject.Properties['defaultAction']) { $p.networkAcls.defaultAction } else { 'Allow' }
                PrivateEndpointCount = $kvPeCount
                PrivateEndpointIds   = $kvPeIds
                Properties           = ConvertTo-SanitisedProperties $p -Exclude @('privateEndpointConnections')
                Tags                 = ConvertTo-TagHashtable $kv.tags
                RoleAssignments      = $kvRoleAssignments
                CollectionErrors     = $kvErrors
            })
        }
        Write-DebugLog "Key vaults collected: $($subData.KeyVaults.Count)"
    }
    catch { Write-DebugLog "Key vault collection error: $_" }

    # -- Custom Image Templates --------------------------------------------------
    Set-ReportStatus "Collecting custom image templates..." -Progress ($subBase + $subBudget) -Sub $sub.Name
    Write-DebugLog "  Collecting custom image templates..."
    try {
        $imageTemplates = @(Get-ArmImageTemplates -SubscriptionId $subId -Token $tok)
        Write-DebugLog "Custom image templates found: $($imageTemplates.Count)"
        foreach ($it in $imageTemplates) {
            $itRg = Get-ResourceGroup $it.id
            $itp  = $it.properties
            $statusCode    = if ($itp.PSObject.Properties['status'] -and $itp.status.PSObject.Properties['status']) { $itp.status.status.code } else { '' }
            $statusProgress = if ($itp.PSObject.Properties['status'] -and $itp.status.PSObject.Properties['progress']) { $itp.status.progress } else { '' }
            $srcType       = if ($itp.PSObject.Properties['source'] -and $itp.source.PSObject.Properties['type']) { $itp.source.type } else { '' }
            $srcResourceId = if ($itp.PSObject.Properties['source'] -and $itp.source.PSObject.Properties['resourceId']) { $itp.source.resourceId } else { '' }
            $srcOffer      = if ($itp.PSObject.Properties['source'] -and $itp.source.PSObject.Properties['offer']) { $itp.source.offer } else { '' }
            $srcSku        = if ($itp.PSObject.Properties['source'] -and $itp.source.PSObject.Properties['sku']) { $itp.source.sku } else { '' }
            $distributeTargets = @()
            if ($itp.PSObject.Properties['distribute']) {
                $distributeTargets = @($itp.distribute | ForEach-Object {
                    $t = $_
                    $tType  = if ($t.PSObject.Properties['type']) { $t.type } else { 'Unknown' }
                    $tGalId = if ($t.PSObject.Properties['galleryImageId']) { $t.galleryImageId } else { '' }
                    $tRunId = if ($t.PSObject.Properties['runOutputName']) { $t.runOutputName } else { '' }
                    if ($tGalId) { "$tType`: $tGalId" } elseif ($tRunId) { "$tType`: $tRunId" } else { $tType }
                })
            }
            $customizeSteps = @()
            if ($itp.PSObject.Properties['customize']) {
                $customizeSteps = @($itp.customize | ForEach-Object {
                    $c = $_
                    $cType = if ($c.PSObject.Properties['type']) { $c.type } else { '' }
                    $cName = if ($c.PSObject.Properties['name']) { $c.name } else { $cType }
                    $cName
                })
            }
            $subData.ImageTemplates.Add([ordered]@{
                Name               = $it.name
                ResourceGroup      = $itRg
                Location           = $it.location
                TemplateStatus     = $statusCode
                BuildProgress      = $statusProgress
                StagingResourceGroup = if ($itp.PSObject.Properties['stagingResourceGroup']) { $itp.stagingResourceGroup } else { '' }
                SourceType         = $srcType
                SourceResourceId   = $srcResourceId
                SourceOffer        = $srcOffer
                SourceSku          = $srcSku
                DistributeTargets  = $distributeTargets
                CustomizeSteps     = $customizeSteps
                Properties         = ConvertTo-SanitisedProperties $itp -Exclude @('customize','distribute','source','status')
            })
        }
        Write-DebugLog "Custom image templates collected: $($subData.ImageTemplates.Count)"
    } catch { Write-DebugLog "Custom image template collection error: $_" }

    # -- App Attach Packages ----------------------------------------------------
    Set-ReportStatus "Collecting app attach packages..." -Progress ($subBase + $subBudget) -Sub $sub.Name
    Write-DebugLog "  Collecting app attach packages..."
    try {
        $appAttachPkgs = @(Get-ArmAppAttachPackages -SubscriptionId $subId -Token $tok)
        Write-DebugLog "App attach packages found: $($appAttachPkgs.Count)"
        foreach ($aap in $appAttachPkgs) {
            $aapRg = Get-ResourceGroup $aap.id
            $aapp  = $aap.properties
            $imgProps = if ($aapp.PSObject.Properties['image']) { $aapp.image } else { $null }
            $hostPoolRefs = @()
            if ($aapp.PSObject.Properties['hostPoolReferences']) {
                $hostPoolRefs = @($aapp.hostPoolReferences | ForEach-Object { if ($_.PSObject.Properties['hostPoolArmPath']) { $_.hostPoolArmPath.Split('/')[-1] } else { $_ } })
            }
            $subData.AppAttachPackages.Add([ordered]@{
                Name                = $aap.name
                ResourceGroup       = $aapRg
                Location            = $aap.location
                PackageAlias        = if ($aapp.PSObject.Properties['packageAlias']) { $aapp.packageAlias } else { '' }
                State               = if ($aapp.PSObject.Properties['registrationStatus']) { $aapp.registrationStatus } else { '' }
                FailHealthCheck     = if ($aapp.PSObject.Properties['failHealthCheckOnStagingFailure']) { $aapp.failHealthCheckOnStagingFailure } else { '' }
                ImagePath           = if ($imgProps -and $imgProps.PSObject.Properties['imagePath']) { $imgProps.imagePath } else { '' }
                PackageName         = if ($imgProps -and $imgProps.PSObject.Properties['packageName']) { $imgProps.packageName } else { '' }
                PackageVersion      = if ($imgProps -and $imgProps.PSObject.Properties['packageVersion']) { $imgProps.packageVersion } else { '' }
                PackagePublisher    = if ($imgProps -and $imgProps.PSObject.Properties['packagePublisher']) { $imgProps.packagePublisher } else { '' }
                IsActive            = if ($imgProps -and $imgProps.PSObject.Properties['isActive']) { $imgProps.isActive } else { '' }
                HostPoolReferences  = $hostPoolRefs
                Properties          = ConvertTo-SanitisedProperties $aapp -Exclude @('image','hostPoolReferences')
            })
        }
        Write-DebugLog "App attach packages collected: $($subData.AppAttachPackages.Count)"
    } catch { Write-DebugLog "App attach package collection error: $_" }

    # -- Compute Galleries -------------------------------------------------------
    Set-ReportStatus "Collecting compute galleries..." -Progress ($subBase + $subBudget) -Sub $sub.Name
    Write-DebugLog "  Collecting compute galleries..."
    try {
        $galleries = @(Get-ArmResourcesScoped -SubscriptionId $subId -Token $tok -ProviderPath 'providers/Microsoft.Compute/galleries' -ApiVersion $script:ApiVersions.ComputeGalleries)
        Write-DebugLog "Compute galleries found: $($galleries.Count)"
        foreach ($gal in $galleries) {
            $galRg   = Get-ResourceGroup $gal.id
            $galName = $gal.name
            $gp      = $gal.properties
            $sharingPermissions = if ($gp.PSObject.Properties['sharingProfile'] -and $gp.sharingProfile.PSObject.Properties['permissions']) { $gp.sharingProfile.permissions } else { 'None' }

            $imageDefs = [System.Collections.Generic.List[object]]::new()
            foreach ($def in @(Get-ArmGalleryImages -SubscriptionId $subId -ResourceGroup $galRg -GalleryName $galName -Token $tok)) {
                $dp      = $def.properties
                $defName = $def.name
                $securityType = 'Standard'
                if ($dp.PSObject.Properties['features']) {
                    $stFeature = @($dp.features) | Where-Object { $_.name -eq 'SecurityType' } | Select-Object -First 1
                    if ($stFeature) { $securityType = $stFeature.value }
                }
                $versions = [System.Collections.Generic.List[object]]::new()
                foreach ($ver in @(Get-ArmGalleryImageVersions -SubscriptionId $subId -ResourceGroup $galRg -GalleryName $galName -ImageName $defName -Token $tok)) {
                    $vp           = $ver.properties
                    $pp           = if ($vp.PSObject.Properties['publishingProfile']) { $vp.publishingProfile } else { $null }
                    $replicaCount = if ($pp -and $pp.PSObject.Properties['replicaCount']) { [int]$pp.replicaCount } else { 1 }
                    $regionReplicas = @()
                    if ($pp -and $pp.PSObject.Properties['targetRegions']) {
                        $regionReplicas = @($pp.targetRegions | ForEach-Object {
                            $rc = if ($_.PSObject.Properties['regionalReplicaCount']) { [int]$_.regionalReplicaCount } else { $replicaCount }
                            "$($_.name) x$rc"
                        })
                    }
                    $versions.Add([ordered]@{
                        Name              = $ver.name
                        ProvisioningState = if ($vp.PSObject.Properties['provisioningState']) { $vp.provisioningState } else { '' }
                        ReplicaCount      = $replicaCount
                        ExcludeFromLatest = if ($pp -and $pp.PSObject.Properties['excludeFromLatest']) { $pp.excludeFromLatest } else { $false }
                        PublishedDate     = if ($pp -and $pp.PSObject.Properties['publishedDate']) { ($pp.publishedDate -replace 'T.*','') } else { '' }
                        RegionReplicas    = $regionReplicas
                    })
                }
                $imageDefs.Add([ordered]@{
                    Name             = $defName
                    OsType           = if ($dp.PSObject.Properties['osType']) { $dp.osType } else { '' }
                    OsState          = if ($dp.PSObject.Properties['osState']) { $dp.osState } else { '' }
                    Publisher        = if ($dp.PSObject.Properties['identifier'] -and $dp.identifier.PSObject.Properties['publisher']) { $dp.identifier.publisher } else { '' }
                    Offer            = if ($dp.PSObject.Properties['identifier'] -and $dp.identifier.PSObject.Properties['offer']) { $dp.identifier.offer } else { '' }
                    Sku              = if ($dp.PSObject.Properties['identifier'] -and $dp.identifier.PSObject.Properties['sku']) { $dp.identifier.sku } else { '' }
                    HyperVGeneration = if ($dp.PSObject.Properties['hyperVGeneration']) { $dp.hyperVGeneration } else { '' }
                    SecurityType     = $securityType
                    VersionCount     = $versions.Count
                    ImageVersions    = $versions.ToArray()
                })
            }
            $subData.ComputeGalleries.Add([ordered]@{
                Name             = $galName
                ResourceGroup    = $galRg
                Location         = $gal.location
                Description      = if ($gp.PSObject.Properties['description']) { $gp.description } else { '' }
                SharingProfile   = $sharingPermissions
                DefinitionCount  = $imageDefs.Count
                ImageDefinitions = $imageDefs.ToArray()
            })
        }
        Write-DebugLog "Compute galleries collected: $($subData.ComputeGalleries.Count)"
    } catch { Write-DebugLog "Compute gallery collection error: $_" }

    # Collect role assignments for AVD-related resource groups
    $avdRgNames = @(
        @($subData.HostPools              | ForEach-Object { $_.ResourceGroup }) +
        @($subData.Workspaces             | ForEach-Object { $_.ResourceGroup }) +
        @($subData.StorageAccounts        | ForEach-Object { $_.ResourceGroup }) +
        @($subData.LogAnalyticsWorkspaces | ForEach-Object { $_.ResourceGroup }) +
        @($subData.KeyVaults              | ForEach-Object { $_.ResourceGroup }) +
        @($subData.ComputeGalleries       | ForEach-Object { $_.ResourceGroup })
    ) | Where-Object { $_ } | Sort-Object -Unique
    $rgRoleAssignments = @{}
    foreach ($rgName in $avdRgNames) {
        $rgId = "/subscriptions/$subId/resourceGroups/$rgName"
        $rgRoleAssignments[$rgName] = @(Resolve-RoleAssignments -ResourceId $rgId)
    }
    $subData['RGRoleAssignments'] = $rgRoleAssignments

    # Batch-resolve all principal IDs via Microsoft Graph
    $allRAs = @(
        $subData['SubscriptionRoleAssignments'] +
        @($subData.HostPools              | ForEach-Object { $_.RoleAssignments }) +
        @($subData.Workspaces             | ForEach-Object { $_.RoleAssignments }) +
        @($subData.HostPools              | ForEach-Object { $_.ApplicationGroups } | ForEach-Object { $_.RoleAssignments }) +
        @($subData.StorageAccounts        | ForEach-Object { $_.RoleAssignments }) +
        @($subData.LogAnalyticsWorkspaces | ForEach-Object { $_.RoleAssignments }) +
        @($subData.KeyVaults              | ForEach-Object { $_.RoleAssignments }) +
        @($rgRoleAssignments.Values       | ForEach-Object { $_ })
    ) | Where-Object { $_ }

    $principalIds = @($allRAs | ForEach-Object { $_['PrincipalId'] } | Where-Object { $_ } | Sort-Object -Unique)
    if ($principalIds.Count -gt 0) {
        try {
            $graphTok = Get-ArmToken -ResourceUrl 'https://graph.microsoft.com/'
            $nameMap  = Get-GraphPrincipalNames -ObjectIds $principalIds -Token $graphTok
            foreach ($ra in $allRAs) {
                $principalId = $ra['PrincipalId']
                if ($principalId -and $nameMap.ContainsKey($principalId)) { $ra['DisplayName'] = $nameMap[$principalId] }
            }
            Write-DebugLog "Resolved $($nameMap.Count) principal names via Graph"
        }
        catch { Write-DebugLog "Graph principal resolution failed: $_" }
    }

    $report.Subscriptions.Add($subData)
}

#endregion

#region -- Networking ---------------------------------------------------------

Set-ReportStatus "Collecting networking data..." -Progress 93 -Sub ''

foreach ($subData in $report.Subscriptions) {
    $usedVnetIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Session host NICs -> subnet -> VNet
    foreach ($hp in $subData.HostPools) {
        foreach ($sh in $hp.SessionHosts) {
            if (-not $sh['NicId']) { continue }
            try {
                $nic = Get-ArmNetworkInterface -ResourceId $sh['NicId'] -Token $tok
                $subnetId = if ($nic -and $nic.PSObject.Properties['properties'] -and @($nic.properties.ipConfigurations).Count -gt 0) {
                    $nic.properties.ipConfigurations[0].properties.subnet.id
                } else { $null }
                if ($subnetId) { [void]$usedVnetIds.Add(($subnetId -split '/subnets/')[0]) }
            } catch { Write-DebugLog "  NIC resolve error $($sh.Name): $_" }
        }
    }

    # Known private endpoint IDs -> subnet -> VNet
    $allPeIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($hp in $subData.HostPools)       { @($hp['PrivateEndpointIds'])  | Where-Object { $_ } | ForEach-Object { [void]$allPeIds.Add($_) } }
    foreach ($ws in $subData.Workspaces)      { @($ws['PrivateEndpointIds'])  | Where-Object { $_ } | ForEach-Object { [void]$allPeIds.Add($_) } }
    foreach ($sa in $subData.StorageAccounts) { @($sa['PrivateEndpointIds'])  | Where-Object { $_ } | ForEach-Object { [void]$allPeIds.Add($_) } }
    foreach ($kv in $subData.KeyVaults)       { @($kv['PrivateEndpointIds'])  | Where-Object { $_ } | ForEach-Object { [void]$allPeIds.Add($_) } }

    foreach ($peId in $allPeIds) {
        try {
            $pe = Get-ArmPrivateEndpoint -ResourceId $peId -Token $tok
            $subnetId = if ($pe -and $pe.PSObject.Properties['properties'] -and $pe.properties.PSObject.Properties['subnet']) { $pe.properties.subnet.id } else { $null }
            if ($subnetId) { [void]$usedVnetIds.Add(($subnetId -split '/subnets/')[0]) }
        } catch { Write-DebugLog "  PE resolve error $peId`: $_" }
    }

    # Fetch referenced VNets
    $vnets = [System.Collections.Generic.List[object]]::new()
    foreach ($vnetId in $usedVnetIds) {
        try {
            $vnet = Get-ArmVirtualNetwork -ResourceId $vnetId -Token $tok
            if (-not $vnet) { continue }
            $vp = $vnet.properties
            $usages = Get-ArmVirtualNetworkUsages -ResourceId $vnetId -Token $tok
            $usageMap = @{}
            foreach ($u in $usages) {
                if ($u.PSObject.Properties['id']) {
                    $snName = $u.id.Split('/')[-1]
                    $usageMap[$snName] = $u
                }
            }
            $vnets.Add([ordered]@{
                Name          = $vnet.name
                ResourceGroup = Get-ResourceGroup $vnet.id
                Location      = $vnet.location
                AddressSpace  = @($vp.addressSpace.addressPrefixes)
                Subnets       = @($vp.subnets | ForEach-Object {
                    $addrPrefix = if ($_.properties.PSObject.Properties['addressPrefix'] -and $_.properties.addressPrefix) {
                        $_.properties.addressPrefix
                    } elseif ($_.properties.PSObject.Properties['addressPrefixes'] -and $_.properties.addressPrefixes) {
                        @($_.properties.addressPrefixes) -join ', '
                    } else { '' }
                    $u = $usageMap[$_.name]
                    $usedIps      = if ($u) { [int]$u.currentValue } else { $null }
                    $availableIps = if ($u) { [int]$u.limit - [int]$u.currentValue } else { $null }
                    [ordered]@{
                        Name          = $_.name
                        AddressPrefix = $addrPrefix
                        UsedIps       = $usedIps
                        AvailableIps  = $availableIps
                        NsgName       = if ($_.properties.PSObject.Properties['networkSecurityGroup'] -and $_.properties.networkSecurityGroup) { $_.properties.networkSecurityGroup.id.Split('/')[-1] } else { $null }
                    }
                })
                Tags          = if ($vnet.PSObject.Properties['tags']) { ConvertTo-TagHashtable $vnet.tags } else { [ordered]@{} }
            })
            Write-DebugLog "  VNet collected: $($vnet.name)"
        } catch { Write-DebugLog "  VNet fetch error $vnetId`: $_" }
    }
    $subData['VirtualNetworks'] = @($vnets)
    Write-DebugLog "Networking: $($vnets.Count) VNet(s) for $($subData.SubscriptionName)"
}

#region -- Save JSON ----------------------------------------------------------

Set-ReportStatus "Saving data to JSON..." -Progress 97 -Sub ''

$timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$filePrefix = if ($CollectCustomerName) {
    $CollectCustomerName -replace '[^A-Za-z0-9\-]', '_'
} else {
    ($report.Subscriptions | ForEach-Object { $_.SubscriptionName -replace '[^A-Za-z0-9\-]', '_' }) -join '_'
}
$encrypt    = ($EncryptPassword -and $EncryptPassword.Length -gt 0)
$jsonPath   = Join-Path $OutputPath ("$filePrefix-AVD-Data-$timestamp." + $(if ($encrypt) { 'cdenc' } else { 'json' }))
$json = $report | ConvertTo-Json -Depth 20
if ($encrypt) { $json = Protect-ReportData $json $EncryptPassword }
[System.IO.File]::WriteAllText($jsonPath, $json, [System.Text.Encoding]::UTF8)

Write-DebugLog "Data collection complete. JSON saved: $jsonPath"

Set-ReportStatus "Data collection complete!" -Progress 100 -Sub ''
Start-Sleep -Milliseconds 600
Close-Splash

Show-MsgBox "Data collection complete.`n`nJSON file saved to:`n$jsonPath`n`nRun Get-AVDReport.ps1 with this file to generate HTML and/or Word reports." -Title 'AVD Data Collector' -Icon 'Info'

}
catch {
    try {
        Close-Splash
    } catch {}

    $errMsg  = $_.Exception.Message
    $errLine = $_.InvocationInfo.ScriptLineNumber
    Write-Host "ERROR at line $errLine`: $errMsg" -ForegroundColor Red
    Show-MsgBox "An error occurred during data collection.`n`nLine $errLine`: $errMsg" -Title 'AVD Data Collector Error' -Icon 'Error'
}

#endregion

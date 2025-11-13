<#
.SYNOPSIS
  VMware Tools version compliance sensor with version-distance check, PS 5.1-safe.

.DESCRIPTION
  Überwacht VMware Tools-Versionen und vergleicht sie mit der offiziellen Baseline.
  
  Hauptfunktionen:
  - Automatische Versionserkennung (Registry + Executable)
  - Baseline-Abgleich mit vTracker API
  - Versionsabstand-Berechnung (wie viele Releases zurück)
  - Exchange-spezifische Sicherheitsrichtlinien
  - Altersberechnung basierend auf lokaler Version
  - Kontextabhängige Ausgabe (PRTG XML, JSON, Text, Farbig)

  Status-Logik:
  - 0-1 Versionen zurück = OK
  - 2 Versionen zurück = Warnung
  - 3+ Versionen zurück = Fehler
  - Nicht gefunden/Policy-Fail = Kritisch

.PARAMETER Mode
  Ausgabemodus: xml | legacy | text | json | auto (Standard: auto)
  
  auto   = Automatische Erkennung (PRTG → xml, Interaktiv → ansi, Sonst → text)
  xml    = PRTG XML-Format
  legacy = Einzeilen-Format (kompatibel mit alten Sensoren)
  text   = Mehrzeiliger Textbericht
  json   = JSON-Format für API/Automatisierung
  ansi   = Farbige Konsolenausgabe (nur interaktiv)

.PARAMETER WarningThreshold
  Anzahl Versionen zurück für Warnung (Standard: 2)

.PARAMETER ErrorThreshold
  Anzahl Versionen zurück für Fehler (Standard: 3)

.PARAMETER TimeoutSec
  Timeout für vTracker API-Anfragen in Sekunden (Standard: 10)

.EXAMPLE
  .\VMwareTools-ComplianceSensor.ps1
  Standard-Ausführung mit Auto-Erkennung (PRTG = XML, Konsole = farbig)

.EXAMPLE
  .\VMwareTools-ComplianceSensor.ps1 -Mode json
  JSON-Ausgabe für Automatisierung/API-Konsum

.EXAMPLE
  .\VMwareTools-ComplianceSensor.ps1 -WarningThreshold 3 -ErrorThreshold 5
  Benutzerdefinierte Schwellwerte (toleranter)

.EXAMPLE
  Invoke-Command -ComputerName Server01 -FilePath .\VMwareTools-ComplianceSensor.ps1 -ArgumentList @('-Mode', 'json')
  Remote-Ausführung über PowerShell Remoting

.NOTES
  Autor: Enterprise VMware Monitoring Team
  Version: 2.0
  Kompatibilität: PowerShell 5.1+, Windows Server 2012 R2+
  
  PRTG-Integration:
  - Sensor-Typ: "EXE/Script Advanced"
  - 64-Bit PowerShell aktivieren
  - Sicherheitskontext: Windows-Anmeldedaten des Geräts
  
  Fehlerbehandlung:
  - vTracker API nicht erreichbar → Fallback-Baseline
  - VMware Tools nicht gefunden → Kritischer Status
  - Registry-Umleitung → Explizite 64-Bit Registry-Prüfung

.LINK
  https://www.virten.net/repo/vTracker.json
  https://docs.vmware.com/en/VMware-Tools/
#>

[CmdletBinding()]
param(
  [ValidateSet('xml','legacy','text','json','ansi','auto')]
  [string]$Mode = 'auto',
  
  [string]$MinMajor = '12.5.0',
  
  [int]$TimeoutSec = 10,
  
  [int]$WarningThreshold = 2,
  
  [int]$ErrorThreshold = 3
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ============================================================================
# CONTEXT DETECTION
# ============================================================================

function Is-PrtgContext { 
    return [bool]$env:PRTG_HOST 
}

function Is-InteractiveShell {
    return [Environment]::UserInteractive -and 
           -not (Is-PrtgContext) -and
           -not $env:TERM_PROGRAM -and
           $Host.Name -notmatch 'ServerRemoteHost'
}

function Get-ExecutionContext {
    if (Is-PrtgContext) { return 'PRTG' }
    if (Is-InteractiveShell) { return 'Interactive' }
    return 'Automated'
}

# Auto-detect mode based on context
if ($Mode -eq 'auto') {
    $context = Get-ExecutionContext
    $Mode = switch ($context) {
        'PRTG'        { 'xml' }
        'Interactive' { 'ansi' }
        'Automated'   { 'text' }
    }
    Write-Verbose "Auto-detected context: $context → Mode: $Mode"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function NN([string]$v, [string]$fallback){
    if ($v) { return $v } else { return $fallback }
}

# ============================================================================
# LOCAL VERSION DETECTION (ENHANCED, PS5.1-SAFE, BYPASSES REDIRECTION)
# ============================================================================

function Get-LocalToolsVersion {
    Write-Verbose "Detecting local VMware Tools version..."
    
    # 1) Try vmtoolsd -v (most reliable when present)
    try {
        $vmtoolsd = "${env:ProgramFiles}\VMware\VMware Tools\vmtoolsd.exe"
        if (-not (Test-Path $vmtoolsd)) {
            $vmtoolsd32 = "${env:ProgramFiles(x86)}\VMware\VMware Tools\vmtoolsd.exe"
            if (Test-Path $vmtoolsd32) { $vmtoolsd = $vmtoolsd32 }
        }
        
        if (Test-Path $vmtoolsd) {
            Write-Verbose "Found vmtoolsd.exe at: $vmtoolsd"
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $vmtoolsd
            $psi.Arguments = "-v"
            $psi.RedirectStandardOutput = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.WindowStyle = 'Hidden'
            
            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $psi
            [void]$proc.Start()
            
            if ($proc.WaitForExit(5000)) {
                $out = $proc.StandardOutput.ReadToEnd()
                if ($out) {
                    $m = [regex]::Match($out, '(\d+\.\d+\.\d+(\.\d+)?)')
                    if ($m.Success) { 
                        Write-Verbose "Version from vmtoolsd.exe: $($m.Groups[1].Value)"
                        return $m.Groups[1].Value 
                    }
                }
            }
        }
    } catch { 
        Write-Verbose "vmtoolsd.exe detection failed: $_"
    }

    # 2) Read 64-bit registry explicitly (bypass 32-bit redirection)
    try {
        Write-Verbose "Trying 64-bit registry..."
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        $subKey = $baseKey.OpenSubKey("SOFTWARE\VMware, Inc.\VMware Tools")
        if ($subKey) {
            $ver = $subKey.GetValue("Version")
            $subKey.Close()
            $baseKey.Close()
            if ($ver) { 
                Write-Verbose "Version from 64-bit registry: $ver"
                return ($ver.ToString().Trim()) 
            }
        }
    } catch { 
        Write-Verbose "64-bit registry detection failed: $_"
    }

    # 3) WOW6432Node fallback (if Tools registered as 32-bit)
    try {
        Write-Verbose "Trying 32-bit registry (WOW6432Node)..."
        $baseKey32 = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry32
        )
        $subKey32 = $baseKey32.OpenSubKey("SOFTWARE\VMware, Inc.\VMware Tools")
        if ($subKey32) {
            $ver32 = $subKey32.GetValue("Version")
            $subKey32.Close()
            $baseKey32.Close()
            if ($ver32) { 
                Write-Verbose "Version from 32-bit registry: $ver32"
                return ($ver32.ToString().Trim()) 
            }
        }
    } catch { 
        Write-Verbose "32-bit registry detection failed: $_"
    }

    # 4) File version of vmtoolsd.exe
    try {
        Write-Verbose "Trying file version..."
        foreach ($path in @(
            "${env:ProgramFiles}\VMware\VMware Tools\vmtoolsd.exe",
            "${env:ProgramFiles(x86)}\VMware\VMware Tools\vmtoolsd.exe"
        )) {
            if (Test-Path $path) {
                $fv = (Get-Item $path).VersionInfo.ProductVersion
                if ($fv) { 
                    Write-Verbose "Version from file: $fv"
                    return $fv.Trim() 
                }
            }
        }
    } catch { 
        Write-Verbose "File version detection failed: $_"
    }

    Write-Verbose "No VMware Tools version detected"
    return $null
}

# ============================================================================
# VTRACKER BASELINE WITH FALLBACK
# ============================================================================

# Replace the Get-BaselineFromVTracker function with this:

function Get-BaselineFromVTracker {
    $url = 'https://www.virten.net/repo/vTracker.json'
    Write-Verbose "Fetching baseline from vTracker: $url"
    
    try {
        $list = Invoke-RestMethod -Uri $url -TimeoutSec $TimeoutSec
        $tools = $list.data.vTracker | Where-Object { $_.product -like 'VMware Tools*' }
        $tools = $tools | Sort-Object { [datetime]$_.releaseDate } -Descending
        
        if ($tools -and $tools.Count -gt 0) {
            Write-Verbose "Retrieved $($tools.Count) VMware Tools releases from vTracker"
            return $tools
        }
    } catch { 
        Write-Verbose "vTracker API unavailable: $_"
    }
    
    # UPDATED Fallback baseline - VMware Tools 13.0.5.0 from September 2025
    Write-Warning "vTracker API not reachable - using static fallback baseline (VMware Tools 13.0.5.0)"
    return @([pscustomobject]@{
        product = 'VMware Tools 13.0.5.0'
        releaseDate = '2025-09-29'
    })
}

# ============================================================================
# VERSION COMPARISON (NORMALIZED TO 3-OCTET)
# ============================================================================

function Get-VersionDistance {
    param($officialList, $localVersion)
    
    if (-not $localVersion) { return -1 }
    
    # Extract and normalize to 3 octets (major.minor.patch)
    $localMatch = [regex]::Match($localVersion, '(\d+)\.(\d+)\.(\d+)')
    if (-not $localMatch.Success) { return -1 }
    
    $localNormalized = "{0}.{1}.{2}" -f $localMatch.Groups[1].Value, $localMatch.Groups[2].Value, $localMatch.Groups[3].Value
    Write-Verbose "Normalized local version: $localNormalized"
    
    # Build normalized baseline list (3-octet versions only)
    $normalizedVersions = @()
    foreach ($item in $officialList) {
        $match = [regex]::Match($item.product, '(\d+)\.(\d+)\.(\d+)')
        if ($match.Success) {
            $normalized = "{0}.{1}.{2}" -f $match.Groups[1].Value, $match.Groups[2].Value, $match.Groups[3].Value
            $normalizedVersions += $normalized
        }
    }
    
    # Find index (distance)
    $idx = $normalizedVersions.IndexOf($localNormalized)
    Write-Verbose "Version distance: $idx (0=latest, -1=not found)"
    
    # If not found, check if we're ahead of baseline (newer than latest)
    if ($idx -eq -1 -and $normalizedVersions.Count -gt 0) {
        try {
            $localVer = [version]$localNormalized
            $baselineVer = [version]$normalizedVersions[0]
            
            # If local is newer than latest baseline, treat as OK (distance 0)
            if ($localVer -gt $baselineVer) {
                Write-Verbose "Local version is newer than baseline - treating as OK"
                return 0
            }
        } catch { }
    }
    
    return $idx
}

# ============================================================================
# EXCHANGE DETECTION
# ============================================================================

function Detect-Exchange {
    Write-Verbose "Detecting Exchange Server installation..."
    
    # Check services
    try {
        $svc = Get-Service -Name 'MSExchangeIS','MSExchangeTransport','MSExchangeFrontEndTransport','MSExchangeADTopology' -ErrorAction SilentlyContinue
        if ($svc -and ($svc | Where-Object { $_.Status -ne $null }).Count -gt 0) { 
            Write-Verbose "Exchange detected via services"
            return $true 
        }
    } catch { }
    
    # Check registry
    try {
        $uninst = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        $x = Get-ChildItem $uninst -ErrorAction SilentlyContinue |
             ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
             Where-Object { $_.DisplayName -match 'Microsoft Exchange' }
        if ($x) { 
            Write-Verbose "Exchange detected via registry"
            return $true 
        }
    } catch { }
    
    Write-Verbose "No Exchange Server detected"
    return $false
}

# ============================================================================
# MAIN DETECTION LOGIC
# ============================================================================

Write-Verbose "=== VMware Tools Compliance Check Started ==="

# 1. Local version
$local = Get-LocalToolsVersion

# 2. Official VMware Tools releases (latest-first)
$toolsList = Get-BaselineFromVTracker
$latest = $toolsList | Select-Object -First 1

# 3. Version distance calculation
$distance = if ($local) { Get-VersionDistance $toolsList $local } else { -1 }

# 4. Age calculation - LOCAL version release date (not baseline!)
$localReleaseDate = $null
if ($local) {
    $localMatch = [regex]::Match($local, '(\d+)\.(\d+)\.(\d+)')
    if ($localMatch.Success) {
        $localNormalized = "{0}.{1}.{2}" -f $localMatch.Groups[1].Value, $localMatch.Groups[2].Value, $localMatch.Groups[3].Value
        
        $localVersionInfo = $toolsList | Where-Object {
            $itemMatch = [regex]::Match($_.product, '(\d+)\.(\d+)\.(\d+)')
            if ($itemMatch.Success) {
                $itemNormalized = "{0}.{1}.{2}" -f $itemMatch.Groups[1].Value, $itemMatch.Groups[2].Value, $itemMatch.Groups[3].Value
                return $itemNormalized -eq $localNormalized
            }
            return $false
        } | Select-Object -First 1
        
        if ($localVersionInfo -and $localVersionInfo.releaseDate) {
            try {
                $localReleaseDate = [datetime]$localVersionInfo.releaseDate
                Write-Verbose "Local version released: $($localReleaseDate.ToString('yyyy-MM-dd'))"
            } catch { }
        }
    }
}

$ageDays = if ($localReleaseDate) { 
    [int]([datetime]::UtcNow - $localReleaseDate.ToUniversalTime()).TotalDays 
} else { 
    $null 
}

# Baseline release date (for reference)
$baselineReleaseDate = $null
if ($latest -and $latest.releaseDate) {
    try {
        $baselineReleaseDate = [datetime]$latest.releaseDate
    } catch { }
}

# 5. Policy check (Exchange-aware)
$MinSafeVersion_General  = '12.5.0'
$MinSafeVersion_Exchange = '12.5.1'
$exchange = Detect-Exchange
$minSafe  = if ($exchange) { $MinSafeVersion_Exchange } else { $MinSafeVersion_General }

Write-Verbose "Minimum safe version: $minSafe (Exchange: $exchange)"

$cmpSafe = if ($local) { 
    try {
        $localMatch = [regex]::Match($local, '(\d+)\.(\d+)\.(\d+)')
        if ($localMatch.Success) {
            $localClean = "{0}.{1}.{2}" -f $localMatch.Groups[1].Value, $localMatch.Groups[2].Value, $localMatch.Groups[3].Value
            ([version]$localClean).CompareTo([version]$minSafe)
        } else {
            $null
        }
    } catch {
        $null
    }
} else { 
    $null 
}

# 6. Determine state (priority: Policy > Distance)
$SecurityState = 0
$State = 0
$statetxt = ''

if (-not $local) {
    $State = 3
    $SecurityState = 2
    $statetxt = 'VMware Tools not installed / unreadable'
}
elseif ($cmpSafe -ne $null -and $cmpSafe -lt 0) {
    # Policy violation takes precedence
    $State = 3
    $SecurityState = 2
    $statetxt = "Policy fail ($local < $minSafe)"
}
elseif ($distance -eq -1) {
    # Unknown version (not in baseline, but passed policy)
    $State = 1
    $SecurityState = 1
    $statetxt = "Warning: Version $local not in baseline list (may be very old or custom build)"
}
elseif ($distance -eq 0) {
    $State = 0
    $SecurityState = 0
    $statetxt = "OK (Latest version: $local)"
}
elseif ($distance -eq 1) {
    $State = 0
    $SecurityState = 0
    $statetxt = "OK (1 version behind: $local)"
}
elseif ($distance -lt $ErrorThreshold) {
    $State = 1
    $SecurityState = 1
    $statetxt = "Warning ($distance versions behind: $local)"
}
else {
    $State = 2
    $SecurityState = 2
    $statetxt = "Error ($distance versions behind: $local)"
}

Write-Verbose "Final state: $State ($statetxt)"

# 7. Build result object
$result = [pscustomobject]@{
    LocalVersion        = $local
    BaselineVersion     = if ($latest -and $latest.product) { 
        [regex]::Match($latest.product, '\d+\.\d+\.\d+(\.\d+)?').Value 
    } else { 
        $null 
    }
    LocalReleaseDate    = if ($localReleaseDate) { 
        $localReleaseDate.ToString('yyyy-MM-dd') 
    } else { 
        $null 
    }
    BaselineReleaseDate = if ($baselineReleaseDate) { 
        $baselineReleaseDate.ToString('yyyy-MM-dd') 
    } else { 
        $null 
    }
    AgeDays             = $ageDays
    ExchangeDetected    = [bool]$exchange
    SecurityState       = [int]$SecurityState
    State               = [int]$State
    Message             = $statetxt
    BaselineSource      = 'vTracker'
    MinSafeApplied      = $minSafe
    VersionsBehind      = $distance
}

# ============================================================================
# OUTPUT RENDERERS
# ============================================================================

function Render-Xml([object]$r){
    $xml  = New-Object System.Xml.XmlDocument
    $prtg = $xml.CreateElement('prtg')
    [void]$xml.AppendChild($prtg)
    
    function Add-TextChannel([string]$ch, [string]$txt){
        $res = $xml.CreateElement('result')
        $e = $xml.CreateElement('channel');   $e.InnerText = $ch;  [void]$res.AppendChild($e)
        $e = $xml.CreateElement('value');     $e.InnerText = '1';  [void]$res.AppendChild($e)
        $e = $xml.CreateElement('text');      $e.InnerText = $txt; [void]$res.AppendChild($e)
        $e = $xml.CreateElement('showchart'); $e.InnerText = '0';  [void]$res.AppendChild($e)
        $e = $xml.CreateElement('showtable'); $e.InnerText = '1';  [void]$res.AppendChild($e)
        [void]$prtg.AppendChild($res)
    }
    
    function Add-NumChannel([string]$ch, [string]$val, [switch]$WithLimits){
        $res = $xml.CreateElement('result')
        $e = $xml.CreateElement('channel');   $e.InnerText = $ch;  [void]$res.AppendChild($e)
        $e = $xml.CreateElement('value');     $e.InnerText = $val; [void]$res.AppendChild($e)
        $e = $xml.CreateElement('showchart'); $e.InnerText = '1';  [void]$res.AppendChild($e)
        $e = $xml.CreateElement('showtable'); $e.InnerText = '1';  [void]$res.AppendChild($e)
        if ($WithLimits){
            $e = $xml.CreateElement('LimitMode');       $e.InnerText = '1'; [void]$res.AppendChild($e)
            $e = $xml.CreateElement('LimitMaxWarning'); $e.InnerText = '0'; [void]$res.AppendChild($e)
            $e = $xml.CreateElement('LimitMaxError');   $e.InnerText = '0'; [void]$res.AppendChild($e)
        }
        [void]$prtg.AppendChild($res)
    }
    
    Add-TextChannel 'LocalVersion'       ("Local {0}"       -f (NN $r.LocalVersion  'n/a'))
    Add-TextChannel 'LocalReleaseDate'   ("Released {0}"    -f (NN $r.LocalReleaseDate 'n/a'))
    Add-TextChannel 'BaselineVersion'    ("Baseline {0}"    -f (NN $r.BaselineVersion 'n/a'))
    Add-TextChannel 'BaselineReleaseDate'("BaselineRel {0}" -f (NN $r.BaselineReleaseDate 'n/a'))
    Add-NumChannel  'AgeDays'            (NN $r.AgeDays '0')
    Add-NumChannel  'ExchangeDetected'   ([int]$r.ExchangeDetected)
    Add-NumChannel  'SecurityState'      $r.SecurityState -WithLimits
    Add-NumChannel  'State'              $r.State         -WithLimits
    Add-NumChannel  'VersionsBehind'     (NN $r.VersionsBehind '-1')
    
    $t = $xml.CreateElement('text')
    $t.InnerText = (NN $r.Message '')
    [void]$prtg.AppendChild($t)
    
    return $xml.OuterXml
}

function Render-Legacy([object]$r){
    $line = ("{0}:Local={1}; LocalRel={2}; Baseline={3}; BaselineRel={4}; AgeDays={5}; Exchange={6}; SecState={7}; VersionsBehind={8}; {9}" -f `
        $r.State,
        (NN $r.LocalVersion 'n/a'),
        (NN $r.LocalReleaseDate 'n/a'),
        (NN $r.BaselineVersion 'n/a'),
        (NN $r.BaselineReleaseDate 'n/a'),
        (NN $r.AgeDays 'n/a'),
        [int]$r.ExchangeDetected,
        $r.SecurityState,
        (NN $r.VersionsBehind '-1'),
        (NN $r.Message '')
    )
    Write-Output $line
}

function Render-Text([object]$r){
    $text = @"
VMware Tools Baseline Report
----------------------------
Local Version        : $(NN $r.LocalVersion 'n/a')
Local Release Date   : $(NN $r.LocalReleaseDate 'n/a')
Baseline Version     : $(NN $r.BaselineVersion 'n/a')  (source: $(NN $r.BaselineSource 'n/a'))
Baseline Release     : $(NN $r.BaselineReleaseDate 'n/a')
Age (days)           : $(NN $r.AgeDays 'n/a')
Exchange Detected    : $($r.ExchangeDetected)
Min Safe Applied     : $(NN $r.MinSafeApplied 'n/a')
Versions Behind      : $(NN $r.VersionsBehind '-1')

Security State       : $($r.SecurityState)   (0=OK,1=Warn,2=Error)
Overall State        : $($r.State)           (0=OK,1=Warn,2=Error,3=PolicyFail/Unknown)

Message              : $(NN $r.Message '')
"@
    Write-Output $text
}

function Render-Json([object]$r){
    $r | ConvertTo-Json -Depth 4
}

function Render-Ansi([object]$r) {
    # State color logic
    $stateColor = switch ($r.State) {
        0 { 'Green' }
        1 { 'Yellow' }
        2 { 'Red' }
        3 { 'White' }
        default { 'Gray' }
    }
    $stateBg = if ($r.State -eq 3) { 'Red' } else { $null }
    
    # Age color logic (months-based)
    $ageColor = 'Green'
    $ageBg = $null
    if ($r.AgeDays -ne $null) {
        $months = [math]::Floor($r.AgeDays / 30)
        if ($months -ge 8) {
            $ageColor = 'Yellow'
            $ageBg = 'Red'
        }
        elseif ($months -ge 5) {
            $ageColor = 'Black'
            $ageBg = 'Yellow'
        }
        elseif ($months -ge 3) {
            $ageColor = 'Yellow'
        }
    }
    
    # Versions behind color
    $versionsBehindColor = 'Gray'
    if ($r.VersionsBehind -ne $null -and $r.VersionsBehind -ge 0) {
        $versionsBehindColor = switch ($r.VersionsBehind) {
            {$_ -le 1} { 'Green' }
            {$_ -eq 2} { 'Yellow' }
            {$_ -ge 3} { 'Red' }
            default { 'Gray' }
        }
    }
    
    # Security state color
    $secStateColor = switch ($r.SecurityState) {
        0 { 'Green' }
        1 { 'Yellow' }
        2 { 'Red' }
        default { 'Gray' }
    }
    
    # Header
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  " -NoNewline -ForegroundColor Cyan
    Write-Host "VMware Tools Compliance Report" -NoNewline -ForegroundColor White
    Write-Host "                          ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Data rows (nested function)
    function Write-DataRow([string]$label, $value, [string]$color = 'White', [string]$bg = $null) {
        $paddedLabel = $label.PadRight(21)
        $valueStr = if ($value -ne $null) { $value.ToString() } else { 'n/a' }
        Write-Host "  " -NoNewline
        Write-Host $paddedLabel -NoNewline -ForegroundColor Gray
        Write-Host ": " -NoNewline
        if ($bg) {
            Write-Host $valueStr -ForegroundColor $color -BackgroundColor $bg
        } else {
            Write-Host $valueStr -ForegroundColor $color
        }
    }
    
    Write-DataRow "Local Version" (NN $r.LocalVersion 'n/a') 'White'
    Write-DataRow "Local Release Date" (NN $r.LocalReleaseDate 'n/a') 'DarkGray'
    Write-DataRow "Baseline Version" (NN $r.BaselineVersion 'n/a') 'Magenta'
    Write-DataRow "Baseline Release" (NN $r.BaselineReleaseDate 'n/a') 'DarkMagenta'
    Write-DataRow "Age (days)" (NN $r.AgeDays 'n/a') $ageColor $ageBg
    Write-DataRow "Versions Behind" (NN $r.VersionsBehind 'n/a') $versionsBehindColor
    Write-DataRow "Exchange Detected" $r.ExchangeDetected 'White'
    Write-DataRow "Min Safe Applied" (NN $r.MinSafeApplied 'n/a') 'White'
    Write-Host ""
    Write-DataRow "Security State" $r.SecurityState $secStateColor
    Write-DataRow "Overall State" $r.State $stateColor $stateBg
    Write-Host ""
    
    # Status message
    Write-Host "  " -NoNewline
    Write-Host "Status Message" -ForegroundColor Gray
    Write-Host "  " -NoNewline
    if ($stateBg) {
        Write-Host $r.Message -ForegroundColor $stateColor -BackgroundColor $stateBg
    } else {
        Write-Host $r.Message -ForegroundColor $stateColor
    }
    Write-Host ""
    
    # Legend
    Write-Host "Legend:" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host "●" -NoNewline -ForegroundColor Green
    Write-Host " OK (0)      " -NoNewline
    Write-Host "●" -NoNewline -ForegroundColor Yellow
    Write-Host " Warning (1)      " -NoNewline
    Write-Host "●" -NoNewline -ForegroundColor Red
    Write-Host " Error (2)      " -NoNewline
    Write-Host "●" -NoNewline -ForegroundColor White -BackgroundColor Red
    Write-Host " Critical (3)"
    Write-Host ""
}

# ============================================================================
# OUTPUT ROUTING
# ============================================================================

if ($Mode -eq 'legacy') {
    Render-Legacy $result
    if (Is-PrtgContext) { exit 0 }
}
elseif ($Mode -eq 'text') {
    Render-Text $result
    if (Is-PrtgContext) { exit 0 }
}
elseif ($Mode -eq 'json') {
    Render-Json $result
    if (Is-PrtgContext) { exit 0 }
}
elseif ($Mode -eq 'ansi') {
    Render-Ansi $result
}
else {
    # XML mode (PRTG)
    Write-Output (Render-Xml $result)
    if (Is-PrtgContext) { exit 0 }
}

Write-Verbose "=== VMware Tools Compliance Check Completed ==="
<#
.SYNOPSIS
  VMware Tools version compliance sensor with dual-branch architecture support.

.DESCRIPTION
  Monitors VMware Tools versions with branch-aware comparison logic.
  
  Branch Strategy:
  - 13.x branch → ESXi 8.x (recommended)
  - 12.x branch → ESXi 7.x/6.x (supported)
  - Both branches maintained in parallel (as of Q4 2025)
  - 11.x and older → End-of-Life (critical)

  Status Logic:
  - Within branch: 0-1 versions behind = OK, 2+ = Warning/Error
  - Cross-branch: No distance calculation (separate lifecycles)
  - EOL branches (11.x-): Always critical

.PARAMETER Mode
  Output mode: xml | legacy | text | json | ansi | auto (Default: auto)

.PARAMETER WarningThreshold
  Versions behind within branch for warning (Default: 2)

.PARAMETER ErrorThreshold
  Versions behind within branch for error (Default: 4)

.PARAMETER StrictBranchPolicy
  If enabled, 12.x branch generates warning on ESXi 8.x environments (Default: $false)

.NOTES
  Version: 4.0 - Dual-Branch Architecture
  Author: Enterprise VMware Monitoring Team
  
  ESXi Compatibility Matrix:
  - ESXi 8.x → VMware Tools 13.x (recommended)
  - ESXi 7.x → VMware Tools 12.x or 13.x (both supported)
  - ESXi 6.x → VMware Tools 12.x (recommended)

.EXAMPLE
  .\VMwareTools-ComplianceSensor-DualBranch.ps1
  Standard execution with auto-detection

.EXAMPLE
  .\VMwareTools-ComplianceSensor-DualBranch.ps1 -StrictBranchPolicy
  Enforce 13.x branch for ESXi 8.x environments
#>

[CmdletBinding()]
param(
  [ValidateSet('xml','legacy','text','json','ansi','auto')]
  [string]$Mode = 'auto',
  
  [int]$TimeoutSec = 10,
  
  [int]$WarningThreshold = 2,
  
  [int]$ErrorThreshold = 4,
  
  [switch]$StrictBranchPolicy = $false
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ============================================================================
# DUAL-BRANCH POLICY CONFIGURATION
# ============================================================================

# Both branches actively maintained (Q4 2025)
$BranchPolicy = @{
    '13' = @{
        Name = '13.x'
        MinVersion = '13.0.5'
        MinVersionSoft = '13.0.0'
        ESXiTarget = '8.x'
        Status = 'Active'
    }
    '12' = @{
        Name = '12.x'
        MinVersion = '12.5.4'
        MinVersionSoft = '12.5.0'
        ESXiTarget = '7.x/6.x'
        Status = 'Active'
    }
    'EOL' = @{
        Threshold = 11  # 11.x and older
        Status = 'End-of-Life'
    }
}

# Exchange-specific (same requirements as general)
$ExchangeMinVersions = @{
    '13' = '13.0.5'
    '12' = '12.5.4'
}

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

function Parse-VersionString([string]$versionString) {
    $match = [regex]::Match($versionString, '(\d+)\.(\d+)\.(\d+)')
    if ($match.Success) {
        return @{
            Major = [int]$match.Groups[1].Value
            Minor = [int]$match.Groups[2].Value
            Patch = [int]$match.Groups[3].Value
            Normalized = "{0}.{1}.{2}" -f $match.Groups[1].Value, $match.Groups[2].Value, $match.Groups[3].Value
            Branch = "{0}.x" -f $match.Groups[1].Value
            IsValid = $true
        }
    }
    return @{ IsValid = $false }
}

# ============================================================================
# LOCAL VERSION DETECTION
# ============================================================================

function Get-LocalToolsVersion {
    Write-Verbose "Detecting local VMware Tools version..."
    
    # Method 1: vmtoolsd.exe -v
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

    # Method 2: 64-bit registry
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

    # Method 3: 32-bit registry
    try {
        Write-Verbose "Trying 32-bit registry..."
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

    # Method 4: File version
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
# VTRACKER BASELINE
# ============================================================================

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
    
    # Fallback: Both active branches
    Write-Warning "vTracker API not reachable - using static fallback baseline (dual-branch)"
    return @(
        [pscustomobject]@{
            product = 'VMware Tools 13.0.5.0'
            releaseDate = '2025-09-29'
        },
        [pscustomobject]@{
            product = 'VMware Tools 12.5.4'
            releaseDate = '2025-09-29'
        }
    )
}

# ============================================================================
# BRANCH-AWARE FILTERING
# ============================================================================

function Get-BranchFilteredList {
    param(
        [array]$fullList,
        [int]$majorVersion
    )
    
    if (-not $fullList -or $fullList.Count -eq 0) {
        Write-Verbose "No baseline list provided"
        return @()
    }
    
    Write-Verbose "Filtering baseline for branch $majorVersion.x"
    
    $filtered = @()
    foreach ($item in $fullList) {
        $parsed = Parse-VersionString $item.product
        if ($parsed.IsValid -and $parsed.Major -eq $majorVersion) {
            $filtered += $item
        }
    }
    
    Write-Verbose "Found $($filtered.Count) releases in $majorVersion.x branch"
    return $filtered
}

# ============================================================================
# VERSION DISTANCE (BRANCH-AWARE)
# ============================================================================

function Get-VersionDistance {
    param(
        [array]$branchList,
        [string]$localVersion
    )
    
    if (-not $localVersion) { return -1 }
    
    $localParsed = Parse-VersionString $localVersion
    if (-not $localParsed.IsValid) {
        Write-Verbose "Could not parse local version: $localVersion"
        return -1
    }
    
    Write-Verbose "Calculating distance for: $($localParsed.Normalized) within branch"
    
    # Build normalized version list from branch
    $normalizedVersions = @()
    foreach ($item in $branchList) {
        $parsed = Parse-VersionString $item.product
        if ($parsed.IsValid) {
            $normalizedVersions += $parsed.Normalized
        }
    }
    
    if ($normalizedVersions.Count -eq 0) {
        Write-Verbose "No versions found in branch for comparison"
        return -1
    }
    
    # Find index (0 = latest within branch)
    $idx = $normalizedVersions.IndexOf($localParsed.Normalized)
    Write-Verbose "Version distance within branch: $idx (0=latest, -1=not found)"
    
    # Check if ahead of baseline (newer than latest in branch)
    if ($idx -eq -1) {
        try {
            $localVer = [version]$localParsed.Normalized
            $branchLatestVer = [version]$normalizedVersions[0]
            
            if ($localVer -gt $branchLatestVer) {
                Write-Verbose "Local version is newer than branch baseline"
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
    
    try {
        $svc = Get-Service -Name 'MSExchangeIS','MSExchangeTransport','MSExchangeFrontEndTransport','MSExchangeADTopology' -ErrorAction SilentlyContinue
        if ($svc -and ($svc | Where-Object { $_.Status -ne $null }).Count -gt 0) { 
            Write-Verbose "Exchange detected via services"
            return $true 
        }
    } catch { }
    
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

Write-Verbose "=== VMware Tools Compliance Check Started (Dual-Branch Architecture) ==="

# 1. Local version detection
$local = Get-LocalToolsVersion
$localParsed = if ($local) { Parse-VersionString $local } else { @{ IsValid = $false } }

# 2. Full baseline from vTracker
$fullBaseline = Get-BaselineFromVTracker

# 3. Branch-specific filtering
$branchList = if ($localParsed.IsValid) {
    Get-BranchFilteredList -fullList $fullBaseline -majorVersion $localParsed.Major
} else {
    $fullBaseline
}

$latestInBranch = $branchList | Select-Object -First 1

# 4. Version distance (within branch)
$distance = if ($localParsed.IsValid) {
    Get-VersionDistance -branchList $branchList -localVersion $local
} else {
    -1
}

# 5. Age calculation (local version release date)
$localReleaseDate = $null
if ($localParsed.IsValid) {
    $localVersionInfo = $branchList | Where-Object {
        $itemParsed = Parse-VersionString $_.product
        $itemParsed.IsValid -and $itemParsed.Normalized -eq $localParsed.Normalized
    } | Select-Object -First 1
    
    if ($localVersionInfo -and $localVersionInfo.releaseDate) {
        try {
            $localReleaseDate = [datetime]$localVersionInfo.releaseDate
            Write-Verbose "Local version released: $($localReleaseDate.ToString('yyyy-MM-dd'))"
        } catch { }
    }
}

$ageDays = if ($localReleaseDate) { 
    [int]([datetime]::UtcNow - $localReleaseDate.ToUniversalTime()).TotalDays 
} else { 
    $null 
}

# Baseline release date
$baselineReleaseDate = $null
if ($latestInBranch -and $latestInBranch.releaseDate) {
    try {
        $baselineReleaseDate = [datetime]$latestInBranch.releaseDate
    } catch { }
}

# 6. Policy evaluation (branch-aware)
$exchange = Detect-Exchange
$isEOL = $localParsed.IsValid -and $localParsed.Major -le $BranchPolicy.EOL.Threshold
$branchInfo = if ($localParsed.IsValid) { $BranchPolicy["$($localParsed.Major)"] } else { $null }

$minSafe = $null
$minSafeSoft = $null
$BranchRecommendation = ''

if ($localParsed.IsValid -and $branchInfo) {
    $minSafe = if ($exchange) { 
        $ExchangeMinVersions["$($localParsed.Major)"] 
    } else { 
        $branchInfo.MinVersion 
    }
    $minSafeSoft = $branchInfo.MinVersionSoft
    
    Write-Verbose "Branch: $($localParsed.Branch), MinSafe: $minSafe, MinSafeSoft: $minSafeSoft"
}

# Version comparison
$cmpSafe = $null
$cmpSafeSoft = $null
if ($localParsed.IsValid -and $minSafe) {
    try {
        $cmpSafe = ([version]$localParsed.Normalized).CompareTo([version]$minSafe)
        $cmpSafeSoft = ([version]$localParsed.Normalized).CompareTo([version]$minSafeSoft)
    } catch {
        Write-Verbose "Version comparison failed: $_"
    }
}

# 7. State determination (Priority: EOL > Policy > Distance)
$SecurityState = 0
$State = 0
$statetxt = ''

if (-not $local) {
    $State = 3
    $SecurityState = 2
    $statetxt = 'VMware Tools not installed / unreadable'
    $BranchRecommendation = 'Install VMware Tools 13.x (ESXi 8.x) or 12.x (ESXi 7.x/6.x)'
}
elseif ($isEOL) {
    $State = 3
    $SecurityState = 2
    $statetxt = "CRITICAL: End-of-Life branch ($local) - Update to 12.x or 13.x required"
    $BranchRecommendation = 'Update to VMware Tools 13.x (ESXi 8.x) or 12.x (ESXi 7.x/6.x)'
}
elseif ($localParsed.Major -eq 12 -and $StrictBranchPolicy) {
    if ($cmpSafe -ne $null -and $cmpSafe -ge 0) {
        $State = 1
        $SecurityState = 1
        $statetxt = "Warning: 12.x branch detected with -StrictBranchPolicy - consider 13.x upgrade"
        $BranchRecommendation = 'Upgrade to VMware Tools 13.x for ESXi 8.x compatibility'
    }
    else {
        $State = 2
        $SecurityState = 2
        $statetxt = "12.x branch below minimum ($local < $minSafe) - update or upgrade to 13.x"
        $BranchRecommendation = "Update to $minSafe+ or upgrade to VMware Tools 13.x"
    }
}
elseif ($cmpSafe -ne $null -and $cmpSafe -lt 0) {
    if ($cmpSafeSoft -ne $null -and $cmpSafeSoft -ge 0) {
        $State = 1
        $SecurityState = 1
        $statetxt = "Warning: Version $local below recommended ($minSafe in $($localParsed.Branch) branch)"
        $BranchRecommendation = "Update to $minSafe+ within $($localParsed.Branch) branch"
    } else {
        $State = 2
        $SecurityState = 2
        $statetxt = "Error: Version $local below minimum ($minSafe in $($localParsed.Branch) branch)"
        $BranchRecommendation = "Update to $minSafe+ within $($localParsed.Branch) branch"
    }
}
elseif ($distance -eq -1) {
    $State = 1
    $SecurityState = 1
    $statetxt = "Warning: Version $local not in baseline list ($($localParsed.Branch) branch)"
    $BranchRecommendation = "Verify version compatibility with ESXi host"
}
elseif ($distance -eq 0) {
    $State = 0
    $SecurityState = 0
    $statetxt = "OK (Latest version in $($localParsed.Branch) branch: $local)"
}
elseif ($distance -le 1) {
    $State = 0
    $SecurityState = 0
    $statetxt = "OK ($distance version behind in $($localParsed.Branch) branch: $local)"
}
elseif ($distance -lt $ErrorThreshold) {
    $State = 1
    $SecurityState = 1
    $statetxt = "Warning ($distance versions behind in $($localParsed.Branch) branch: $local)"
    $BranchRecommendation = "Update to latest $($localParsed.Branch) release ($minSafe+)"
}
else {
    $State = 2
    $SecurityState = 2
    $statetxt = "Error ($distance versions behind in $($localParsed.Branch) branch: $local)"
    $BranchRecommendation = "Update to latest $($localParsed.Branch) release ($minSafe+)"
}

Write-Verbose "Final state: $State ($statetxt)"

# 8. Build result object
$result = [pscustomobject]@{
    LocalVersion         = $local
    LocalBranch          = if ($localParsed.IsValid) { $localParsed.Branch } else { 'Unknown' }
    BaselineVersion      = if ($latestInBranch -and $latestInBranch.product) { 
        $parsed = Parse-VersionString $latestInBranch.product
        if ($parsed.IsValid) { $parsed.Normalized } else { $null }
    } else { 
        $null 
    }
    LocalReleaseDate     = if ($localReleaseDate) { 
        $localReleaseDate.ToString('yyyy-MM-dd') 
    } else { 
        $null 
    }
    BaselineReleaseDate  = if ($baselineReleaseDate) { 
        $baselineReleaseDate.ToString('yyyy-MM-dd') 
    } else { 
        $null 
    }
    AgeDays              = $ageDays
    ExchangeDetected     = [bool]$exchange
    SecurityState        = [int]$SecurityState
    State                = [int]$State
    Message              = $statetxt
    BaselineSource       = 'vTracker'
    MinSafeApplied       = $minSafe
    VersionsBehind       = $distance
    BranchPolicy         = 'Dual-Branch (12.x + 13.x parallel)'
    IsEOL                = $isEOL
    BranchRecommendation = $BranchRecommendation
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
    
    Add-TextChannel 'LocalVersion'       ("Local {0} ({1})" -f (NN $r.LocalVersion 'n/a'), (NN $r.LocalBranch 'n/a'))
    Add-TextChannel 'LocalReleaseDate'   ("Released {0}"    -f (NN $r.LocalReleaseDate 'n/a'))
    Add-TextChannel 'BaselineVersion'    ("Baseline {0}"    -f (NN $r.BaselineVersion 'n/a'))
    Add-TextChannel 'BranchPolicy'       ("Policy: {0}"     -f (NN $r.BranchPolicy 'n/a'))
    Add-NumChannel  'AgeDays'            (NN $r.AgeDays '0')
    Add-NumChannel  'ExchangeDetected'   ([int]$r.ExchangeDetected)
    Add-NumChannel  'IsEOL'              ([int]$r.IsEOL)
    Add-NumChannel  'SecurityState'      $r.SecurityState -WithLimits
    Add-NumChannel  'State'              $r.State         -WithLimits
    Add-NumChannel  'VersionsBehind'     (NN $r.VersionsBehind '-1')
    
    $t = $xml.CreateElement('text')
    $t.InnerText = (NN $r.Message '')
    [void]$prtg.AppendChild($t)
    
    return $xml.OuterXml
}

function Render-Legacy([object]$r){
    $line = ("{0}:Local={1}; Branch={2}; EOL={3}; Baseline={4}; AgeDays={5}; VersionsBehind={6}; {7}" -f `
        $r.State,
        (NN $r.LocalVersion 'n/a'),
        (NN $r.LocalBranch 'n/a'),
        [int]$r.IsEOL,
        (NN $r.BaselineVersion 'n/a'),
        (NN $r.AgeDays 'n/a'),
        (NN $r.VersionsBehind '-1'),
        (NN $r.Message '')
    )
    Write-Output $line
}

function Render-Text([object]$r){
    $text = @"
VMware Tools Baseline Report (Dual-Branch Architecture)
--------------------------------------------------------
Local Version        : $(NN $r.LocalVersion 'n/a')
Local Branch         : $(NN $r.LocalBranch 'n/a')
Local Release Date   : $(NN $r.LocalReleaseDate 'n/a')
Baseline Version     : $(NN $r.BaselineVersion 'n/a')  (source: $(NN $r.BaselineSource 'n/a'))
Baseline Release     : $(NN $r.BaselineReleaseDate 'n/a')
Age (days)           : $(NN $r.AgeDays 'n/a')
Exchange Detected    : $($r.ExchangeDetected)
Min Safe Applied     : $(NN $r.MinSafeApplied 'n/a')
Versions Behind      : $(NN $r.VersionsBehind '-1') (within branch)
Branch Policy        : $(NN $r.BranchPolicy 'n/a')
Is End-of-Life       : $($r.IsEOL)

Security State       : $($r.SecurityState)   (0=OK,1=Warn,2=Error)
Overall State        : $($r.State)           (0=OK,1=Warn,2=Error,3=Critical)

Message              : $(NN $r.Message '')
Recommendation       : $(NN $r.BranchRecommendation 'None')

Branch Compatibility Matrix:
  13.x → ESXi 8.x (recommended)
  12.x → ESXi 7.x/6.x (supported)
  11.x → End-of-Life (critical)
"@
    Write-Output $text
}

function Render-Json([object]$r){
    $r | ConvertTo-Json -Depth 4
}

function Render-Ansi([object]$r) {
    # State color
    $stateColor = switch ($r.State) {
        0 { 'Green' }
        1 { 'Yellow' }
        2 { 'Red' }
        3 { 'White' }
        default { 'Gray' }
    }
    $stateBg = if ($r.State -eq 3) { 'Red' } else { $null }
    
    # Branch color
    $branchColor = switch ($r.LocalBranch) {
        '13.x' { 'Cyan' }
        '12.x' { 'Green' }
        default { if ($r.IsEOL) { 'White' } else { 'Yellow' } }
    }
    $branchBg = if ($r.IsEOL) { 'Red' } else { $null }
    
    # Age color
    $ageColor = 'Green'
    $ageBg = $null
    if ($r.AgeDays -ne $null) {
        $months = [math]::Floor($r.AgeDays / 30)
        if ($months -ge 8) { $ageColor = 'Yellow'; $ageBg = 'Red' }
        elseif ($months -ge 5) { $ageColor = 'Black'; $ageBg = 'Yellow' }
        elseif ($months -ge 3) { $ageColor = 'Yellow' }
    }
    
    # Versions behind color
    $versionsBehindColor = 'Gray'
    if ($r.VersionsBehind -ne $null -and $r.VersionsBehind -ge 0) {
        if ($r.VersionsBehind -le 1) {
            $versionsBehindColor = 'Green'
        }
        elseif ($r.VersionsBehind -eq 2) {
            $versionsBehindColor = 'Yellow'
        }
        elseif ($r.VersionsBehind -ge 3) {
            $versionsBehindColor = 'Red'
        }
    }
    
    # Header
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  " -NoNewline -ForegroundColor Cyan
    Write-Host "VMware Tools Compliance" -NoNewline -ForegroundColor White
    Write-Host " (Dual-Branch: 12.x+13.x)  ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Data rows
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
    Write-DataRow "Local Branch" (NN $r.LocalBranch 'n/a') $branchColor $branchBg
    Write-DataRow "Local Release Date" (NN $r.LocalReleaseDate 'n/a') 'DarkGray'
    Write-DataRow "Baseline Version" (NN $r.BaselineVersion 'n/a') 'Magenta'
    Write-DataRow "Age (days)" (NN $r.AgeDays 'n/a') $ageColor $ageBg
    Write-DataRow "Versions Behind" (NN $r.VersionsBehind 'n/a') $versionsBehindColor
    Write-DataRow "Branch Policy" (NN $r.BranchPolicy 'n/a') 'Cyan'
    $eolStatus = if ($r.IsEOL) { "YES (CRITICAL)" } else { "No" }
    Write-DataRow "Is End-of-Life" $eolStatus $branchColor $branchBg
    Write-DataRow "Exchange Detected" $r.ExchangeDetected 'White'
    Write-DataRow "Min Safe Applied" (NN $r.MinSafeApplied 'n/a') 'White'
    Write-Host ""
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
    
    if ($r.BranchRecommendation) {
        Write-Host ""
        Write-Host "  " -NoNewline
        Write-Host "Recommendation" -ForegroundColor Yellow
        Write-Host "  " -NoNewline
        Write-Host $r.BranchRecommendation -ForegroundColor Yellow
    }
    
    Write-Host ""
    
    # Legend
    Write-Host "Legend:" -ForegroundColor Cyan
    Write-Host "  " -NoNewline
    Write-Host "Branch: " -NoNewline -ForegroundColor Gray
    Write-Host "13.x" -NoNewline -ForegroundColor Cyan
    Write-Host " (ESXi 8.x)  " -NoNewline
    Write-Host "12.x" -NoNewline -ForegroundColor Green
    Write-Host " (ESXi 7.x/6.x)  " -NoNewline
    Write-Host "11.x-" -ForegroundColor White -BackgroundColor Red -NoNewline
    Write-Host " (EOL)"
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
    Write-Output (Render-Xml $result)
    if (Is-PrtgContext) { exit 0 }
}

Write-Verbose "=== VMware Tools Compliance Check Completed ==="
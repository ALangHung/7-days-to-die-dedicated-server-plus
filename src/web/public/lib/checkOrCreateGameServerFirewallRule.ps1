param(
    [Parameter(Mandatory = $true)]
    [string]$ProgramPath,

    # This is a prefix; final rule names will append " - TCP (All Ports)" and " - UDP (All Ports)"
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,

    [Parameter(Mandatory = $false)]
    [string]$Description = 'Allow inbound TCP/UDP on all ports for the specified program (all profiles).'
)

# --- require admin ---
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$wp = [Security.Principal.WindowsPrincipal]::new($wi)
if (-not $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Please run this script as Administrator.'
}

function Convert-ProgramPath([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($p)
    try { $full = [System.IO.Path]::GetFullPath($expanded) } catch { $full = $expanded }
    return ($full -replace '[\\/]+', '\').ToLowerInvariant()
}

# 一次判斷是否已具備 TCP/UDP「全埠」規則，避免逐條慢速查詢
function Get-AllPortsInboundCoverage([string]$ProgramFullPathNorm) {
    # 1) 先抓入站＋允許＋啟用（只看 ActiveStore），一次取回
    $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -PolicyStore ActiveStore -ErrorAction SilentlyContinue
    if (-not $rules) { return [pscustomobject]@{ HasTCP = $false; HasUDP = $false } }
  
    # 2) 批次抓 ApplicationFilter / PortFilter（輸入陣列，避免 N 次呼叫）
    $appFilters = $rules | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    $portFilters = $rules | Get-NetFirewallPortFilter        -ErrorAction SilentlyContinue
  
    # 3) 建索引：RuleName -> Program（正規化後）
    $progByRule = @{}
    foreach ($af in $appFilters) {
        if ($af -and $af.Program) {
            $progByRule[$af.InstanceID] = (Convert-ProgramPath $af.Program)
        }
    }
  
    # 4) 建索引：RuleName -> PortFilter（可能多個，先分桶）
    $pfByRule = @{}
    foreach ($pf in $portFilters) {
        $key = $pf.InstanceID
        if (-not $pfByRule.ContainsKey($key)) { $pfByRule[$key] = @() }
        $pfByRule[$key] += $pf
    }
  
    $hasTCP = $false
    $hasUDP = $false
  
    foreach ($r in $rules) {
        # ApplicationFilter 沒綁 Program 的規則跳過
        $progNorm = $progByRule[$r.Name]
        if (-not $progNorm) { continue }
        if ($progNorm -ne $ProgramFullPathNorm) { continue }
  
        # 取該規則的所有 PortFilter
        $pfs = $pfByRule[$r.Name]
        if (-not $pfs) { continue }
  
        foreach ($pf in $pfs) {
            # 全埠條件：LocalPort 為 'Any' 或空
            $isAllPorts = ($pf.LocalPort -eq 'Any' -or [string]::IsNullOrWhiteSpace($pf.LocalPort))
            if (-not $isAllPorts) { continue }
  
            if ($pf.Protocol -eq 'TCP') { $hasTCP = $true }
            elseif ($pf.Protocol -eq 'UDP') { $hasUDP = $true }
  
            if ($hasTCP -and $hasUDP) { break } # 都找到就提早結束
        }
  
        if ($hasTCP -and $hasUDP) { break }
    }
  
    return [pscustomobject]@{ HasTCP = $hasTCP; HasUDP = $hasUDP }
}

# resolve ProgramPath relative to script location
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProgramPath = Join-Path $ScriptDir $ProgramPath

# do not check file existence; allow pre-creating rules
$ProgramFull = Convert-ProgramPath $ProgramPath
if ([string]::IsNullOrWhiteSpace($ProgramFull)) {
    throw "Invalid ProgramPath: $ProgramPath"
}

Write-Host '=== Checking inbound firewall rules ==='
Write-Host "  Program: $ProgramFull"
Write-Host "  Display name prefix: $DisplayName"
Write-Host ''

$cov = Get-AllPortsInboundCoverage $ProgramFull
$needTCP = -not $cov.HasTCP
$needUDP = -not $cov.HasUDP

if (-not $needTCP -and -not $needUDP) {
    Write-Host 'Already present: TCP/UDP all-ports inbound rules for this program.'
    return
}

if ($needTCP) {
    $tcpParams = @{
        DisplayName = "$DisplayName - TCP (All Ports)"
        Direction   = 'Inbound'
        Action      = 'Allow'
        Enabled     = 'True'
        Program     = $ProgramFull
        Protocol    = 'TCP'
        Profile     = 'Domain,Private,Public'
        Description = $Description
    }
    New-NetFirewallRule @tcpParams | Out-Null
    Write-Host 'Created: TCP all-ports inbound rule.'
}

if ($needUDP) {
    $udpParams = @{
        DisplayName = "$DisplayName - UDP (All Ports)"
        Direction   = 'Inbound'
        Action      = 'Allow'
        Enabled     = 'True'
        Program     = $ProgramFull
        Protocol    = 'UDP'
        Profile     = 'Domain,Private,Public'
        Description = $Description
    }
    New-NetFirewallRule @udpParams | Out-Null
    Write-Host 'Created: UDP all-ports inbound rule.'
}

Write-Host ''
Write-Host 'Done.'

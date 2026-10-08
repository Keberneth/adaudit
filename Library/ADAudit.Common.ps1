<#
    .SYNOPSIS
        ADAudit shared library: run state and helpers used by every check.

    .DESCRIPTION
        Dot-sourced by AdAudit-PS7.ps1 before the check files, so everything here runs in the
        runner's script scope. Holds the output-folder helpers, console logging, the per-check
        failure wrapper (Invoke-AuditCheck / Invoke-AuditStep), "could not assess" tracking
        (Register-ADAuditNotAssessed), the Nessus export, the shared report CSS / navigation,
        module import, CIM / registry helpers, the DSInternals replication cache and the
        optional-dependency installer (-installdeps).

        State lives in $script: variables of the runner (CheckFailures, NotAssessed, output
        directories ...). Check files must call these helpers instead of reaching for the
        variables, and must be dot-sourced (never run with '&'): a child script scope would
        resolve $script: to the wrong place.

    .NOTES
        Functions moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was split.
#>
function Import-ADAuditModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$Required,

        [switch]$PreferWindowsPowerShell
    )

    $loaded = Get-Module -Name $Name | Select-Object -First 1
    if ($loaded) { return $loaded }

    $available = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending
    if (-not $available) {
        if ($Required) { throw "Module '$Name' is not available on this host." }
        return $null
    }

    $attempts = New-Object System.Collections.Generic.List[hashtable]
    if ($script:ADAuditIsPowerShell7Plus -and $PreferWindowsPowerShell) {
        $attempts.Add(@{ UseWindowsPowerShell = $true })
    }

    $attempts.Add(@{})

    if ($script:ADAuditIsPowerShell7Plus) {
        $attempts.Add(@{ SkipEditionCheck = $true })
    }

    if ($script:ADAuditIsPowerShell7Plus -and -not $PreferWindowsPowerShell) {
        $attempts.Add(@{ UseWindowsPowerShell = $true })
    }

    $lastError = $null
    foreach ($attempt in $attempts) {
        try {
            Import-Module -Name $Name @attempt -ErrorAction Stop | Out-Null
            return (Get-Module -Name $Name | Sort-Object Version -Descending | Select-Object -First 1)
        }
        catch {
            $lastError = $_
        }
    }

    if ($Required) {
        if ($lastError) {
            throw "Failed to import module '$Name'. $($lastError.Exception.Message)"
        }
        throw "Failed to import module '$Name'."
    }

    return $null
}

function Get-ADAuditCimInstance {
    [CmdletBinding(DefaultParameterSetName = 'ByClass')]
    param(
        [Parameter(ParameterSetName = 'ByClass', Mandatory = $true)]
        [string]$ClassName,

        [Parameter(ParameterSetName = 'ByQuery', Mandatory = $true)]
        [string]$Query,

        [string]$Namespace = 'root/cimv2',

        [string]$Filter,

        [string[]]$Property,

        [string]$ComputerName = $env:COMPUTERNAME,

        [switch]$UseWsmanFallback
    )

    if (-not $script:ADAuditIsWindows) {
        throw "Get-ADAuditCimInstance requires Windows."
    }

    $remoteTarget = $ComputerName -and $ComputerName -notin @('.', 'localhost', $env:COMPUTERNAME)
    $baseParams = @{ Namespace = $Namespace; ErrorAction = 'Stop' }

    if ($PSCmdlet.ParameterSetName -eq 'ByClass') {
        $baseParams.ClassName = $ClassName
        if ($Filter)   { $baseParams.Filter = $Filter }
        if ($Property) { $baseParams.Property = $Property }
    }
    else {
        $baseParams.Query = $Query
    }

    if (-not $remoteTarget) {
        return Get-CimInstance @baseParams
    }

    $session = $null
    try {
        $sessionOption = New-CimSessionOption -Protocol Dcom
        $session = New-CimSession -ComputerName $ComputerName -SessionOption $sessionOption -ErrorAction Stop
        $baseParams.CimSession = $session
        return Get-CimInstance @baseParams
    }
    catch {
        if ($UseWsmanFallback) {
            try {
                $fallbackParams = @{}
                foreach ($entry in $baseParams.GetEnumerator()) {
                    if ($entry.Key -ne 'CimSession') {
                        $fallbackParams[$entry.Key] = $entry.Value
                    }
                }
                $fallbackParams.ComputerName = $ComputerName
                return Get-CimInstance @fallbackParams
            }
            catch {
                throw
            }
        }

        throw
    }
    finally {
        if ($session) {
            $session | Remove-CimSession -ErrorAction SilentlyContinue
        }
    }
}

function Convert-ADAuditFileTime {
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return $null }

    $raw = [string]$Value
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    try {
        return [datetime]::FromFileTimeUtc([int64]$raw).ToLocalTime()
    }
    catch {
        return $null
    }
}

function Get-ADAuditFunctionalLevelRank {
    param([string]$Mode)

    # Ranks cover every Domain/Forest mode the ActiveDirectory module emits,
    # going back to NT4 (rank 0) and forward to Server 2025 (rank 10). Earlier
    # versions of this table only covered 2016+, which made
    # Test-ADAuditFunctionalLevelAtLeast return $false whenever the minimum
    # mode was Windows2003/2008/2008R2/2012/2012R2 because $minimumRank ended
    # up $null - which broke the Protected Users / Authentication Policies
    # checks on every estate at or above DFL 2008R2.
    switch ($Mode) {
        'Windows2000Domain'        { return 0 }
        'Windows2000Forest'        { return 0 }
        'Windows2003InterimDomain' { return 1 }
        'Windows2003InterimForest' { return 1 }
        'Windows2003Domain'        { return 2 }
        'Windows2003Forest'        { return 2 }
        'Windows2008Domain'        { return 3 }
        'Windows2008Forest'        { return 3 }
        'Windows2008R2Domain'      { return 4 }
        'Windows2008R2Forest'      { return 4 }
        'Windows2012Domain'        { return 5 }
        'Windows2012Forest'        { return 5 }
        'Windows2012R2Domain'      { return 6 }
        'Windows2012R2Forest'      { return 6 }
        'Windows2016Domain'        { return 7 }
        'Windows2016Forest'        { return 7 }
        'WinThreshold'             { return 7 }
        'Windows2019Domain'        { return 8 }
        'Windows2019Forest'        { return 8 }
        'Windows2022Domain'        { return 9 }
        'Windows2022Forest'        { return 9 }
        'Windows2025Domain'        { return 10 }
        'Windows2025Forest'        { return 10 }
        default                    { return $null }
    }
}

function Get-ADAuditFunctionalLevelMode {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Rank,

        [ValidateSet('Domain','Forest')]
        [string]$Scope = 'Domain'
    )

    switch ($Rank) {
        0  { return "Windows2000$Scope" }
        2  { return "Windows2003$Scope" }
        3  { return "Windows2008$Scope" }
        4  { return "Windows2008R2$Scope" }
        5  { return "Windows2012$Scope" }
        6  { return "Windows2012R2$Scope" }
        7  { return "Windows2016$Scope" }
        8  { return "Windows2019$Scope" }
        9  { return "Windows2022$Scope" }
        10 { return "Windows2025$Scope" }
        default { return $null }
    }
}

function Test-ADAuditFunctionalLevelAtLeast {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [string]$MinimumMode
    )

    $modeRank = Get-ADAuditFunctionalLevelRank -Mode $Mode
    $minimumRank = Get-ADAuditFunctionalLevelRank -Mode $MinimumMode

    if ($null -eq $modeRank -or $null -eq $minimumRank) {
        return $false
    }

    return ($modeRank -ge $minimumRank)
}

function Get-ADAuditDcFunctionalLevelCapRank {
    param(
        [Parameter(Mandatory = $true)]
        $DomainController
    )

    $operatingSystem = [string]$DomainController.OperatingSystem
    $version = [string]$DomainController.OperatingSystemVersion

    if ($operatingSystem -match '2025') { return 10 }
    if ($operatingSystem -match '2022') { return 9 }
    if ($operatingSystem -match '2019') { return 8 }
    if ($operatingSystem -match '2016') { return 7 }
    if ($operatingSystem -match '2012 ?R2') { return 6 }
    if ($operatingSystem -match '2012') { return 5 }
    if ($operatingSystem -match '2008 ?R2') { return 4 }
    if ($operatingSystem -match '2008') { return 3 }
    if ($operatingSystem -match '2003') { return 2 }
    if ($operatingSystem -match '2000') { return 0 }

    try {
        $parsedVersion = [version]$version
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 26000) { return 10 }
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 20348) { return 9 }
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 17763) { return 8 }
        if ($parsedVersion.Major -eq 10) { return 7 }
        if ($parsedVersion.Major -eq 6 -and $parsedVersion.Minor -eq 3) { return 6 }
        if ($parsedVersion.Major -eq 6 -and $parsedVersion.Minor -eq 2) { return 5 }
        if ($parsedVersion.Major -eq 6 -and $parsedVersion.Minor -eq 1) { return 4 }
        if ($parsedVersion.Major -eq 6 -and $parsedVersion.Minor -eq 0) { return 3 }
        if ($parsedVersion.Major -eq 5 -and $parsedVersion.Minor -eq 2) { return 2 }
    }
    catch { }

    return $null
}

$script:ADAuditReplAccountCache = @{}

function Get-ADAuditReplAccountsCached {
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$NamingContext
    )
    # Full-domain secrets replication (Get-ADReplAccount -All, a DCSync) is the single
    # most expensive and most SOC-alarming operation in this tool. Both the password
    # quality check and the high-risk baseline need it; cache the result per
    # Server+NamingContext so a single -all run replicates once, not twice.
    $key = "$Server|$NamingContext"
    if ($script:ADAuditReplAccountCache.ContainsKey($key)) {
        return $script:ADAuditReplAccountCache[$key]
    }
    $accounts = Get-ADReplAccount -All -Server $Server -NamingContext $NamingContext -ErrorAction Stop
    $script:ADAuditReplAccountCache[$key] = $accounts
    return $accounts
}

Function Get-Variables() {
    #Retrieve group names and OS version
    $script:OSVersion = (Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
    $script:Administrators = (Get-ADGroup -Identity S-1-5-32-544).SamAccountName
    $script:Users = (Get-ADGroup -Identity S-1-5-32-545).SamAccountName
    $domainSidValue = (Get-ADDomain -Current LoggedOnUser).domainsid.value
    $script:DomainAdminsSID = $domainSidValue + "-512"
    $script:DomainUsersSID = $domainSidValue + "-513"
    $script:DomainControllersSID = $domainSidValue + "-516"
    # Schema Admins (518) and Enterprise Admins (519) exist only in the FOREST
    # ROOT domain; in a child domain the current domain's SID-518/519 resolve
    # to nothing and the lookups below would leave the names null.
    $rootDomainSidValue = $domainSidValue
    try {
        $forestRootDomain = (Get-ADForest -ErrorAction Stop).RootDomain
        $rootDomainSidValue = (Get-ADDomain -Identity $forestRootDomain -ErrorAction Stop).domainsid.value
    } catch { }
    $script:SchemaAdminsSID = $rootDomainSidValue + "-518"
    $script:EnterpriseAdminsSID = $rootDomainSidValue + "-519"
    $script:EveryOneSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
    $script:EntrepriseDomainControllersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-9"
    $script:AuthenticatedUsersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-11"
    $script:SystemSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
    $script:LocalServiceSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-19"
    $script:DomainAdmins = (Get-ADGroup -Identity $DomainAdminsSID).SamAccountName
    $script:DomainUsers = (Get-ADGroup -Identity $DomainUsersSID).SamAccountName
    $script:DomainControllers = (Get-ADGroup -Identity $DomainControllersSID).SamAccountName
    # Fall back to the well-known English names rather than leaving these null:
    # downstream -match/-eq checks against a null name would match everything.
    $script:SchemaAdmins = try { (Get-ADGroup -Identity $SchemaAdminsSID -ErrorAction Stop).SamAccountName } catch { 'Schema Admins' }
    $script:EnterpriseAdmins = try { (Get-ADGroup -Identity $EnterpriseAdminsSID -ErrorAction Stop).SamAccountName } catch { 'Enterprise Admins' }
    $script:EveryOne = $EveryOneSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:EntrepriseDomainControllers = $EntrepriseDomainControllersSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:AuthenticatedUsers = $AuthenticatedUsersSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:System = $SystemSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:LocalService = $LocalServiceSID.Translate([System.Security.Principal.NTAccount]).Value
    Write-Both "    [+] Administrators               : $Administrators"
    Write-Both "    [+] Users                        : $Users"
    Write-Both "    [+] Domain Admins                : $DomainAdmins"
    Write-Both "    [+] Domain Users                 : $DomainUsers"
    Write-Both "    [+] Domain Controllers           : $DomainControllers"
    Write-Both "    [+] Schema Admins                : $SchemaAdmins"
    Write-Both "    [+] Enterprise Admins            : $EnterpriseAdmins"
    Write-Both "    [+] Every One                    : $EveryOne"
    Write-Both "    [+] Entreprise Domain Controllers: $EntrepriseDomainControllers"
    Write-Both "    [+] Authenticated Users          : $AuthenticatedUsers"
    Write-Both "    [+] System                       : $System"
    Write-Both "    [+] Local Service                : $LocalService"
}

Function Write-Both() {
    #Writes to console only. Findings are rendered into the HTML audit and management reports.
    Write-Host "$args"
}

Function Get-HtmlReportsDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    if ([string]::IsNullOrWhiteSpace($BaseRoot)) {
        $BaseRoot = Join-Path (Get-Location) $env:COMPUTERNAME
    }

    $path = if ($script:HtmlReportsDir) { $script:HtmlReportsDir } else { Join-Path $BaseRoot 'HTML Reports' }
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}

Function Get-RawDataDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    if ([string]::IsNullOrWhiteSpace($BaseRoot)) {
        $BaseRoot = Join-Path (Get-Location) $env:COMPUTERNAME
    }

    $path = if ($script:EvidenceFilesDir) { $script:EvidenceFilesDir } else { Join-Path $BaseRoot 'Raw Data' }
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}

Function Get-RawSourceDataDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    $path = if ($script:LegacyArtifactsDir) { $script:LegacyArtifactsDir } else { Join-Path (Get-RawDataDir -BaseRoot $BaseRoot) 'Source' }
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}

Function Get-PreparedDataDir {
    # Merged into Source - all output now goes to the same folder to eliminate duplication
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    return (Get-RawSourceDataDir -BaseRoot $BaseRoot)
}

Function Get-HtmlDownloadsDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    return (Get-PreparedDataDir -BaseRoot $BaseRoot)
}

Function Get-ADAuditReportCss {
    <#
    .SYNOPSIS
        Returns the shared CSS style block used by all companion HTML reports.
        Matches the design language of ADAudit-Results.html (light default + dark mode).
    #>
    return @'
<style>
:root {
  --bg:#f5f7fb; --panel:#ffffff; --text:#1b2430; --muted:#5f6b7a;
  --line:#d9e0ea; --shadow:0 10px 24px rgba(15,23,42,.08); --radius:14px;
  --accent:#3b82f6; --accent-soft:#dbeafe;
  --critical:#c62828; --critical-soft:#fdecec;
  --high:#ef6c00;    --high-soft:#fff2e5;
  --medium:#0277bd;  --medium-soft:#e8f4fd;
  --low:#2e7d32;     --low-soft:#edf8ee;
  --info:#6c757d;    --info-soft:#f2f4f6;
}
@media(prefers-color-scheme:dark){
  :root {
    --bg:#0f172a; --panel:#1e293b; --text:#e2e8f0; --muted:#94a3b8;
    --line:#334155; --shadow:0 10px 24px rgba(0,0,0,.4);
    --accent:#60a5fa; --accent-soft:rgba(96,165,250,.15);
    --critical:#f87171; --critical-soft:rgba(248,113,113,.15);
    --high:#fb923c;    --high-soft:rgba(251,146,60,.15);
    --medium:#60a5fa;  --medium-soft:rgba(96,165,250,.15);
    --low:#4ade80;     --low-soft:rgba(74,222,128,.15);
    --info:#94a3b8;    --info-soft:rgba(148,163,184,.15);
  }
}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;padding:32px 24px;font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif;
  background:var(--bg);color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}
.container{max-width:1280px;margin:0 auto}
.hero{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);
  padding:32px 36px;margin-bottom:28px}
.hero h1{margin:0 0 4px;font-size:1.65rem;font-weight:700}
.hero .meta{color:var(--muted);font-size:.88rem}
.mono{font-family:Consolas,Menlo,Monaco,monospace;font-size:.92em}
h2{font-size:1.25rem;font-weight:600;margin:28px 0 14px;padding-bottom:8px;border-bottom:2px solid var(--line)}
h3{font-size:1.05rem;font-weight:600;margin:20px 0 10px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:Consolas,Menlo,Monaco,monospace;font-size:.9em;background:var(--accent-soft);
  padding:2px 7px;border-radius:5px}
pre{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:16px 20px;overflow-x:auto;font-size:.88rem;font-family:Consolas,Menlo,Monaco,monospace}

/* Tables */
table{width:100%;border-collapse:separate;border-spacing:0;margin:12px 0 20px;
  background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
thead th{background:var(--accent-soft);color:var(--text);font-weight:600;font-size:.85rem;
  text-transform:uppercase;letter-spacing:.04em;padding:12px 14px;text-align:left;
  position:sticky;top:0;z-index:1;border-bottom:2px solid var(--line)}
tbody td{padding:10px 14px;border-bottom:1px solid var(--line);font-size:.92rem;vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--accent-soft)}

/* Severity badges */
.badge{display:inline-block;padding:3px 12px;border-radius:999px;font-size:.82rem;font-weight:600;letter-spacing:.02em}
.badge-critical{background:var(--critical-soft);color:var(--critical)}
.badge-high{background:var(--high-soft);color:var(--high)}
.badge-medium{background:var(--medium-soft);color:var(--medium)}
.badge-low{background:var(--low-soft);color:var(--low)}
.badge-info{background:var(--info-soft);color:var(--info)}

/* Stat cards */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin:16px 0 24px}
.stat{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);
  padding:18px 20px;text-align:center}
.stat .val{font-size:1.8rem;font-weight:700;line-height:1.1}
.stat .lbl{font-size:.82rem;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.04em}

/* Details/Accordion */
details{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);
  margin:10px 0;border-left:5px solid var(--accent)}
details[open]{border-left-color:var(--accent)}
summary{cursor:pointer;padding:14px 20px;font-weight:600;font-size:.95rem;list-style:none;
  display:flex;align-items:center;gap:10px}
summary::-webkit-details-marker{display:none}
summary::before{content:'\25B8';font-size:1rem;transition:transform .15s ease;display:inline-block}
details[open]>summary::before{transform:rotate(90deg)}
details>div,details>.detail-body{padding:0 20px 16px}
details table{box-shadow:none;margin:0}

/* List styling */
ul.link-list{list-style:none;padding:0}
ul.link-list li{padding:8px 14px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px}
ul.link-list li:last-child{border-bottom:none}
ul.link-list li::before{content:'\1F4C4';font-size:1rem}

/* Footer */
.footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--line);
  color:var(--muted);font-size:.82rem;text-align:center}

/* Responsive */
@media(max-width:768px){
  body{padding:16px 12px}
  .hero{padding:20px}
  .stats{grid-template-columns:repeat(auto-fit,minmax(120px,1fr))}
  table{display:block;overflow-x:auto}
}
</style>
'@
}

Function Get-ADAuditReportHeader {
    <#
    .SYNOPSIS
        Returns the HTML header/doctype block for companion reports.
    #>
    param([string]$Title = 'AD Audit Report')
    $css = Get-ADAuditReportCss
    return @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>$Title</title>
$css
</head>
<body>
<div class="container">
"@
}

Function Get-ADAuditReportFooter {
    <#
    .SYNOPSIS
        Returns the HTML footer block for companion reports.
    #>
    return @"
<div class="footer">Generated by AD Audit &mdash; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
</div>
</body>
</html>
"@
}

Function Get-ADAuditPrimaryNav {
    <#
    .SYNOPSIS
        Returns the shared CSS + <nav> block linking the primary HTML reports.
        The Operations tab is intentionally not included - it is not part of the audit.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('audit','risk','health','overlap','lateral','none')]
        [string]$Active = 'none'
    )
    $links = @(
        [pscustomobject]@{ Key='audit';   Href='ADAudit-Results.html';            Label='Audit Results' }
        [pscustomobject]@{ Key='risk';    Href='Risk-Report.html';                Label='Risk Report' }
        [pscustomobject]@{ Key='health';  Href='AD_Health.html';                  Label='AD Health' }
        [pscustomobject]@{ Key='overlap'; Href='overlapping_group_memberships.html'; Label='Overlapping Groups' }
        [pscustomobject]@{ Key='lateral'; Href='Lateral-Movement.html';            Label='Lateral Movement' }
    )
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(@'
<style>
.primary-nav{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 20px;padding:10px 14px;background:var(--panel,#fff);border:1px solid var(--line,#d9e0ea);border-radius:12px;box-shadow:var(--shadow,0 10px 24px rgba(15,23,42,.08))}
.primary-nav-link{padding:6px 12px;border-radius:999px;font-size:.85rem;font-weight:600;text-decoration:none;color:var(--text,#1b2430);border:1px solid transparent}
.primary-nav-link:hover{background:var(--accent-soft,#dbeafe);text-decoration:none}
.primary-nav-link.active{background:var(--accent,#3b82f6);color:#fff;border-color:var(--accent,#3b82f6)}
</style>
'@)
    [void]$sb.Append("<nav class='primary-nav'>")
    foreach ($link in $links) {
        $cls = if ($link.Key -eq $Active) { 'primary-nav-link active' } else { 'primary-nav-link' }
        [void]$sb.Append("<a class='$cls' href='$($link.Href)'>$($link.Label)</a>")
    }
    [void]$sb.AppendLine("</nav>")
    return $sb.ToString()
}

Function Get-EvidencePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )
    $dir = Get-RawSourceDataDir
    return (Join-Path $dir $FileName)
}

# ---------------------------------------------------------------------------
# Audit check resilience: per-check try/catch wrapper + FSMO context lookup
# Lets a single failing check (DNS, Delegated Permissions, etc.) be logged
# without stopping the entire script. A separate connection_failures.txt /
# .csv summarises every failure, the error, the suspected target server, and
# - if reachable - the FSMO roles that server holds, so the operator knows
# exactly which checks were skipped and why.
# ---------------------------------------------------------------------------
$script:CheckFailures = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# "Could not assess" tracking. Distinct from CheckFailures (thrown errors):
# this records checks/targets we deliberately could NOT evaluate (e.g. a DC
# was unreachable over remote PowerShell/CIM, or the host running the script
# is not a DC so a host-local setting could not be read from a DC). These are
# NEVER turned into Nessus/risk findings - an un-assessable check must lower
# confidence, not raise the risk score.
# ---------------------------------------------------------------------------
$script:NotAssessed = New-Object System.Collections.Generic.List[object]

$script:ADAuditIsDC = $null

Function Get-FsmoRolesForServer {
    [CmdletBinding()]
    param([string]$ServerHostnameOrFqdn)

    if ([string]::IsNullOrWhiteSpace($ServerHostnameOrFqdn)) { return @() }
    $needle = $ServerHostnameOrFqdn.Trim().TrimEnd('.').ToLowerInvariant()
    $shortNeedle = ($needle -split '\.')[0]

    $roles = @()
    try {
        $forest = Get-ADForest -ErrorAction Stop
        if ($forest) {
            foreach ($pair in @(
                @{ N='SchemaMaster';        V=$forest.SchemaMaster },
                @{ N='DomainNamingMaster';  V=$forest.DomainNamingMaster }
            )) {
                if ($pair.V) {
                    $v = $pair.V.ToString().ToLowerInvariant().TrimEnd('.')
                    $vShort = ($v -split '\.')[0]
                    if ($v -eq $needle -or $vShort -eq $shortNeedle) { $roles += $pair.N }
                }
            }
        }
    } catch { }
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        if ($domain) {
            foreach ($pair in @(
                @{ N='PDCEmulator';          V=$domain.PDCEmulator },
                @{ N='RIDMaster';            V=$domain.RIDMaster },
                @{ N='InfrastructureMaster'; V=$domain.InfrastructureMaster }
            )) {
                if ($pair.V) {
                    $v = $pair.V.ToString().ToLowerInvariant().TrimEnd('.')
                    $vShort = ($v -split '\.')[0]
                    if ($v -eq $needle -or $vShort -eq $shortNeedle) { $roles += $pair.N }
                }
            }
        }
    } catch { }
    return ,$roles
}

Function Resolve-ServerHintFromError {
    [CmdletBinding()]
    param([string]$ErrorMessage)

    if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { return @() }
    $hints = New-Object System.Collections.Generic.List[string]

    foreach ($pat in @(
        "(?i)server\s+'([^']+)'",
        '(?i)server\s+"([^"]+)"',
        '(?i)on\s+server\s+([A-Za-z0-9_\-\.]+)',
        '(?i)from\s+server\s+([A-Za-z0-9_\-\.]+)',
        '(?i)computer\s+''([^'']+)''',
        '(?i)host\s+([A-Za-z0-9_\-\.]+)',
        '(?i)\\\\([A-Za-z0-9_\-\.]+)\\',
        '(?i)to\s+([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-\.]+)'
    )) {
        foreach ($m in [regex]::Matches($ErrorMessage, $pat)) {
            if ($m.Groups.Count -gt 1) {
                $val = $m.Groups[1].Value.Trim()
                if ($val -and $val -notmatch '^\s*$') { $hints.Add($val) | Out-Null }
            }
        }
    }
    return ,(@($hints | Sort-Object -Unique))
}

Function Test-IsConnectionError {
    [CmdletBinding()]
    param([string]$ErrorMessage, [string]$ErrorType)
    if (-not $ErrorMessage) { return $false }
    if ($ErrorMessage -match '(?i)\b(rpc|the rpc server is unavailable|cannot find|could not contact|server is not operational|cannot connect|connection (refused|timed out|reset|failed)|network path was not found|firewall|unreachable|0x80004005|access (is )?denied|no logon servers|target principal name is incorrect)\b') { return $true }
    if ($ErrorType -match '(?i)CimException|RpcException|RemoteException|DirectoryServerDownException|ActiveDirectoryServerDownException|EndpointNotFound') { return $true }
    return $false
}

Function Register-AuditFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory)][string]$Name,
        [string]$Description,
        [string]$Switch,
        [string]$Prefix = '    [!] STEP FAILED'
    )

    $errMsg  = $ErrorRecord.Exception.Message
    $errType = $ErrorRecord.Exception.GetType().FullName
    $isConn  = Test-IsConnectionError -ErrorMessage $errMsg -ErrorType $errType

    $serverHints = Resolve-ServerHintFromError -ErrorMessage $errMsg
    $fsmoEntries = New-Object System.Collections.Generic.List[string]
    foreach ($hint in $serverHints) {
        $rolesForHost = Get-FsmoRolesForServer -ServerHostnameOrFqdn $hint
        if ($rolesForHost.Count -gt 0) {
            $fsmoEntries.Add("$hint = [$($rolesForHost -join ', ')]") | Out-Null
        }
    }

    $script:CheckFailures.Add([pscustomobject]@{
        Time                = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        CheckName           = $Name
        Switch              = $Switch
        Description         = if ($Description) { $Description } else { $Name }
        ErrorType           = $errType
        ErrorMessage        = $errMsg
        IsConnectionIssue   = $isConn
        ServerHints         = ($serverHints -join ', ')
        FsmoOnFailedServers = ($fsmoEntries -join '; ')
        ScriptStackTrace    = ([string]$ErrorRecord.ScriptStackTrace)
    }) | Out-Null

    Write-Both ("{0} ({1}): {2}" -f $Prefix, $Name, $errMsg)
    if ($isConn) {
        Write-Both "    [!] Reason: connection / RPC / firewall / authentication issue with an AD or DNS server."
    }
    if ($serverHints.Count -gt 0) {
        Write-Both ("    [!] Suspected server(s) from error: {0}" -f ($serverHints -join ', '))
    }
    if ($fsmoEntries.Count -gt 0) {
        foreach ($entry in $fsmoEntries) {
            Write-Both "    [!] FSMO holder: $entry"
        }
    } elseif ($isConn -and $serverHints.Count -gt 0) {
        Write-Both "    [!] FSMO lookup: server(s) above do not appear to currently hold FSMO roles (or AD lookup also failed)."
    }
}

Function Invoke-AuditCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Body,
        [string]$Switch
    )

    Write-Both "[*] $Description"
    try {
        & $Body
    } catch {
        Register-AuditFailure -ErrorRecord $_ -Name $Name -Description $Description -Switch $Switch -Prefix '    [!] CHECK FAILED'
        Write-Both "    [*] Continuing with remaining checks..."
    }
}

Function Invoke-AuditStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body,
        [string]$Switch
    )

    try {
        & $Body
    } catch {
        Register-AuditFailure -ErrorRecord $_ -Name $Name -Switch $Switch -Prefix '    [!] STEP FAILED'
    }
}

Function Write-CheckFailuresReport {
    [CmdletBinding()]
    param([string]$BaseRoot)

    if (-not $script:CheckFailures -or $script:CheckFailures.Count -eq 0) { return }

    $rawDir = Get-RawSourceDataDir
    if (-not (Test-Path -LiteralPath $rawDir)) {
        New-Item -ItemType Directory -Path $rawDir -Force | Out-Null
    }
    $txtPath = Join-Path $rawDir 'connection_failures.txt'
    $csvPath = Join-Path $rawDir 'connection_failures.csv'

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(' AUDIT CHECK FAILURES (script continued past these)')
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(" Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine(" Total failures: $($script:CheckFailures.Count)")
    [void]$sb.AppendLine('---------------------------------------------------------------------')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('What this file means:')
    [void]$sb.AppendLine(' - One or more audit checks could not complete (typically because an AD')
    [void]$sb.AppendLine('   or DNS server was unreachable, RPC was blocked, the user lacked')
    [void]$sb.AppendLine('   permissions, or a required PowerShell module was missing).')
    [void]$sb.AppendLine(' - The script kept running and finished every other check. Anything that')
    [void]$sb.AppendLine('   appears below was SKIPPED, so the corresponding section of the HTML')
    [void]$sb.AppendLine('   report may be incomplete.')
    [void]$sb.AppendLine(' - For each failure we record the suspected target server (parsed from')
    [void]$sb.AppendLine('   the error message) and which FSMO role(s) that server holds, so you')
    [void]$sb.AppendLine('   can decide whether to retry from a different DC.')
    [void]$sb.AppendLine('')

    $i = 0
    foreach ($f in $script:CheckFailures) {
        $i++
        [void]$sb.AppendLine("[$i] $($f.CheckName)  ($($f.Time))")
        [void]$sb.AppendLine("    Description : $($f.Description)")
        if ($f.Switch) { [void]$sb.AppendLine("    Switch      : -$($f.Switch)") }
        [void]$sb.AppendLine("    Connection  : $(if($f.IsConnectionIssue){'YES (RPC / network / auth)'}else{'no - other error'})")
        [void]$sb.AppendLine("    Error type  : $($f.ErrorType)")
        [void]$sb.AppendLine("    Error       : $($f.ErrorMessage)")
        if ($f.ServerHints)         { [void]$sb.AppendLine("    Server hint : $($f.ServerHints)") }
        if ($f.FsmoOnFailedServers) { [void]$sb.AppendLine("    FSMO held   : $($f.FsmoOnFailedServers)") }
        [void]$sb.AppendLine("    Effect      : results for this check are MISSING from the report.")
        [void]$sb.AppendLine('')
    }

    Set-Content -LiteralPath $txtPath -Value $sb.ToString() -Encoding UTF8
    $script:CheckFailures | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    Write-Both ""
    Write-Both "[!] $($script:CheckFailures.Count) check(s) failed during this run - see connection_failures.txt"

    try {
        Write-Nessus-Finding "AuditCheckFailures" "KB1300" ([System.IO.File]::ReadAllText($txtPath))
    } catch {}
}

Function Test-ADAuditIsDomainController {
    # Returns $true if the host running the script is itself a Domain Controller.
    # Cached for the run. Used so host-local checks (registry/SMB config) know
    # whether reading the LOCAL machine is meaningful or whether they must target
    # a DC remotely (or report "could not assess").
    if ($null -ne $script:ADAuditIsDC) { return $script:ADAuditIsDC }
    try {
        # Win32_OperatingSystem.ProductType: 1=Workstation, 2=Domain Controller, 3=Member/Standalone Server
        $pt = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType
        $script:ADAuditIsDC = ($pt -eq 2)
    }
    catch {
        try {
            # DomainRole: 4=Backup DC, 5=Primary DC
            $role = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
            $script:ADAuditIsDC = ($role -in 4, 5)
        }
        catch { $script:ADAuditIsDC = $false }
    }
    return $script:ADAuditIsDC
}

Function Register-ADAuditNotAssessed {
    # Records a check (or a per-target portion of a check) that could NOT be
    # assessed, with the reason. Deliberately does NOT emit a Nessus/risk finding
    # so an un-assessable check never inflates the risk score.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Reason,
        [string]$Switch,
        [string]$Target,
        [switch]$RequiresRemotePS
    )
    $script:NotAssessed.Add([pscustomobject]@{
        Time             = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        CheckName        = $Name
        Switch           = $Switch
        Target           = $Target
        Reason           = $Reason
        RequiresRemotePS = [bool]$RequiresRemotePS
    }) | Out-Null
    $tgt = if ($Target) { " [$Target]" } else { "" }
    Write-Both "    [~] NOT ASSESSED ($Name$tgt): $Reason"
}

Function Get-ADAuditRemoteRegistryDword {
    # Reads a single HKLM REG_DWORD from a (possibly remote) host via the StdRegProv
    # WMI provider, trying DCOM first then WSMan/WinRM. Returns a tri-state hashtable:
    #   Success=$true,  Value=<int>  -> reached the host, value is set
    #   Success=$true,  Value=$null  -> reached the host, value is NOT set
    #   Success=$false, Error=<msg>  -> could not reach/query the host (=> NotAssessed)
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$ValueName
    )
    $HKLM = [uint32]2147483650
    $result = @{ Success = $false; Value = $null; Error = $null }
    $regArgs = @{ hDefKey = $HKLM; sSubKeyName = $SubKey; sValueName = $ValueName }
    $isLocal = $ComputerName -in @('.', 'localhost', $env:COMPUTERNAME)

    if ($isLocal) {
        try {
            $r = Invoke-CimMethod -Namespace 'root/default' -ClassName StdRegProv -MethodName GetDWORDValue -Arguments $regArgs -ErrorAction Stop
            # Invoke-CimMethod does not throw on provider-level failures; StdRegProv
            # reports them via ReturnValue (1/2 = value/key not present, 5 = access
            # denied, other = read failure). Only 1/2 mean 'value is not set'.
            if ($r.ReturnValue -eq 0) { $result.Success = $true; $result.Value = $r.uValue }
            elseif ($r.ReturnValue -in 1, 2) { $result.Success = $true; $result.Value = $null }
            else { $result.Error = "StdRegProv GetDWORDValue failed (ReturnValue=$($r.ReturnValue))" }
        }
        catch { $result.Error = $_.Exception.Message }
        return $result
    }

    foreach ($proto in @('Dcom', 'Wsman')) {
        $session = $null
        try {
            $opt = New-CimSessionOption -Protocol $proto
            $session = New-CimSession -ComputerName $ComputerName -SessionOption $opt -ErrorAction Stop
            $r = Invoke-CimMethod -CimSession $session -Namespace 'root/default' -ClassName StdRegProv -MethodName GetDWORDValue -Arguments $regArgs -ErrorAction Stop
            if ($r.ReturnValue -eq 0) { $result.Success = $true; $result.Value = $r.uValue; $result.Error = $null }
            elseif ($r.ReturnValue -in 1, 2) { $result.Success = $true; $result.Value = $null; $result.Error = $null }
            else { $result.Success = $false; $result.Value = $null; $result.Error = "StdRegProv GetDWORDValue failed (ReturnValue=$($r.ReturnValue))" }
            if ($result.Success) { return $result }
        }
        catch { $result.Error = $_.Exception.Message }
        finally { if ($session) { $session | Remove-CimSession -ErrorAction SilentlyContinue } }
    }
    return $result
}

Function Write-NotAssessedReport {
    # Writes the "could not assess" artifacts (not_assessed.txt/.csv) at end of run.
    # Surfaced as informational only - never scored.
    [CmdletBinding()]
    param([string]$BaseRoot)

    if (-not $script:NotAssessed -or $script:NotAssessed.Count -eq 0) { return }

    $rawDir = Get-RawSourceDataDir
    if (-not (Test-Path -LiteralPath $rawDir)) {
        New-Item -ItemType Directory -Path $rawDir -Force | Out-Null
    }
    $txtPath = Join-Path $rawDir 'not_assessed.txt'
    $csvPath = Join-Path $rawDir 'not_assessed.csv'

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(' CHECKS / TARGETS THAT COULD NOT BE ASSESSED')
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(" Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine(" Total: $($script:NotAssessed.Count)")
    [void]$sb.AppendLine('---------------------------------------------------------------------')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('What this file means:')
    [void]$sb.AppendLine(' - These checks (or specific DC targets) could NOT be evaluated, usually')
    [void]$sb.AppendLine('   because this host is not a DC and remote PowerShell/CIM to a DC was')
    [void]$sb.AppendLine('   unavailable, a DC was unreachable, or a required data source was absent.')
    [void]$sb.AppendLine(' - These are NOT findings and do NOT raise the risk score. They indicate')
    [void]$sb.AppendLine('   REDUCED COVERAGE: the corresponding posture is unknown, not "good".')
    [void]$sb.AppendLine(' - To assess them, re-run from a Domain Controller, or enable remote')
    [void]$sb.AppendLine('   PowerShell (WinRM) / DCOM to the DCs from this management host.')
    [void]$sb.AppendLine('')

    $i = 0
    foreach ($n in $script:NotAssessed) {
        $i++
        [void]$sb.AppendLine("[$i] $($n.CheckName)  ($($n.Time))")
        if ($n.Switch) { [void]$sb.AppendLine("    Switch          : -$($n.Switch)") }
        if ($n.Target) { [void]$sb.AppendLine("    Target          : $($n.Target)") }
        [void]$sb.AppendLine("    Requires remote : $(if($n.RequiresRemotePS){'YES (remote PowerShell/CIM to a DC)'}else{'no'})")
        [void]$sb.AppendLine("    Reason          : $($n.Reason)")
        [void]$sb.AppendLine('')
    }

    Set-Content -LiteralPath $txtPath -Value $sb.ToString() -Encoding UTF8
    $script:NotAssessed | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    Write-Both ""
    Write-Both "[~] $($script:NotAssessed.Count) item(s) could not be assessed (reduced coverage, not risk) - see not_assessed.txt"
}

Function Write-Nessus-Header() {
    #Creates nessus XML file header
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<?xml version=`"1.0`" ?><AdAudit>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<Report name=`"$env:ComputerName`" xmlns:cm=`"http://www.nessus.org/cm`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportHost name=`"$env:ComputerName`"><HostProperties></HostProperties>"
}

# Maps ADAudit KB identifiers to a Nessus severity tier so the exported
# .nessus file can be triaged by risk instead of every item landing on "Low".
# Anything not listed defaults to Medium; callers may override per finding by
# passing -Severity (Critical/High/Medium/Low/Info).
$script:NessusSeverityByKB = @{
    'KB510' = 'Critical'; 'KB1200' = 'Critical'; 'KB253' = 'Critical'; 'KB611' = 'Critical'
    'KB720' = 'Critical'; 'KB1095' = 'Critical'; 'KB1096' = 'Critical'; 'KB1205' = 'Critical'
    'KB329' = 'Critical'
    'KB842' = 'High'; 'KB551' = 'High'; 'KB426' = 'High'; 'KB427' = 'High'; 'KB428' = 'High'
    'KB262' = 'High'; 'KB263' = 'High'; 'KB81' = 'High'; 'KB290' = 'High'; 'KB479' = 'High'
    'KB995' = 'High'; 'KB1101' = 'High'; 'KB1203' = 'High'; 'KB1204' = 'High'; 'KB258' = 'High'
    'KB250' = 'Medium'; 'KB251' = 'Medium'; 'KB254' = 'Medium'; 'KB259' = 'Medium'
    'KB500' = 'Medium'; 'KB546' = 'Medium'; 'KB547' = 'Medium'; 'KB549' = 'Medium'
    'KB550' = 'Medium'; 'KB552' = 'Medium'; 'KB1202' = 'Medium'; 'KB1310' = 'Medium'
    'KB309' = 'Medium'; 'KB1201' = 'Medium'
    'KB501' = 'Low'; 'KB1300' = 'Low'
}

function Get-NessusSeverityTuple([string]$Severity) {
    switch ($Severity) {
        'Critical' { return @{ Num = 4; Risk = 'Critical' } }
        'High'     { return @{ Num = 3; Risk = 'High' } }
        'Medium'   { return @{ Num = 2; Risk = 'Medium' } }
        'Low'      { return @{ Num = 1; Risk = 'Low' } }
        'Info'     { return @{ Num = 0; Risk = 'None' } }
        default    { return @{ Num = 2; Risk = 'Medium' } }
    }
}

Function Write-Nessus-Finding( [string]$pluginname, [string]$pluginid, [string]$pluginexample, [string]$Severity = '') {
    # Resolve severity: explicit override, else KB map, else Medium.
    if ([string]::IsNullOrWhiteSpace($Severity)) {
        $kb = ($pluginid -replace '[^A-Za-z0-9]', '')
        if ($script:NessusSeverityByKB.ContainsKey($kb)) { $Severity = $script:NessusSeverityByKB[$kb] }
        else { $Severity = 'Medium' }
    }
    $sev = Get-NessusSeverityTuple $Severity

    # Escape every value at write time so evidence text containing < > & " '
    # can never produce malformed XML (the previous post-hoc sanitizer could
    # not distinguish markup from content and left the file unparseable).
    $nameEsc = [System.Security.SecurityElement]::Escape([string]$pluginname)
    $idEsc = [System.Security.SecurityElement]::Escape([string]$pluginid)
    $exEsc = [System.Security.SecurityElement]::Escape([string]$pluginexample)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("<ReportItem port=`"0`" svc_name=`"`" protocol=`"`" severity=`"$($sev.Num)`" pluginID=`"ADAudit_$idEsc`" pluginName=`"$nameEsc`" pluginFamily=`"Windows`">")
    [void]$sb.AppendLine("<description>Active Directory audit finding: $nameEsc</description>")
    [void]$sb.AppendLine("<plugin_type>remote</plugin_type><risk_factor>$($sev.Risk)</risk_factor>")
    [void]$sb.AppendLine("<solution>Review the '$nameEsc' finding in the ADAudit report and remediate per its recommended action.</solution>")
    [void]$sb.AppendLine("<synopsis>ADAudit detected a potential issue: $nameEsc</synopsis>")
    [void]$sb.AppendLine("<plugin_output>$exEsc</plugin_output></ReportItem>")
    Add-Content -Path "$outputdir\adaudit.nessus" -Value $sb.ToString().TrimEnd()
}

Function Write-Nessus-Footer() {
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "</ReportHost></Report></AdAudit>"
}

Function Install-Dependencies {
    #Install optional dependency modules for the audit
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch { }

    Write-Both "    [+] Preparing optional dependency installation"

    try {
        if (Get-Command Install-PSResource -ErrorAction SilentlyContinue) {
            $repo = Get-PSResourceRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($repo -and -not $repo.Trusted) {
                Set-PSResourceRepository -Name PSGallery -Trusted -ErrorAction Stop
            }

            if (-not (Get-Module -ListAvailable -Name DSInternals)) {
                Install-PSResource -Name DSInternals -Scope CurrentUser -TrustRepository -ErrorAction Stop
            }
        }
        elseif (Get-Command Install-Module -ErrorAction SilentlyContinue) {
            $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($repo -and $repo.InstallationPolicy -eq 'Untrusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            }

            if (-not (Get-Module -ListAvailable -Name DSInternals)) {
                Install-Module -Name DSInternals -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
        }
        else {
            Write-Both "    [!] No supported PowerShell package manager was found. Install DSInternals manually."
            return
        }

        if (Import-ADAuditModule -Name DSInternals) {
            Write-Both "    [+] DSInternals module is available."
        }
        else {
            Write-Both "    [!] DSInternals installation completed, but the module could not be imported in the current session."
        }

        if (Get-Module -ListAvailable -Name LAPS) {
            Write-Both "    [+] Windows LAPS module is available on this host."
        }
        elseif (Get-Module -ListAvailable -Name 'AdmPwd.PS') {
            Write-Both "    [+] Legacy Microsoft LAPS module (AdmPwd.PS) is available on this host."
        }
        else {
            Write-Both "    [*] No LAPS module was found. Windows LAPS ships with supported Windows builds; legacy Microsoft LAPS uses AdmPwd.PS."
        }
    }
    catch {
        Write-Both "    [!] Failed to install optional dependencies. $($_.Exception.Message)"
    }
}


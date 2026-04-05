<#
    .NOTES
        Author       : phillips321.co.uk
        updated and modified by Keberneth
        Creation Date: 16/08/2018
        Script Name  : ADAudit.ps1
    .SYNOPSIS
        PowerShell Script to perform a quick AD audit
    .DESCRIPTION
        o Compatibility :
            * PowerShell 7.x on Windows (with conditional Windows PowerShell compatibility only for legacy modules that still require it)
            * Target platform: Windows Server 2025 and supported RSAT-equipped Windows management hosts
            * All languages (you may need to adjust $AdministratorTranslation variable)
        o Requirements :
            * ActiveDirectory PowerShell module (installed with RSAT tools)
            * DnsServer PowerShell module (installed with DNS Server role)
            * Windows LAPS PowerShell module (LAPS) for Windows LAPS estates, or AdmPwd.PS for legacy Microsoft LAPS
            * DSInternals and NuGet PowerShell module, installed by script if -installdeps switch is used)
              Offline installation help using ADAudit-run.ps1 script
        o Changelog :
            [X] Version 8.2 - 05/04/2026
                Fixed KRBTGT password age scoring: no longer adds risk points when age is within 180-day baseline
                Fixed password quality account counts: header/footer lines in pq_*.txt files were inflating counts
                    (added Get-PqAccountLines helper to extract only DOMAIN\account entries)
                Improved no-password check: cross-references with Users.csv to differentiate enabled vs disabled accounts
                    Enabled accounts with no password remain Critical; all-disabled accounts downgraded to Low severity
                Improved KRBTGT age parsing to handle Observed column format when AgeDays column is absent
            [ ] Version 8.1 - 02/04/2026
                Added Get-KerberosUnconstrainedDelegation function to detect non-DC accounts with unconstrained delegation
                Added Get-GMSAStatus function to identify service accounts not using Group Managed Service Accounts
                Added Get-TombstoneLifetime function to check AD tombstone lifetime configuration
                Added Get-PrintSpoolerOnDCs function to detect Print Spooler running on domain controllers
                Added Get-SMBSigningStatus function to check SMB signing enforcement on domain controllers
                Added audit metadata to Management Report (script version, running account, start/end time)
                Added Findings by Category breakdown table to Management Report
                Evidence files now written directly to Raw Data\Source instead of root output directory
                Removed duplicate nessus file output (sanitization now in-place)
                Added finding definitions, context, and recommendations for all new checks
                Added new report categories: Delegation and service accounts, DC hardening
                Multiple bug fixes: broken string interpolation, wrong NTLM variable, duplicate encryption type,
                    typo in web_enrollment variable, erroneous @ prefix in DN strings, duplicate code and comments
                Added Split-PasswordQualityReport function to split password_quality.txt into category files:
                    pq_reversible_encryption.txt, pq_lm_hashes.txt, pq_no_password.txt,
                    pq_dictionary_passwords.txt, pq_historical_dictionary.txt, pq_duplicate_passwords.txt,
                    pq_default_computer_passwords.txt, pq_missing_aes_keys.txt, pq_no_preauth.txt,
                    pq_des_only.txt, pq_admin_delegation.txt, pq_password_never_expires.txt,
                    pq_password_not_required.txt, pq_kerberoastable.txt
                Each split password quality category now generates its own finding in both reports with
                    appropriate severity scoring (LM hashes, no password, dictionary, DES-only = Critical;
                    default computer passwords, admin delegation, password not required = High;
                    missing AES keys = Medium)
                Added finding definitions (category, why-it-matters, recommendation) for all new findings
                Original password_quality.txt is retained alongside the split files
            [ ] Version 8.0 - 22/03/2026
                Converted AdAudit.ps1 to PowerShell 7
                Windows LAPS + legacy Microsoft LAPS support
                CIM/DCOM remote compatibility and Windows Server 2025 functional-level awareness
            [ ] Version 7.2 - 03/03/2026
                All reports have been remade
            [ ] Version 7.1.6 - 21/01/2026
                Added function for checking overlapping group memberships.
            [ ] Version 7.1.5 - 21/01/2026
                Management report added to the script
                Minor fixes to multiple functions
            [ ] Version 7.1.4 - 28/12/2025
                Removed ntds export function.
                Fixed bug with Win32 FileTime
            [ ] Version 7.1.3 - 28/12/2025
                Added check for tier overlapping accounts in privileged groups.
            [ ] Version 7.1.2 - 26/12/2025
                Added inactive computers report.
            [ ] Version 7.1.1 - 25/12/2025
                Added Windows Update audit for high risk missing updates.
            [ ] Version 7.1.0 - 24/12/2025
                Added Get-DNSZoneInsecure function to check for DNS zones allowing insecure updates.
                Added DNS zone report.
                Added deligated permissions report.
                Improved reporting
            [] Version 7.0.1 - 20/11/2025
                Added explination for "These accounts are susceptible to the Kerberoasting attack"
            [ ] Version 7.0 - 20/11/2025
                Added offline installation of DSInternals and NuGet.
                Added comments for Password audit files and kerberos and ciphers checks.
                Added Audit reports for delegated permissions as separate script.
                Now posible to run Audit from an other server with RSAT tools installed. (Need to run powershell using domain admin account)
            [ ] Version 6.0 - 22/12/2023
                * Fix "BUILTIN\$Administrators" quoting, in order to use $Administrators variable when script enumerates Default Domain Controllers Policy
                * Fix RDP logon policy check in the same function above
            [ ] Version 5.9 - 20/12/2023
                * Contempled all cases of DCs with weak Kerberos algorithm and saves finding according to them
                * Fix "Cannot get time source for DC" as a warning
            [ ] Version 5.8 - 27/03/2023
                * Updated switches, users can now select functions, or run -all with exclusions
                * Added LDAP security checks 
            [ ] Version 5.7 - 11/03/2023
                * Added ACL Checks
            [ ] Version 5.6 - 09/03/2023
                * Added kerberoasting checks
                * Added ASREProasting Checks
            [ ] Version 5.5 - 08/03/2023
                * ADCS vulnerabilities added, checks for ESC1,2,3,4 and 8.
            [ ] Version 5.4 - 16/08/2022
                * Added nessus output tags for LAPS
                * Added nessus output for GPO issues
            [ ] Version 5.3 - 07/03/2022
                * Added SamAccountName to Get-PrivilegedGroupMembership output
                * Swapped some write-host to write-both so it's captured in the consolelog.txt
            [ ] Version 5.2 - 28/01/2022
                * Enhanced Get-LAPSStatus
                * Added news checks (AD services + Windows Update + NTP source + Computer/User container + RODC + Locked accounts + Password Quality + SYSVOL & NETLOGON share presence)
                * Added support for WS 2022
                * Fix OS version difference check for WS 2008
                * Fix Write-Progress not disappearing when done
            [ ] Version 5.1
                * Added check for newly created users and groups
                * Added check for replication mechanism
                * Added check for Recycle Bin
                * Fix ProtectedUsers for WS 2008
            [ ] Version 5.0
                * Make the script compatible with other language than English
                * Fix the cpassword search in GPO
                * Fix Get-ACL bad syntax error
                * Fix Get-DNSZoneInsecure for WS 2008
            [ ] Version 4.9
                * Bug fix in checking password comlexity
            [ ] Version 4.8
                * Added checks for vista, win7 and 2008 old operating systems
                * Added insecure DNS zone checks
            [ ] Version 4.7
                * Added powershel-v2 suport and fixed array issue
            [ ] Version 4.6
                * Fixed potential division by zero
            [ ] Version 4.5
                * PR to resolve count issue when count = 1
            [ ] Version 4.4
                * Reinstated nessus fix and put output in a list for findings
                * Changed Get-AdminSDHolders with Get-PrivilegedGroupAccounts
            [ ] Version 4.3
                * Temp fix with nessus output
            [ ] Version 4.2
                * Bug fix on cpassword count
            [ ] Version 4.1
                * Loads of fixes
                * Works with Powershellv2 again now
                * Filtered out disabled accounts
                * Improved domain trusts checking
                * OUperms improvements and filtering
                * Check for w2k
                * Fixed typos/spelling and various other fixes
            [ ] Version 4.0
                * Added XML output for import to CheckSecCanopy
            [ ] Version 3.5
                * Added KB more references for internal use
            [ ] Version 3.4
                * Added KB references for internal use
            [ ] Version 3.3
                * Added a greater level of accuracy to Inactive Accounts (thanks exceedio)
            [ ] Version 3.2
                * Added search for DCs not owned by Domain Admins group
            [ ] Version 3.1
                * Added progress to functions that have count
                * Added check for transitive trusts
            [ ] Version 3.0
                * Added ability to choose functions before runtime
                * Cleaned up get-ouperms output
            [ ] Version 2.5
                * Bug fixes to version check for 2012R2 or greater specific checks
            [ ] Version 2.4
                * Forked project
                * Added Get-OUPerms, Get-LAPSStatus, Get-AdminSDHolders, Get-ProtectedUsers and Get-AuthenticationPoliciesAndSilos functions
                * Also added FineGrainedPasswordPolicies to Get-PasswordPolicy and changed order slightly
            [ ] Version 2.3
                * Added more useful user output to .txt files (Cheers DK)
            [ ] Version 2.2
                * Minor typo fix
            [ ] Version 2.1
                * Added check for null sessions
            [ ] Version 2.0
                * Multiple Additions and knocked off lots of the todo list
            [ ] Version 1.9
                * Fixed bug, that used Administrator account name instead of UID 500 and a bug with inactive accounts timespan
            [ ] Version 1.8
                * Added check for last time 'Administrator' account logged on
            [ ] Version 1.6
                * Added Get-FunctionalLevel and krbtgt password last changed check
            [ ] Version 1.5
                * Added Get-HostDetails to output simple info like username, hostname, etc...
            [ ] Version 1.4
                * Added Get-WinVersion version to assist with some checks (SMBv1 currently)
            [ ] Version 1.3
                * Added XML output for GPO (for offline processing using grouper https://github.com/l0ss/Grouper/blob/master/grouper.psm1)
            [ ] Version 1.2
                * Added check for modules
            [ ] Version 1.1
                * Fixed bug where SYSVOL research returns empty
            [ ] Version 1.0
                * First release
    .EXAMPLE
        PS> ADAudit.ps1 -installdeps -all
        Install external features and launch all checks
    .EXAMPLE
        PS> ADAudit.ps1 -all
        Launch all checks (but do not install external modules)
    .EXAMPLE
        PS> ADAudit.ps1 -installdeps
        Installs optionnal features (DSInternals)
    .EXAMPLE
        PS> ADAudit.ps1 -hostdetails -domainaudit
        Retrieves hostname and other useful audit info
        Retrieves information about the AD such as functional level
#>
[CmdletBinding()]
Param (
    [switch]$installdeps = $false,
    [switch]$hostdetails = $false,
    [switch]$domainaudit = $false,
    [switch]$trusts = $false,
    [switch]$accounts = $false,
    [switch]$InactiveComputers = $false,
    [switch]$passwordpolicy = $false,
    [switch]$oldboxes = $false,
    [switch]$gpo = $false,
    [switch]$ouperms = $false,
    [switch]$laps = $false,
    [switch]$authpolsilos = $false,
    [switch]$insecurednszone = $false,
    [Alias('dns-zone')][switch]$dnszone = $false,
    [string]$DnsZoneOutputRoot,
    [switch]$DnsIncludeRecordCounts = $false,
    [switch]$DnsIncludeSystemZones = $false,
    [switch]$recentchanges = $false,
    [switch]$adcs = $false,
    [switch]$spn = $false,
    [switch]$asrep = $false,
    [switch]$acl = $false,
    [switch]$ldapsecurity = $false,
    [switch]$dataextract = $false,
    [Alias('delegated-permissions','delegated')][switch]$delegatedpermissions = $false,
    [string]$DelegatedOutputRoot,
    [switch]$DelegIncludeSystemTrustees = $false,
    [switch]$DelegIncludeDeny = $false,
    [switch]$DelegIncludeInherited = $false,
    [string]$DelegServer,
    [switch]$highrisk = $false,
    [switch]$overlappinggroups = $false,
    [switch]$all = $false,
    [string[]]$exclude = @(),
    [string]$select,
    [switch]$KeepLegacyArtifacts = $false
)

$selectedChecks = @()
if ($select) { $selectedChecks = $select.Split(',') }

$versionnum = "v8.2"
$AdministratorTranslation = @("Administrator", "Administrateur", "Administrador")#If missing put the default Administrator name for your own language here

$script:ADAuditIsWindows = ($env:OS -eq 'Windows_NT')
$script:ADAuditIsPowerShell7Plus = ($PSVersionTable.PSVersion.Major -ge 7)

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

    switch ($Mode) {
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

    try {
        $parsedVersion = [version]$version
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 26000) { return 10 }
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 20348) { return 9 }
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 17763) { return 8 }
        if ($parsedVersion.Major -eq 10) { return 7 }
    }
    catch { }

    return $null
}


Function Get-Variables() {
    #Retrieve group names and OS version
    $script:OSVersion = (Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
    $script:Administrators = (Get-ADGroup -Identity S-1-5-32-544).SamAccountName
    $script:Users = (Get-ADGroup -Identity S-1-5-32-545).SamAccountName
    $script:DomainAdminsSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-512"
    $script:DomainUsersSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-513"
    $script:DomainControllersSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-516"
    $script:SchemaAdminsSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-518"
    $script:EnterpriseAdminsSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-519"
    $script:EveryOneSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
    $script:EntrepriseDomainControllersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-9"
    $script:AuthenticatedUsersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-11"
    $script:SystemSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
    $script:LocalServiceSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-19"
    $script:DomainAdmins = (Get-ADGroup -Identity $DomainAdminsSID).SamAccountName
    $script:DomainUsers = (Get-ADGroup -Identity $DomainUsersSID).SamAccountName
    $script:DomainControllers = (Get-ADGroup -Identity $DomainControllersSID).SamAccountName
    $script:SchemaAdmins = (Get-ADGroup -Identity $SchemaAdminsSID).SamAccountName
    $script:EnterpriseAdmins = (Get-ADGroup -Identity $EnterpriseAdminsSID).SamAccountName
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
summary::before{content:'â–¸';font-size:1rem;transition:transform .15s ease;display:inline-block}
details[open]>summary::before{transform:rotate(90deg)}
details>div,details>.detail-body{padding:0 20px 16px}
details table{box-shadow:none;margin:0}

/* List styling */
ul.link-list{list-style:none;padding:0}
ul.link-list li{padding:8px 14px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px}
ul.link-list li:last-child{border-bottom:none}
ul.link-list li::before{content:'ðŸ“„';font-size:1rem}

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
Function Get-EvidencePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )
    $dir = Get-RawSourceDataDir
    return (Join-Path $dir $FileName)
}
Function Write-Nessus-Header() {
    #Creates nessus XML file header
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<?xml version=`"1.0`" ?><AdAudit>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<Report name=`"$env:ComputerName`" xmlns:cm=`"http://www.nessus.org/cm`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportHost name=`"$env:ComputerName`"><HostProperties></HostProperties>"
}
Function Write-Nessus-Finding( [string]$pluginname, [string]$pluginid, [string]$pluginexample) {
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportItem port=`"0`" svc_name=`"`" protocol=`"`" severity=`"0`" pluginID=`"ADAudit_$pluginid`" pluginName=`"$pluginname`" pluginFamily=`"Windows`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<description>There's an issue with $pluginname</description>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<plugin_type>remote</plugin_type><risk_factor>Low</risk_factor>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<solution>CCS Recommends fixing the issues with $pluginname on the host</solution>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<synopsis>There's an issue with the $pluginname settings on the host</synopsis>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<plugin_output>$pluginexample</plugin_output></ReportItem>"
}
Function Write-Nessus-Footer() {
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "</ReportHost></Report></AdAudit>"
}
Function Get-DNSZoneInsecure {
    # Check DNS zones allowing insecure updates on all DNS servers in the domain

    try {
        Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null
        Import-ADAuditModule -Name DnsServer -Required | Out-Null
    }
    catch {
        Write-Both "    [!] Could not load required modules (ActiveDirectory/DnsServer). $_"
        return
    }

    # Get all domain controllers; we'll probe each one to see if DNS is installed
    try {
        $dcList = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
    }
    catch {
        Write-Both "    [!] Failed to enumerate domain controllers from AD. $_"
        return
    }

    if (-not $dcList -or $dcList.Count -eq 0) {
        Write-Both "    [-] No domain controllers found."
        return
    }

    $globalInsecureZonesFile = Get-EvidencePath 'insecure_dns_zones.txt'
    if (Test-Path $globalInsecureZonesFile) {
        Remove-Item $globalInsecureZonesFile -Force
    }

    $totalcount = 0

    foreach ($dnsServer in $dcList) {

        Write-Both "    [*] Checking potential DNS server: $dnsServer"

        # Optional: check remote OS version to skip 2008 if needed
        $skipServer = $false
        try {
            $os = Get-ADAuditCimInstance -ClassName Win32_OperatingSystem -ComputerName $dnsServer -UseWsmanFallback
            $osCaption = $os.Caption
            if ($osCaption -like "Windows Server 2008*") {
                Write-Both "        [-] $dnsServer is Windows Server 2008, skipping Get-DNSZoneInsecure check on this server."
                $skipServer = $true
            }
        }
        catch {
            Write-Both "        [!] Could not determine OS version for $dnsServer, continuing anyway. $_"
        }

        if ($skipServer) { continue }

        # Try to query DNS zones; if DNS role is not installed, this will fail and we skip
        try {
            $insecurezones = Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop |
                             Where-Object { $_.DynamicUpdate -like '*nonsecure*' }
        }
        catch {
            Write-Both "        [-] $dnsServer does not appear to have the DNS role (or access failed), skipping. $_"
            continue
        }

        if ($insecurezones) {
            foreach ($insecurezone in $insecurezones) {
                Add-Content -Path $globalInsecureZonesFile -Value (
"@The DNS Zone {0} on DNS server {1} allows insecure updates ({2})" -f `
                    $insecurezone.ZoneName, $dnsServer, $insecurezone.DynamicUpdate
                )
                $totalcount++
            }
        }
        else {
            Write-Both "        [-] No insecure DNS zones found on $dnsServer."
        }
    }

    if ($totalcount -gt 0) {
        Write-Both "    [!] There were $totalcount DNS zones configured to allow insecure updates (KB842) across all DNS servers."
        Write-Nessus-Finding "InsecureDNSZone" "KB842" ([System.IO.File]::ReadAllText($globalInsecureZonesFile))
    }
    else {
        Write-Both "    [-] No insecure DNS zones found on any discovered DNS server."
    }
}
Function Get-OUPerms {
    #Check for non-standard perms for authenticated users, domain users, users and everyone groups
    $count = 0
    $progresscount = 0
    $objects = (Get-ADObject -Filter *)
    $totalcount = ($objects | Measure-Object | Select-Object Count).count
    foreach ($object in $objects) {
        if ($totalcount -eq 0) { break }
        $progresscount++
        Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
        try {
            $output = (Get-Acl -Path "AD:$object" -ErrorAction Stop).Access | Where-Object { ($_.IdentityReference -eq "$AuthenticatedUsers") -or ($_.IdentityReference -eq "$EveryOne") -or ($_.IdentityReference -like "*\$DomainUsers") -or ($_.IdentityReference -eq "BUILTIN\$Users") } | Where-Object { ($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'GenericExecute') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.ActiveDirectoryRights -ne 'ListObject') -and ($_.ActiveDirectoryRights -ne 'ListChildren') -and ($_.ActiveDirectoryRights -ne 'ListChildren, ReadProperty, ListObject') -and ($_.ActiveDirectoryRights -ne 'ReadProperty, GenericExecute') -and ($_.AccessControlType -ne 'Deny') }
        } catch {
            $output = $null
        }
        if ($output -ne $null) {
            $count++
            Add-Content -Path (Get-EvidencePath 'ou_permissions.txt') -Value "OU: $object"
            Add-Content -Path (Get-EvidencePath 'ou_permissions.txt') -Value "[!] Rights: $($output.IdentityReference) $($output.ActiveDirectoryRights) $($output.AccessControlType)"
        }
    }
    Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] Issue identified, see $outputdir\ou_permissions.txt"
        Write-Nessus-Finding "OUPermissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'ou_permissions.txt')))
    }
}
Function Get-LAPSStatus {
    #Check for presence of Windows LAPS and/or legacy Microsoft LAPS in the forest
    $schemaNC = (Get-ADRootDSE).SchemaNamingContext
    $legacySchema = $null
    $windowsSchema = $null

    try {
        $legacySchema = Get-ADObject -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwd)' -SearchBase $schemaNC -ErrorAction Stop
    }
    catch { }

    try {
        $windowsSchema = Get-ADObject -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' -SearchBase $schemaNC -ErrorAction Stop
    }
    catch { }

    $legacyDetected = ($null -ne $legacySchema)
    $windowsDetected = ($null -ne $windowsSchema)

    if (-not $legacyDetected -and -not $windowsDetected) {
        Write-Both "    [!] LAPS Not Installed in domain (KB258)"
        Write-Nessus-Finding "LAPSMissing" "KB258" "LAPS Not Installed in domain"
        return
    }

    if ($windowsDetected) {
        Write-Both "    [+] Windows LAPS schema detected in the forest"
    }
    if ($legacyDetected) {
        Write-Both "    [+] Legacy Microsoft LAPS schema detected in the forest"
    }

    $missingPath = Get-EvidencePath 'laps_missing-computers.txt'
    $expiredPath = Get-EvidencePath 'laps_expired-passwords.txt'
    $rightsPath  = Get-EvidencePath 'laps_read-extendedrights.txt'

    Remove-Item -LiteralPath $missingPath,$expiredPath,$rightsPath -Force -ErrorAction SilentlyContinue

    if ($windowsDetected) {
        $lapsModule = Import-ADAuditModule -Name LAPS
        if ($lapsModule) {
            $missingComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(!(msLAPS-PasswordExpirationTime=*)))' -Properties msLAPS-PasswordExpirationTime | Select-Object -ExpandProperty Name)
            if ($missingComputers.Count -gt 0) {
                foreach ($name in $missingComputers) {
                    Add-Content -Path $missingPath -Value "[Windows LAPS] $name"
                }
                Write-Both "    [!] Some computers/servers don't have Windows LAPS password expiration data set, see $missingPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($missingPath))
            }

            $windowsComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(msLAPS-PasswordExpirationTime=*))' -Properties msLAPS-PasswordExpirationTime)
            foreach ($computer in $windowsComputers) {
                $expiration = Convert-ADAuditFileTime $computer.'msLAPS-PasswordExpirationTime'
                if ($expiration -and $expiration -lt (Get-Date)) {
                    Add-Content -Path $expiredPath -Value "[Windows LAPS] $($computer.Name) password is expired since $expiration"
                }
            }
            if (Test-Path -LiteralPath $expiredPath) {
                Write-Both "    [!] Some computers/servers have Windows LAPS password expired, see $expiredPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($expiredPath))
            }

            Get-ADOrganizationalUnit -Filter * | Find-LapsADExtendedRights -PipelineVariable OU | ForEach-Object {
                foreach ($holder in $_.ExtendedRightHolders) {
                    if ($holder -and $holder -ne $System) {
                        Add-Content -Path $rightsPath -Value "[Windows LAPS] $holder can read password attribute of $($_.ObjectDN)"
                    }
                }
            }
            if (Test-Path -LiteralPath $rightsPath) {
                Write-Both "    [!] Windows LAPS extended rights exported, see $rightsPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($rightsPath))
            }

            $DomainLevel = (Get-ADDomain).DomainMode
            if (-not (Test-ADAuditFunctionalLevelAtLeast -Mode $DomainLevel -MinimumMode 'Windows2016Domain')) {
                Write-Both "    [*] Windows LAPS is present, but domain functional level is below Windows Server 2016; encryption and DSRM management features may be limited."
            }
        }
        else {
            Write-Both "    [!] Windows LAPS schema detected, but the LAPS PowerShell module is not available on this host."
        }
    }

    if ($legacyDetected) {
        $legacyModule = Import-ADAuditModule -Name 'AdmPwd.PS' -PreferWindowsPowerShell
        if ($legacyModule) {
            $missingComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(!(ms-Mcs-AdmPwd=*)))' -Properties ms-Mcs-AdmPwd | Select-Object -ExpandProperty Name)
            if ($missingComputers.Count -gt 0) {
                foreach ($name in $missingComputers) {
                    Add-Content -Path $missingPath -Value "[Legacy LAPS] $name"
                }
                Write-Both "    [!] Some computers/servers don't have legacy LAPS password set, see $missingPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($missingPath))
            }

            $legacyComputers = @(Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*))' -Properties ms-Mcs-AdmPwdExpirationTime)
            foreach ($computer in $legacyComputers) {
                $expiration = Convert-ADAuditFileTime $computer.'ms-Mcs-AdmPwdExpirationTime'
                if ($expiration -and $expiration -lt (Get-Date)) {
                    Add-Content -Path $expiredPath -Value "[Legacy LAPS] $($computer.Name) password is expired since $expiration"
                }
            }
            if (Test-Path -LiteralPath $expiredPath) {
                Write-Both "    [!] Some computers/servers have legacy LAPS password expired, see $expiredPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($expiredPath))
            }

            Get-ADOrganizationalUnit -Filter * | Find-AdmPwdExtendedRights -PipelineVariable OU | ForEach-Object {
                foreach ($holder in $_.ExtendedRightHolders) {
                    if ($holder -and $holder -ne $System) {
                        Add-Content -Path $rightsPath -Value "[Legacy LAPS] $holder can read password attribute of $($OU.ObjectDN)"
                    }
                }
            }
            if (Test-Path -LiteralPath $rightsPath) {
                Write-Both "    [!] Legacy LAPS extended rights exported, see $rightsPath"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($rightsPath))
            }
        }
        else {
            Write-Both "    [!] Legacy Microsoft LAPS schema detected, but the AdmPwd.PS module is not available on this host."
        }
    }
}
Function Get-PrivilegedGroupAccounts {
    #Lists users in Admininstrators, DA and EA groups
    [array]$privilegedusers = @()
    $privilegedusers += Get-ADGroupMember $Administrators   -Recursive
    $privilegedusers += Get-ADGroupMember $DomainAdmins     -Recursive
    $privilegedusers += Get-ADGroupMember $EnterpriseAdmins -Recursive
    $privusersunique = $privilegedusers | Sort-Object -Unique
    $count = 0
    $totalcount = ($privilegedusers | Measure-Object | Select-Object Count).count
    foreach ($account in $privusersunique) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'accounts_userPrivileged.txt') -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts in privileged groups, see accounts_userPrivileged.txt (KB426)"
        Write-Nessus-Finding "AdminSDHolders" "KB426" ([System.IO.File]::ReadAllText((Get-EvidencePath 'accounts_userPrivileged.txt')))
    }
}

function Get-OverlappingGroupMemberships {
    [CmdletBinding()]
    param(
        [string]$OutputDir = $(if ($script:outputdir) { $script:outputdir } else { $outputdir }),

        [string]$UserLdapFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",

        [ValidateRange(1,100)]
        [int]$MaxDepth = 15,

        [switch]$IncludeHtml = $true,

        [ValidateRange(0,1000000)]
        [int]$ProgressEvery = 250
    )

    $ErrorActionPreference = 'Stop'

    function Write-Log {
        param([string]$Message)
        if (Get-Command Write-Both -ErrorAction SilentlyContinue) { Write-Both $Message } else { Write-Host $Message }
    }

    Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null

    if (-not $OutputDir) {
        throw "OutputDir is empty. Ensure `$outputdir is set by the main script, or pass -OutputDir."
    }
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $csvPath  = Join-Path $OutputDir "overlapping_group_memberships.csv"
    $htmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $OutputDir) "overlapping_group_memberships.html"

    $nestedCsvPath  = Join-Path $OutputDir "multiple_nested_paths.csv"
    $nestedHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $OutputDir) "multiple_nested_paths.html"

    # Cache groups by DN to reduce LDAP calls
    $groupCache = @{}

    function Get-CachedGroup {
        param([Parameter(Mandatory)][string]$DistinguishedName)

        if ($groupCache.ContainsKey($DistinguishedName)) { return $groupCache[$DistinguishedName] }

        try {
            $g = Get-ADGroup -Identity $DistinguishedName -Properties memberOf, name, samAccountName -ErrorAction Stop
        } catch {
            return $null
        }

        $obj = [pscustomobject]@{
            DN       = $g.DistinguishedName
            Name     = $g.Name
            Sam      = $g.SamAccountName
            MemberOf = @($g.memberOf)
        }

        $groupCache[$DistinguishedName] = $obj
        return $obj
    }

    function Add-Path {
        param(
            [Parameter(Mandatory)][hashtable]$PathsByDn,
            [Parameter(Mandatory)][string]$TargetDn,
            [Parameter(Mandatory)][string]$PathString,
            [Parameter(Mandatory)][string]$StartGroup
        )

        if (-not $PathsByDn.ContainsKey($TargetDn)) { $PathsByDn[$TargetDn] = @() }

        $PathsByDn[$TargetDn] += [pscustomobject]@{
            Path  = $PathString
            Start = $StartGroup
            Len   = ($PathString -split '\s->\s').Count
        }
    }

    Write-Log "    [*] Overlapping group membership routes (domain-wide)"

    $users = Get-ADUser -LDAPFilter $UserLdapFilter -Properties displayName, distinguishedName, samAccountName, memberOf `
        -ResultPageSize 2000 -ResultSetSize $null

    $total = ($users | Measure-Object).Count
    Write-Log ("    [*] Users to process: {0}" -f $total)

    $overlapResults    = New-Object System.Collections.Generic.List[object]
    $nestedPathResults = New-Object System.Collections.Generic.List[object]

    $i = 0
    foreach ($u in $users) {
        $i++
        if ($ProgressEvery -gt 0 -and ($i % $ProgressEvery) -eq 0) {
            Write-Log ("    [*] Processed {0}/{1} users..." -f $i, $total)
        }

        # DIRECT groups from memberOf
        $directGroupDns = @($u.memberOf)
        if (-not $directGroupDns -or $directGroupDns.Count -eq 0) { continue }

        # Resolve direct groups to names
        $directGroups = foreach ($gdn in $directGroupDns) {
            $g = Get-CachedGroup -DistinguishedName $gdn
            if ($g) { [pscustomobject]@{ Name = $g.Name; DN = $g.DN } }
        }
        $directGroups = @($directGroups | Where-Object { $_ })
        if ($directGroups.Count -eq 0) { continue }

        # targetGroupDN -> list of path objects
        $pathsByDn = @{}

        foreach ($dg in $directGroups) {
            $startName = [string]$dg.Name
            $startDn   = [string]$dg.DN

            $stack = New-Object System.Collections.ArrayList
            [void]$stack.Add([pscustomobject]@{
                Dn      = $startDn
                Path    = @($startName)
                PathDns = @($startDn)
                Depth   = 0
            })

            while ($stack.Count -gt 0) {
                $node = $stack[$stack.Count - 1]
                $stack.RemoveAt($stack.Count - 1)

                $currentDn  = $node.Dn
                $currentStr = ($node.Path -join ' -> ')

                Add-Path -PathsByDn $pathsByDn -TargetDn $currentDn -PathString $currentStr -StartGroup $startName

                if ($node.Depth -ge $MaxDepth) { continue }

                $g = Get-CachedGroup -DistinguishedName $currentDn
                if (-not $g) { continue }

                foreach ($parentDn in @($g.MemberOf)) {
                    if (-not $parentDn) { continue }
                    if ($node.PathDns -contains $parentDn) { continue } # loop guard

                    $parent = Get-CachedGroup -DistinguishedName $parentDn
                    if (-not $parent) { continue }

                    [void]$stack.Add([pscustomobject]@{
                        Dn      = $parent.DN
                        Path    = @($node.Path + @($parent.Name))
                        PathDns = @($node.PathDns + @($parent.DN))
                        Depth   = ($node.Depth + 1)
                    })
                }
            }
        }

        foreach ($targetDn in $pathsByDn.Keys) {
            $pathObjs = $pathsByDn[$targetDn]
            if (-not $pathObjs -or $pathObjs.Count -lt 2) { continue }

            $uniquePaths = @($pathObjs | Select-Object -ExpandProperty Path -Unique)
            if ($uniquePaths.Count -le 1) { continue }

            $targetGroup = Get-CachedGroup -DistinguishedName $targetDn
            $targetName  = if ($targetGroup) { $targetGroup.Name } else { $targetDn }

            # Path arrays
            $pathArrays = @()
            foreach ($p in $uniquePaths) {
                $arr = @($p -split '\s->\s' | Where-Object { $_ })
                if ($arr.Count -gt 0) { $pathArrays += ,$arr }
            }
            if ($pathArrays.Count -lt 2) { continue }

            # Direct entry groups
            $directEntryGroups = @($pathArrays | ForEach-Object { $_[0] } | Sort-Object -Unique)

            # Union contributing groups (excluding target)
            $allGroups = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
            foreach ($arr in $pathArrays) {
                foreach ($gName in $arr) {
                    if ($gName -and ($gName -ne $targetName)) { [void]$allGroups.Add($gName) }
                }
            }
            $contribUnion = @($allGroups | Sort-Object)

            # Intersection common groups (excluding target)
            $common = $null
            foreach ($arr in $pathArrays) {
                $set = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
                foreach ($gName in $arr) {
                    if ($gName -and ($gName -ne $targetName)) { [void]$set.Add($gName) }
                }

                if ($null -eq $common) { $common = $set }
                else { $common.IntersectWith($set) }
            }
            $commonGroups = if ($common) { @($common | Sort-Object) } else { @() }

            # ContributingGroups output: direct entry + other contributing (dedup)
            $entrySet = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
            foreach ($e in $directEntryGroups) { [void]$entrySet.Add($e) }

            $nonEntryContrib = @()
            foreach ($g in $contribUnion) {
                if (-not $entrySet.Contains($g)) { $nonEntryContrib += $g }
            }

            $hasDirect = $false
            $hasIndirect = $false
            foreach ($p in $pathObjs) {
                if ($p.Len -eq 1) { $hasDirect = $true } else { $hasIndirect = $true }
            }

            $overlapType =
                if ($hasDirect -and $hasIndirect) { "Direct+Indirect" }
                elseif ($directEntryGroups.Count -gt 1) { "MultipleDirectGroups" }
                else { "MultiplePaths" }

            $resultObj = [pscustomobject]@{
                UserSamAccountName = $u.SamAccountName
                UserDisplayName    = $u.DisplayName
                UserDN             = $u.DistinguishedName

                TargetGroup        = $targetName
                TargetGroupDN      = $targetDn

                OverlapType        = $overlapType
                PathCount          = $uniquePaths.Count

                DirectEntryGroups  = ($directEntryGroups -join '; ')
                ContributingGroups = (($directEntryGroups + $nonEntryContrib) | Sort-Object -Unique) -join '; '
                CommonGroups       = ($commonGroups -join '; ')

                Paths              = ($uniquePaths -join ' | ')
            }

            if ($overlapType -eq 'MultiplePaths') {
                $nestedPathResults.Add($resultObj) | Out-Null
            } else {
                $overlapResults.Add($resultObj) | Out-Null
            }
        }
    }

    # --- Overlapping Group Memberships (MultipleDirectGroups / Direct+Indirect) ---
    if (Test-Path -LiteralPath $csvPath) { Remove-Item -LiteralPath $csvPath -Force }
    $overlapResults | Sort-Object UserSamAccountName, TargetGroup | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    if ($IncludeHtml) {
        if (Test-Path -LiteralPath $htmlPath) { Remove-Item -LiteralPath $htmlPath -Force }

        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine((Get-ADAuditReportHeader -Title 'Overlapping Group Memberships'))
        [void]$sb.AppendLine("<div class='hero'><h1>Overlapping Group Memberships</h1>")
        [void]$sb.AppendLine("<div class='meta'>Users who reach the same target group via multiple direct group memberships.</div></div>")

        $userCount = ($overlapResults | Select-Object -Property UserSamAccountName -Unique).Count
        [void]$sb.AppendLine("<div class='stats'>")
        [void]$sb.AppendLine("<div class='stat'><div class='val'>$($overlapResults.Count)</div><div class='lbl'>Total Findings</div></div>")
        [void]$sb.AppendLine("<div class='stat'><div class='val'>$userCount</div><div class='lbl'>Affected Users</div></div>")
        [void]$sb.AppendLine("</div>")

        $byUser = $overlapResults | Group-Object UserSamAccountName
        foreach ($ug in $byUser) {
            $userRows = $ug.Group
            $dn   = ($userRows | Select-Object -First 1).UserDN
            $disp = ($userRows | Select-Object -First 1).UserDisplayName

            [void]$sb.AppendLine("<details>")
            [void]$sb.AppendLine("<summary>$($ug.Name) &mdash; $disp ($($userRows.Count) target group(s) with overlap)</summary>")
            [void]$sb.AppendLine("<div class='detail-body'><p><code>$dn</code></p>")
            [void]$sb.AppendLine("<table><thead><tr><th>Target Group</th><th>Overlap Type</th><th>Direct Entry Groups</th><th>Contributing Groups</th><th>Common Groups</th><th>Paths</th></tr></thead><tbody>")

            foreach ($r in ($userRows | Sort-Object TargetGroup)) {
                $pathsHtml = ($r.Paths -split '\s\|\s' | ForEach-Object { "<div><code>$($_)</code></div>" }) -join ''
                [void]$sb.AppendLine("<tr><td>$($r.TargetGroup)</td><td>$($r.OverlapType)</td><td>$($r.DirectEntryGroups)</td><td>$($r.ContributingGroups)</td><td>$($r.CommonGroups)</td><td>$pathsHtml</td></tr>")
            }

            [void]$sb.AppendLine("</tbody></table></div></details>")
        }

        [void]$sb.AppendLine((Get-ADAuditReportFooter))
        [System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
    }

    # --- Multiple Nested Paths (MultiplePaths) ---
    if (Test-Path -LiteralPath $nestedCsvPath) { Remove-Item -LiteralPath $nestedCsvPath -Force }
    $nestedPathResults | Sort-Object UserSamAccountName, TargetGroup | Export-Csv -LiteralPath $nestedCsvPath -NoTypeInformation -Encoding UTF8

    if ($IncludeHtml) {
        if (Test-Path -LiteralPath $nestedHtmlPath) { Remove-Item -LiteralPath $nestedHtmlPath -Force }

        $sb2 = New-Object System.Text.StringBuilder
        [void]$sb2.AppendLine((Get-ADAuditReportHeader -Title 'Multiple Nested Paths'))
        [void]$sb2.AppendLine("<div class='hero'><h1>Multiple Nested Paths</h1>")
        [void]$sb2.AppendLine("<div class='meta'>Users who reach the same target group via multiple nesting chains from a single direct group membership. These represent group nesting complexity, not necessarily duplicate effective permissions.</div></div>")

        $nestedUserCount = ($nestedPathResults | Select-Object -Property UserSamAccountName -Unique).Count
        [void]$sb2.AppendLine("<div class='stats'>")
        [void]$sb2.AppendLine("<div class='stat'><div class='val'>$($nestedPathResults.Count)</div><div class='lbl'>Total Findings</div></div>")
        [void]$sb2.AppendLine("<div class='stat'><div class='val'>$nestedUserCount</div><div class='lbl'>Affected Users</div></div>")
        [void]$sb2.AppendLine("</div>")

        $byUser2 = $nestedPathResults | Group-Object UserSamAccountName
        foreach ($ug in $byUser2) {
            $userRows = $ug.Group
            $dn   = ($userRows | Select-Object -First 1).UserDN
            $disp = ($userRows | Select-Object -First 1).UserDisplayName

            [void]$sb2.AppendLine("<details>")
            [void]$sb2.AppendLine("<summary>$($ug.Name) &mdash; $disp ($($userRows.Count) target group(s) with multiple paths)</summary>")
            [void]$sb2.AppendLine("<div class='detail-body'><p><code>$dn</code></p>")
            [void]$sb2.AppendLine("<table><thead><tr><th>Target Group</th><th>Overlap Type</th><th>Direct Entry Groups</th><th>Contributing Groups</th><th>Common Groups</th><th>Paths</th></tr></thead><tbody>")

            foreach ($r in ($userRows | Sort-Object TargetGroup)) {
                $pathsHtml = ($r.Paths -split '\s\|\s' | ForEach-Object { "<div><code>$($_)</code></div>" }) -join ''
                [void]$sb2.AppendLine("<tr><td>$($r.TargetGroup)</td><td>$($r.OverlapType)</td><td>$($r.DirectEntryGroups)</td><td>$($r.ContributingGroups)</td><td>$($r.CommonGroups)</td><td>$pathsHtml</td></tr>")
            }

            [void]$sb2.AppendLine("</tbody></table></div></details>")
        }

        [void]$sb2.AppendLine((Get-ADAuditReportFooter))
        [System.IO.File]::WriteAllText($nestedHtmlPath, $sb2.ToString(), [System.Text.Encoding]::UTF8)
    }

    # --- Log output ---
    if ($overlapResults.Count -gt 0) {
        Write-Log "    [!] Overlapping membership findings: $($overlapResults.Count) row(s)."
        Write-Log "        - CSV: $(Split-Path -Leaf $csvPath)"
        if ($IncludeHtml) { Write-Log "        - HTML: $(Split-Path -Leaf $htmlPath)" }
    } else {
        Write-Log "    [+] No overlapping group membership routes found."
        Write-Log "        - CSV (empty): $(Split-Path -Leaf $csvPath)"
        if ($IncludeHtml) { Write-Log "        - HTML: $(Split-Path -Leaf $htmlPath)" }
    }

    if ($nestedPathResults.Count -gt 0) {
        Write-Log "    [!] Multiple nested path findings: $($nestedPathResults.Count) row(s)."
        Write-Log "        - CSV: $(Split-Path -Leaf $nestedCsvPath)"
        if ($IncludeHtml) { Write-Log "        - HTML: $(Split-Path -Leaf $nestedHtmlPath)" }
    } else {
        Write-Log "    [+] No multiple nested path findings."
        Write-Log "        - CSV (empty): $(Split-Path -Leaf $nestedCsvPath)"
        if ($IncludeHtml) { Write-Log "        - HTML: $(Split-Path -Leaf $nestedHtmlPath)" }
    }
}


Function Get-ProtectedUsers {
    #Lists users in "Protected Users" group (2019 and above)
    $DomainLevel = (Get-ADDomain).DomainMode
    if (Test-ADAuditFunctionalLevelAtLeast -Mode $DomainLevel -MinimumMode 'Windows2019Domain') {
        $ProtectedUsersSID = ((Get-ADDomain -Current LoggedOnUser).DomainSID.Value) + "-525"
        $ProtectedUsers = (Get-ADGroup -Identity $ProtectedUsersSID).SamAccountName
        $count = 0
        $protectedaccounts = (Get-ADGroup $ProtectedUsers -Properties Members).Members
        $totalcount = ($protectedaccounts | Measure-Object | Select-Object -ExpandProperty Count)
        foreach ($members in $protectedaccounts) {
            if ($totalcount -eq 0) { break }
            Write-Progress -Activity "Searching for protected users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
            $account = Get-ADObject $members -Properties SamAccountName
            Add-Content -Path (Get-EvidencePath 'accounts_protectedusers.txt') -Value "$($account.SamAccountName) ($($account.Name))"
            $count++
        }
        Write-Progress -Activity "Searching for protected users..." -Status "Ready" -Completed
        if ($count -gt 0) {
            Write-Both "    [!] There are $count accounts in the 'Protected Users' group, see accounts_protectedusers.txt"
            Write-Nessus-Finding "ProtectedUsers" "KB549" ([System.IO.File]::ReadAllText((Get-EvidencePath 'accounts_protectedusers.txt')))
        }
    }
    else {
        Write-Both "    [-] Domain functional level is below Windows Server 2019, skipping Get-ProtectedUsers check."
    }
}
Function Get-AuthenticationPoliciesAndSilos {
    #Lists any authentication policies and silos (2019 forest/domain and above)
    $DomainLevel = (Get-ADDomain).DomainMode
    $ForestLevel = (Get-ADForest).ForestMode

    if (
        (Test-ADAuditFunctionalLevelAtLeast -Mode $DomainLevel -MinimumMode 'Windows2019Domain') -and
        (Test-ADAuditFunctionalLevelAtLeast -Mode $ForestLevel -MinimumMode 'Windows2019Forest')
    ) {
        $count = 0
        foreach ($policy in Get-ADAuthenticationPolicy -Filter *) {
            Write-Both "    [!] Found $policy Authentication Policy"
            $count++
        }
        if ($count -lt 1) {
            Write-Both "    [!] There were no AD Authentication Policies found in the domain"
        }

        $count = 0
        foreach ($policysilo in Get-ADAuthenticationPolicySilo -Filter *) {
            Write-Both "    [!] Found $policysilo Authentication Policy Silo"
            $count++
        }
        if ($count -lt 1) {
            Write-Both "    [!] There were no AD Authentication Policy Silos found in the domain"
        }
    }
    else {
        Write-Both "    [-] Forest/domain functional level is below Windows Server 2019, skipping Authentication Policies and Silos check."
    }
}
Function Get-MachineAccountQuota {
    #Get number of machines a user can add to a domain
    $MachineAccountQuota = (Get-ADDomain | select -ExpandProperty DistinguishedName | Get-ADObject -Property 'ms-DS-MachineAccountQuota' | select -ExpandProperty ms-DS-MachineAccountQuota)
    if ($MachineAccountQuota -gt 0) {
        Write-Both "    [!] Domain users can add $MachineAccountQuota devices to the domain! (KB251)"
        Write-Nessus-Finding "DomainAccountQuota" "KB251" "Domain users can add $MachineAccountQuota devices to the domain"
    }
}
Function Get-InactiveComputerObjects {
    $count = 0
    $DaysAgo = (Get-Date).AddDays(-90)

    $ReportPath = Get-EvidencePath 'computers_inactive_90days.txt'
    Remove-Item -Path $ReportPath -ErrorAction SilentlyContinue

    $inactiveComputers = Get-ADComputer -Filter { LastLogonTimeStamp -lt $DaysAgo -and Enabled -eq "true" } -Properties LastLogonTimeStamp, DNSHostName, OperatingSystem
    $totalcount = ($inactiveComputers | Measure-Object | Select-Object Count).count

    foreach ($computer in $inactiveComputers) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for inactive computer objects (>90 days)..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)

        $datelastlogon = if ($computer.LastLogonTimeStamp) { [DateTime]::FromFileTime($computer.LastLogonTimeStamp) } else { "Never" }

        Add-Content -Path $ReportPath -Value "Computer $($computer.Name) ($($computer.DNSHostName)) OS: $($computer.OperatingSystem) last logon: $datelastlogon"
        $count++
    }

    Write-Progress -Activity "Searching for inactive computer objects (>90 days)..." -Status "Ready" -Completed

    if ($count -gt 0) {
        Write-Both "    [!] $count enabled computer objects inactive for >90 days, see computers_inactive_90days.txt (KB###)"
        Write-Nessus-Finding "InactiveComputers90Days" "KB###" ([System.IO.File]::ReadAllText($ReportPath))
    }
}

Function Get-PasswordPolicy {
    Write-Both "    [+] Checking default password policy"
    if (!(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled) {
        Write-Both "    [!] Password Complexity not enabled (KB262)"
        Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold -lt 5) {
        Write-Both "    [!] Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold) (KB263)"
        Write-Nessus-Finding "LockoutThreshold" "KB263" "Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold)"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength -lt 14) {
        Write-Both "    [!] Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength) (KB262)"
        Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength)"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled) {
        Write-Both "    [!] Reversible encryption is enabled"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge -eq "00:00:00") {
        Write-Both "    [!] Passwords do not expire (KB254)"
        Write-Nessus-Finding "PasswordsDoNotExpire" "KB254" "Passwords do not expire"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount -lt 12) {
        Write-Both "    [!] Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount) (KB262)"
        Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount)"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).NoLmHash -eq 0) {
        Write-Both "    [!] LM Hashes are stored! (KB510)"
        Write-Nessus-Finding "LMHashesAreStored" "KB510" "LM Hashes are stored"
    }
    Write-Both "    [-] Finished checking default password policy"
    Write-Both "    [+] Checking fine-grained password policies if they exist"
    foreach ($finegrainedpolicy in Get-ADFineGrainedPasswordPolicy -Filter *) {
        $finegrainedpolicyappliesto = $finegrainedpolicy.AppliesTo
        Write-Both "    [!] Policy: $finegrainedpolicy"
        Write-Both "    [!] AppliesTo: $($finegrainedpolicyappliesto)"
        if (!($finegrainedpolicy).PasswordComplexity) {
            Write-Both "    [!] Password Complexity not enabled (KB262)"
            Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled for $finegrainedpolicy"
        }
        if (($finegrainedpolicy).LockoutThreshold -lt 5) {
            Write-Both "    [!] Lockout threshold is less than 5, currently set to $(($finegrainedpolicy).LockoutThreshold) (KB263)"
            Write-Nessus-Finding "LockoutThreshold" "KB263" " Lockout threshold for $finegrainedpolicy is less than 5, currently set to $(($finegrainedpolicy).LockoutThreshold)"
        }
        if (($finegrainedpolicy).MinPasswordLength -lt 14) {
            Write-Both "    [!] Minimum password length is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength) (KB262)"
            Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length for $finegrainedpolicy is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength)"
        }
        if (($finegrainedpolicy).ReversibleEncryptionEnabled) {
            Write-Both "    [!] Reversible encryption is enabled"
        }
        if (($finegrainedpolicy).MaxPasswordAge -eq "00:00:00") {
            Write-Both "    [!] Passwords do not expire (KB254)"
        }
        if (($finegrainedpolicy).PasswordHistoryCount -lt 12) {
            Write-Both "    [!] Passwords history is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount) (KB262)"
            Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history for $finegrainedpolicy is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount)"
        }
    }
    Write-Both "    [-] Finished checking fine-grained password policy"
}
Function Get-NULLSessions {
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymous -eq 0) {
        Write-Both "    [!] RestrictAnonymous is set to 0! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" " RestrictAnonymous is set to 0"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymousSam -eq 0) {
        Write-Both "    [!] RestrictAnonymousSam is set to 0! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" " RestrictAnonymous is set to 0"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).everyoneincludesanonymous -eq 1) {
        Write-Both "    [!] EveryoneIncludesAnonymous is set to 1! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" "EveryoneIncludesAnonymous is set to 1"
    }
}
Function Get-DomainTrusts {
    #Lists domain trusts if they are bad
    foreach ($trust in (Get-ADObject -Filter { objectClass -eq "trustedDomain" } -Properties TrustPartner, TrustDirection, trustType, trustAttributes)) {
        if ($trust.TrustDirection -eq 2) {
            if ($trust.TrustAttributes -eq 1 -or $trust.TrustAttributes -eq 4) {
                #1 means trust is non-transitive, 4 is external so we check for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain."
            }
            else {
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"
            }
        }
        if ($trust.TrustDirection -eq 3) {
            if ($trust.TrustAttributes -eq 1 -or $trust.TrustAttributes -eq 4) {
                #1 means trust is non-transitive, 4 is external so we check for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain."
            }
            else {
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"
            }
        }
    }
}
Function Get-WinVersion {
    $WinVersion = [single]([string][environment]::OSVersion.Version.Major + "." + [string][environment]::OSVersion.Version.Minor)
    return [single]$WinVersion
}
Function Get-SMB1Support {
    #Check if server supports SMBv1
    if ([single](Get-WinVersion) -le [single]6.1) {
        #NT6.1 or less detected so checking reg key
        if (!(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters).SMB1 -eq 0) {
            Write-Both "    [!] SMBv1 is not disabled (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled"
        }
    }
    elseif ([single](Get-WinVersion) -ge [single]6.2) {
        #NT6.2 or greater detected so using powershell function
        if ((Get-SmbServerConfiguration).EnableSMB1Protocol) {
            Write-Both "    [!] SMBv1 is enabled! (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled"
        }
    }
}
Function Get-UserPasswordNotChangedRecently {
    #Reports users that haven't changed passwords in more than 90 days
    $count = 0
    $DaysAgo = (Get-Date).AddDays(-90)
    $accountsoldpasswords = Get-ADUser -Filter { PwdLastSet -lt $DaysAgo -and Enabled -eq "true" } -Properties PasswordLastSet
    $totalcount = ($accountsoldpasswords | Measure-Object | Select-Object Count).count
    foreach ($account in $accountsoldpasswords) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        if ($account.PasswordLastSet) {
            $datelastchanged = $account.PasswordLastSet
        }
        else {
            $datelastchanged = "Never"
        }
        Add-Content -Path (Get-EvidencePath 'accounts_with_old_passwords.txt') -Value "User $($account.SamAccountName) ($($account.Name)) has not changed their password since $datelastchanged"
        $count++
    }
    Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count accounts with passwords older than 90days, see accounts_with_old_passwords.txt (KB550)"
        Write-Nessus-Finding "AccountsWithOldPasswords" "KB550" ([System.IO.File]::ReadAllText((Get-EvidencePath 'accounts_with_old_passwords.txt')))
    }
    $krbtgtPasswordDate = (Get-ADUser -Filter { SamAccountName -eq "krbtgt" } -Properties PasswordLastSet).PasswordLastSet
    if ($krbtgtPasswordDate -lt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] krbtgt password not changed since $krbtgtPasswordDate! (KB253)"
        Write-Nessus-Finding "krbtgtPasswordNotChanged" "KB253" "krbtgt password not changed since $krbtgtPasswordDate"
    }
}
Function Get-GPOtoFile {
    #Outputs complete GPO report
    $gpoHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'GPOReport.html'
    if (Test-Path $gpoHtmlPath) { Remove-Item $gpoHtmlPath -Recurse }
    Get-GPOReport -All -ReportType HTML -Path $gpoHtmlPath
    Write-Both "    [+] GPO Report saved to HTML Reports\GPOReport.html"
    if (Test-Path "$outputdir\GPOReport.xml") { Remove-Item "$outputdir\GPOReport.xml" -Recurse }
    Get-GPOReport -All -ReportType XML -Path "$outputdir\GPOReport.xml"
    Write-Both "    [+] GPO Report saved to GPOReport.xml, now run Grouper offline using the following command (KB499)"
    Write-Both "    [+]     PS>Import-Module Grouper.psm1 ; Invoke-AuditGPOReport -Path C:\GPOReport.xml -Level 3"
}
Function Get-GPOsPerOU {
    #Lists all OUs and which GPOs apply to them
    $count = 0
    $ousgpos = @(Get-ADOrganizationalUnit -Filter *)
    $totalcount = ($ousgpos | Measure-Object | Select-Object Count).count
    foreach ($ouobject in $ousgpos) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Currently identifed $count OUs" -PercentComplete ($count / $totalcount * 100)
        $combinedgpos = ($(((Get-GPInheritance -Target $ouobject).InheritedGpoLinks) | select DisplayName) | ForEach-Object { $_.DisplayName }) -join ','
        Add-Content -Path (Get-EvidencePath 'ous_inheritedGPOs.txt') -Value "$($ouobject.Name) Inherits these GPOs: $combinedgpos"
        $count++
    }
    Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Ready" -Completed
    Write-Both "    [+] Inherited GPOs saved to ous_inheritedGPOs.txt"
}
Function Get-SYSVOLXMLS {
    #Finds XML files in SYSVOL (thanks --> https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
    $XMLFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml'
    $count = 0
    if ($XMLFiles) {
        $progresscount = 0
        $totalcount = ($XMLFiles | Measure-Object | Select-Object Count).count
        foreach ($File in $XMLFiles) {
            if ($totalcount -eq 0) { break }
            $progresscount++
            Write-Progress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Currently searched through $count" -PercentComplete ($progresscount / $totalcount * 100)
            $Filename = Split-Path $File -Leaf
            $Distinguishedname = (Split-Path (Split-Path (Split-Path( Split-Path (Split-Path $File -Parent) -Parent ) -Parent ) -Parent) -Leaf).Substring(1).TrimEnd('}')
            [xml]$Xml = Get-Content ($File)
            if ($Xml.innerxml -like "*cpassword*" -and $Xml.innerxml -notlike '*cpassword=""*') {
                if (!(Test-Path "$outputdir\sysvol")) { New-Item -ItemType Directory -Path "$outputdir\sysvol" | Out-Null }
                Write-Both "    [!] cpassword found in file, copying to output folder (KB329)"
                Write-Both "        $File"
                Copy-Item -Path $File -Destination $outputdir\sysvol\$Distinguishedname.$Filename
                $count++
            }
        }
        Write-Progress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Ready" -Completed
    }
    if ($count -eq 0) {
        Write-Both "    ...cpassword not found in the $($XMLFiles.count) XML files found."
    }
    else {
        $GPOxml = (Get-Content "$outputdir\sysvol\*.xml" -ErrorAction SilentlyContinue)
        $GPOxml = $GPOxml -Replace "<", "&lt;"
        $GPOxml = $GPOxml -Replace ">", "&gt;"
        Write-Nessus-Finding "GPOPasswordStorage" "KB329" "$GPOxml"
    }
}

Function Get-InactiveAccounts {

    [CmdletBinding()]
    param(
        [int]$InactiveDays = 180
    )

    $ErrorActionPreference = 'Stop'

    $count = 0
    $progresscount = 0

    # Output paths (match script convention: txt in root outputdir, csv in HighRisk)
    $txtPath = Get-EvidencePath 'accounts_inactive.txt'
    $highRiskDir = Join-Path (Get-RawSourceDataDir) 'HighRisk'
    $csvPath = Join-Path $highRiskDir ("accounts_inactive_{0}days.csv" -f $InactiveDays)

    if (-not (Test-Path -LiteralPath $highRiskDir)) {
        New-Item -ItemType Directory -Path $highRiskDir -Force | Out-Null
    }

    # lastLogonTimestamp is replicated; good for inactivity reporting
    $cutoffUtc = [datetime]::UtcNow.AddDays(-1 * [math]::Abs($InactiveDays))
    $cutoffFt  = $cutoffUtc.ToFileTimeUtc()

    # Enabled users + inactive (old lastLogonTimestamp or missing)
    $ldapFilter =
        "(&(objectCategory=person)(objectClass=user)" +
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
        "(|(lastLogonTimestamp<=$cutoffFt)(!(lastLogonTimestamp=*))))"

    $props = @('samAccountName','name','distinguishedName','lastLogonTimestamp','whenCreated','pwdLastSet')

    $inactiveUsers = Get-ADUser -LDAPFilter $ldapFilter -Properties $props

    $totalcount = ($inactiveUsers | Measure-Object).Count

    if ($totalcount -gt 0) {
        "@Accounts inactive (no logon) for the past $InactiveDays days (based on lastLogonTimestamp)" |
            Set-Content -Encoding UTF8 -Path $txtPath
    } else {
        # Ensure no stale file from previous runs
        if (Test-Path -LiteralPath $txtPath) { Remove-Item -LiteralPath $txtPath -Force -ErrorAction SilentlyContinue }
        # Also clear CSV
        if (Test-Path -LiteralPath $csvPath) { Remove-Item -LiteralPath $csvPath -Force -ErrorAction SilentlyContinue }
    }

    $results = foreach ($u in $inactiveUsers) {
        $progresscount++
        Write-Progress -Activity "Searching for inactive users..." -Status "Currently identified $count" -PercentComplete (($progresscount / [math]::Max($totalcount,1)) * 100)

        $lastLogonUtc = $null
        if ($u.lastLogonTimestamp) {
            try { $lastLogonUtc = [datetime]::FromFileTimeUtc([int64]$u.lastLogonTimestamp) } catch { $lastLogonUtc = $null }
        }

        $pwdLastSetUtc = $null
        if ($u.pwdLastSet) {
            try { $pwdLastSetUtc = [datetime]::FromFileTimeUtc([int64]$u.pwdLastSet) } catch { $pwdLastSetUtc = $null }
        }

        $lltText = if ($lastLogonUtc) { $lastLogonUtc.ToString('yyyy-MM-dd HH:mm:ss') } else { 'Never' }

        Add-Content -Encoding UTF8 -Path $txtPath -Value "User $($u.SamAccountName) ($($u.Name)) has not logged on since $lltText"
        $count++

        [pscustomobject]@{
            SamAccountName    = $u.SamAccountName
            Name              = $u.Name
            LastLogonDateUTC  = $lastLogonUtc
            PwdLastSetUTC     = $pwdLastSetUtc
            WhenCreated       = $u.whenCreated
            DistinguishedName = $u.DistinguishedName
        }
    }

    Write-Progress -Activity "Searching for inactive users..." -Status "Ready" -Completed

    if ($count -gt 0) {
        # Sort: oldest logon first (nulls last)
        $resultsSorted = $results | Sort-Object @{
            Expression = { if ($_.LastLogonDateUTC) { $_.LastLogonDateUTC } else { [datetime]::MaxValue } }
            Ascending  = $true
        }, SamAccountName

        $resultsSorted | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

        Write-Both "    [!] $count inactive user accounts($InactiveDays days), see accounts_inactive.txt (KB500)"
        Write-Both "        - CSV: HighRisk\$(Split-Path -Leaf $csvPath)"
        Write-Nessus-Finding "InactiveAccounts" "KB500" ([System.IO.File]::ReadAllText($txtPath))
    }
}

Function Get-AdminAccountChecks {
    #Checks if Administrator account has been renamed, replaced and is no longer used.
    $AdministratorSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-500"
    $AdministratorSAMAccountName = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties SamAccountName).SamAccountName
    $AdministratorName = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties SamAccountName).Name
    if ($AdministratorTranslation -contains $AdministratorSAMAccountName) {
        Write-Both "    [!] Local Administrator account (UID500) has not been renamed (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Local Administrator account (UID500) has not been renamed"
    }
    else {
        $count = 0
        foreach ($AdminName in $AdministratorTranslation) {
            if ((Get-ADUser -Filter { SamAccountName -eq $AdminName })) { $count++ }
        }
        if ($count -eq 0) {
            Write-Both "    [!] Local Administrator account renamed to $AdministratorSAMAccountName ($($AdministratorName)), but a dummy account not made in it's place! (KB309)"
            Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Local Admin account renamed to $AdministratorSAMAccountName ($($AdministratorName)), but a dummy account not made in it's place"
        }
    }
    $AdministratorLastLogonDate = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties LastLogonDate).LastLogonDate
    if ($AdministratorLastLogonDate -gt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] UID500 (LocalAdministrator) account is still used, last used $AdministratorLastLogonDate! (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "UID500 (LocalAdmini) account is still used, last used $AdministratorLastLogonDate"
    }
}


Function Get-DomainAdminsGroupOverlap {
    [CmdletBinding()]
    Param(
        # Baseline groups that should NOT be treated as overlap for Tier-0 admin accounts
        [string[]]$BaselineGroups = @(
            'Domain Users',
            'Domain Admins',
            'Administrators',
            'Users',

            # Common Tier-0 extensions (policy-based but usually acceptable for Tier-0 accounts)
            'Group Policy Creator Owners',
            'Protected Users',
            'Key Admins',
            'Enterprise Key Admins',

            # Forest-level Tier-0 (only if the account is intended to operate at forest scope)
            'Schema Admins',
            'Enterprise Admins'
        ),

        # Tier-0 groups (for detecting tier-mixing, not for allowlisting)
        [string[]]$Tier0Groups = @(
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Domain Admins',
            'Group Policy Creator Owners',
            'Protected Users',
            'Key Admins',
            'Enterprise Key Admins'
        ),

        # Tier-1 groups (membership by a DA should be considered overlap / tier mixing)
        [string[]]$Tier1Groups = @(
            'Account Operators',
            'Server Operators',
            'Backup Operators',
            'Print Operators',
            'DnsAdmins',
            'Certificate Publishers',
            'Remote Desktop Users'
        ),

        # If set, only write results when overlap is found (default: true)
        [switch]$OnlyReportFindings = $true
    )

    # Ensure HighRisk output folder exists
    $highRiskDir = Join-Path (Get-RawSourceDataDir) 'HighRisk'
    if (-not (Test-Path $highRiskDir)) {
        New-Item -Path $highRiskDir -ItemType Directory -Force | Out-Null
    }

    # Output files:
    # - TXT in root output folder
    # - CSV in HighRisk folder (as requested)
    $outTxt = Join-Path $outputdir   "accounts_domain_admins_group_overlap.txt"
    $outCsv = Join-Path $highRiskDir "accounts_domain_admins_group_overlap.csv"

    # Resolve the Domain Admins group name already used by the script if present
    $daGroupName = $script:DomainAdmins
    if ([string]::IsNullOrEmpty($daGroupName)) { $daGroupName = 'Domain Admins' }

    # Case-insensitive lookup tables
    $baselineSet = @{}
    foreach ($g in $BaselineGroups) {
        if ($g) { $baselineSet[$g.ToLowerInvariant()] = $true }
    }

    $tier0Set = @{}
    foreach ($g in $Tier0Groups) {
        if ($g) { $tier0Set[$g.ToLowerInvariant()] = $true }
    }

    $tier1Set = @{}
    foreach ($g in $Tier1Groups) {
        if ($g) { $tier1Set[$g.ToLowerInvariant()] = $true }
    }

    $results = @()

    try {
        # Enumerate effective members (recursive) of Domain Admins
        $members = Get-ADGroupMember -Identity $daGroupName -Recursive -ErrorAction Stop |
            Where-Object { $_.objectClass -eq 'user' }
    }
    catch {
        Write-Both "    [!] Failed to enumerate members of '$daGroupName' : $($_.Exception.Message)"
        return
    }

    foreach ($m in $members) {
        try {
            $u = Get-ADUser -Identity $m.DistinguishedName -Properties Enabled,SamAccountName,Name,DistinguishedName -ErrorAction Stop

            # Effective group membership (includes nested groups)
            $groups = Get-ADPrincipalGroupMembership -Identity $u.DistinguishedName -ErrorAction Stop |
                Select-Object -ExpandProperty SamAccountName

            $groupsNorm = @($groups | Where-Object { $_ } | ForEach-Object { $_.ToString() })

            # Extra groups beyond baseline (case-insensitive)
            $extra = @()
            foreach ($g in $groupsNorm) {
                if (-not $baselineSet.ContainsKey($g.ToLowerInvariant())) {
                    $extra += $g
                }
            }

            # Tier hits (not mutually exclusive)
            $tier0Hits = @()
            $tier1Hits = @()
            foreach ($g in $groupsNorm) {
                $gl = $g.ToLowerInvariant()
                if ($tier0Set.ContainsKey($gl)) { $tier0Hits += $g }
                if ($tier1Set.ContainsKey($gl)) { $tier1Hits += $g }
            }

            $flagExtra    = (($extra | Measure-Object).Count -gt 0)
            $flagTier1    = (($tier1Hits | Measure-Object).Count -gt 0)
            $flagTierMix  = (($tier0Hits | Measure-Object).Count -gt 0 -and ($tier1Hits | Measure-Object).Count -gt 0)

            if ($flagExtra -or $flagTier1 -or $flagTierMix) {
                $flags = @()
                if ($flagExtra)   { $flags += 'ExtraGroupsBeyondBaseline' }
                if ($flagTier1)   { $flags += 'Tier1MembershipDetected' }
                if ($flagTierMix) { $flags += 'Tier0AndTier1Overlap' }

                $results += [pscustomobject]@{
                    SamAccountName     = $u.SamAccountName
                    Name               = $u.Name
                    Enabled            = $u.Enabled
                    ExtraGroupCount    = ($extra | Measure-Object).Count
                    ExtraGroups        = ($extra | Sort-Object -Unique) -join '; '
                    Tier0GroupsFound   = ($tier0Hits | Sort-Object -Unique) -join '; '
                    Tier1GroupsFound   = ($tier1Hits | Sort-Object -Unique) -join '; '
                    Flags              = ($flags -join '|')
                }
            }
            elseif (-not $OnlyReportFindings) {
                $results += [pscustomobject]@{
                    SamAccountName     = $u.SamAccountName
                    Name               = $u.Name
                    Enabled            = $u.Enabled
                    ExtraGroupCount    = 0
                    ExtraGroups        = ''
                    Tier0GroupsFound   = ($tier0Hits | Sort-Object -Unique) -join '; '
                    Tier1GroupsFound   = ''
                    Flags              = ''
                }
            }
        }
        catch {
            Write-Both "    [!] Failed processing DA member '$($m.SamAccountName)' : $($_.Exception.Message)"
        }
    }

    if (($results | Measure-Object).Count -gt 0) {
        # CSV -> HighRisk folder
        $results | Sort-Object ExtraGroupCount -Descending |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outCsv

        # TXT -> root output folder
        "Domain Admins users with group overlap beyond baseline ($($BaselineGroups -join ', ')):" |
            Out-File -Encoding UTF8 $outTxt

        $results | Sort-Object ExtraGroupCount -Descending |
            ForEach-Object {
                "{0} ({1}) Enabled={2} ExtraGroups={3} Flags={4}`n  Extra: {5}`n  Tier0:  {6}`n  Tier1:  {7}`n" -f `
                    $_.SamAccountName, $_.Name, $_.Enabled, $_.ExtraGroupCount, $_.Flags, $_.ExtraGroups, $_.Tier0GroupsFound, $_.Tier1GroupsFound
            } | Add-Content -Encoding UTF8 -Path $outTxt

        Write-Both "    [!] Domain Admins group overlap findings: $((($results | Measure-Object).Count)) account(s)."
        Write-Both "        - TXT: $(Split-Path -Leaf $outTxt)"
        Write-Both "        - CSV: HighRisk\$(Split-Path -Leaf $outCsv)"
    }
    else {
        Write-Both "    [+] No Domain Admin users found with group overlap beyond baseline."
    }
}
Function Get-DisabledAccounts {

    [CmdletBinding()]
    param()

    $ErrorActionPreference = 'Stop'

    $count = 0
    $txtPath = Get-EvidencePath 'accounts_disabled.txt'

    # Disabled user accounts (UAC bit 0x2)
    $ldapFilter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"

    $disabledaccounts = Get-ADUser -LDAPFilter $ldapFilter -Properties SamAccountName,Name

    $totalcount = ($disabledaccounts | Measure-Object).Count

    if ($totalcount -gt 0) {
        # Reset file for this run
        Set-Content -Encoding UTF8 -Path $txtPath -Value "@Disabled user accounts"
    } else {
        # Ensure no stale output from previous runs
        if (Test-Path -LiteralPath $txtPath) { Remove-Item -LiteralPath $txtPath -Force -ErrorAction SilentlyContinue }
    }

    foreach ($account in $disabledaccounts) {
        if ($totalcount -eq 0) { break }

        Write-Progress -Activity "Searching for disabled users..." -Status "Currently identified $count" -PercentComplete (($count / $totalcount) * 100)

        Add-Content -Encoding UTF8 -Path $txtPath -Value "Account $($account.SamAccountName) ($($account.Name)) is disabled"
        $count++
    }

    Write-Progress -Activity "Searching for disabled users..." -Status "Ready" -Completed

    if ($count -gt 0) {
        Write-Both "    [!] $count disabled user accounts, see accounts_disabled.txt (KB501)"
        Write-Nessus-Finding "DisabledAccounts" "KB501" ([System.IO.File]::ReadAllText($txtPath))
    }
}

Function Get-LockedAccounts {
    #Lists locked accounts
    $lockedAccounts = Get-ADUser -Filter * -Properties LockedOut | Where-Object { $_.LockedOut -eq $true }
    $count = 0
    $totalcount = ($lockedAccounts | Measure-Object | Select-Object Count).Count
    foreach ($account in $lockedAccounts) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for locked users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'accounts_locked.txt') -Value "Account $($account.SamAccountName) ($($account.Name)) is locked"
        $count++
    }
    Write-Progress -Activity "Searching for locked users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count locked user accounts, see accounts_locked.txt"
    }
}
Function Get-AccountPassDontExpire {
    #Lists accounts who's passwords dont expire
    $count = 0
    $nonexpiringpasswords = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object { $_.Enabled -eq $true }
    $totalcount = ($nonexpiringpasswords | Measure-Object | Select-Object Count).count
    foreach ($account in $nonexpiringpasswords) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'accounts_passdontexpire.txt') -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts that don't expire, see accounts_passdontexpire.txt (KB254)"
        Write-Nessus-Finding "AccountsThatDontExpire" "KB254" ([System.IO.File]::ReadAllText((Get-EvidencePath 'accounts_passdontexpire.txt')))
    }
}
Function Get-OldBoxes {
    #Lists machines running OS older than Windows Server 2019
    $count = 0
    $oldboxes = Get-ADComputer -Filter { Enabled -eq "true" -and (OperatingSystem -Like "*2016*" -or OperatingSystem -Like "*2012*" -or OperatingSystem -Like "*2008*" -or OperatingSystem -Like "*2003*" -or OperatingSystem -Like "*2000*" -or OperatingSystem -Like "*XP*" -or OperatingSystem -like '*Windows 7*' -or OperatingSystem -like '*Windows 8*' -or OperatingSystem -like '*Windows 10*' -or OperatingSystem -like '*vista*') } -Property OperatingSystem
    $totalcount = ($oldboxes | Measure-Object | Select-Object Count).count
    foreach ($machine in $oldboxes) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for unsupported OS devices joined to the domain..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'machines_old.txt') -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersion), $($machine.IPv4Address)"
        $count++
    }
    Write-Progress -Activity "Searching for unsupported OS devices joined to the domain..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] We found $count machines running an unsupported OS (older than Server 2019)! see machines_old.txt (KB3/37/38/KB259)"
        Write-Nessus-Finding "OldBoxes" "KB259" ([System.IO.File]::ReadAllText((Get-EvidencePath 'machines_old.txt')))
    }
}
if ($InactiveComputers -or ($all -and 'inactivecomputers' -notin $exclude) -or 'inactivecomputers' -in $selectedChecks) {
    $running = $true
    Write-Both "[*] Inactive Computer Objects Audit"
    Get-InactiveComputerObjects
}
Function Get-DCsNotOwnedByDA {
    #Searches for DC objects not owned by the Domain Admins group
    $count = 0
    $progresscount = 0
    $domaincontrollers = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } -Property *
    $totalcount = ($domaincontrollers | Measure-Object | Select-Object Count).count
    if ($totalcount -gt 0) {
        foreach ($machine in $domaincontrollers) {
            $progresscount++
            Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
            if ($machine.ntsecuritydescriptor.Owner -ne "$env:UserDomain\$DomainAdmins") {
                Add-Content -Path (Get-EvidencePath 'dcs_not_owned_by_da.txt') -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersion), $($machine.IPv4Address), owned by $($machine.ntsecuritydescriptor.Owner)"
                $count++
            }
        }
        Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Ready" -Completed
    }
    if ($count -gt 0) {
        Write-Both "    [!] We found $count DCs not owned by Domains Admins group! see dcs_not_owned_by_da.txt"
        Write-Nessus-Finding "DCsNotByDA" "KB547" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dcs_not_owned_by_da.txt')))
    }
}
Function Get-HostDetails {
    #Gets basic information about the host
    Write-Both "    [+] Device Name:  $env:ComputerName"
    Write-Both "    [+] Domain Name:  $env:UserDomain"
    Write-Both "    [+] User Name  :  $env:UserName"
    Write-Both "    [+] NT Version :  $(Get-WinVersion)"
    Write-Both "    [+] PowerShell :  $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)"
    $IPAddresses = [net.dns]::GetHostAddresses("") | Select-Object -ExpandProperty IPAddressToString
    foreach ($ip in $IPAddresses) {
        if ($ip -ne "::1") {
            Write-Both "    [+] IP Address :  $ip"
        }
    }
}
Function Get-FunctionalLevel {
    #Gets the functional level for domain and forest using the current DC OS inventory
    $domain = Get-ADDomain
    $forest = Get-ADForest
    $dcs = @(Get-ADDomainController -Filter *)

    $domainLevel = [string]$domain.DomainMode
    $forestLevel = [string]$forest.ForestMode

    Write-Both "    [+] Domain functional level: $domainLevel"
    Write-Both "    [+] Forest functional level: $forestLevel"

    if (-not $dcs -or $dcs.Count -eq 0) {
        Write-Both "    [!] Unable to enumerate domain controllers to validate functional level posture."
        return
    }

    $dcCaps = @()
    foreach ($dc in $dcs) {
        $capRank = Get-ADAuditDcFunctionalLevelCapRank -DomainController $dc
        $dcCaps += [pscustomobject]@{
            Name             = $dc.HostName
            OperatingSystem  = $dc.OperatingSystem
            Version          = $dc.OperatingSystemVersion
            MaxRank          = $capRank
        }
    }

    $knownCaps = @($dcCaps | Where-Object { $null -ne $_.MaxRank })
    $unknownCaps = @($dcCaps | Where-Object { $null -eq $_.MaxRank })

    if ($unknownCaps.Count -gt 0) {
        foreach ($dc in $unknownCaps) {
            Write-Both "    [*] Unable to map DC functional-level capability from OS inventory: $($dc.Name) [$($dc.OperatingSystem)] [$($dc.Version)]"
        }
    }

    if ($knownCaps.Count -eq 0) {
        Write-Both "    [!] Unable to determine the maximum supported functional level from DC OS inventory."
        return
    }

    $supportedRank = ($knownCaps | Measure-Object -Property MaxRank -Minimum).Minimum
    $recommendedDomainMode = Get-ADAuditFunctionalLevelMode -Rank $supportedRank -Scope Domain
    $recommendedForestMode = Get-ADAuditFunctionalLevelMode -Rank $supportedRank -Scope Forest

    $domainRank = Get-ADAuditFunctionalLevelRank -Mode $domainLevel
    $forestRank = Get-ADAuditFunctionalLevelRank -Mode $forestLevel

    if ($null -ne $domainRank -and $domainRank -lt $supportedRank) {
        $message = "DomainLevel can be raised from $domainLevel to $recommendedDomainMode based on current domain controller operating systems."
        Write-Both "    [!] $message"
        Write-Nessus-Finding "FunctionalLevel" "KB546" $message
    }
    else {
        Write-Both "    [+] Domain functional level is aligned with the current domain controller operating systems."
    }

    if ($null -ne $forestRank -and $forestRank -lt $supportedRank) {
        $message = "ForestLevel can be raised from $forestLevel to $recommendedForestMode based on current domain controller operating systems."
        Write-Both "    [!] $message"
        Write-Nessus-Finding "FunctionalLevel" "KB546" $message
    }
    else {
        Write-Both "    [+] Forest functional level is aligned with the current domain controller operating systems."
    }

    if ($supportedRank -eq 10) {
        Write-Both "    [+] Domain controller inventory supports the Windows Server 2025 functional level."
    }
    elseif ($supportedRank -eq 9) {
        Write-Both "    [+] Domain controller inventory supports up to the Windows Server 2022 functional level."
    }
    elseif ($supportedRank -eq 8) {
        Write-Both "    [+] Domain controller inventory supports up to the Windows Server 2019 functional level."
    }
    elseif ($supportedRank -eq 7) {
        Write-Both "    [+] Domain controller inventory supports up to the Windows Server 2016 functional level."
    }
}
Function Get-GPOEnum {
    #Loops GPOs for some important domain-wide settings
    $AllowedJoin = @()
    $HardenNTLM = @()
    $DenyNTLM = @()
    $AuditNTLM = @()
    $NTLMAuthExceptions = @()
    $EncryptionTypesNotConfigured = $true
    $AdminLocalLogonAllowed = $true
    $AdminRPDLogonAllowed = $true
    $AdminNetworkLogonAllowed = $true
    $AllGPOs = Get-GPO -All | sort DisplayName
    foreach ($GPO in $AllGPOs) {
        $GPOreport = Get-GPOReport -Guid $GPO.Id -ReportType Xml
        #Look for GPO that allows join PC to domain
        $permissionindex = $GPOreport.IndexOf('<q1:Name>SeMachineAccountPrivilege</q1:Name>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeMachineAccountPrivilege' }).Member) ) {
                $obj = New-Object -TypeName PSObject
                $obj | Add-Member -MemberType NoteProperty -Name GPO  -Value $GPO.DisplayName
                $obj | Add-Member -MemberType NoteProperty -Name SID  -Value $member.Sid.'#text'
                $obj | Add-Member -MemberType NoteProperty -Name Name -Value $member.Name.'#text'
                $AllowedJoin += $obj
            }
        }
        #Look for GPO that hardens NTLM
        $permissionindex = $GPOreport.IndexOf('NoLMHash</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'NoLMHash' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "NoLMHash $($value.Display.DisplayBoolean)"
            $HardenNTLM += $obj
        }
        $permissionindex = $GPOreport.IndexOf('LmCompatibilityLevel</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'LmCompatibilityLevel' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "LmCompatibilityLevel $($value.Display.DisplayString)"
            $HardenNTLM += $obj
        }
        #Look for GPO that denies NTLM
        $permissionindex = $GPOreport.IndexOf('RestrictNTLMInDomain</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'RestrictNTLMInDomain' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "RestrictNTLMInDomain $($value.Display.DisplayString)"
            $DenyNTLM += $obj
        }
        #Look for GPO that audits NTLM
        $permissionindex = $GPOreport.IndexOf('AuditNTLMInDomain</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'AuditNTLMInDomain' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "AuditNTLMInDomain $($value.Display.DisplayString)"
            $AuditNTLM += $obj
        }
        $permissionindex = $GPOreport.IndexOf('AuditReceivingNTLMTraffic</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'AuditReceivingNTLMTraffic' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "AuditReceivingNTLMTraffic $($value.Display.DisplayString)"
            $AuditNTLM += $obj
        }
        #Look for GPO that allows NTLM exclusions
        $permissionindex = $GPOreport.IndexOf('DCAllowedNTLMServers</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'DCAllowedNTLMServers' }).SettingStrings.Value) ) {
                $NTLMAuthExceptions += $member
            }
        }
        #Validate Kerberos Encryption algorithm
        $permissionindex = $GPOreport.IndexOf('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes')
        if ($permissionindex -gt 0) {
            $EncryptionTypesNotConfigured = $false
            $xmlreport = [xml]$GPOreport
            $EncryptionTypes = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions.Display.DisplayFields.Field
            if (($EncryptionTypes     | Where-Object { $_.Name -eq 'DES_CBC_CRC' }             | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_CRC for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'DES_CBC_MD5' }             | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_MD5 for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'RC4_HMAC_MD5' }            | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled RC4_HMAC_MD5 for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'AES128_HMAC_SHA1' }        | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] AES128_HMAC_SHA1 not enabled for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'AES256_HMAC_SHA1' }        | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] AES256_HMAC_SHA1 not enabled for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'Future encryption types' } | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] Future encryption types not enabled for Kerberos!" }
        }
        #Validates Admins local logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyInteractiveLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyInteractiveLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminLocalLogonAllowed = $false
                    Add-Content -Path (Get-EvidencePath 'admin_logon_restrictions.txt') -Value "$($GPO.DisplayName) SeDenyInteractiveLogonRight $($member.Name.'#text')"
                }
            }
        }
        #Validates Admins RDP logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyRemoteInteractiveLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyRemoteInteractiveLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminRPDLogonAllowed = $false
                    Add-Content -Path (Get-EvidencePath 'admin_logon_restrictions.txt') -Value "$($GPO.DisplayName) SeDenyRemoteInteractiveLogonRight $($member.Name.'#text')"
                }
            }
        }
        #Validates Admins network logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyNetworkLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyNetworkLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminNetworkLogonAllowed = $false
                    Add-Content -Path (Get-EvidencePath 'admin_logon_restrictions.txt') -Value "$($GPO.DisplayName) SeDenyNetworkLogonRight $($member.Name.'#text')"
                }
            }
        }
    }
    #Output for join PC to domain
    foreach ($record in $AllowedJoin) {
        Write-Both "    [+] GPO [$($record.GPO)] allows [$($record.Name)] to join computers to domain"
    }
    #Output for Admins local logon restrictions
    if ($AdminLocalLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise local logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise local logon across domain!"
    }
    #Output for Admins RDP logon restrictions
    if ($AdminRPDLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise RDP logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise RDP logon across domain!"
    }
    #Output for Admins network logon restrictions
    if ($AdminNetworkLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise network logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise network logon across domain!"
    }
    #Output for Validate Kerberos Encryption algorithm
    if ($EncryptionTypesNotConfigured) {
        Write-Both "    [!] RC4_HMAC_MD5 enabled for Kerberos across domain!!!"
    }
    #Output for deny NTLM
    if ($DenyNTLM.count -eq 0) {
        if ($HardenNTLM.count -eq 0) {
            Write-Both "    [!] No GPO denies NTLM authentication!"
            Write-Both "    [!] No GPO explicitely restricts LM or NTLMv1!"
        }
        else {
            Write-Both "    [+] NTLM authentication hardening implemented, but NTLM not denied"
            foreach ($record in $HardenNTLM) {
                Write-Both "        [-] $($record.value)"
                Add-Content -Path (Get-EvidencePath 'ntlm_restrictions.txt') -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
            }
        }
    }
    else {
        foreach ($record in $DenyNTLM) {
            Add-Content -Path (Get-EvidencePath 'ntlm_restrictions.txt') -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
        }
    }
    #Output for NTLM exceptions
    if ($NTLMAuthExceptions.count -ne 0) {
        foreach ($record in $NTLMAuthExceptions) {
            Add-Content -Path (Get-EvidencePath 'ntlm_restrictions.txt') -Value "NTLM auth exceptions $($record)"
        }
    }
    #Output for NTLM audit
    if ($AuditNTLM.count -eq 0) {
        Write-Both "    [!] No GPO enables NTLM audit authentication!"
    }
    else {
        foreach ($record in $AuditNTLM) {
            Add-Content -Path (Get-EvidencePath 'ntlm_restrictions.txt') -Value "NTLM audit GPO [$($record.gpo)] with value [$($record.value)]"
        }
    }
}
Function Get-PrivilegedGroupMembership {
    #List Domain Admins, Enterprise Admins and Schema Admins members
    $SchemaMembers = Get-ADGroup $SchemaAdmins     | Get-ADGroupMember
    $EnterpriseMembers = Get-ADGroup $EnterpriseAdmins | Get-ADGroupMember
    $DomainAdminsMembers = Get-ADGroup $DomainAdmins     | Get-ADGroupMember
    if (($SchemaMembers | measure).count -ne 0) {
        Write-Both "    [!] Schema Admins not empty!!!"
        foreach ($member in $SchemaMembers) {
            Add-Content -Path (Get-EvidencePath 'schema_admins.txt') -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
        }
    }
    if (($EnterpriseMembers | measure).count -ne 0) {
        Write-Both "    [!] Enterprise Admins not empty!!!"
        foreach ($member in $EnterpriseMembers) {
            Add-Content -Path (Get-EvidencePath 'enterprise_admins.txt') -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
        }
    }
    foreach ($member in $DomainAdminsMembers) {
        Add-Content -Path (Get-EvidencePath 'domain_admins.txt') -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
    }
}
Function Get-DCEval {
    #Basic validation of all DCs in forest
    #Collect all DCs in forest
    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $ADs = Get-ADDomainController -Filter { Site -like "*" }
    #Validate OS version of DCs
    $osList = @()
    $ADs | ForEach-Object { $osList += $_.OperatingSystem }
    if (($osList | sort -Unique | measure).Count -eq 1) {
        Write-Both "    [+] All DCs are the same OS version of $($osList | sort -Unique)"
    }
    else {
        Write-Both "    [!] Operating system differs across DCs!!!"
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2019' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2019"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2019' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2022' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2022"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2022' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2025' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2025"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2025' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
    }
    #Validate DCs hotfix level
    if ( (( $ADs | Select-Object OperatingSystemHotfix -Unique ) | measure).count -eq 1 -or ( $ADs | Select-Object OperatingSystemHotfix -Unique ) -eq $null ) {
        Write-Both "    [+] All DCs have the same hotfix of [$($ADs | Select-Object OperatingSystemHotFix -Unique | ForEach-Object {$_.OperatingSystemHotfix})]"
    }
    else {
        Write-Both "    [!] Hotfix level differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) hotfix [$($_.OperatingSystemHotfix)]"
        }
    }
    #Validate DCs Service Pack level
    if ((($ADs | Select-Object OperatingSystemServicePack -Unique) | measure).count -eq 1 -or ($ADs | Select-Object OperatingSystemServicePack -Unique) -eq $null) {
        Write-Both "    [+] All DCs have the same Service Pack of [$($ADs | Select-Object OperatingSystemServicePack -Unique | ForEach-Object {$_.OperatingSystemServicePack})]"
    }
    else {
        Write-Both "    [!] Service Pack level differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) Service Pack [$($_.OperatingSystemServicePack)]"
        }
    }
    #Validate DCs OS Version
    if ((($ADs | Select-Object OperatingSystemVersion -Unique ) | measure).count -eq 1 -or ($ADs | Select-Object OperatingSystemVersion -Unique) -eq $null) {
        Write-Both "    [+] All DCs have the same OS Version of [$($ADs | Select-Object OperatingSystemVersion -Unique | ForEach-Object {$_.OperatingSystemVersion})]"
    }
    else {
        Write-Both "    [!] OS Version differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) OS Version [$($_.OperatingSystemVersion)]"
        }
    }
    #List sites without GC
    $SitesWithNoGC = $false
    foreach ($Site in $Forest.Sites) {
        if (($ADs | Where-Object { $_.Site -eq $Site.Name } | Where-Object { $_.IsGlobalCatalog -eq $true }) -eq $null) {
            $SitesWithNoGC = $true
            Add-Content -Path (Get-EvidencePath 'sites_no_gc.txt') -Value "$($Site.Name)"
        }
    }
    if ($SitesWithNoGC -eq $true) {
        Write-Both "    [!] You have sites with no Global Catalog!"
    }
    #Does one DC holds all FSMO
    if (($ADs | Where-Object { $_.OperationMasterRoles -ne $null } | measure).count -eq 1) {
        Write-Both "    [!] DC $($ADs | Where-Object {$_.OperationMasterRoles -ne $null} | select -ExpandProperty Hostname) holds all FSMO roles!"
    }
    #DCs with weak Kerberos algorithm (*CH* Changed below to look for msDS-SupportedEncryptionTypes to work with 2008R2)
$ADcomputers = $ADs | ForEach-Object { Get-ADComputer $_.Name -Properties msDS-SupportedEncryptionTypes }
$WeakKerberos = $false

# Mapping of encryption types
$encryptionTypes = @{
    0  = "Not defined - defaults to RC4_HMAC_MD5"
    1  = "DES_CBC_CRC"
    2  = "DES_CBC_MD5"
    3  = "DES_CBC_CRC, DES_CBC_MD5"
    4  = "RC4"
    5  = "DES_CBC_CRC, RC4"
    6  = "DES_CBC_MD5, RC4"
    7  = "DES_CBC_CRC, DES_CBC_MD5, RC4"
    8  = "AES 128"
    9  = "DES_CBC_CRC, AES 128"
    10 = "DES_CBC_MD5, AES 128"
    11 = "DES_CBC_CRC, DES_CBC_MD5, AES 128"
    12 = "RC4, AES 128"
    13 = "DES_CBC_CRC, RC4, AES 128"
    14 = "DES_CBC_MD5, RC4, AES 128"
    15 = "DES_CBC_CRC, DES_CBC_MD5, RC4, AES 128"
    16 = "AES 256"
    17 = "DES_CBC_CRC, AES 256"
    18 = "DES_CBC_MD5, AES 256"
    19 = "DES_CBC_CRC, DES_CBC_MD5, AES 256"
    20 = "RC4, AES 256"
    21 = "DES_CBC_CRC, RC4, AES 256"
    22 = "DES_CBC_MD5, RC4, AES 256"
    23 = "DES_CBC_CRC, DES_CBC_MD5, RC4, AES 256"
    24 = "AES 128, AES 256"
    25 = "DES_CBC_CRC, AES 128, AES 256"
    26 = "DES_CBC_MD5, AES 128, AES 256"
    27 = "DES_CBC_CRC, DES_CBC_MD5, AES 128, AES 256"
    28 = "RC4, AES 128, AES 256"
    29 = "DES_CBC_CRC, RC4, AES 128, AES 256"
    30 = "DES_CBC_MD5, RC4, AES 128, AES 256"
    31 = "DES_CBC_CRC, DES_CBC_MD5, RC4-HMAC, AES128-CTS-HMAC-SHA1-96, AES256-CTS-HMAC-SHA1-96"
}

foreach ($DC in $ADcomputers) {
    $encType = $DC."msDS-SupportedEncryptionTypes"
    if ($encType -ne 8 -and $encType -ne 16 -and $encType -ne 24) {
        $WeakKerberos = $true
        $hexValue = "0x{0:X}" -f $encType
        $supportedTypes = $encryptionTypes[$encType]
        Add-Content -Path (Get-EvidencePath 'dcs_weak_kerberos_ciphersuite.txt') -Value "$($DC.DNSHostName)`nDecimal Value: $encType`nHex Value: $hexValue`nSupported Encryption Types: $supportedTypes`n"
    }
}

if ($WeakKerberos) {
    Add-Content -Path (Get-EvidencePath 'dcs_weak_kerberos_ciphersuite.txt') -Value "`nLink: https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797`n"
    Write-Both "    [!] You have DCs with RC4 or DES allowed for Kerberos!!!"
    Write-Nessus-Finding "WeakKerberosEncryption" "KB995" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dcs_weak_kerberos_ciphersuite.txt')))
}
    #Check where newly joined computers go
    $newComputers = (Get-ADDomain).ComputersContainer
    $newUsers = (Get-ADDomain).UsersContainer
    Write-Both "    [+] New joined computers are stored in $newComputers"
    Write-Both "    [+] New users are stored in $newUsers"
}
Function Get-DefaultDomainControllersPolicy {
    #Enumerates Default Domain Controllers Policy for default unsecure and excessive options
    $ExcessiveDCInteractiveLogon = $false
    $ExcessiveDCBackupPermissions = $false
    $ExcessiveDCRestorePermissions = $false
    $ExcessiveDCDriverPermissions = $false
    $ExcessiveDCLocalShutdownPermissions = $false
    $ExcessiveDCRemoteShutdownPermissions = $false
    $ExcessiveDCTimePermissions = $false
    $ExcessiveDCBatchLogonPermissions = $false
    $ExcessiveDCRDPLogonPermissions = $false
    $GPO = Get-GPO 'Default Domain Controllers Policy'
    $GPOreport = Get-GPOReport -Guid $GPO.Id -ReportType Xml
    #Interactive local logon
    $permissionindex = $GPOreport.IndexOf('SeInteractiveLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeInteractiveLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$EntrepriseDomainControllers") {
                $ExcessiveDCInteractiveLogon = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeInteractiveLogonRight $($member.Name.'#text')"
            }
        }
    }
    #Batch logon
    $permissionindex = $GPOreport.IndexOf('SeBatchLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeBatchLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCBatchLogonPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeBatchLogonRight $($member.Name.'#text')"
            }
        }
    }
    #RDP logon
    $permissionindex = $GPOreport.IndexOf('SeRemoteInteractiveLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRemoteInteractiveLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$EntrepriseDomainControllers") {
                $ExcessiveDCRDPLogonPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeRemoteInteractiveLogonRight $($member.Name.'#text')"
            }
        }
    }
    #Backup
    $permissionindex = $GPOreport.IndexOf('SeBackupPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeBackupPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCBackupPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeBackupPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Restore
    $permissionindex = $GPOreport.IndexOf('SeRestorePrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRestorePrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCRestorePermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeRestorePrivilege $($member.Name.'#text')"
            }
        }
    }
    #Load driver
    $permissionindex = $GPOreport.IndexOf('SeLoadDriverPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeLoadDriverPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCDriverPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeLoadDriverPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Local shutdown
    $permissionindex = $GPOreport.IndexOf('SeShutdownPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeShutdownPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCLocalShutdownPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeShutdownPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Remote shutdown
    $permissionindex = $GPOreport.IndexOf('SeRemoteShutdownPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRemoteShutdownPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCRemoteShutdownPermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeRemoteShutdownPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Change time
    $permissionindex = $GPOreport.IndexOf('SeSystemTimePrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeSystemTimePrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$LocalService") {
                $ExcessiveDCTimePermissions = $true
                Add-Content -Path (Get-EvidencePath 'default_domain_controller_policy_audit.txt') -Value "SeSystemTimePrivilege $($member.Name.'#text')"
            }
        }
    }
    #Output for Default Domain Controllers Policy
    if ($ExcessiveDCInteractiveLogon -or $ExcessiveDCBackupPermissions -or $ExcessiveDCRestorePermissions -or $ExcessiveDCDriverPermissions -or $ExcessiveDCLocalShutdownPermissions -or $ExcessiveDCRemoteShutdownPermissions -or $ExcessiveDCTimePermissions -or $ExcessiveDCBatchLogonPermissions -or $ExcessiveDCRDPLogonPermissions) {
        Write-Both "    [!] Excessive permissions in Default Domain Controllers Policy detected!"
    }
}
Function Get-RecentChanges() {
    #Retrieve users and groups that have been created during last 30 days
    $DateCutOff = ((Get-Date).AddDays(-30)).Date
    $newUsers = Get-ADUser  -Filter { whenCreated -ge $DateCutOff } -Properties whenCreated | select whenCreated, SamAccountName
    $newGroups = Get-ADGroup -Filter { whenCreated -ge $DateCutOff } -Properties whenCreated | select whenCreated, SamAccountName
    $countUsers = 0
    $countGroups = 0
    $progresscountUsers = 0
    $progresscountGroups = 0
    $totalcountUsers = ($newUsers  | Measure-Object | Select-Object Count).count
    $totalcountGroups = ($newGroups | Measure-Object | Select-Object Count).count
    if ($totalcountUsers -gt 0) {
        # Add header line (overwrite any existing file)
"@User Created within the last 30 days" | Set-Content -Path (Get-EvidencePath 'new_users.txt')
        foreach ($newUser in $newUsers ) { Add-Content -Path (Get-EvidencePath 'new_users.txt') -Value "Account $($newUser.SamAccountName) was created $($newUser.whenCreated)" }
        Write-Both "    [!] $totalcountUsers new users were created last 30 days, see $outputdir\new_users.txt"
    }
    if ($totalcountGroups -gt 0) {
        foreach ($newGroup in $newGroups ) { Add-Content -Path (Get-EvidencePath 'new_groups.txt') -Value "Group $($newGroup.SamAccountName) was created $($newGroup.whenCreated)" }
        Write-Both "    [!] $totalcountGroups new groups were created last 30 days, see $outputdir\new_groups.txt"
    }
}
Function Get-ReplicationType {
    #Retrieve replication mechanism (FRS or DFSR)
    $objectName = "DFSR-GlobalSettings"
    $searcher = [ADSISearcher] "(objectClass=msDFSR-GlobalSettings)"
    $objectExists = $searcher.FindOne() -ne $null
    if ($objectExists) {
        $DFSRFlags = (Get-ADObject -Identity "CN=DFSR-GlobalSettings,$((Get-ADDomain).systemscontainer)" -Properties msDFSR-Flags).'msDFSR-Flags'
        switch ($DFSRFlags) {
            0 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: started!" }
            16 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: prepared!" }
            32 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: redirected!" }
            48 { Write-Both "    [+] DFSR mechanism is used to replicate across domain controllers." }
        }
    }
    else {
        Write-Both "    [!] FRS mechanism is still used to replicate across domain controllers, you should migrate to DFSR!"
    }
}
Function Get-RecycleBinState {
    #Check if recycle bin is enabled
    if ((Get-ADOptionalFeature -Filter 'Name -eq "Recycle Bin Feature"').EnabledScopes) {
        Write-Both "    [+] Recycle Bin is enabled in the domain"
    }
    else {
        Write-Both "    [!] Recycle Bin is disabled in the domain, you should consider enabling it!"
    }
}
Function Get-CriticalServicesStatus {
    #Check AD services status
    Write-Both "    [+] Checking services on all DCs"
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    $searcher = [ADSISearcher] "(objectClass=msDFSR-GlobalSettings)"
    $objectExists = $searcher.FindOne() -ne $null
    if ($objectExists) {
        $services = @("dns", "netlogon", "kdc", "w32time", "dfsr")
    }
    else {
        $services = @("dns", "netlogon", "kdc", "w32time", "ntfrs")
    }

    foreach ($DC in $dcList) {
        foreach ($service in $services) {
            try {
                $checkService = Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName $DC -Filter "Name='$service'"
                if (-not $checkService) {
                    Write-Both "        [!] Service $service cannot be checked on $DC!"
                    continue
                }

                $serviceStatus = [string]$checkService.State
                if (-not $serviceStatus) {
                    Write-Both "        [!] Service $service cannot be checked on $DC!"
                }
                elseif ($serviceStatus -ne "Running") {
                    Write-Both "        [!] Service $service is not running on $DC!"
                }
            }
            catch {
                Write-Both "        [!] Service $service cannot be checked on $DC!"
            }
        }
    }
}
Function Get-LastWUDate {
    #Check Windows update status and last install date
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    $lastMonth = (Get-Date).AddDays(-30)
    Write-Both "    [+] Checking Windows Update"
    foreach ($DC in $dcList) {
        try {
            $wuService = Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName $DC -Filter "Name='wuauserv'"
            $startMode = $wuService.StartMode
            if (-not $startMode) {
                Write-Both "        [!] Windows Update service cannot be checked on $DC!"
            }
            elseif ($startMode -eq "Disabled") {
                Write-Both "        [!] Windows Update service is disabled on $DC!"
            }
        }
        catch {
            Write-Both "        [!] Windows Update service cannot be checked on $DC!"
        }
    }

    $progresscount = 0
    $totalcount = ($dcList | Measure-Object | Select-Object -ExpandProperty Count)
    foreach ($DC in $dcList) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for last Windows Update installation on all DCs..." -Status "Currently searching on $DC" -PercentComplete ($progresscount / $totalcount * 100)
        try {
            $lastHotfix = (Get-HotFix -ComputerName $DC | Where-Object { $_.InstalledOn -ne $null } | Sort-Object -Descending InstalledOn | Select-Object -First 1).InstalledOn
            if ($lastHotfix -lt $lastMonth) {
                Write-Both "        [!] Windows is not up to date on $DC, last install: $lastHotfix"
            }
            else {
                Write-Both "        [+] Windows is up to date on $DC, last install: $lastHotfix"
            }
        }
        catch {
            Write-Both "        [!] Cannot check last update date on $DC"
        }
        $progresscount++
    }
    Write-Progress -Activity "Searching for last Windows Update installation on all DCs..." -Status "Ready" -Completed
}
Function Get-TimeSource {
    #Get NTP sync source
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    Write-Both "    [+] Checking NTP configuration"
    foreach ($DC in $dcList) {
        $ntpSource = w32tm /query /source /computer:$DC
        if ($ntpSource -like '*0x800706BA*') {
            Write-Both "        [!] Cannot get time source for $DC"
        }
        else {
            Write-Both "        [+] $DC is syncing time from $ntpSource"
        }
    }
}
Function Get-RODC {
    #Check for RODC
    Write-Both "    [+] Checking for Read Only DCs"
    $ADs = Get-ADDomainController -Filter { Site -like "*" }
    $ADs | ForEach-Object {
        if ($_.IsReadOnly) {
            Write-Both "        [+] DC $($_.Name) is a RODC server!"
        }
    }
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
Function Remove-StringLatinCharacters {
    #Removes latin characters
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}

function Add-KerberoastExplanationToPasswordQualityReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,
        [Parameter(Mandatory = $false)]
        [string]$DomainController
    )

    if (-not (Test-Path -LiteralPath $ReportPath)) { return }

    $lines = Get-Content -LiteralPath $ReportPath
    $header = 'These accounts are susceptible to the Kerberoasting attack:'

    # Find the simple list block under the header
    $headerIndex = [array]::IndexOf($lines, $header)
    if ($headerIndex -lt 0) { return }

    # Collect the simple list items that follow the header (until a blank line)
    $simpleList = @()
    for ($i = $headerIndex + 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if (-not $line) { break }
        $simpleList += $lines[$i]
    }

    if ($simpleList.Count -eq 0) { return }

    # Normalize SAM names
    $kerberoastAccounts = @()
    foreach ($l in $simpleList) {
        $trimmed = $l.Trim()
        if ($trimmed) { $kerberoastAccounts += $trimmed }
    }

    # Split into krbtgt vs service accounts
    $krbtgtAccounts  = @()
    $serviceAccounts = @()
    foreach ($acct in $kerberoastAccounts) {
        $sam = $acct
        if ($acct -like '*\*') {
            $parts = $acct.Split('\', 2)
            $sam   = $parts[1]
        }
        if ($sam -ieq 'krbtgt') { $krbtgtAccounts += $acct } else { $serviceAccounts += $acct }
    }

    # Optional: krbtgt details
    $krbtgtInfo = $null
    if ($krbtgtAccounts.Count -gt 0 -and $DomainController) {
        try {
            $krbtgtInfo = Get-ADUser -Server $DomainController -Filter { SamAccountName -eq 'krbtgt' } -Properties PasswordLastSet -ErrorAction Stop
        } catch { }
    }

    # Build replacement
    $replacement = New-Object System.Collections.Generic.List[string]
    $replacement.Add($header)

    if ($krbtgtAccounts.Count -gt 0) {
        $replacement.Add('  Password not changed in at least 180 days for the built-in krbtgt account (Golden Ticket / ticket-forgery risk):')
        foreach ($acct in $krbtgtAccounts) { $replacement.Add(("    {0}" -f $acct)) }
        $replacement.Add('  Reference: Microsoft guidance "Reset the krbtgt account password".')
        $replacement.Add('')
    }

    if ($serviceAccounts.Count -gt 0) {
        $replacement.Add('  The account is a user or service account with a password that could be weak / brute-forceable (Kerberoastable due to SPN / service ticket exposure):')
        foreach ($acct in $serviceAccounts) { $replacement.Add(("    {0}" -f $acct)) }
        $replacement.Add('  Reference: Microsoft security guidance on mitigating Kerberoasting.')
        $replacement.Add('')
    }

    # Splice into file
    $endOfBlock = $headerIndex + 1 + $simpleList.Count
    $newContent = @()
    if ($headerIndex -gt 0) { $newContent += $lines[0..($headerIndex-1)] }
    $newContent += $replacement
    if ($endOfBlock -lt $lines.Count) { $newContent += $lines[$endOfBlock..($lines.Count-1)] }

    Set-Content -LiteralPath $ReportPath -Value $newContent
}

Function Get-PasswordQuality {
    # Use DSInternals to evaluate password quality (supports remote execution)
    # Output is split into category-specific files for easier consumption and reporting.
    if (Import-ADAuditModule -Name DSInternals) {
        try {
            $cfgNC = (Get-ADRootDSE).ConfigurationNamingContext

            $sites = Get-ADObject `
                -LDAPFilter '(objectClass=site)' `
                -SearchBase $cfgNC `
                -ErrorAction Stop

            $totalSite = ($sites | Measure-Object).Count
            $count = 0

            foreach ($site in $sites) {
                if ($site.Name -eq (Remove-StringLatinCharacters $site.Name)) {
                    $count++
                }
            }

            if ($count -ne $totalSite) {
                Write-Both "    [!] One or more sites have illegal characters in their name, can't get password quality!"
                return
            }
        }
        catch {
            Write-Both "    [!] Failed to enumerate AD sites for password quality test: $($_.Exception.Message)"
            return
        }

        # Determine a single DC to query (fallback chain to ensure we get a plain string)
        $dcObj = Get-ADDomainController -Discover
        $dc = $dcObj.DNSHostName
        if (-not $dc) { $dc = $dcObj.HostName }
        if (-not $dc) { $dc = $dcObj.Name }
        if (-not $dc -or [string]::IsNullOrWhiteSpace($dc)) {
            Write-Both "    [!] Could not determine a domain controller hostname for password quality test."
            return
        }
        $dc = [string]$dc

        try {
            $domain = Get-ADDomain
            $domainDN = $domain.DistinguishedName

            $accounts = Get-ADReplAccount `
                -All `
                -Server $dc `
                -NamingContext $domainDN `
                -ErrorAction Stop

            if ($accounts) {
                # Run DSInternals password quality test and capture the full report
                $passwordQualityPath = Get-EvidencePath 'password_quality.txt'

                $accounts |
                    Test-PasswordQuality -IncludeDisabledAccounts |
                    Out-File -FilePath $passwordQualityPath

                if (Test-Path $passwordQualityPath) {
                    Write-Both "    [!] Password quality test done, see password_quality.txt"

                    # Post-process the DSInternals report to clarify why accounts are marked as Kerberoastable
                    try {
                        Add-KerberoastExplanationToPasswordQualityReport `
                            -ReportPath $passwordQualityPath `
                            -DomainController $dc
                    }
                    catch {
                        Write-Both "    [*] Failed to append Kerberoast clarification to password quality report: $($_.Exception.Message)"
                    }

                    # Split the combined report into category-specific files
                    try {
                        Split-PasswordQualityReport -ReportPath $passwordQualityPath
                    }
                    catch {
                        Write-Both "    [*] Failed to split password quality report into category files: $($_.Exception.Message)"
                    }
                }
                else {
                    Write-Both "    [!] Password quality test ran but output file was not created."
                }
            }
            else {
                Write-Both "    [!] No replication accounts retrieved from DC $dc; skipping password quality test."
            }
        }
        catch {
            # Delimit $dc to avoid $dc: being parsed as an (invalid) scope qualifier
            Write-Both "    [!] Failed password quality test on DC ${dc}: $($_.Exception.Message)"
        }
    }
    else {
        Write-Both "    [!] DSInternals module not available; skipping password quality test."
    }
}

function Split-PasswordQualityReport {
    # Parses the combined password_quality.txt from DSInternals Test-PasswordQuality and writes
    # each section into a dedicated evidence file.  The original combined file is kept intact.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )

    if (-not (Test-Path -LiteralPath $ReportPath)) { return }

    $allLines = @(Get-Content -LiteralPath $ReportPath -ErrorAction Stop)
    if ($allLines.Count -eq 0) { return }

    # Map each DSInternals section header to a target evidence file name and a nessus KB id
    $sectionMap = [ordered]@{
        'Passwords of these accounts are stored using reversible encryption:'                    = @{ File = 'pq_reversible_encryption.txt';       KB = 'KB997';  Severity = 'Critical'; Label = 'reversible encryption' }
        'LM hashes of passwords of these accounts are present:'                                 = @{ File = 'pq_lm_hashes.txt';                   KB = 'KB998';  Severity = 'Critical'; Label = 'LM hashes present' }
        'These accounts have no password set:'                                                  = @{ File = 'pq_no_password.txt';                 KB = 'KB999';  Severity = 'Critical'; Label = 'no password set' }
        'Passwords of these accounts have been found in the dictionary:'                        = @{ File = 'pq_dictionary_passwords.txt';        KB = 'KB1000'; Severity = 'Critical'; Label = 'dictionary passwords' }
        'Historical passwords of these accounts have been found in the dictionary:'             = @{ File = 'pq_historical_dictionary.txt';       KB = 'KB1001'; Severity = 'Medium';   Label = 'historical dictionary passwords' }
        'These groups of accounts have the same passwords:'                                     = @{ File = 'pq_duplicate_passwords.txt';         KB = 'KB1002'; Severity = 'High';     Label = 'duplicate passwords' }
        'These computer accounts have default passwords:'                                       = @{ File = 'pq_default_computer_passwords.txt';  KB = 'KB1003'; Severity = 'High';     Label = 'default computer passwords' }
        'Kerberos AES keys are missing from these accounts:'                                    = @{ File = 'pq_missing_aes_keys.txt';            KB = 'KB1004'; Severity = 'Medium';   Label = 'missing Kerberos AES keys' }
        'Kerberos pre-authentication is not required for these accounts:'                       = @{ File = 'pq_no_preauth.txt';                  KB = 'KB1005'; Severity = 'High';     Label = 'Kerberos pre-auth not required' }
        'Only DES encryption is allowed to be used with these accounts:'                        = @{ File = 'pq_des_only.txt';                    KB = 'KB1006'; Severity = 'Critical'; Label = 'DES-only encryption' }
        'These administrative accounts are allowed to be delegated to a service:'               = @{ File = 'pq_admin_delegation.txt';            KB = 'KB1007'; Severity = 'High';     Label = 'admin accounts delegatable' }
        'Passwords of these accounts will never expire:'                                        = @{ File = 'pq_password_never_expires.txt';      KB = 'KB1008'; Severity = 'Medium';   Label = 'password never expires' }
        'These accounts are not required to have a password:'                                   = @{ File = 'pq_password_not_required.txt';       KB = 'KB1009'; Severity = 'High';     Label = 'password not required' }
        'These accounts are susceptible to the Kerberoasting attack:'                           = @{ File = 'pq_kerberoastable.txt';              KB = 'KB1010'; Severity = 'High';     Label = 'Kerberoastable accounts' }
    }

    # Build a list of known headers for quick lookup
    $knownHeaders = $sectionMap.Keys

    # Parse the file into sections
    $sections = [ordered]@{}
    $currentHeader = $null
    $currentLines  = New-Object 'System.Collections.Generic.List[string]'

    foreach ($line in $allLines) {
        $trimmed = $line.Trim()

        # Check if this line is a known section header
        $matchedHeader = $null
        foreach ($h in $knownHeaders) {
            if ($trimmed -eq $h) {
                $matchedHeader = $h
                break
            }
        }

        if ($matchedHeader) {
            # Save previous section if any
            if ($currentHeader) {
                $sections[$currentHeader] = $currentLines.ToArray()
            }
            $currentHeader = $matchedHeader
            $currentLines  = New-Object 'System.Collections.Generic.List[string]'
        }
        elseif ($currentHeader) {
            $currentLines.Add($line) | Out-Null
        }
    }
    # Save last section
    if ($currentHeader) {
        $sections[$currentHeader] = $currentLines.ToArray()
    }

    $filesWritten = 0

    foreach ($header in $sections.Keys) {
        $bodyLines = $sections[$header]
        # Strip leading/trailing blank lines and get account entries
        $accountEntries = @($bodyLines | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })

        if ($accountEntries.Count -eq 0) { continue }

        $meta = $sectionMap[$header]
        if (-not $meta) { continue }

        $targetPath = Get-EvidencePath $meta.File

        $fileContent = @"
=====================================================================
 PASSWORD QUALITY: $($meta.Label.ToUpper())
=====================================================================
 Source    : DSInternals Test-PasswordQuality
 Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
 Accounts  : $($accountEntries.Count)
---------------------------------------------------------------------

$header

"@
        # For "groups of accounts have the same passwords" the format is different (grouped)
        # so we write the raw block preserving structure
        if ($header -match 'groups of accounts have the same passwords') {
            $fileContent += ($bodyLines -join "`n")
        }
        else {
            foreach ($entry in $accountEntries) {
                $fileContent += "  $entry`n"
            }
        }

        $fileContent += @"

---------------------------------------------------------------------
 Total accounts: $($accountEntries.Count)
=====================================================================
"@

        Set-Content -LiteralPath $targetPath -Value $fileContent -Encoding UTF8
        $filesWritten++

        Write-Both "    [+] Password quality category: $($meta.Label) - $($accountEntries.Count) accounts -> $($meta.File)"

        # Write nessus finding for each non-empty category
        Write-Nessus-Finding "PasswordQuality_$($meta.Label -replace '\s+','_')" $meta.KB $fileContent
    }

    if ($filesWritten -gt 0) {
        Write-Both "    [+] Password quality report split into $filesWritten category files"
    }
}


Function Check-Shares {
    #Check SYSVOL and NETLOGON share exists
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    Write-Both "    [+] Checking SYSVOL and NETLOGON shares on all DCs"
    foreach ($DC in $dcList) {
        try {
            $shareList = @(Get-ADAuditCimInstance -ClassName Win32_Share -ComputerName $DC)
        }
        catch {
            $shareList = @()
        }

        if (-not $shareList -or $shareList.Count -eq 0) {
            Write-Both "        [!] Cannot test shares on $DC!"
        }
        else {
            $sysvolShare = ($shareList | Where-Object { $_.Name -eq 'SYSVOL' } | Measure-Object).Count
            $netlogonShare = ($shareList | Where-Object { $_.Name -eq 'NETLOGON' } | Measure-Object).Count
            if ($sysvolShare -eq 0) { Write-Both "        [!] SYSVOL share is missing on $DC!" }
            if ($netlogonShare -eq 0) { Write-Both "        [!] NETLOGON share is missing on $DC!" }
        }
    }
}
Function Get-ADCSVulns {
    #Check for ADCS Vulnerabiltiies, ESC1,2,3,4 and 8. ESC8 will output to a different issues mapped to Nessus. 
    $certutil_output = certutil -v -template
    $certutil_lines = $certutil_output.Trim().Split("`n")
    $templates = @()
    $current_template = ""

    foreach ($line in $certutil_lines) {
        if ($line.StartsWith("Template[")) {
            if ($current_template) {
                $template_unparsed = $current_template.TrimEnd(",").Split(",")
                $SuppliesSubjectCheck = $false
                $ClientAuthCheck = $false
                $AllowEnrollCheck = $false
                $AnyPurposeCheck = $false
                $AllowWriteCheck = $false
                $AllowFullControl = $false
                $CertificateRequestAgentCheck = $false
                $TemplatePropCommonName = $null

                foreach ($detail in $template_unparsed) {
                    if ($detail -like "*TemplatePropCommonName =*") { $TemplatePropCommonName = $detail.Split("=")[1].Trim() }
                    if ($detail -like "*CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1*") { $SuppliesSubjectCheck = $true }
                    if ($detail -like "*Client Authentication*") { $ClientAuthCheck = $true }
                    if ($detail -match "^\s*Allow Enroll\s+.*\\Authenticated Users\s*$|^\s*Allow Enroll\s+.*\\Domain Users\s*$") { $AllowEnrollCheck = $true }
                    if ($detail -like "2.5.29.37.0 Any Purpose") { $AnyPurposeCheck = $true }
                    if ($detail -match "^\s*Allow Write\s+.*\\Authenticated Users\s*$|^\s*Allow Write\s+.*\\Domain Users\s*$") { $AllowWriteCheck = $true }
                    if ($detail -match "^\s*Allow Full Control\s+.*\\Authenticated Users\s*$|^\s*Allow Full Control\s+.*\\Domain Users\s*$") { $AllowFullControl = $true }
                    if ($detail -like "Certificate Request Agent (1.3.6.1.4.1.311.20.2.1)") { $CertificateRequestAgentCheck = $true }
                }

                $templates += [pscustomobject]@{
                    SuppliesSubjectCheck         = $SuppliesSubjectCheck
                    ClientAuthCheck              = $ClientAuthCheck
                    AllowEnrollCheck             = $AllowEnrollCheck
                    AnyPurposeCheck              = $AnyPurposeCheck
                    AllowWriteCheck              = $AllowWriteCheck
                    AllowFullControl             = $AllowFullControl
                    TemplatePropCommonName       = $TemplatePropCommonName
                    CertificateRequestAgentCheck = $CertificateRequestAgentCheck
                }
            }
            $current_template = $line + ","
        } else {
            $current_template += $line + ","
        }
    }

    # Check for ESC1
    # ESC1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1 and  Client Authentication and ( enroll or full control )

    $ESC1 = @()
    $ESC1e = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowEnrollCheck }
    $ESC1f = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowFullControl }
    $ESC1w = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowWriteCheck }
    $ESC1 += $ESC1e
    $ESC1 += $ESC1f
    $ESC1 += $ESC1w
    # Remove duplicates
    $ESC1 = $ESC1 | Select-Object -Property TemplatePropCommonName -unique
    $ESC2 = $templates | Where-Object { $_.AnyPurposeCheck -and $_.AllowEnrollCheck }
    $ESC3 = $templates | Where-Object { $_.CertificateRequestAgentCheck -and $_.AllowEnrollCheck }
    $ESC4 = $templates | Where-Object { $_.AllowWriteCheck -or $_.AllowFullControl }

    $template_path = Get-EvidencePath 'vulnerable_templates.txt'
    $web_enrollment_path = Get-EvidencePath 'web_enrollment.txt'

    foreach ($template in $ESC1) {
        $ESC1line = "ESC1 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC1line
        Write-Both "    [!] $ESC1line"
    }
    foreach ($template in $ESC2) {
        $ESC2line = "ESC2 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC2line
        Write-Both "    [!] $ESC2line"
    }
    foreach ($template in $ESC3) {
        $ESC3line = "ESC3 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC3line
        Write-Both "    [!] $ESC3line"
    }
    foreach ($template in $ESC4) {
        $ESC4line = "ESC4 Vulnerable Templates:" + $template.TemplatePropCommonName
        Add-Content -Path $template_path -Value $ESC4line
        Write-Both "    [!] $ESC4line"
    }
    # ESC8 Check, If error 401 and response is unauthorized, then vulnerable
    try {
        $certInfo = & certutil
        $serverName = ($certInfo | Select-String 'Server:' | Select-Object -First 1).ToString().Split(':')[1].Trim().Replace('"', '')
        $response = Invoke-WebRequest -Uri ("http://$serverName/certsrv/") -ErrorAction Stop
        $response
    }
    catch {
        # If error and response is unauthorised, then vulnerable
        if ($_.Exception.Response.StatusCode -eq 401) {
            Add-Content -Path $web_enrollment_path -Value "ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
            Write-Both "    [!] ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
        }
        else {
            Write-Both "    [+] ESC8 not vulnerable"
        }
    }
    if (Test-Path (Get-EvidencePath 'web_enrollment.txt')) {
        Write-Nessus-Finding "Active Directory Certificate Service Web Enrollment Enabled in HTTP" "KB1095" ([System.IO.File]::ReadAllText((Get-EvidencePath 'web_enrollment.txt')))
    }
    if (Test-Path (Get-EvidencePath 'vulnerable_templates.txt')) {
        Write-Nessus-Finding "Active Directory Certificate Service Vulnerable Templates" "KB1096" ([System.IO.File]::ReadAllText((Get-EvidencePath 'vulnerable_templates.txt')))
    }
}

Function Get-SPNs {
    [CmdletBinding()]
    param(
        # Optional: explicitly target a DC when running from a jump server
        [string]$Server
    )

    # Ensure AD module is available (required on JUMP/RSAT host)
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        throw "The ActiveDirectory module is not available. Install RSAT / AD DS tools on this host."
    }

    Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null

    # If no DC specified, let AD pick one
    if (-not $Server) {
        try {
            $Server = (Get-ADDomainController -Discover -ErrorAction Stop).HostName
        }
        catch {
            throw "Unable to discover a domain controller. Specify -Server explicitly or check network/credentials."
        }
    }

    Write-Both "    [+] Using domain controller: $Server"

    # Default/high-value groups we care about
    $default_groups = @(
        # Core AD Tier 0
        "Enterprise Admins",
        "Domain Admins",
        "Schema Admins",
        "Administrators",
    
        # Domain Controllers / AD control plane
        "Domain Controllers",
        "Read-only Domain Controllers",
        "Group Policy Creator Owners",
    
        # Built-in privileged operator groups (often overlooked Tier 0)
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators",
    
        # Privilege escalation vectors
        "DnsAdmins",
        "Cryptographic Operators",
    
        # Exchange (only if Exchange on-prem exists)
        "Exchange Servers",
        "Exchange Trusted Subsystem",
        "Organization Management"
    )

    $base_groups = @()

    foreach ($group in $default_groups) {
        try {
            $ADGrp = Get-ADGroup -Identity $group -Server $Server -ErrorAction Stop
            if ($ADGrp) {
                $base_groups += $ADGrp.Name
            }
        }
        catch {
            # Ignore missing groups in this environment
            Write-Both "    [*] Skipping non-existent group '$group' on $Server."
        }
    }

    $all_groups = @()
    $all_groups += $base_groups

    # Single-level nested groups
    foreach ($group in $base_groups) {
        try {
            $ADGrp = Get-ADGroup -Identity $group -Server $Server -ErrorAction Stop
            $QueryResult = Get-ADGroup -LDAPFilter "(&(objectCategory=group)(memberof=$($ADGrp.DistinguishedName)))" -Server $Server
            foreach ($result in $QueryResult) {
                if ($all_groups -notcontains $result.Name) {
                    $all_groups += $result.Name
                }
            }
        }
        catch {
            # Non-fatal; just continue
        }
    }

    # Recursively walk nested groups
    while ($base_groups.Count -gt 0) {
        $new_groups = @()
        foreach ($group in $base_groups) {
            try {
                $ADGrp = Get-ADGroup -Identity $group -Server $Server -ErrorAction Stop
                $QueryResult = Get-ADGroup -LDAPFilter "(&(objectCategory=group)(memberof=$($ADGrp.DistinguishedName)))" -Server $Server
                foreach ($result in $QueryResult) {
                    if ($all_groups -notcontains $result.Name) {
                        $all_groups += $result.Name
                        $new_groups += $result.Name
                    }
                }
            }
            catch {
                # Ignore failures
            }
        }
        $base_groups = $new_groups
    }

    # Prepare output file on *local* machine (DC or jump host)
    $spnFile = Get-EvidencePath 'SPNs.txt'
    New-Item -Path $spnFile -ItemType File -Force | Out-Null
    Clear-Content -Path $spnFile -ErrorAction SilentlyContinue

    Write-Both "    [+] Enumerating SPN-bearing user accounts from DC: $Server"

    # Get all objects with SPNs, restrict to users
    $SPNs = Get-ADObject -Server $Server -Filter { serviceprincipalname -like "*" } -Properties MemberOf,objectClass |
            Where-Object { $_.ObjectClass -eq "user" } |
            ForEach-Object {
                $groups = @()
                if ($_.MemberOf) {
                    $groups = $_.MemberOf | Get-ADObject -Server $Server | Where-Object { $_.ObjectClass -eq "group" }
                }
                $_ | Select-Object Name, @{
                    Name       = "Groups"
                    Expression = { $groups.Name -join ',' }
                }
            }

    $high_value_users = @()

    foreach ($spn in $SPNs) {
        if (-not $spn.Groups) {
            continue
        }

        $spn_groups = $spn.Groups.Split(',') | Where-Object { $_ -and $_.Trim() -ne "" }
        $name = $spn.Name

        foreach ($spn_group in $spn_groups) {
            if ($all_groups -contains $spn_group) {
                if ($high_value_users.Name -notcontains $name) {
                    $user = [PSCustomObject]@{
                        Name  = $name
                        Group = $spn_group
                    }
                    $high_value_users += $user
                }
            }
        }
    }

    if ($high_value_users.Count -eq 0) {
        Write-Both "    [+] No high value kerberoastable user accounts identified."
        Add-Content -Path $spnFile -Value "No high value kerberoastable user accounts identified."
    }
    else {
        foreach ($user in $high_value_users) {
            $kerbuser = '    [!]' + $user.Name + ' in groups: ' + $user.Group
            Write-Both $kerbuser
            Add-Content -Path $spnFile -Value $user.Name
        }
    }

    # Safe ReadAllText regardless of DC vs jump server
    $spnContent = [System.IO.File]::ReadAllText($spnFile)
    Write-Nessus-Finding "Kerberoast Attack - Services Configured With a Weak Password" "KB611" $spnContent
}

function Get-ADUsersWithoutPreAuth {
    try {
        $asrepUsers = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq True -and Enabled -eq True' `
                                 -Properties SamAccountName, Name, userAccountControl
    }
    catch {
        $asrepUsers = @()
    }

    if (-not $asrepUsers -or $asrepUsers.Count -eq 0) {
        $asrepUsers = Get-ADUser -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
                                 -Properties SamAccountName, Name, userAccountControl
    }

    $asrepUsers = $asrepUsers | Select-Object SamAccountName, Name, userAccountControl

    if (-not $asrepUsers -or $asrepUsers.Count -eq 0) {
        Write-Both "    [+] No ASREP Accounts"
        return
    }

    $asrepPath = Get-EvidencePath 'ASREP.txt'
    $header = @(
        'AS-REP Roastable accounts detected (DONT_REQ_PREAUTH set).',
        '',
        'To list all vulnerable accounts:',
        "  Get-ADUser -Filter 'DoesNotRequirePreAuth -eq True -and Enabled -eq True' | Select SamAccountName, Enabled",
        '  # Or LDAP bitwise (server-side):',
        "  Get-ADUser -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' | Select SamAccountName, Enabled",
        '',
        'Mitigate (clear DONT_REQ_PREAUTH bit 0x00400000):',
        '  $u = Get-ADUser <username> -Properties userAccountControl',
        '  Set-ADUser <username> -Replace @{userAccountControl = ($u.userAccountControl -band (-bnot 0x00400000))}',
        '',
        'Force password reset (must meet domain policy):',
        '  Set-ADAccountPassword -Identity <username> -Reset -NewPassword (Read-Host -AsSecureString)',
        '',
        '------------------------------------------------------------',
        '',
        'Accounts (Display Name (sAMAccountName)) with per-account commands:'
    )
    $header | Set-Content -LiteralPath $asrepPath -Encoding UTF8

    foreach ($user in $asrepUsers) {
        $display = ("{0} ({1})" -f $user.Name, $user.SamAccountName)
        Write-Both ("    [!] AS-REP Roastable user: {0}" -f $display)

        @(
            $display,
            '      # Verify vulnerable bit (non-zero means vulnerable):',
            "      (Get-ADUser '$($user.SamAccountName)' -Properties userAccountControl).userAccountControl -band 0x00400000",
            '      # Mitigate (clear bit 0x00400000):',
            "      `$u = Get-ADUser '$($user.SamAccountName)' -Properties userAccountControl",
            "      Set-ADUser '$($user.SamAccountName)' -Replace @{userAccountControl = (`$u.userAccountControl -band (-bnot 0x00400000))}",
            '      # Optional: force password reset (use compliant password):',
            "      Set-ADAccountPassword -Identity '$($user.SamAccountName)' -Reset -NewPassword (Read-Host -AsSecureString)",
            ''
        ) | Add-Content -LiteralPath $asrepPath -Encoding UTF8
    }

    Write-Nessus-Finding "AS-REP Roasting Attack" "KB720" ([System.IO.File]::ReadAllText($asrepPath))
}

function Get-LDAPSecurity {
    # Check if LDAP signing is enabled
    $computerName = $env:COMPUTERNAME
    
    # Check if LDAP signing is enabled
    try {
        $ldapSigning = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters -Name "LDAPServerIntegrity" -ErrorAction Stop).LDAPServerIntegrity

        if ($ldapSigning -eq 2) {
            Write-Both "    [+] LDAP signing is enabled on $computerName"
        }
        else {
            Write-Both "    [!] Issue identified LDAP signing is not enabled on $computerName, the registry value is currently set to $ldapSigning."
            Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAP signing is not enabled on $computerName, the registry key does not exist"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enabled on $computerName, the registry key does not exist"
        }
    }
    catch {
        Write-Both "    [!] Issue identified LDAP signing is not enabled on $computerName, the registry key does not exist."
        Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAP signing is not enabled on $computerName, the registry key does not exist"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enabled on $computerName, the registry key does not exist"
    }

    # Check if LDAPS is configured
    $serverAuthOid = '1.3.6.1.5.5.7.3.1'
    $ldapsCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
        $_.Extensions -like "System.Security.Cryptography.Oid*" -and
        $_.Extensions.Oid.Value -eq $serverAuthOid
    }

    if ($ldapsCert) {
        Write-Both "    [+] LDAPS is configured on $computerName"
    }
    else {
        Write-Both "    [!] Issue identified LDAPS is not configured on $computerName, LDAPs certificates are not configured"
        Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAPS is not configured on $computerName, LDAPs certificates are not configured"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS is not configured on $computerName, LDAPs certificates are not configured"
    }


    # Check if LDAPS Channel binding is enabled
    try {
        $ldapsBinding = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction Stop).LdapEnforceChannelBinding

        if ($ldapsBinding -eq 2) {
            Write-Both "    [+] LDAPS channel binding is enabled on $computerName"
        }
        else {
            Write-Both "    [!] Issue identified LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
            Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
        }
    }
    catch {
        Write-Both "    [!] Issue identified LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
        Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
    }


    # Check for LDAP null sessions
    $Server = (Get-ADDomainController -Discover).HostName
    $Port = 389

    try {
        # Load required assemblies
        Add-Type -AssemblyName System.DirectoryServices.Protocols

        # Create LDAP connection
        $ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection("$Server`:$Port")

        # Set connection timeout
        $ldapConnection.Timeout = [System.TimeSpan]::FromSeconds(5)

        # Create an empty NetworkCredential for anonymous bind
        $anonymousCredential = New-Object System.Net.NetworkCredential("", "")

        # Bind to the LDAP server anonymously
        $ldapConnection.Bind($anonymousCredential)

        Write-Both "    [!] Issue identified LDAP null session allowed on server $Server`:$Port"
        Add-Content -Path (Get-EvidencePath 'LDAPSecurity.txt') -Value "null session allowed on server $Server`:$Port"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP null session allowed on server $Server`:$Port"
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        Write-Both "    [+] LDAP null session not allowed on server $Server`:$Port"
    }
    catch {
        Write-Both "Error occurred: $_"
    }
}

function Get-ADObjectAclSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [string]$Server
    )
    # Prefer AD: provider; fall back to ADSI if DN contains characters the AD provider struggles with.
    try {
        if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
            Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null | Out-Null
            try { New-PSDrive -Name AD -PSProvider ActiveDirectory -Root "//RootDSE/" -ErrorAction Stop | Out-Null } catch {}
        }
        return Get-Acl -Path ("AD:\" + $DistinguishedName) -ErrorAction Stop
    } catch {
        try {
            $ldapPath = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
            $entry = [ADSI]$ldapPath
            return $entry.psbase.ObjectSecurity
        } catch {
            throw $_
        }
    }
}

function Find-DangerousACLPermissions {
    #Specify the ACLs and Groups to check against
    $dangerousAces = @('GenericAll', 'GenericWrite', 'ForceChangePassword', 'WriteDacl', 'WriteOwner', 'Delete')
    $groupsToCheck = @('NT AUTHORITY\Authenticated Users', 'DOMAIN\Domain Users', 'Everyone')

    # Find dangerous permissions on Computers
    $computers = Get-ADObject -Filter { objectClass -eq 'computer' -and objectCategory -eq 'computer' } -Properties *
    $computerResults = foreach ($computer in $computers) {
        try {
            $acl = Get-ADObjectAclSafe -DistinguishedName $computer.DistinguishedName
        }
        catch {
            Write-Warning "Could not retrieve ACL for computer '$computer': $_"
            continue
        }

        $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }

        if ($dangerousRules) {
            foreach ($rule in $dangerousRules) {
                [PSCustomObject]@{
                    ObjectType            = 'Computer'
                    ObjectName            = $computer
                    IdentityReference     = $rule.IdentityReference
                    AccessControlType     = $rule.AccessControlType
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights
                }
            }
        }
        Write-Progress -Activity "Searching for dangerous ACL permissions on computers" -Status "Computers searched: $($computers.IndexOf($computer) + 1)/$($computers.Count)" -PercentComplete (($computers.IndexOf($computer) + 1) / $computers.Count * 100)
    }

    # Find dangerous permissions on groups
    $groups = Get-ADObject -Filter { objectClass -eq 'group' -and objectCategory -eq 'group' } -Properties *
    $groupResults = foreach ($group in $groups) {
        try {
            $acl = Get-ADObjectAclSafe -DistinguishedName $group.DistinguishedName
        }
        catch {
            Write-Warning "Could not retrieve ACL for group '$group': $_"
            continue
        }

        $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }

        if ($dangerousRules) {
            foreach ($rule in $dangerousRules) {
                [PSCustomObject]@{
                    ObjectType            = 'Group'
                    ObjectName            = $group
                    IdentityReference     = $rule.IdentityReference
                    AccessControlType     = $rule.AccessControlType
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights
                }
            }
        }
        Write-Progress -Activity "Searching for dangerous ACL permissions on groups" -Status "Groups searched: $($groups.IndexOf($group) + 1)/$($groups.Count)" -PercentComplete (($groups.IndexOf($group) + 1) / $groups.Count * 100)
    }
    # Find dangerous permissions on users
    $users = Get-ADObject -Filter { objectClass -eq 'user' -and objectCategory -eq 'person' } -Properties *

    $userResults = foreach ($user in $users) {
        $acl = $null
        $acl = Get-ADObjectAclSafe -DistinguishedName $user.DistinguishedName
        if ($acl) {
            $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }
            if ($dangerousRules) {
                foreach ($rule in $dangerousRules) {
                    [PSCustomObject]@{
                        ObjectType            = 'User'
                        ObjectName            = $user
                        IdentityReference     = $rule.IdentityReference
                        AccessControlType     = $rule.AccessControlType
                        ActiveDirectoryRights = $rule.ActiveDirectoryRights
                    }
                }
            }
            Write-Progress -Activity "Searching for dangerous ACL permissions on users" -Status "Users searched: $($users.IndexOf($user) + 1)/$($users.Count)" -PercentComplete (($users.IndexOf($user) + 1) / $users.Count * 100)
        }
    }

    # Output results
    $dangerousAclHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'dangerousACLs.html'
    $hasAnyAcl = $false

    if ($computerResults) {
        $hasAnyAcl = $true
        $computerResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType | Out-File (Get-EvidencePath 'dangerousACL_Computer.txt') -Encoding UTF8
        Write-Both "    [!] Issue identified, vulnerable ACL on Computer, see $outputdir\dangerousACL_Computer.txt"
        Write-Nessus-Finding "Weak Computer Permissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dangerousACL_Computer.txt')))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any computer."
    }

    if ($groupResults) {
        $hasAnyAcl = $true
        $groupResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType, ActiveDirectoryRights | Out-File (Get-EvidencePath 'dangerousACL_Groups.txt')
        Write-Both "    [!] Issue identified, vulnerable ACL on Group, see $outputdir\dangerousACL_Groups.txt"
        Write-Nessus-Finding "Weak Group Permissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dangerousACL_Groups.txt')))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any group."
    }
    if ($userResults) {
        $hasAnyAcl = $true
        $userResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType, ActiveDirectoryRights | Out-File (Get-EvidencePath 'dangerousACLUsers.txt')
        Write-Both "    [!] Issue identified, vulnerable ACL on User, see $outputdir\dangerousACLUsers.txt"
        Write-Nessus-Finding "Weak User Permissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dangerousACLUsers.txt')))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any user."
    }

    # Build consolidated modern HTML report
    if ($hasAnyAcl) {
        $aclSb = New-Object System.Text.StringBuilder
        [void]$aclSb.AppendLine((Get-ADAuditReportHeader -Title 'Dangerous ACL Permissions'))
        [void]$aclSb.AppendLine("<div class='hero'><h1>Dangerous ACL Permissions</h1>")
        [void]$aclSb.AppendLine("<div class='meta'>Objects with potentially dangerous access control entries that could allow privilege escalation.</div></div>")

        $compCount = if ($computerResults) { $computerResults.Count } else { 0 }
        $grpCount  = if ($groupResults) { $groupResults.Count } else { 0 }
        $usrCount  = if ($userResults) { $userResults.Count } else { 0 }
        [void]$aclSb.AppendLine("<div class='stats'>")
        [void]$aclSb.AppendLine("<div class='stat'><div class='val'>$($compCount + $grpCount + $usrCount)</div><div class='lbl'>Total Findings</div></div>")
        [void]$aclSb.AppendLine("<div class='stat'><div class='val'>$compCount</div><div class='lbl'>Computer ACLs</div></div>")
        [void]$aclSb.AppendLine("<div class='stat'><div class='val'>$grpCount</div><div class='lbl'>Group ACLs</div></div>")
        [void]$aclSb.AppendLine("<div class='stat'><div class='val'>$usrCount</div><div class='lbl'>User ACLs</div></div>")
        [void]$aclSb.AppendLine("</div>")

        function Write-AclTable($sb, $title, $results, $nameLabel) {
            if (-not $results -or $results.Count -eq 0) { return }
            [void]$sb.AppendLine("<h2>$title ($($results.Count))</h2>")
            [void]$sb.AppendLine("<table><thead><tr><th>Type</th><th>$nameLabel</th><th>Allowed Group</th><th>Access Control</th><th>AD Rights</th></tr></thead><tbody>")
            foreach ($r in $results) {
                [void]$sb.AppendLine("<tr><td><span class='badge badge-high'>$title</span></td><td><code>$($r.ObjectName)</code></td><td>$($r.IdentityReference)</td><td>$($r.AccessControlType)</td><td>$($r.ActiveDirectoryRights)</td></tr>")
            }
            [void]$sb.AppendLine("</tbody></table>")
        }

        Write-AclTable $aclSb 'Computer' $computerResults 'Computer Name'
        Write-AclTable $aclSb 'Group' $groupResults 'Group Name'
        Write-AclTable $aclSb 'User' $userResults 'User Name'

        [void]$aclSb.AppendLine((Get-ADAuditReportFooter))
        [System.IO.File]::WriteAllText($dangerousAclHtmlPath, $aclSb.ToString(), [System.Text.Encoding]::UTF8)
    }
}
#region AD raw data extract (Get-ADAuditData style)
function New-ZipFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateScript({ Test-Path $_ -PathType 'Container' })]
        [string]$Source
    )

    try {
        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }

        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $Source,
            $Path,
            [System.IO.Compression.CompressionLevel]::Optimal,
            $true
        )

        return $true
    }
    catch {
        try {
            Compress-Archive -Path $Source -DestinationPath $Path -CompressionLevel Optimal -Force -ErrorAction Stop
            return $true
        }
        catch {
            Write-Both "    [!] Failed to create ZIP file '$Path'. $($_.Exception.Message)"
            return $false
        }
    }
}
function Remove-InvalidFileNameChars {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [AllowEmptyString()]
        [string]$Name
    )
    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
    return ($Name -replace $re,'#')
}

function ConvertFrom-UAC {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    $uacOptions = @{
        512='Enabled';514='Disabled';528='Enabled - Locked Out';530='Disabled - Locked Out'
        4096='Enabled - Workstation Trust Account';4098='Disabled - Workstation Trust Account'
        8192='Enabled - Server Trust Account';8194='Disabled - Server Trust Account'
        66048='Enabled - Password Does Not Expire';66050='Disabled - Password Does Not Expire'
        1049088='Enabled - Not Delegated';1049090='Disabled - Not Delegated'
        2097664='Enabled - Use DES Key Only';4194816='Enabled - PreAuthorization Not Required'
        16781312='Enabled - Workstation Trust Account - Trusted to Authenticate For Delegation'
    }
    if ($null -eq $Value) { return "Unknown User Account Type - No Value Available" }
    if ($uacOptions.ContainsKey([int]$Value)) { return [string]$uacOptions[[int]$Value] }
    return "Unknown User Account Type - $Value"
}

function ConvertFrom-UACComputed {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    $uacComputed = @{
        0='Refer to userAccountControl Field';16='Locked Out';8388608='Password Expired'
        8388624='Locked Out - Password Expired';67108864='Partial Secrets Account';2147483648='Use AES Keys'
    }
    if ($null -eq $Value) { return "Unknown User Account Type - No Value Available" }
    if ($uacComputed.ContainsKey([int64]$Value)) { return [string]$uacComputed[[int64]$Value] }
    return "Unknown User Account Type - $Value"
}

function ConvertFrom-PasswordExpiration {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -eq 0 -or $Value -ge 922337203685477000) { return '' }
    try { return ([datetime]::FromFileTime([int64]$Value)).ToString("M/d/yyyy h:mm:ss tt") } catch { return '' }
}

function ConvertFrom-trustDirection {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    $trustDirect = @{
        0='Disabled (Trust exists but disabled)'
        1='Inbound (One-Way Trust) (TrustING Domain)'
        2='Outbound (One-Way Trust) (TrustED Domain)'
        3='Bidirectional (Two-Way Trust)'
    }
    if ($null -eq $Value) { return "Unknown Trust Direction - No Value Available" }
    if ($trustDirect.ContainsKey([int]$Value)) { return $trustDirect[[int]$Value] }
    return "Unknown Trust Direction - $Value"
}

function ConvertFrom-trustType {
    param([Parameter(ValueFromPipeline=$true)]$Value)
    $trustType = @{
        1='Downlevel Trust (Windows NT / External)'
        2='Uplevel Trust (Windows 2000+ / AD)'
        3='MIT Kerberos v5 Realm'
        4='DCE Realm'
    }
    if ($null -eq $Value) { return "Unknown Trust Type - No Value Available" }
    if ($trustType.ContainsKey([int]$Value)) { return [string]$trustType[[int]$Value] }
    return "Unknown Trust Type - $Value"
}

function ConvertFrom-trustAttribute {
    param([Parameter(Mandatory=$true, ValueFromPipeline=$true)]$Value)
    $trustAttribute = @{
        0='Non-Verifiable Trust'
        1='Non-Transitive Trust'
        2='Up-level Trust'
        4='Quarantined Domain External Trust (SID Filtering Enabled)'
        8='Forest Transitive Trust'
        16='Selective Authentication'
        20='Intra-Forest Trust'
        32='Forest-Internal'
        64='SIDHistory enabled'
        80='Uses RC4 Encryption'
        400='PIM Trust'
    }
    if ($null -eq $Value) { return "Unknown Trust Attribute - No Value Available" }
    if ($trustAttribute.ContainsKey([int]$Value)) { return [string]$trustAttribute[[int]$Value] }
    return "Unknown Trust Attribute - $Value"
}

function Export-ADAuditDataExtract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateScript({ Test-Path $_ -PathType 'Container' })]
        [string]$Path = (Join-Path (Get-RawDataDir -BaseRoot $outputdir) 'ADExtract'),

        [Parameter(Mandatory=$false)]
        [string]$SearchBase = (Get-ADRootDSE | Select-Object -ExpandProperty defaultNamingContext)
    )

    try { Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null } catch { Write-Both "    [!] ActiveDirectory module missing. $_"; return }
    try { Import-ADAuditModule -Name GroupPolicy -Required -PreferWindowsPowerShell | Out-Null } catch { Write-Both "    [!] GroupPolicy module missing. $_"; return }

    $domainInfo = Get-ADDomain -Current LocalComputer
    $domainDN   = $domainInfo.DistinguishedName
    $outRoot    = Join-Path $Path $domainDN

    if (Test-Path $outRoot) { Remove-Item $outRoot -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $outRoot -Force | Out-Null

    $log = Join-Path $outRoot 'consoleOutput.txt'
    "@Starting AD data extract at $(Get-Date -Format G)" | Out-File -FilePath $log -Encoding utf8
    "@Path parameter: '$outRoot'"                        | Out-File -FilePath $log -Append -Encoding utf8
    "@SearchBase parameter: '$SearchBase'"               | Out-File -FilePath $log -Append -Encoding utf8

    # OS info
    $sysInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $PSVersionTable | Out-File -FilePath (Join-Path $outRoot "$env:COMPUTERNAME-sysinfo.txt") -Append -Encoding utf8
    $sysInfo | Select-Object BuildNumber,Caption,InstallDate,LastBootUpTime,LocalDateTime,OSArchitecture,Version |
        Out-File -FilePath (Join-Path $outRoot "$env:COMPUTERNAME-sysinfo.txt") -Append -Encoding utf8

    # Domain / DC / Forest
    $domainInfo | Select-Object @{Name='ChildDomains';Expression={$_.ChildDomains -join ';'}},ComputersContainer,DeletedObjectsContainer,
        DistinguishedName,DNSRoot,DomainControllersContainer,DomainMode,DomainSID,Forest,InfrastructureMaster,Name,NetBIOSName,
        ParentDomain,PDCEmulator,RIDMaster,SystemsContainer,UsersContainer |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-Info.csv") -Append

    Get-ADDomainController -Filter * -Server $domainInfo.DnsRoot |
        Select-Object ComputerObjectDN,DefaultPartition,Domain,Enabled,Forest,HostName,IsGlobalCatalog,IsReadOnly,Name,
            OperatingSystem,OperatingSystemVersion,@{Name='OperationMasterRoles';Expression={$_.OperationMasterRoles -join ';'}},ServerObjectDN,Site |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-domainControllerInfo.csv") -Append

    Get-ADForest -Current LocalComputer |
        Select-Object DomainNamingMaster,@{Name='Domains';Expression={$_.Domains -join ';'}},ForestMode,
            @{Name='GlobalCatalogs';Expression={$_.GlobalCatalogs -join ';'}},Name,RootDomain,SchemaMaster,
            @{Name='UPNSuffixes';Expression={$_.UPNSuffixes -join ';'}} |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-ForestInfo.csv") -Append

    # -------------------------
    # Users (SAFE RAW LDAP EXPORT)
    # -------------------------
    $delimiter = '|'
    $eol = "`r`n"

    function _SafeFileTimeToString {
        param([object]$v)
        if ($null -eq $v) { return '' }
        try {
            $ft = [int64]$v
            if ($ft -le 0) { return '' }
            return [datetime]::FromFileTimeUtc($ft).ToString("o")
        } catch {
            return ''   # invalid/out-of-range FILETIME -> blank, do not fail export
        }
    }

    function _PropFirst {
        param($props, [string]$name)
        if ($props.Contains($name) -and $props[$name] -and $props[$name].Count -gt 0) { return $props[$name][0] }
        return $null
    }

    function _PropJoin {
        param($props, [string]$name, [string]$sep)
        if ($props.Contains($name) -and $props[$name] -and $props[$name].Count -gt 0) {
            return ($props[$name] | ForEach-Object { [string]$_ }) -join $sep
        }
        return ''
    }

    function _SidBytesToString {
        param([object]$sidObj)
        try {
            if ($sidObj -is [byte[]]) {
                return (New-Object System.Security.Principal.SecurityIdentifier($sidObj,0)).Value
            }
            if ($sidObj) { return [string]$sidObj }
            return ''
        } catch { return '' }
    }

    # Keep your original header list, but source values via LDAP safely
    $userProps = @(
        'accountExpirationDate','adminCount','canonicalName','cn','comment','company','department','description','displayName',
        'distinguishedName','employeeID','employeeNumber','employeeType','givenName','info','LastLogonDate','mail','managedObjects',
        'manager','memberOf','middleName','msDS-AllowedToDelegateTo','msDS-PSOApplied','msDS-ResultantPSO',
        'msDS-User-Account-Control-Computed','msDS-UserPasswordExpiryTimeComputed','name','objectSid','PasswordExpired',
        'PasswordLastSet','primaryGroupID','sAMAccountName','servicePrincipalName','sIDHistory','sn','title','uid','uidNumber',
        'userAccountControl','userWorkstations','whenChanged','whenCreated'
    )
    $userHeader = $userProps + @('relativeIdentifier')

    # LDAP properties to load (raw names)
    # - accountExpirationDate comes from accountExpires (FILETIME)
    # - PasswordLastSet comes from pwdLastSet (FILETIME)
    # - LastLogonDate comes from lastLogonTimestamp (FILETIME)
    $ldapLoad = @(
        'accountExpires','adminCount','canonicalName','cn','comment','company','department','description','displayName',
        'distinguishedName','employeeID','employeeNumber','employeeType','givenName','info','lastLogonTimestamp','mail','managedObjects',
        'manager','memberOf','middleName','msDS-AllowedToDelegateTo','msDS-PSOApplied','msDS-ResultantPSO',
        'msDS-User-Account-Control-Computed','msDS-UserPasswordExpiryTimeComputed','name','objectSid','primaryGroupID',
        'pwdLastSet','sAMAccountName','servicePrincipalName','sIDHistory','sn','title','uid','uidNumber',
        'userAccountControl','userWorkstations','whenChanged','whenCreated'
    )

    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
        $ds = New-Object System.DirectoryServices.DirectorySearcher($root)
        $ds.PageSize = 2000
        $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $ds.Filter = '(&(objectCategory=person)(objectClass=user))'
        $ds.PropertiesToLoad.Clear()
        foreach ($p in $ldapLoad) { [void]$ds.PropertiesToLoad.Add($p) }

        $usersCsvPath = Join-Path $outRoot "$($domainInfo.DNSRoot)-Users.csv"
        $w = $null
        try {
            $w = [System.IO.StreamWriter]::new($usersCsvPath, $false, [System.Text.Encoding]::UTF8)
            $w.Write(($userHeader -join $delimiter) + $eol)

            foreach ($r in $ds.FindAll()) {
                $p = $r.Properties

                $managed = ''
                if ($p.Contains('managedobjects')) {
                    $managed = ($p['managedobjects'] | ForEach-Object { ((($_ -split ',')[0]) -replace '^CN=','') }) -join ', '
                }

                $memberof = ''
                if ($p.Contains('memberof')) {
                    $memberof = ($p['memberof'] | ForEach-Object { ((($_ -split ',')[0]) -replace '^CN=','') }) -join ', '
                }

                $psoApplied = (_PropJoin $p 'msds-psoapplied' ';')
                $psoRes     = (_PropJoin $p 'msds-resultantpso' ';')
                if ($psoApplied) { $psoApplied = ($psoApplied -replace ",CN=Password Settings Container,CN=System,$domainDN",'') -replace 'CN=','' }
                if ($psoRes)     { $psoRes     = ($psoRes     -replace ",CN=Password Settings Container,CN=System,$domainDN",'') -replace 'CN=','' }

                $sidStr = _SidBytesToString (_PropFirst $p 'objectsid')
                $rid = ''
                if ($sidStr -match '^(S-\d-\d+-.+)-(\d+)$') { $rid = $matches[2] }

                # Derive the fields that were previously auto-converted by AD cmdlets
                $accountExpirationDate = _SafeFileTimeToString (_PropFirst $p 'accountexpires')
                $passwordLastSet       = _SafeFileTimeToString (_PropFirst $p 'pwdlastset')
                $lastLogonDate         = _SafeFileTimeToString (_PropFirst $p 'lastlogontimestamp')
                $pwdExpiryComputed     = _SafeFileTimeToString (_PropFirst $p 'msds-userpasswordexpirytimecomputed')

                # PasswordExpired was previously from AD cmdlet; keep best-effort blank (or compute if you want later)
                $passwordExpired = ''

                $line = @(
                    [string]$accountExpirationDate
                    (_PropFirst $p 'admincount')
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'canonicalname')))
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'cn')))
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'comment')))
                    [string](_PropFirst $p 'company')
                    [string](_PropFirst $p 'department')
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'description')))
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'displayname')))
                    [string](_PropFirst $p 'distinguishedname')
                    [string](_PropFirst $p 'employeeid')
                    [string](_PropFirst $p 'employeenumber')
                    [string](_PropFirst $p 'employeetype')
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'givenname')))
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'info')))
                    [string]$lastLogonDate
                    [string](_PropFirst $p 'mail')
                    [string]$managed
                    [string](_PropFirst $p 'manager')
                    [string]$memberof
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'middlename')))
                    (_PropJoin $p 'msds-allowedtodelegateto' ';')
                    [string]$psoApplied
                    [string]$psoRes
                    (ConvertFrom-UACComputed (_PropFirst $p 'msds-user-account-control-computed'))
                    (ConvertFrom-PasswordExpiration (_PropFirst $p 'msds-userpasswordexpirytimecomputed'))
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'name')))
                    [string]$sidStr
                    [string]$passwordExpired
                    [string]$passwordLastSet
                    [string](_PropFirst $p 'primarygroupid')
                    [string](_PropFirst $p 'samaccountname')
                    (_PropJoin $p 'serviceprincipalname' ';')
                    (_PropJoin $p 'sidhistory' ';')
                    (Remove-InvalidFileNameChars ([string](_PropFirst $p 'sn')))
                    [string](_PropFirst $p 'title')
                    (_PropJoin $p 'uid' ';')
                    [string](_PropFirst $p 'uidnumber')
                    (ConvertFrom-UAC (_PropFirst $p 'useraccountcontrol'))
                    [string](_PropFirst $p 'userworkstations')
                    [string](_PropFirst $p 'whenchanged')
                    [string](_PropFirst $p 'whencreated')
                    [string]$rid
                ) -join $delimiter

                $w.Write($line + $eol)
            }
        } finally {
            if ($w) { $w.Close() }
        }
    } catch {
        "@Problem exporting users (raw LDAP): $_" | Out-File -FilePath $log -Append -Encoding utf8
        Write-Both "    [!] Problem exporting users. See consoleOutput.txt"
    }

    # Groups
    $groupProps = @('CN','description','displayName','distinguishedName','GroupCategory','GroupScope','ManagedBy','memberOf','msDS-PSOApplied','name','objectSID','sAMAccountName','whenCreated','whenChanged')
    $groupHeader = $groupProps + @('relativeIdentifier')
    $groups = Get-ADGroup -SearchBase $SearchBase -Filter * -Properties $groupProps -ErrorAction SilentlyContinue

    $groupsCsvPath = Join-Path $outRoot "$($domainInfo.DNSRoot)-Groups.csv"
    $w = $null
    try {
        $w = [System.IO.StreamWriter]::new($groupsCsvPath, $false, [System.Text.Encoding]::UTF8)
        $w.Write(($groupHeader -join $delimiter) + $eol)
        foreach ($g in $groups) {
            $memberof = ($g.memberOf | ForEach-Object { ((($_ -split ',')[0]) -replace '^CN=','') }) -join ', '
            $pso = (($g.'msDS-PSOApplied' -join ';') -replace ",CN=Password Settings Container,CN=System,$domainDN",'') -replace 'CN=',''
            $line = @(
                (Remove-InvalidFileNameChars $g.CN)
                (Remove-InvalidFileNameChars $g.description)
                (Remove-InvalidFileNameChars $g.displayName)
                $g.distinguishedName
                $g.GroupCategory
                $g.GroupScope
                $g.ManagedBy
                $memberof
                $pso
                (Remove-InvalidFileNameChars $g.name)
                $g.objectSid
                $g.sAMAccountName
                [string]$g.whenCreated
                [string]$g.whenChanged
                (($g.SID.Value).Split('-')[-1])
            ) -join $delimiter
            $w.Write($line + $eol)
        }
    } finally {
        if ($w) { $w.Close() }
    }

    # Computers (keep as-is; if you later hit FileTime errors here, apply the same raw LDAP pattern)
    $computerProps = @('cn','description','displayName','distinguishedName','LastLogonDate','name','objectSid','operatingSystem','operatingSystemServicePack','operatingSystemVersion','primaryGroupID','PasswordLastSet','userAccountControl','whenCreated','whenChanged')
    $computers = Get-ADComputer -SearchBase $SearchBase -Filter * -Properties $computerProps -ErrorAction SilentlyContinue
    $computers | Select-Object $computerProps | ForEach-Object {
        $_.userAccountControl = ConvertFrom-UAC $_.userAccountControl
        $_
    } | ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-Computers.csv") -Append

    # OUs (unchanged)
    $ouProps = @('CanonicalName','Description','DisplayName','DistinguishedName','ManagedBy','Name','whenChanged','whenCreated')
    Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * -Properties $ouProps -ErrorAction SilentlyContinue |
        Select-Object CanonicalName,Description,DisplayName,DistinguishedName,ManagedBy,Name,whenChanged,whenCreated |
        ForEach-Object {
            $_.CanonicalName = Remove-InvalidFileNameChars $_.CanonicalName
            $_.Description   = Remove-InvalidFileNameChars $_.Description
            $_.DisplayName   = Remove-InvalidFileNameChars $_.DisplayName
            $_.Name          = Remove-InvalidFileNameChars $_.Name
            $_
        } | ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-OUs.csv") -Append

    # GPO Reports + inheritance (harden filenames + ensure dirs exist)
    $gpRoot = Join-Path $outRoot 'GroupPolicy'
    New-Item -ItemType Directory -Path $gpRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $gpRoot 'Reports') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $gpRoot 'Inheritance') -Force | Out-Null

    $gpos = Get-GPO -All -ErrorAction SilentlyContinue
    foreach ($gpo in $gpos) {
        $name = Remove-InvalidFileNameChars $gpo.DisplayName

        # Prevent path-too-long / weird names
        if ($name.Length -gt 150) { $name = $name.Substring(0,150) }

        $reportPath = Join-Path (Join-Path $gpRoot 'Reports') "$name.html"
        try {
            Get-GPOReport -Guid $gpo.Id -ReportType Html -Path $reportPath -ErrorAction Stop
        } catch {
            "@Problem exporting GPO report '$($gpo.DisplayName)' to '$reportPath': $_" | Out-File -FilePath $log -Append -Encoding utf8
        }
    }

    $domainGPI = Get-GPInheritance -Target $domainDN -ErrorAction SilentlyContinue
    $domainGPI | Select-Object Name,ContainerType,Path,GpoInheritanceBlocked | Format-List |
        Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$domainDN.txt")
    $domainGPI | Select-Object -ExpandProperty InheritedGpoLinks |
        Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$domainDN.txt") -Append

    $adOUs = Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * -ErrorAction SilentlyContinue
    foreach ($ou in $adOUs) {
        $fn = Remove-InvalidFileNameChars $ou.DistinguishedName
        if ($fn.Length -gt 150) { $fn = $fn.Substring(0,150) }

        $gpi = Get-GPInheritance -Target $ou.DistinguishedName -ErrorAction SilentlyContinue
        $gpi | Select-Object Name,ContainerType,Path,GpoInheritanceBlocked | Format-List |
            Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$fn.txt")
        $gpi | Select-Object -ExpandProperty InheritedGpoLinks |
            Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$fn.txt") -Append
    }

    # OU ACLs (unchanged)
    New-Item -ItemType Directory -Path (Join-Path $outRoot 'OU\ACLs') -Force | Out-Null
    $schemaIDGUID = @{}
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
    Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name,schemaIDGUID |
        ForEach-Object { $schemaIDGUID[[Guid]$_.schemaIDGUID] = $_.name }
    Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name,rightsGUID |
        ForEach-Object { $schemaIDGUID[[Guid]$_.rightsGUID] = $_.name }
    $ErrorActionPreference = $eap

    $ouDns = @()
    if ($SearchBase -eq (Get-ADRootDSE).defaultNamingContext) {
        $ouDns += (Get-ADDomain).DistinguishedName
        $ouDns += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
        $ouDns += Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -SearchScope OneLevel -LDAPFilter '(objectClass=container)' | Select-Object -ExpandProperty DistinguishedName
    } else {
        $ouDns += Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * | Select-Object -ExpandProperty DistinguishedName
    }

    foreach ($ouDN in $ouDns) {
        $fn = Remove-InvalidFileNameChars $ouDN
        if ($fn.Length -gt 150) { $fn = $fn.Substring(0,150) }

        $csvPath = Join-Path (Join-Path $outRoot 'OU\ACLs') "$fn.csv"
        try {
            Get-Acl -Path "AD:$ouDN" -ErrorAction Stop |
                Select-Object -ExpandProperty Access |
                Select-Object @{n='organizationalUnit';e={$ouDN}},
                    @{n='objectTypeName';e={ if ($_.ObjectType -eq [Guid]::Empty) {'All'} else { $schemaIDGUID[$_.ObjectType] } }},
                    @{n='inheritedObjectTypeName';e={ $schemaIDGUID[$_.InheritedObjectType] }}, * |
                ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
                Out-File -FilePath $csvPath -Append
        } catch {
            "@Problem reading ACL for '$ouDN': $_" | Out-File -FilePath $log -Append -Encoding utf8
        }
    }

    # Confidentiality bit (unchanged)
    try {
        Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$domainDN" -LDAPFilter '(searchFlags:1.2.840.113556.1.4.803:=128)' |
            Select-Object DistinguishedName,Name |
            ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
            Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-confidentialBit.csv") -Append
    } catch {
        "@Problem exporting confidentiality bit: $_" | Out-File -FilePath $log -Append -Encoding utf8
    }

    # Default password policy + FGPP (unchanged)
    Get-ADDefaultDomainPasswordPolicy |
        Select-Object ComplexityEnabled,DistinguishedName,LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,
            MinPasswordAge,MinPasswordLength,PasswordHistoryCount,ReversibleEncryptionEnabled |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-defaultDomainPasswordPolicy.csv") -Append

    Get-ADFineGrainedPasswordPolicy -Filter * -Properties appliesTo |
        Select-Object ComplexityEnabled,DistinguishedName,LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,
            MinPasswordAge,MinPasswordLength,
            @{Name='msDS-PSOAppliesTo';Expression={(($_.appliesTo -split "," | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" }},
            Name,PasswordHistoryCount,Precedence,ReversibleEncryptionEnabled |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-fgppDetails.csv") -Append

    # Trusts (unchanged)
    if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {
        Get-ADTrust -Filter * -Properties * |
            Select-Object CanonicalName,CN,Created,Deleted,Description,DisallowTransivity,DisplayName,DistinguishedName,flatName,
                ForestTransitive,IntraForest,Name,SelectiveAuthentication,Source,Target,TGTDelegation,
                @{Name='TrustAttributes';Expression={ConvertFrom-trustAttribute $_.TrustAttributes}},
                @{Name='trustDirection';Expression={ConvertFrom-trustDirection $_.trustDirection}},
                @{Name='TrustType';Expression={ConvertFrom-trustType $_.TrustType}},
                TrustingPolicy,trustPartner,UplevelOnly,UsesAESKeys,UsesRC4Encryption,whenChanged,whenCreated |
            ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
            Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-trustedDomains.csv") -Append
    } else {
        & netdom query trust > (Join-Path $outRoot "$($domainInfo.DNSRoot)-trustedDomains-netdom.txt")
    }

    "@Finished AD data extract at $(Get-Date -Format G)" | Out-File -FilePath $log -Append -Encoding utf8

    # Zip output (best-effort)
    $zip = Join-Path $Path ("$domainDN.zip")
    if (New-ZipFile -Path $zip -Source $outRoot) {
        "@Compressed output: $zip" | Out-File -FilePath $log -Append -Encoding utf8
    } else {
        "@.NET 4.5.2+ not detected - skipping zip" | Out-File -FilePath $log -Append -Encoding utf8
    }

    Write-Both "    [+] AD raw data export complete: $outRoot"
}

#region DNS Zone Posture Report (merged)
function Invoke-DnsZonePostureReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputRoot,
        [switch]$IncludeRecordCounts,
        [switch]$IncludeSystemZones
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # ----------------------------
    # Config (function args)
    # ----------------------------
    $script:IncludeRecordCounts  = [bool]$IncludeRecordCounts
    $script:PreferZoneStatistics = $true
    $script:RecordCountMaxRecords= 250000
    $script:IncludeSystemZones   = [bool]$IncludeSystemZones
    $script:FailSoft             = $true
    $script:WriteErrorReport     = $true

    # ----------------------------
    # Error bucket
    # ----------------------------
    $script:CollectionErrors = @()
    $script:ZoneFailures     = @()

    function Add-Err {
        param([string]$Context, [object]$Err)
        $script:CollectionErrors += [pscustomobject]@{
            Time    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Context = $Context
            Error   = ($Err.Exception.Message)
            Type    = ($Err.Exception.GetType().FullName)
        }
    }

    function Safe-Get {
        param(
            [Parameter(Mandatory)] [scriptblock]$Script,
            [object]$Default = $null,
            [string]$Context = $null
        )
        try { & $Script }
        catch {
            if ($Context) { Add-Err -Context $Context -Err $_ }
            $Default
        }
    }

    function Get-Prop {
        param(
            [Parameter(Mandatory)] [object]$Obj,
            [Parameter(Mandatory)] [string]$Name,
            [object]$Default = $null
        )
        if (-not $Obj) { return $Default }
        $p = $Obj.PSObject.Properties[$Name]
        if ($p) { return $p.Value }
        $Default
    }

    function Format-TimeSpan {
        param([Nullable[TimeSpan]]$Ts)
        if (-not $Ts) { return $null }
        ("{0}d {1}h {2}m" -f $Ts.Days, $Ts.Hours, $Ts.Minutes)
    }

    function Convert-ServerListToString {
        param([object]$Value)
        if (-not $Value) { return $null }

        $items = @()
        foreach ($o in @($Value)) {
            if ($null -eq $o) { continue }

            $ipProp = $o.PSObject.Properties['IPAddressToString']
            if ($ipProp -and $ipProp.Value) { $items += [string]$ipProp.Value; continue }

            $found = $false
            foreach ($p in @('IPAddress','Address','ServerName','Name')) {
                $pp = $o.PSObject.Properties[$p]
                if ($pp -and $pp.Value) { $items += [string]$pp.Value; $found = $true; break }
            }
            if (-not $found) { $items += [string]$o }
        }

        $items = $items | Where-Object { $_ -and $_.Trim() } | Sort-Object -Unique
        if (-not $items) { return $null }
        ($items -join ', ')
    }

    function Ensure-Folder {
        param([string]$Path)
        if (-not (Test-Path -Path $Path)) { New-Item -Path $Path -ItemType Directory | Out-Null }
        $Path
    }

function New-ReportsFolder {
        param([string]$Root, [string]$ServerName)
        $safeServer = ($ServerName -replace '[\\/:*?"<>| ]','_')

        # Folder structure: DNS-Reports/<ComputerName>
        $dnsRoot = Join-Path -Path $Root -ChildPath 'DNS-Reports'
        Ensure-Folder $dnsRoot | Out-Null
        $reports = Join-Path -Path $dnsRoot -ChildPath $safeServer
        Ensure-Folder $reports
    }

    # ----------------------------
    # Detect target DNS server (no args)
    # ----------------------------
    function Get-TargetDnsServer {
        $localOk = Safe-Get -Context "Detect: Get-DnsServer local" -Default $false -Script {
            Import-ADAuditModule -Name DnsServer -Required | Out-Null
            $null = Get-DnsServer -ComputerName $env:COMPUTERNAME -ErrorAction Stop
            $true
        }
        if ($localOk) { return $env:COMPUTERNAME }

        $dnsIps = Safe-Get -Context "Detect: Get-DnsClientServerAddress" -Default @() -Script {
            $addrs = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop
            $active = $addrs | Where-Object { $_.InterfaceAlias -and $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 }
            ($active | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
        }

        if (-not $dnsIps -or @($dnsIps).Count -eq 0) {
            throw "Could not detect a DNS server from local NIC DNS settings, and local host does not appear to be a DNS server."
        }

        foreach ($ip in $dnsIps) {
            $ok = Safe-Get -Context "Detect: Test-NetConnection $ip:53" -Default $false -Script {
                (Test-NetConnection -ComputerName $ip -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue)
            }
            if ($ok) { return $ip }
        }

        $dnsIps[0]
    }

    # ----------------------------
    # Preflight module
    # ----------------------------
    $dnsModule = Safe-Get -Context "Preflight: Get-Module DnsServer" -Default $null -Script {
        Get-Module -ListAvailable -Name DnsServer | Sort-Object Version -Descending | Select-Object -First 1
    }
    if (-not $dnsModule) { throw "DnsServer module not found. Install DNS role tools / RSAT DNS (DnsServer) on this host." }

    Import-ADAuditModule -Name DnsServer -Required | Out-Null

    $ComputerName = Get-TargetDnsServer

    $serverInfo = Safe-Get -Context "Preflight: Get-DnsServer -ComputerName $ComputerName" -Default $null -Script {
        Get-DnsServer -ComputerName $ComputerName -ErrorAction Stop
    }
    if (-not $serverInfo) {
        throw "Unable to query DNS server '$ComputerName'. Check connectivity, firewall/RPC, permissions, and that DNS Server role is present."
    }

    # ----------------------------
    # Output paths (Reports + type subfolders)
    # ----------------------------
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outDir    = New-ReportsFolder -Root $OutputRoot -ServerName $ComputerName

    $txtDir  = Ensure-Folder (Join-Path $outDir 'txt')
    $htmlDir = Ensure-Folder (Join-Path $outDir 'html')

    $csvPath     = Join-Path $outDir  "DNSAudit-$timestamp.csv"
    $jsonPath    = Join-Path $outDir  "DNSAudit-$timestamp.json"
    $htmlPath    = Join-Path $htmlDir "DNSAudit-$timestamp.html"
    $errJsonPath = Join-Path $outDir  "DNSAudit-Errors-$timestamp.json"
    $recHtmlPath = Join-Path $htmlDir "DNS-Recommendations-$timestamp.html"
    $recTxtPath  = Join-Path $txtDir  "DNS-Recommendations-$timestamp.txt"

    # ----------------------------
    # Server posture
    # ----------------------------
    $serverSettings = Safe-Get -Context "Server: Get-DnsServerSetting" -Default $null -Script {
        Get-DnsServerSetting -ComputerName $ComputerName -ErrorAction Stop
    }
    $serverScavenging = Safe-Get -Context "Server: Get-DnsServerScavenging" -Default $null -Script {
        Get-DnsServerScavenging -ComputerName $ComputerName -ErrorAction Stop
    }
    $serverForwarders = Safe-Get -Context "Server: Get-DnsServerForwarder" -Default $null -Script {
        Get-DnsServerForwarder -ComputerName $ComputerName -ErrorAction Stop
    }
    $serverDiagnostics = Safe-Get -Context "Server: Get-DnsServerDiagnostics" -Default $null -Script {
        Get-DnsServerDiagnostics -ComputerName $ComputerName -ErrorAction Stop
    }
    $serverCache = Safe-Get -Context "Server: Get-DnsServerCache" -Default $null -Script {
        Get-DnsServerCache -ComputerName $ComputerName -ErrorAction Stop
    }

    $serverPosture = [pscustomobject]@{
        TargetDnsServer        = $ComputerName
        Generated              = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        RunAs                  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        PowerShellVersion      = $PSVersionTable.PSVersion.ToString()
        OSVersion              = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version -ErrorAction SilentlyContinue)
        DnsServerModuleVersion = $dnsModule.Version.ToString()

        IsDsAvailable          = Get-Prop $serverInfo 'DsAvailable' $null
        Recursion              = Get-Prop $serverSettings 'EnableRecursion' (Get-Prop $serverInfo 'EnableRecursion' $null)

        Forwarders             = Convert-ServerListToString (Get-Prop $serverForwarders 'IPAddress' (Get-Prop $serverForwarders 'IPAddresses' $null))
        ForwarderTimeoutSec    = Get-Prop $serverForwarders 'Timeout' $null
        ForwarderUseRootHints  = Get-Prop $serverForwarders 'UseRootHint' $null

        ScavengingEnabled      = Get-Prop $serverScavenging 'ScavengingState' $null
        ScavRefreshInterval    = Safe-Get -Context "Server: Scav RefreshInterval stringify" -Default $null -Script { [string](Get-Prop $serverScavenging 'RefreshInterval' $null) }
        ScavNoRefreshInterval  = Safe-Get -Context "Server: Scav NoRefreshInterval stringify" -Default $null -Script { [string](Get-Prop $serverScavenging 'NoRefreshInterval' $null) }

        CacheMaxTTL            = Safe-Get -Context "Server: Cache MaxTTL stringify" -Default $null -Script { [string](Get-Prop $serverCache 'MaxTTL' $null) }
        CacheMaxNegativeTTL    = Safe-Get -Context "Server: Cache MaxNegativeTTL stringify" -Default $null -Script { [string](Get-Prop $serverCache 'MaxNegativeTTL' $null) }

        Diagnostics            = if ($serverDiagnostics) { "Available" } else { "Not available" }
    }

    function Get-ServerIssuesAndRisk {
        param([pscustomobject]$Posture)

        $issues = @()
        $reco   = @()
        $riskScore = 0

        if ($Posture.Recursion -eq $true) {
            $issues += "Server recursion: enabled (review exposure)."
            $reco   += "Confirm the server is not exposed to untrusted networks. Restrict access via firewall/interface binding/allow-lists."
            $riskScore += 2
        }
        if (-not $Posture.Forwarders) {
            $issues += "Forwarders: none detected."
            $reco   += "If external resolution is required, configure forwarders to approved resolvers; otherwise document intent."
            $riskScore += 1
        }
        if ($Posture.ScavengingEnabled -ne $true) {
            $issues += "Server scavenging: disabled or unknown."
            $reco   += "If using dynamic zones, enable scavenging at server level and validate zone aging intervals."
            $riskScore += 1
        }

        $riskLevel = if ($riskScore -ge 5) { 'High' } elseif ($riskScore -ge 2) { 'Medium' } else { 'Low' }

        [pscustomobject]@{
            RiskScore       = $riskScore
            RiskLevel       = $riskLevel
            Issues          = $issues
            Recommendations = $reco
        }
    }

    # ----------------------------
    # Zone helpers
    # ----------------------------
    function Get-ZoneAgingSummary {
        param([string]$ZoneName)

        $aging = Safe-Get -Context "Zone '$ZoneName': Get-DnsServerZoneAging" -Default $null -Script {
            Get-DnsServerZoneAging -ComputerName $ComputerName -ZoneName $ZoneName -ErrorAction Stop
        }

        if (-not $aging) {
            return [pscustomobject]@{
                AgingEnabled         = $null
                RefreshInterval      = $null
                NoRefreshInterval    = $null
                AvailForScavengeTime = $null
                ScavengeServers      = $null
                AgingNote            = "Aging/Scavenging info not available."
            }
        }

        [pscustomobject]@{
            AgingEnabled         = Get-Prop $aging 'AgingEnabled' $null
            RefreshInterval      = Format-TimeSpan (Get-Prop $aging 'RefreshInterval' $null)
            NoRefreshInterval    = Format-TimeSpan (Get-Prop $aging 'NoRefreshInterval' $null)
            AvailForScavengeTime = Safe-Get -Context "Zone '$ZoneName': AvailForScavengeTime stringify" -Default $null -Script { (Get-Prop $aging 'AvailForScavengeTime' $null).ToString() }
            ScavengeServers      = Convert-ServerListToString (Get-Prop $aging 'ScavengeServers' $null)
            AgingNote            = $null
        }
    }

    function Get-ZoneTransferEvidence {
        param([object]$ZoneDetails)

        [pscustomobject]@{
            ZoneTransferType  = Get-Prop $ZoneDetails 'ZoneTransferType' $null
            SecureSecondaries = Get-Prop $ZoneDetails 'SecureSecondaries' $null
            Notify            = Get-Prop $ZoneDetails 'Notify' $null
            NotifyServers     = Convert-ServerListToString (Get-Prop $ZoneDetails 'NotifyServers' $null)
            SecondaryServers  = Convert-ServerListToString (Get-Prop $ZoneDetails 'SecondaryServers' $null)
            MasterServers     = Convert-ServerListToString (Get-Prop $ZoneDetails 'MasterServers' $null)
            TransferNote      = $null
        }
    }

    function Get-ZoneRecordCounts {
        param([string]$ZoneName)

        if (-not $script:IncludeRecordCounts) {
            return [pscustomobject]@{
                TotalRecords    = $null
                A=$null; AAAA=$null; CNAME=$null; MX=$null; NS=$null; SRV=$null; TXT=$null; PTR=$null
                RecordCountNote = "Record counting disabled."
            }
        }

        if ($script:PreferZoneStatistics) {
            $zs = Safe-Get -Context "Zone '$ZoneName': Get-DnsServerZoneStatistics" -Default $null -Script {
                Get-DnsServerZoneStatistics -ComputerName $ComputerName -ZoneName $ZoneName -ErrorAction Stop
            }
            if ($zs) {
                return [pscustomobject]@{
                    TotalRecords    = Get-Prop $zs 'TotalRecordCount' (Get-Prop $zs 'RecordCount' $null)
                    A               = Get-Prop $zs 'ARecordCount' $null
                    AAAA            = Get-Prop $zs 'AAAARecordCount' $null
                    CNAME           = Get-Prop $zs 'CNAMERecordCount' $null
                    MX              = Get-Prop $zs 'MXRecordCount' $null
                    NS              = Get-Prop $zs 'NSRecordCount' $null
                    SRV             = Get-Prop $zs 'SRVRecordCount' $null
                    TXT             = Get-Prop $zs 'TXTRecordCount' $null
                    PTR             = Get-Prop $zs 'PTRRecordCount' $null
                    RecordCountNote = "Counts from Get-DnsServerZoneStatistics (best-effort)."
                }
            }
        }

        $recs = Safe-Get -Context "Zone '$ZoneName': Get-DnsServerResourceRecord (enumeration)" -Default $null -Script {
            Get-DnsServerResourceRecord -ComputerName $ComputerName -ZoneName $ZoneName -ErrorAction Stop
        }
        if (-not $recs) {
            return [pscustomobject]@{
                TotalRecords    = $null
                A=$null; AAAA=$null; CNAME=$null; MX=$null; NS=$null; SRV=$null; TXT=$null; PTR=$null
                RecordCountNote = "Record counting failed (permissions/size/zone type)."
            }
        }

        $arr = @($recs)
        $truncated = $false
        if ($script:RecordCountMaxRecords -gt 0 -and $arr.Count -gt $script:RecordCountMaxRecords) {
            $arr = $arr[0..($script:RecordCountMaxRecords-1)]
            $truncated = $true
        }

        $byType = $arr | Group-Object -Property RecordType -NoElement

        function Count-Type([string]$t, $groups) {
            $g = @($groups | Where-Object Name -eq $t) | Select-Object -First 1
            if ($g -and $null -ne $g.PSObject.Properties['Count']) { return [int]$g.Count }
            return 0
        }

        [pscustomobject]@{
            TotalRecords    = ($arr | Measure-Object).Count
            A               = (Count-Type 'A' $byType)
            AAAA            = (Count-Type 'AAAA' $byType)
            CNAME           = (Count-Type 'CNAME' $byType)
            MX              = (Count-Type 'MX' $byType)
            NS              = (Count-Type 'NS' $byType)
            SRV             = (Count-Type 'SRV' $byType)
            TXT             = (Count-Type 'TXT' $byType)
            PTR             = (Count-Type 'PTR' $byType)
            RecordCountNote = if ($truncated) { "Counts truncated to first $($script:RecordCountMaxRecords) records (safety cap)." } else { $null }
        }
    }

    function Get-ZoneIssuesAndRisk {
        param([pscustomobject]$ZoneRow, [pscustomobject]$ServerPosture)

        $issues = @()
        $reco   = @()
        $riskScore = 0
        $factors = @()

        if ($null -eq $ZoneRow.DynamicUpdate) {
            $issues += "Dynamic updates: unknown (property not available)."
            $reco   += "Verify zone dynamic update setting in DNS Manager (Zone Properties -> General)."
            $riskScore += 1
            $factors += "DU=Unknown"
        } else {
            switch ([string]$ZoneRow.DynamicUpdate) {
                'Secure' { $factors += "DU=Secure" }
                'None'   {
                    $issues += "Dynamic updates: disabled."
                    $reco   += "If this zone must accept registrations, enable Secure dynamic updates (AD-integrated recommended)."
                    $riskScore += 1
                    $factors += "DU=None"
                }
                default  {
                    $issues += "Dynamic updates: non-secure updates allowed."
                    $reco   += "Set dynamic updates to Secure (especially on AD-integrated zones)."
                    $riskScore += 5
                    $factors += "DU=NonSecure"
                }
            }
        }

        if ($ZoneRow.IsDsIntegrated -ne $true) {
            $issues += "Zone is not AD-integrated."
            $reco   += "If this is an internal zone, consider AD-integrated for secure updates and replication benefits."
            $riskScore += 2
            $factors += "ADI=No"
        } else {
            $factors += "ADI=Yes"
        }

        if ($ZoneRow.ZoneTransferType -and ($ZoneRow.ZoneTransferType -match 'Any')) {
            $issues += "Zone transfers: allowed to any server."
            $reco   += "Restrict zone transfers to explicit authorized secondaries or IP allow-lists."
            $riskScore += 5
            $factors += "XFR=Any"
        } elseif ($ZoneRow.SecureSecondaries -ne $null -and $ZoneRow.SecureSecondaries -eq $false) {
            $issues += "Zone transfer security (SecureSecondaries) is disabled."
            $reco   += "Restrict zone transfers (secure secondaries / explicit allow-list)."
            $riskScore += 3
            $factors += "XFR=Insecure"
        }

        if ($ZoneRow.AgingEnabled -eq $false) {
            $issues += "Aging/Scavenging: disabled."
            $reco   += "Enable aging where appropriate and validate refresh/no-refresh intervals."
            $riskScore += 2
            $factors += "Aging=Off"
        } elseif ($ZoneRow.AgingEnabled -eq $true -and $ServerPosture.ScavengingEnabled -ne $true) {
            $issues += "Zone aging enabled but server scavenging appears disabled/unknown."
            $reco   += "Enable scavenging at server level or validate intended posture."
            $riskScore += 1
            $factors += "Scav=Mismatch"
        }

        $riskLevel = if ($riskScore -ge 7) { 'High' } elseif ($riskScore -ge 3) { 'Medium' } else { 'Low' }

        [pscustomobject]@{
            RiskScore       = $riskScore
            RiskLevel       = $riskLevel
            Issues          = $issues
            Recommendations = $reco
            RiskFactors     = $factors
        }
    }

    # ----------------------------
    # Recommendations report generator
    # ----------------------------
    $RecommendationDisclaimer = @"
Recommendations disclaimer:
These recommendations are based on information from Microsoft and general DNS/AD best practices.
Technicians must take into consideration their own:
- best practices and operational standards
- internal policies and compliance requirements
- risk assessments and threat models
- change management procedures and service impact
before implementing any changes.
"@

    function Build-Recommendations {
        param(
            [pscustomobject]$ServerPosture,
            [pscustomobject]$ServerRisk,
            [array]$Rows
        )

        $items = New-Object System.Collections.Generic.List[object]

        if ($ServerPosture.Recursion -eq $true) {
            $items.Add([pscustomobject]@{
                Priority = "Medium"
                Area = "Server"
                Topic = "Recursion exposure"
                Evidence = "Recursion enabled = $($ServerPosture.Recursion)"
                Recommendation = "Ensure the DNS server is not exposed to untrusted networks. Restrict client access via firewall/interface binding/allow-lists and document allowed resolvers."
            }) | Out-Null
        }

        if (-not $ServerPosture.Forwarders) {
            $items.Add([pscustomobject]@{
                Priority = "Low"
                Area = "Server"
                Topic = "Forwarders"
                Evidence = "Forwarders not detected"
                Recommendation = "If external resolution is required, configure forwarders to approved resolvers. If not required, document the design (e.g., root hints in controlled networks)."
            }) | Out-Null
        }

        if ($ServerPosture.ScavengingEnabled -ne $true) {
            $items.Add([pscustomobject]@{
                Priority = "Low"
                Area = "Server"
                Topic = "Scavenging"
                Evidence = "Server scavenging state = $($ServerPosture.ScavengingEnabled)"
                Recommendation = "If dynamic DNS is used, enable scavenging at server level and validate zone aging intervals to reduce stale records."
            }) | Out-Null
        }

        $hasNonSecureDU = ($Rows | Where-Object { $_.Issues -match 'non-secure updates' } | Select-Object -First 1)
        if ($hasNonSecureDU) {
            $items.Add([pscustomobject]@{
                Priority = "High"
                Area = "Zones"
                Topic = "Non-secure dynamic updates"
                Evidence = "At least one zone allows non-secure dynamic updates"
                Recommendation = "Set dynamic updates to Secure on AD-integrated zones. Avoid non-secure updates unless justified by a documented exception and compensating controls."
            }) | Out-Null
        }

        $hasAnyXfr = ($Rows | Where-Object { $_.Issues -match 'Zone transfers: allowed to any' } | Select-Object -First 1)
        if ($hasAnyXfr) {
            $items.Add([pscustomobject]@{
                Priority = "High"
                Area = "Zones"
                Topic = "Zone transfers to any"
                Evidence = "At least one zone appears to allow transfers to any server"
                Recommendation = "Restrict zone transfers to explicit authorized secondaries or IP allow-lists. Review Notify settings and validate secondaries."
            }) | Out-Null
        }

        $hasAgingOff = ($Rows | Where-Object { $_.Issues -match 'Aging/Scavenging: disabled' } | Select-Object -First 1)
        if ($hasAgingOff) {
            $items.Add([pscustomobject]@{
                Priority = "Medium"
                Area = "Zones"
                Topic = "Aging disabled"
                Evidence = "At least one zone has aging/scavenging disabled"
                Recommendation = "Enable aging where appropriate and ensure refresh/no-refresh intervals align with operational needs. Validate scavenging impact prior to enabling."
            }) | Out-Null
        }

        $items.Add([pscustomobject]@{
            Priority = "Medium"
            Area = "Baseline"
            Topic = "Least privilege and auditing"
            Evidence = "Administrative control of DNS is high impact"
            Recommendation = "Use least-privilege admin groups and enable auditing/monitoring for DNS changes. Separate duties where possible."
        }) | Out-Null

        $items.Add([pscustomobject]@{
            Priority = "Medium"
            Area = "Baseline"
            Topic = "Patch and hardening"
            Evidence = "DNS is critical infrastructure"
            Recommendation = "Keep DNS servers patched, restrict management access, and baseline configuration against Microsoft security guidance."
        }) | Out-Null

        $items
    }

    # ----------------------------
    # Collect zones
    # ----------------------------
    $zones = Safe-Get -Context "Get-DnsServerZone -ComputerName $ComputerName" -Default @() -Script {
        @(Get-DnsServerZone -ComputerName $ComputerName -ErrorAction Stop)
    }

    if (-not $script:IncludeSystemZones) {
        $zones = @($zones | Where-Object { $_.IsAutoCreated -ne $true -and $_.ZoneName -notmatch '^TrustAnchors$' })
    }

    $serverRisk = Get-ServerIssuesAndRisk -Posture $serverPosture

    $rows = @()
    foreach ($z in $zones) {
        $zn = $z.ZoneName
        try {
            $zoneDetails = Safe-Get -Context "Zone '$zn': Get-DnsServerZone -Name" -Default $z -Script {
                Get-DnsServerZone -ComputerName $ComputerName -Name $zn -ErrorAction Stop
            }

            $aging  = Get-ZoneAgingSummary -ZoneName $zn
            $xfr    = Get-ZoneTransferEvidence -ZoneDetails $zoneDetails
            $counts = Get-ZoneRecordCounts -ZoneName $zn

            $baseRow = [pscustomobject]@{
                Server              = $ComputerName
                ZoneName            = Get-Prop $zoneDetails 'ZoneName' $zn
                ZoneType            = Get-Prop $zoneDetails 'ZoneType' $null
                IsDsIntegrated      = Get-Prop $zoneDetails 'IsDsIntegrated' $null
                ReplicationScope    = Get-Prop $zoneDetails 'ReplicationScope' $null
                IsReverseLookupZone = Get-Prop $zoneDetails 'IsReverseLookupZone' $null
                IsAutoCreated       = Get-Prop $zoneDetails 'IsAutoCreated' $null
                DynamicUpdate       = Get-Prop $zoneDetails 'DynamicUpdate' $null

                ZoneTransferType    = $xfr.ZoneTransferType
                SecureSecondaries   = $xfr.SecureSecondaries
                Notify              = $xfr.Notify
                NotifyServers       = $xfr.NotifyServers
                SecondaryServers    = $xfr.SecondaryServers
                MasterServers       = $xfr.MasterServers

                AgingEnabled        = $aging.AgingEnabled
                NoRefreshInterval   = $aging.NoRefreshInterval
                RefreshInterval     = $aging.RefreshInterval
                AvailForScavengeTime= $aging.AvailForScavengeTime
                ScavengeServers     = $aging.ScavengeServers

                TotalRecords        = $counts.TotalRecords
                A                   = $counts.A
                AAAA                = $counts.AAAA
                CNAME               = $counts.CNAME
                MX                  = $counts.MX
                NS                  = $counts.NS
                SRV                 = $counts.SRV
                TXT                 = $counts.TXT
                PTR                 = $counts.PTR

                Notes               = ((@($aging.AgingNote, $counts.RecordCountNote, $xfr.TransferNote) | Where-Object { $_ }) -join ' | ')
            }

            $risk = Get-ZoneIssuesAndRisk -ZoneRow $baseRow -ServerPosture $serverPosture

            $rows += [pscustomobject]@{
                Server              = $baseRow.Server
                ZoneName            = $baseRow.ZoneName
                ZoneType            = $baseRow.ZoneType
                IsDsIntegrated      = $baseRow.IsDsIntegrated
                ReplicationScope    = $baseRow.ReplicationScope
                IsReverseLookupZone = $baseRow.IsReverseLookupZone
                DynamicUpdate       = $baseRow.DynamicUpdate

                ZoneTransferType    = $baseRow.ZoneTransferType
                SecureSecondaries   = $baseRow.SecureSecondaries
                Notify              = $baseRow.Notify
                NotifyServers       = $baseRow.NotifyServers
                SecondaryServers    = $baseRow.SecondaryServers
                MasterServers       = $baseRow.MasterServers

                AgingEnabled        = $baseRow.AgingEnabled
                NoRefreshInterval   = $baseRow.NoRefreshInterval
                RefreshInterval     = $baseRow.RefreshInterval
                AvailForScavengeTime= $baseRow.AvailForScavengeTime
                ScavengeServers     = $baseRow.ScavengeServers

                TotalRecords        = $baseRow.TotalRecords
                A                   = $baseRow.A
                AAAA                = $baseRow.AAAA
                CNAME               = $baseRow.CNAME
                MX                  = $baseRow.MX
                NS                  = $baseRow.NS
                SRV                 = $baseRow.SRV
                TXT                 = $baseRow.TXT
                PTR                 = $baseRow.PTR

                RiskLevel           = $risk.RiskLevel
                RiskScore           = $risk.RiskScore
                RiskFactors         = ($risk.RiskFactors -join ';')
                Issues              = ($risk.Issues -join ' | ')
                Recommendations     = ($risk.Recommendations -join ' | ')
                Notes               = $baseRow.Notes

                _IssueList          = $risk.Issues
                _RecoList           = $risk.Recommendations
                _RiskFactorList     = $risk.RiskFactors
            }
        }
        catch {
            $script:ZoneFailures += [pscustomobject]@{
                ZoneName = $zn
                Error    = $_.Exception.Message
                Type     = $_.Exception.GetType().FullName
            }
            if (-not $script:FailSoft) { throw }
        }
    }

    # ----------------------------
    # Summary + top findings
    # ----------------------------
    $totalZones = ($rows | Measure-Object).Count
    $high   = ($rows | Where-Object RiskLevel -eq 'High'   | Measure-Object).Count
    $medium = ($rows | Where-Object RiskLevel -eq 'Medium' | Measure-Object).Count
    $low    = ($rows | Where-Object RiskLevel -eq 'Low'    | Measure-Object).Count

    $topFindings = $rows |
        ForEach-Object { $_._IssueList } |
        Where-Object { $_ } |
        ForEach-Object { $_ } |
        Group-Object |
        Sort-Object Count -Descending |
        Select-Object -First 10

    # ----------------------------
    # Recommendations report
    # ----------------------------
    $recommendations = Build-Recommendations -ServerPosture $serverPosture -ServerRisk $serverRisk -Rows $rows

    # TXT
    $recTxt = @()
    $recTxt += "DNS Recommendations Report"
    $recTxt += "Target DNS server: $ComputerName"
    $recTxt += "Generated: $($serverPosture.Generated)"
    $recTxt += ""
    $recTxt += $RecommendationDisclaimer.Trim()
    $recTxt += ""
    $recTxt += "Recommendations:"
    $recTxt += ($recommendations | ForEach-Object {
        "- [$($_.Priority)] $($_.Area) - $($_.Topic)`r`n  Evidence: $($_.Evidence)`r`n  Recommendation: $($_.Recommendation)"
    })
    $recTxt -join "`r`n" | Set-Content -Encoding UTF8 -Path $recTxtPath

    # HTML
    $recRowsHtml = ($recommendations | ForEach-Object {
        $badgeCls = switch ($_.Priority) { 'High' { 'badge-high' } 'Medium' { 'badge-medium' } default { 'badge-low' } }
        "<tr><td><span class='badge $badgeCls'>$($_.Priority)</span></td><td>$($_.Area)</td><td>$($_.Topic)</td><td>$($_.Evidence)</td><td>$($_.Recommendation)</td></tr>"
    }) -join "`r`n"

    $recHighCount = @($recommendations | Where-Object { $_.Priority -eq 'High' }).Count
    $recMedCount  = @($recommendations | Where-Object { $_.Priority -eq 'Medium' }).Count
    $recLowCount  = @($recommendations | Where-Object { $_.Priority -eq 'Low' }).Count

@"
$(Get-ADAuditReportHeader -Title 'DNS Recommendations Report')
<div class="hero">
<h1>DNS Recommendations Report</h1>
<div class="meta">Target DNS server: <code>$ComputerName</code> &mdash; Generated: $($serverPosture.Generated)</div>
</div>

<div class="stats">
<div class="stat"><div class="val">$(@($recommendations).Count)</div><div class="lbl">Total</div></div>
<div class="stat"><div class="val" style="color:var(--high)">$recHighCount</div><div class="lbl">High Priority</div></div>
<div class="stat"><div class="val" style="color:var(--medium)">$recMedCount</div><div class="lbl">Medium Priority</div></div>
<div class="stat"><div class="val" style="color:var(--low)">$recLowCount</div><div class="lbl">Low Priority</div></div>
</div>

<h2>Disclaimer</h2>
<pre>$($RecommendationDisclaimer.Trim())</pre>

<h2>Recommendations</h2>
<table><thead>
<tr><th>Priority</th><th>Area</th><th>Topic</th><th>Evidence</th><th>Recommendation</th></tr>
</thead><tbody>
$recRowsHtml
</tbody></table>

$(Get-ADAuditReportFooter)
"@ | Set-Content -Encoding UTF8 -Path $recHtmlPath

    # ----------------------------
    # Write audit outputs
    # ----------------------------
    $rows |
        Sort-Object -Property @{Expression="RiskScore";Descending=$true}, @{Expression="ZoneName";Descending=$false} |
        Select-Object Server,ZoneName,ZoneType,IsDsIntegrated,ReplicationScope,IsReverseLookupZone,DynamicUpdate,
                      ZoneTransferType,SecureSecondaries,Notify,NotifyServers,SecondaryServers,MasterServers,
                      AgingEnabled,NoRefreshInterval,RefreshInterval,AvailForScavengeTime,ScavengeServers,
                      TotalRecords,A,AAAA,CNAME,MX,NS,SRV,TXT,PTR,
                      RiskLevel,RiskScore,RiskFactors,Issues,Recommendations,Notes |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

    $jsonObj = [pscustomobject]@{
        ServerPosture = $serverPosture
        ServerRisk    = $serverRisk
        Summary       = [pscustomobject]@{
            ZonesTotal      = $totalZones
            HighRiskZones   = $high
            MediumRiskZones = $medium
            LowRiskZones    = $low
            ZoneFailures    = ($script:ZoneFailures | Measure-Object).Count
        }
        TopFindings   = @($topFindings | Select-Object Name, Count)
        Zones         = @(
            $rows | ForEach-Object {
                [pscustomobject]@{
                    Server              = $_.Server
                    ZoneName            = $_.ZoneName
                    ZoneType            = $_.ZoneType
                    IsDsIntegrated      = $_.IsDsIntegrated
                    ReplicationScope    = $_.ReplicationScope
                    IsReverseLookupZone = $_.IsReverseLookupZone
                    DynamicUpdate       = $_.DynamicUpdate
                    ZoneTransferType    = $_.ZoneTransferType
                    SecureSecondaries   = $_.SecureSecondaries
                    Notify              = $_.Notify
                    NotifyServers       = $_.NotifyServers
                    SecondaryServers    = $_.SecondaryServers
                    MasterServers       = $_.MasterServers
                    AgingEnabled        = $_.AgingEnabled
                    NoRefreshInterval   = $_.NoRefreshInterval
                    RefreshInterval     = $_.RefreshInterval
                    AvailForScavengeTime= $_.AvailForScavengeTime
                    ScavengeServers     = $_.ScavengeServers
                    TotalRecords        = $_.TotalRecords
                    A                   = $_.A
                    AAAA                = $_.AAAA
                    CNAME               = $_.CNAME
                    MX                  = $_.MX
                    NS                  = $_.NS
                    SRV                 = $_.SRV
                    TXT                 = $_.TXT
                    PTR                 = $_.PTR
                    RiskLevel           = $_.RiskLevel
                    RiskScore           = $_.RiskScore
                    RiskFactors         = $_._RiskFactorList
                    Issues              = $_._IssueList
                    Recommendations     = $_._RecoList
                    Notes               = $_.Notes
                }
            }
        )
        Recommendations = @($recommendations)
        Failures        = @($script:ZoneFailures)
        CollectionErrors= @($script:CollectionErrors)
    }

    $jsonObj | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 -Path $jsonPath

    if ($script:WriteErrorReport) {
        [pscustomobject]@{
            ZoneFailures     = @($script:ZoneFailures)
            CollectionErrors = @($script:CollectionErrors)
        } | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $errJsonPath
    }

    # ----------------------------
    # HTML audit report
    # ----------------------------
    $css = Get-ADAuditReportCss

    $riskBadgeClass = switch ($serverRisk.RiskLevel) { 'High' { 'badge-high' } 'Medium' { 'badge-medium' } default { 'badge-low' } }

    $serverSummaryHtml = @"
<table><thead>
<tr><th>Field</th><th>Value</th></tr>
</thead><tbody>
<tr><td>TargetDnsServer</td><td><code>$($serverPosture.TargetDnsServer)</code></td></tr>
<tr><td>Generated</td><td>$($serverPosture.Generated)</td></tr>
<tr><td>RunAs</td><td><code>$($serverPosture.RunAs)</code></td></tr>
<tr><td>PowerShellVersion</td><td>$($serverPosture.PowerShellVersion)</td></tr>
<tr><td>OSVersion</td><td>$($serverPosture.OSVersion)</td></tr>
<tr><td>DnsServerModuleVersion</td><td>$($serverPosture.DnsServerModuleVersion)</td></tr>
<tr><td>Recursion</td><td>$($serverPosture.Recursion)</td></tr>
<tr><td>Forwarders</td><td>$($serverPosture.Forwarders)</td></tr>
<tr><td>ScavengingEnabled</td><td>$($serverPosture.ScavengingEnabled)</td></tr>
</tbody></table>
"@

    $zonesTable = $rows |
        Sort-Object -Property @{Expression="RiskScore";Descending=$true}, @{Expression="ZoneName";Descending=$false} |
        Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate,
                      ZoneTransferType, SecureSecondaries, Notify, NotifyServers, SecondaryServers,
                      AgingEnabled, NoRefreshInterval, RefreshInterval,
                      TotalRecords, RiskLevel, RiskScore, RiskFactors, Issues, Recommendations, Notes

    $zonesHtml = ($zonesTable | ConvertTo-Html -Fragment) `
        -replace '<td>High</td>','<td><span class="badge badge-high">High</span></td>' `
        -replace '<td>Medium</td>','<td><span class="badge badge-medium">Medium</span></td>' `
        -replace '<td>Low</td>','<td><span class="badge badge-low">Low</span></td>'

    # Fix ConvertTo-Html <table> to use <thead>/<tbody>
    $zonesHtml = $zonesHtml -replace '<table>\s*<tr><th','<table><thead><tr><th' -replace '</th></tr>\s*<tr><td','</th></tr></thead><tbody><tr><td' -replace '</td></tr>\s*</table>','</td></tr></tbody></table>'

    $findingsHtml = (($topFindings | Select-Object Name, Count) | ConvertTo-Html -Fragment)
    $findingsHtml = $findingsHtml -replace '<table>\s*<tr><th','<table><thead><tr><th' -replace '</th></tr>\s*<tr><td','</th></tr></thead><tbody><tr><td' -replace '</td></tr>\s*</table>','</td></tr></tbody></table>'

@"
$(Get-ADAuditReportHeader -Title 'DNS Audit Report')
<div class="hero">
<h1>DNS Audit Report</h1>
<div class="meta">
Target DNS server: <code>$ComputerName</code> &mdash;
Zones: Total=$totalZones, High=$high, Medium=$medium, Low=$low &mdash;
<a href="DNS-Recommendations-$timestamp.html">Recommendations Report</a>
</div>
</div>

<div class="stats">
<div class="stat"><div class="val">$totalZones</div><div class="lbl">Total Zones</div></div>
<div class="stat"><div class="val" style="color:var(--high)">$high</div><div class="lbl">High Risk</div></div>
<div class="stat"><div class="val" style="color:var(--medium)">$medium</div><div class="lbl">Medium Risk</div></div>
<div class="stat"><div class="val" style="color:var(--low)">$low</div><div class="lbl">Low Risk</div></div>
</div>

<h2>Server Posture <span class="badge $riskBadgeClass">$($serverRisk.RiskLevel) (Score: $($serverRisk.RiskScore))</span></h2>
$serverSummaryHtml

<h2>Top Findings</h2>
$findingsHtml

<h2>Zone Details</h2>
$zonesHtml

$(Get-ADAuditReportFooter)
"@ | Set-Content -Encoding UTF8 -Path $htmlPath

    Write-Host "Report generated:"
    Write-Host "  Target DNS:      $ComputerName"
    Write-Host "  Reports folder:  $outDir"
    Write-Host "  HTML folder:     $htmlDir"
    Write-Host "  TXT folder:      $txtDir"
    Write-Host "  Audit HTML:      $htmlPath"
    Write-Host "  Audit CSV:       $csvPath"
    Write-Host "  Audit JSON:      $jsonPath"
    Write-Host "  Reco HTML:       $recHtmlPath"
    Write-Host "  Reco TXT:        $recTxtPath"
    if ($script:WriteErrorReport) { Write-Host "  ERR JSON:        $errJsonPath" }
}

# Backward-compatible wrapper (older call site in this script)
function Invoke-DNSZoneReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputRoot,
        [switch]$IncludeRecordCounts,
        [switch]$IncludeSystemZones
    )
    Invoke-DnsZonePostureReport -OutputRoot $OutputRoot -IncludeRecordCounts:$IncludeRecordCounts -IncludeSystemZones:$IncludeSystemZones
}

#endregion DNS Zone Posture Report




#region Delegated Permissions Report (merged)
function Invoke-DelegatedPermissionsReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputRoot,
        [switch]$IncludeSystemTrustees,
        [switch]$IncludeDeny,
        [switch]$IncludeInherited,
        [string]$Server
    )

    # Embedded from Delegated_Permissions.ps1 (working version)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null

    # Timestamped folders
    $ts   = Get-Date -Format 'yyyyMMdd_HHmmss'
    $base = Join-Path $OutputRoot "ADAudit_Reports_$ts"
    $ouDir  = Join-Path $base 'OUs'
    $allDir = Join-Path $base 'All'
    New-Item -ItemType Directory -Path $base,$ouDir,$allDir -Force | Out-Null

    # Transcript
    $log = Join-Path $base "Transcript_$ts.txt"
    try { Start-Transcript -Path $log -ErrorAction SilentlyContinue | Out-Null } catch {}

    # RootDSE and NCs
    $rootDse  = if ($Server) { Get-ADRootDSE -Server $Server } else { Get-ADRootDSE }
    $domainNC = $rootDse.defaultNamingContext
    $schemaNC = $rootDse.schemaNamingContext
    $configNC = $rootDse.configurationNamingContext

    # Server-pinned ACL read to avoid referrals
    function Get-AclForDn {
      param([Parameter(Mandatory)][string]$Dn,[string]$Server)
      if ($Server) {
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$Dn")
        $de.RefreshCache()
        return $de.ObjectSecurity
      } else {
        return (Get-Acl -Path "AD:$Dn")
      }
    }

    # Simple retry wrapper
    function Invoke-Retry([scriptblock]$Script,[int]$Max=3,[int]$DelaySec=2){
      for($i=1;$i -le $Max;$i++){
        try { return & $Script } catch { if($i -eq $Max){ throw } Start-Sleep -Seconds $DelaySec }
      }
    }

    # GUID cache: attributes, classes, extended rights, property sets
    $guidCache = @{}

    # Schema objects
    $schemaObjects = if ($Server) {
      Get-ADObject -Server $Server -SearchBase $schemaNC -LDAPFilter '(|(objectClass=classSchema)(objectClass=attributeSchema))' -Properties lDAPDisplayName,schemaIDGUID
    } else {
      Get-ADObject -SearchBase $schemaNC -LDAPFilter '(|(objectClass=classSchema)(objectClass=attributeSchema))' -Properties lDAPDisplayName,schemaIDGUID
    }
    foreach ($s in $schemaObjects) {
      try { $g = [Guid]$s.schemaIDGUID; $guidCache[$g.Guid] = $s.lDAPDisplayName } catch {}
    }

    # Extended rights (controlAccessRight) in Configuration NC
    $carObjects = if ($Server) {
      Get-ADObject -Server $Server -SearchBase $configNC -LDAPFilter '(objectClass=controlAccessRight)' -Properties displayName,rightsGuid,cn
    } else {
      Get-ADObject -SearchBase $configNC -LDAPFilter '(objectClass=controlAccessRight)' -Properties displayName,rightsGuid,cn
    }
    foreach ($c in $carObjects) {
      try {
        $g = [Guid]$c.rightsGuid
        $friendly = if ($c.displayName) { $c.displayName } else { $c.cn }
        $guidCache[$g.Guid] = $friendly
      } catch {}
    }

    function Resolve-GuidName {
      param($GuidValue)
      if (-not $GuidValue -or $GuidValue -eq [Guid]::Empty) { return $null }
      try {
        $g = [Guid]$GuidValue
        if ($guidCache.ContainsKey($g.Guid)) { return $guidCache[$g.Guid] }
        return $g.Guid
      } catch {
        return $GuidValue.ToString()
      }
    }

    # Trustee classification
    function Get-PrincipalType {
      param([string]$Identity)
      try {
        $filter = "(|(sAMAccountName=$Identity)(distinguishedName=$Identity)(objectSid=$Identity))"
        $obj = if ($Server) {
          Get-ADObject -Server $Server -LDAPFilter $filter -Properties objectClass -ErrorAction Stop
        } else {
          Get-ADObject -LDAPFilter $filter -Properties objectClass -ErrorAction Stop
        }
        if ($obj.objectClass -contains 'group')     { return 'Group' }
        if ($obj.objectClass -contains 'user')      { return 'User' }
        if ($obj.objectClass -contains 'computer')  { return 'Computer' }
        if ($obj.objectClass -contains 'foreignSecurityPrincipal') { return 'FSP' }
      } catch {}
      if ($Identity -match '^S-\d-\d+') { return 'SID' }
      return 'WellKnownOrExternal'
    }

    # Canonical path helper
    function Get-Canonical {
      param([string]$Dn)
      try {
        $p = @{ Identity=$Dn; Properties='CanonicalName'; ErrorAction='Stop' }
        if ($Server) { $p['Server'] = $Server }
        (Get-ADObject @p).CanonicalName
      } catch { $null }
    }

    # Built-in trustees to optionally suppress
    $systemTrustees = @(
      'NT AUTHORITY\SELF',
      'NT AUTHORITY\Authenticated Users',
      'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
      'NT AUTHORITY\Everyone',
      'BUILTIN\Administrators',
      'NT AUTHORITY\SYSTEM'
    )

    # Scope discovery
    $ouParams = @{ Filter='*'; Properties=@('DistinguishedName','Name') }
    if ($Server) { $ouParams['Server'] = $Server }
    $OUs = Get-ADOrganizationalUnit @ouParams

    $scopes = New-Object 'System.Collections.Generic.List[string]'
    [void]$scopes.Add($domainNC)
    $OUs | ForEach-Object { [void]$scopes.Add($_.DistinguishedName) }

    $wellKnownContainers = @(
"CN=Users,$domainNC",
"CN=Computers,$domainNC",
"CN=System,$domainNC",
"CN=Managed Service Accounts,$domainNC"
    ) | Where-Object { Test-Path "AD:$_" }
    $wellKnownContainers | ForEach-Object { [void]$scopes.Add($_) }

    $adminSDHolder = "CN=AdminSDHolder,CN=System,$domainNC"
    if (Test-Path "AD:$adminSDHolder") { [void]$scopes.Add($adminSDHolder) }

    # Data store
    $records = New-Object System.Collections.Generic.List[object]

    # Iterate scopes and collect ACEs
    foreach ($dn in $scopes) {
      $scopeType = if ($dn -eq $domainNC) { 'Domain' }
                   elseif ($dn -eq $adminSDHolder) { 'AdminSDHolder' }
                   elseif ($wellKnownContainers -contains $dn) { 'Container' }
                   else { 'OU' }

      try {
        $acl = Invoke-Retry { Get-AclForDn -Dn $dn -Server $Server }
      } catch {
        Write-Warning "ACL read failed: $dn. $_"
        continue
      }

      foreach ($ace in $acl.Access) {
        if (-not $IncludeInherited -and $ace.IsInherited) { continue }
        if (-not $IncludeDeny -and $ace.AccessControlType -ne 'Allow') { continue }
        $trustee = $ace.IdentityReference.Value
        if (-not $IncludeSystemTrustees -and ($systemTrustees -contains $trustee)) { continue }

        $objTypeName      = Resolve-GuidName $ace.ObjectType
        $inheritedObjName = Resolve-GuidName $ace.InheritedObjectType

        [void]$records.Add([pscustomobject]@{
          ScopeDN               = $dn
          CanonicalScope        = Get-Canonical $dn
          ScopeType             = $scopeType
          Trustee               = $trustee
          TrusteeType           = Get-PrincipalType $trustee
          AccessControlType     = $ace.AccessControlType
          ActiveDirectoryRights = $ace.ActiveDirectoryRights
          InheritanceType       = $ace.InheritanceType
          AppliesToClass        = $inheritedObjName
          AppliesToProperty     = $objTypeName
          ObjectTypeGuid        = if ($ace.ObjectType -and $ace.ObjectType -ne [Guid]::Empty) { $ace.ObjectType } else { $null }
          InheritedObjectGuid   = if ($ace.InheritedObjectType -and $ace.InheritedObjectType -ne [Guid]::Empty) { $ace.InheritedObjectType } else { $null }
          IsInherited           = $ace.IsInherited
          PropagationFlags      = $ace.PropagationFlags
          InheritanceFlags      = $ace.InheritanceFlags
        })
      }

      # Per-scope TXT summary grouped by trustee
      $safeName = ($dn -replace '[=,]','_') -replace '[^\w\.-]','_'
      $perScope = $records | Where-Object { $_.ScopeDN -eq $dn }
      $txt = @()
      $txt += "Delegated Permissions for ${scopeType}: $dn"
      $txt += ('=' * 80)
      foreach ($grp in ($perScope | Group-Object Trustee)) {
        $first = $grp.Group | Select-Object -First 1
        $txt += "Trustee: $($grp.Name)  [$($first.TrusteeType)]"
        foreach ($r in $grp.Group) {
          $txt += "  Rights: $($r.ActiveDirectoryRights)  Type: $($r.AccessControlType)"
          if ($r.AppliesToClass)    { $txt += "  Class:    $($r.AppliesToClass)" }
          if ($r.AppliesToProperty) { $txt += "  Property: $($r.AppliesToProperty)" }
          $txt += "  Inheritance: $($r.InheritanceType)  InheritFlags: $($r.InheritanceFlags)  PropFlags: $($r.PropagationFlags)"
        }
        $txt += ""
      }
      $txtPath = Join-Path -Path $ouDir -ChildPath "ADAudit_$safeName.txt"
      $txt -join [Environment]::NewLine | Out-File -FilePath $txtPath -Encoding UTF8
      Write-Host "Wrote: $txtPath"
    }

    # De-duplicate identical ACE rows to reduce noise
    $records = $records |
      Sort-Object ScopeDN,Trustee,AccessControlType,ActiveDirectoryRights,AppliesToClass,AppliesToProperty,InheritanceType,IsInherited,ObjectTypeGuid,InheritedObjectGuid -Unique

    # ------- Analytics and risk outputs (always generated) -------

    # Windows LAPS + legacy LAPS attributes
    $lapsAttributes = @('ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime','msLAPS-Password','msLAPS-PasswordExpirationTime')

    $overDelegations = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'GenericAll|WriteDacl|DeleteTree'
    }
    $accountOperators = $records | Where-Object { $_.Trustee -eq 'BUILTIN\Account Operators' }
    $printOperators   = $records | Where-Object { $_.Trustee -eq 'BUILTIN\Print Operators' }
    $exchangePattern  = 'Exchange Trusted Subsystem','Organization Management','Exchange Windows Permissions'
    $exchangeDelegations = $records | Where-Object { $_.Trustee -in $exchangePattern }
    $serviceAcctDelegations = $records | Where-Object {
      $_.Trustee -match '^(svc|SVC)[\-_]' -or $_.Trustee -match 'DomainJoin' -or $_.Trustee -match 'DJ\b'
    }
    $unknownSids = @($records | Where-Object { $_.TrusteeType -eq 'SID' } | Select-Object -Expand Trustee | Sort-Object -Unique)
    $membershipControl = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'WriteProperty' -and $_.AppliesToProperty -eq 'member'
    }
    $preWin2k  = $records | Where-Object { $_.Trustee -eq 'Pre-Windows 2000 Compatible Access' }
    $lapsRead  = $records | Where-Object {
      $_.AppliesToProperty -in $lapsAttributes -and $_.ActiveDirectoryRights.ToString() -match 'ReadProperty|ExtendedRight'
    }
    $computerCreate = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'CreateChild' -and ($_.AppliesToClass -match 'computer')
    }

    # Safe counts under StrictMode
    $cntOver            = ($overDelegations      | Measure-Object).Count
    $cntAcctOps         = ($accountOperators     | Measure-Object).Count
    $cntPrintOps        = ($printOperators       | Measure-Object).Count
    $cntExchange        = ($exchangeDelegations  | Measure-Object).Count
    $cntSvc             = ($serviceAcctDelegations | Measure-Object).Count
    $cntUnknownSids     = ($unknownSids          | Measure-Object).Count
    $cntMemberCtrl      = ($membershipControl    | Measure-Object).Count
    $cntPreWin2k        = ($preWin2k             | Measure-Object).Count
    $cntLaps            = ($lapsRead             | Measure-Object).Count
    $cntComputerCreate  = ($computerCreate       | Measure-Object).Count

    # High-risk CSV
    $highRisk = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'GenericAll|WriteDacl|DeleteTree' -or
      ($_.AppliesToProperty -in ($lapsAttributes + 'member') -and $_.ActiveDirectoryRights.ToString() -match 'WriteProperty|ReadProperty|ExtendedRight')
    }
    $highCsv = Join-Path -Path $allDir -ChildPath "ADAudit_HighRisk_$ts.csv"
    $highRisk | Export-Csv -NoTypeInformation -Path $highCsv -Encoding UTF8
    Write-Host "High-Risk CSV:  $highCsv"

    # Risk assessment
    $riskItems = @()
    $riskItems += "Delegated Permissions Risk Assessment"
    $riskItems += ('=' * 80)
    $riskItems += "Timestamp: $(Get-Date -Format o)"
    $riskItems += "Total ACE records analyzed: $($records.Count)"
    $riskItems += ""
    $riskItems += "1. Over-delegation (GenericAll / WriteDacl / DeleteTree): $cntOver"
    if ($cntOver -gt 0) {
      $sampleTrustees = ($overDelegations | Select-Object -Expand Trustee | Sort-Object -Unique | Select-Object -First 10) -join ', '
      $riskItems += "   Sample trustees: $sampleTrustees"
    }
    $riskItems += "2. Account Operators present: $cntAcctOps  | Print Operators present: $cntPrintOps"
    $riskItems += "3. Exchange broad delegations: $cntExchange"
    $riskItems += "4. Service account elevated delegations: $cntSvc"
    $riskItems += "5. Unknown / unresolved SIDs: $cntUnknownSids"
    if ($cntUnknownSids -gt 0) { $riskItems += "   SIDs: $($unknownSids -join ', ')" }
    $riskItems += "6. Group membership modification rights (WriteProperty member): $cntMemberCtrl"
    $riskItems += "7. Legacy Pre-Windows 2000 Compatible Access ACEs: $cntPreWin2k"
    $riskItems += "8. LAPS password read delegations: $cntLaps"
    $riskItems += "9. Computer object creation rights (CreateChild on computer): $cntComputerCreate"
    $riskItems += ""

    $riskLevel = if ($cntOver -gt 50 -or $cntSvc -gt 30 -or $cntMemberCtrl -gt 40) { 'High' }
                 elseif ($cntOver -gt 10 -or $cntSvc -gt 10) { 'Medium' }
                 else { 'Low' }
    $riskItems += "Overall qualitative risk level: $riskLevel"
    $riskItems += ""
    $riskItems += "Key Observations:"
    if ($cntOver -gt 0)       { $riskItems += " - Broad rights (GenericAll/WriteDacl/DeleteTree) increase takeover and lateral movement risk." }
    if ($cntAcctOps -gt 0)    { $riskItems += " - Account Operators delegation can indirectly create privileged paths; often should be empty." }
    if ($cntExchange -gt 0)   { $riskItems += " - Exchange security groups hold rights beyond mail scope; review least privilege." }
    if ($cntSvc -gt 0)        { $riskItems += " - Service accounts with write/create rights enable SPN abuse and escalation." }
    if ($cntUnknownSids -gt 0){ $riskItems += " - Unknown SIDs may be orphaned or foreign; validate and remove if unnecessary." }
    if ($cntMemberCtrl -gt 0) { $riskItems += " - Write access to group 'member' permits escalation via nesting." }
    if ($cntComputerCreate -gt 0){ $riskItems += " - Excessive computer creation rights can enable RBCD abuse." }
    if ($cntLaps -gt 0)       { $riskItems += " - LAPS password read delegations increase credential exposure." }
    if ($cntPreWin2k -gt 0)   { $riskItems += " - Legacy read groups expand enumeration; prune if not required." }
    $riskItems += ""

    $riskPath = Join-Path $base 'ADAudit_RiskAssessment.txt'
    $riskItems -join [Environment]::NewLine | Out-File -FilePath $riskPath -Encoding UTF8
    Write-Host "Wrote: $riskPath"

    # Recommendations (always generate)
    $rec = @()
    $rec += "Delegated Permissions Recommendations"
    $rec += ('=' * 80)
    $rec += "Prioritized Actions:"
    $rec += " 1. Remove unnecessary GenericAll / WriteDacl / DeleteTree delegations."
    $rec += " 2. Remove BUILTIN\Account Operators and Print Operators from OUs unless explicitly required."
    $rec += " 3. Review Exchange-related ACLs; align with Microsoft minimums; eliminate GenericAll."
    $rec += " 4. Resolve unknown SIDs; remove orphaned entries."
    $rec += " 5. Enforce least privilege for service accounts (scoped rights, rotation, tiering)."
    $rec += " 6. Restrict WriteProperty(member) to controlled group admins; isolate Tier0 groups."
    $rec += " 7. Decommission Pre-Windows 2000 Compatible Access if no legacy need."
    $rec += " 8. Harden Tier0 OUs: only Enterprise Admins / Domain Admins."
    $rec += " 9. Constrain computer account creation to a dedicated join group with quota."
    $rec += "10. Monitor ACL changes with auditing and alerts."
    $rec += ""
    $rec += "Microsoft Reference Links:"
    $rec += " - AD DS security best practices: https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices"
    $rec += " - AD partitions and naming contexts: https://learn.microsoft.com/windows/win32/ad/active-directory-partitions"
    $rec += " - Control access rights (rightsGuid): https://learn.microsoft.com/windows/win32/ad/control-access-rights"
    $rec += " - AdminSDHolder and protected groups: https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices#ad-protected-accounts-and-groups"
    $rec += " - Windows LAPS overview: https://learn.microsoft.com/windows-server/identity/laps/laps-overview"
    $rec += ""
    $rec += "Disclaimer: Automated heuristic assessment; verify before remediation."
    $recPath = Join-Path $base 'ADAudit_Recommendations.txt'
    $rec -join [Environment]::NewLine | Out-File -FilePath $recPath -Encoding UTF8
    Write-Host "Wrote: $recPath"

    # CSVs
    $masterCsv = Join-Path -Path $allDir -ChildPath "ADAudit_AllScopes_$ts.csv"
    $records | Sort-Object ScopeType,ScopeDN,Trustee | Export-Csv -NoTypeInformation -Path $masterCsv -Encoding UTF8

    $byScope = $records | Group-Object ScopeDN
    foreach ($g in $byScope) {
      $safeName = ($g.Name -replace '[=,]','_') -replace '[^\w\.-]','_'
      $csvPath = Join-Path -Path $ouDir -ChildPath "ADAudit_$safeName.csv"
      $g.Group | Export-Csv -NoTypeInformation -Path $csvPath -Encoding UTF8
    }

    # HTML index
    $index = New-Object System.Collections.Generic.List[string]
    $index.Add((Get-ADAuditReportHeader -Title 'AD Delegated Permissions Report'))
    $index.Add("<div class='hero'><h1>AD Delegated Permissions Report</h1>")
    $index.Add("<div class='meta'>Generated: $(Get-Date -Format 'u')</div></div>")

    $index.Add("<div class='stats'>")
    $index.Add("<div class='stat'><div class='val'>$($scopes.Count)</div><div class='lbl'>Scopes Analyzed</div></div>")
    $index.Add("<div class='stat'><div class='val'>$($records.Count)</div><div class='lbl'>Total Permissions</div></div>")
    $hrCount = if ($highRisk) { @($highRisk).Count } else { 0 }
    $index.Add("<div class='stat'><div class='val' style='color:var(--high)'>$hrCount</div><div class='lbl'>High-Risk</div></div>")
    $index.Add("</div>")

    $index.Add('<h2>Scopes</h2>')
    foreach ($dn in $scopes) {
      $safe = ($dn -replace '[=,]','_') -replace '[^\w\.-]','_'
      $index.Add("<details><summary><code>$dn</code></summary><div class='detail-body'><a href='OUs/ADAudit_$safe.csv'>CSV</a> &nbsp;|&nbsp; <a href='OUs/ADAudit_$safe.txt'>TXT</a></div></details>")
    }

    $index.Add('<h2>Summary Files</h2><ul class="link-list">')
    $index.Add("<li><a href='All/ADAudit_AllScopes_$ts.csv'>Master CSV &mdash; all scopes combined</a></li>")
    $index.Add("<li><a href='All/ADAudit_HighRisk_$ts.csv'>High-Risk CSV &mdash; flagged permissions</a></li>")
    $index.Add("<li><a href='ADAudit_RiskAssessment.txt'>Risk Assessment</a></li>")
    $index.Add("<li><a href='ADAudit_Recommendations.txt'>Recommendations</a></li>")
    $index.Add('</ul>')
    $index.Add((Get-ADAuditReportFooter))
    $indexPath = Join-Path $base 'index.html'
    $index -join "`r`n" | Out-File -Encoding UTF8 -FilePath $indexPath
    Write-Host "Index: $indexPath"

    Write-Host "Reports folder: $base"
    Write-Host "Master CSV:     $masterCsv"

    # End transcript
    try { Stop-Transcript | Out-Null } catch {}
}

#endregion Delegated Permissions Report

Function Get-HighRiskADBaselineReport {
    <#
        .SYNOPSIS
            Generates an executive high-risk AD baseline report (TXT + CSVs + HTML index).
        .DESCRIPTION
            Outputs:
              - ad_high_risk_baseline.txt
              - HighRisk\Summary.csv
              - HighRisk\<RiskId>.csv (one per risk category)
              - ad_high_risk_baseline_index.html (HTML index linking to the outputs)
        .NOTES
            This function is additive and does not modify existing checks or outputs.
    #>

    # Baseline (opinionated, aligned with Microsoft tiering + common security guidance)
    $baseline = [ordered]@{
        'Domain Admins (permanent members)'        = '<= 5'
        'Enterprise Admins (permanent members)'    = '0-2 (temporary only)'
        'Schema Admins (permanent members)'        = '0 (except during schema change)'
        'BUILTIN\Administrators (permanent members)' = 'Minimal (avoid non-DA users)'
        'Account Operators / Server Operators / Backup Operators / Print Operators' = 'Empty'
        'krbtgt password age'                      = '<= 180 days (rotate; 2x after incident)'
        'Enabled user inactivity'                  = 'Disable if inactive > 180 days (adjust to org policy)'
        'Disabled user retention'                  = 'Review/remove if disabled > 180 days'
        'Password never expires (humans)'          = '0 (use gMSA/MSA for services)'
        'MachineAccountQuota'                      = '0'
        'Duplicate passwords'                      = '0 shared passwords (no duplicate NT hashes)'
        'Windows cumulative update (Patch Tuesday)'   = 'Latest monthly cumulative update installed (current Patch Tuesday cycle)'
    }

    $riskOutDir = Join-Path (Get-RawSourceDataDir) 'HighRisk'
    New-Item -ItemType Directory -Path $riskOutDir -Force | Out-Null

    $txtPath = Get-EvidencePath 'ad_high_risk_baseline.txt'
    $summaryCsv = Join-Path $riskOutDir 'Summary.csv'
    $indexPath = Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'ad_high_risk_baseline_index.html'

    # Helper: safe group member enumeration
    function _Get-GroupMembersBySidOrName {
        param(
            [Parameter(Mandatory=$true)][string]$Identity
        )
        try {
            $g = Get-ADGroup -Identity $Identity -ErrorAction Stop
            return @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop)
        } catch {
            return @()
        }
    }

    # Helper: convert byte[] hash to hex
    function _ToHex {
        param([byte[]]$Bytes)
        if (-not $Bytes) { return $null }
        -join ($Bytes | ForEach-Object { $_.ToString('x2') })
    }

    # Collect privileged groups (covering domain/forest + builtin operator groups)
    $domainSid = (Get-ADDomain -Current LoggedOnUser).DomainSID.Value

    $groupDefs = @(
        @{ RiskId='PRIV_DA';   Name='Domain Admins';        Identity=($domainSid + '-512'); Baseline='<= 5'; Severity='CRITICAL' }
        @{ RiskId='PRIV_EA';   Name='Enterprise Admins';    Identity=($domainSid + '-519'); Baseline='0-2 (temporary only)'; Severity='CRITICAL' }
        @{ RiskId='PRIV_SA';   Name='Schema Admins';        Identity=($domainSid + '-518'); Baseline='0 (except during schema change)'; Severity='CRITICAL' }
        @{ RiskId='PRIV_ADM';  Name='BUILTIN\Administrators'; Identity='S-1-5-32-544';        Baseline='Minimal'; Severity='HIGH' }
        @{ RiskId='PRIV_AO';   Name='BUILTIN\Account Operators'; Identity='S-1-5-32-548';     Baseline='Empty'; Severity='HIGH' }
        @{ RiskId='PRIV_SO';   Name='BUILTIN\Server Operators';  Identity='S-1-5-32-549';     Baseline='Empty'; Severity='HIGH' }
        @{ RiskId='PRIV_BO';   Name='BUILTIN\Backup Operators';  Identity='S-1-5-32-551';     Baseline='Empty'; Severity='HIGH' }
        @{ RiskId='PRIV_PO';   Name='BUILTIN\Print Operators';   Identity='S-1-5-32-550';     Baseline='Empty'; Severity='MEDIUM' }
    )

    $privDetails = @()
    $privSamSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($gd in $groupDefs) {
        $members = _Get-GroupMembersBySidOrName -Identity $gd.Identity
        foreach ($m in $members) {
            $sam = $m.SamAccountName
            if ($sam) { [void]$privSamSet.Add([string]$sam) }
            $privDetails += [pscustomobject]@{
                RiskId        = $gd.RiskId
                Group         = $gd.Name
                MemberSam     = $m.SamAccountName
                MemberName    = $m.Name
                ObjectClass   = $m.objectClass
                Baseline      = $gd.Baseline
                Severity      = $gd.Severity
            }
        }
    }

    # Summarize privileged group counts vs baseline thresholds
    $privSummary = @()
    foreach ($gd in $groupDefs) {
        $cnt = ($privDetails | Where-Object { $_.RiskId -eq $gd.RiskId } | Measure-Object).Count

        $isFinding = $false
        if ($gd.RiskId -eq 'PRIV_DA' -and $cnt -gt 5) { $isFinding = $true }
        elseif ($gd.RiskId -eq 'PRIV_EA' -and $cnt -gt 2) { $isFinding = $true }
        elseif ($gd.RiskId -eq 'PRIV_SA' -and $cnt -gt 0) { $isFinding = $true }
        elseif ($gd.RiskId -in @('PRIV_AO','PRIV_SO','PRIV_BO','PRIV_PO') -and $cnt -gt 0) { $isFinding = $true }
        elseif ($gd.RiskId -eq 'PRIV_ADM' -and $cnt -gt 0) { $isFinding = $true } # "Minimal" -> always worth review

        $privSummary += [pscustomobject]@{
            RiskId         = $gd.RiskId
            Category       = 'Privileged Group Membership'
            Item           = $gd.Name
            Severity       = $gd.Severity
            Baseline       = $gd.Baseline
            Observed       = $cnt
            IsFinding      = $isFinding
            Recommendation = 'Minimize permanent membership; use JIT/PIM where possible; keep Tier0 separate; monitor changes.'
        }
    }

    # Domain Admins group overlap (DA members in extra groups)
    $daOverlapCsv = Join-Path $riskOutDir 'accounts_domain_admins_group_overlap.csv'
    $daOverlapSummaryObj = $null

    if (Test-Path $daOverlapCsv) {
        $overlaps = Import-Csv $daOverlapCsv

        # Prefer unique accounts (not rows) if SamAccountName exists
        if ($overlaps -and ($overlaps[0].PSObject.Properties.Name -contains 'SamAccountName')) {
            $overlapCount = ($overlaps | Select-Object -ExpandProperty SamAccountName -Unique | Measure-Object).Count
        } else {
            $overlapCount = ($overlaps | Measure-Object).Count
        }

        $daOverlapSummaryObj = [pscustomobject]@{
            RiskId         = 'PRIV_DA_OVERLAP'
            Category       = 'Privileged Group Membership'
            Item           = 'Domain Admins group overlap (extra group memberships)'
            Severity       = 'CRITICAL'
            Baseline       = 0
            Observed       = $overlapCount
            IsFinding      = ($overlapCount -gt 0)
            Recommendation = 'Remove Domain Admin accounts from all non-essential groups. Tier0 identities must be isolated; avoid Tier0+Tier1 overlap and delegated memberships.'
        }
    }

    # krbtgt password age
    $krbtgt = Get-ADUser -Filter { SamAccountName -eq "krbtgt" } -Properties PasswordLastSet -ErrorAction SilentlyContinue
    $krbtgtLastSet = $null
    if ($krbtgt) { $krbtgtLastSet = $krbtgt.PasswordLastSet }
    $krbtgtDays = $null
    if ($krbtgtLastSet) { $krbtgtDays = [int]((New-TimeSpan -Start $krbtgtLastSet -End (Get-Date)).TotalDays) }
    $krbtgtFinding = $false
    if ($krbtgtDays -ne $null -and $krbtgtDays -gt 180) { $krbtgtFinding = $true }

    $krbtgtObj = [pscustomobject]@{
        RiskId='KRB_KRBTGT'
        Category='Kerberos'
        Item='krbtgt password age'
        Severity='CRITICAL'
        Baseline='<= 180 days'
        Observed= $(if ($krbtgtLastSet) { "$krbtgtLastSet ($krbtgtDays days)" } else { 'Unknown' })
        IsFinding=$krbtgtFinding
        Recommendation='Rotate krbtgt regularly; after incident perform two resets per Microsoft guidance (allow ticket lifetime between resets).'
    }

    # Enabled inactive users (>180 days)
    # Enabled inactive users (>180 days) - SAFE (handles invalid FILETIME values)
$inactiveDays = 180
$cutoff = (Get-Date).AddDays(-$inactiveDays)

function _SafeFromFileTimeUtc {
    param([Nullable[long]]$FileTime)
    if ($null -eq $FileTime) { return $null }
    try { return [datetime]::FromFileTimeUtc([int64]$FileTime) } catch { return $null }
}

$inactiveDetails = @()

# Enabled users (bitwise filter for "not disabled")
$enabledUsers = Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
    -Properties lastLogonTimestamp,whenCreated,SamAccountName,Name -ErrorAction SilentlyContinue

foreach ($u in $enabledUsers) {
    $lltRaw = $null
    try { $lltRaw = [int64]$u.lastLogonTimestamp } catch { $lltRaw = $null }

    $llt = _SafeFromFileTimeUtc -FileTime $lltRaw
    $invalidFileTime = ($null -ne $lltRaw -and $null -eq $llt)

    # If lastLogonTimestamp is missing/invalid, fall back to whenCreated as a best-effort heuristic
    $isInactive =
        (($llt -ne $null) -and ($llt -lt $cutoff)) -or
        (($llt -eq $null) -and ($u.whenCreated -lt $cutoff))

    if ($isInactive) {
        $inactiveDetails += [pscustomobject]@{
            RiskId               = 'ACCT_INACTIVE'
            SamAccountName       = $u.SamAccountName
            Name                 = $u.Name
            LastLogonDate        = $llt
            LastLogonTimestampRaw= $lltRaw
            InvalidFileTime      = $invalidFileTime
            WhenCreated          = $u.whenCreated
            Baseline             = "Disable if inactive > $inactiveDays days"
            Severity             = 'HIGH'
            IsPrivileged         = $privSamSet.Contains([string]$u.SamAccountName)
        }
    }
}

$inactiveObj = [pscustomobject]@{
    RiskId='ACCT_INACTIVE'
    Category='Account Hygiene'
    Item="Enabled accounts inactive > $inactiveDays days"
    Severity='HIGH'
    Baseline="0 (disable if inactive > $inactiveDays days)"
    Observed=($inactiveDetails | Measure-Object).Count
    IsFinding=((($inactiveDetails | Measure-Object).Count) -gt 0)
    Recommendation='Disable or remove accounts that are no longer used; verify HR/offboarding; prioritize privileged and service accounts.'
}
    
    # Password never expires (enabled users)
    $pneUsers = Search-ADAccount -PasswordNeverExpires -UsersOnly -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
    $pneDetails = @()
    foreach ($u in $pneUsers) {
        $pneDetails += [pscustomobject]@{
            RiskId='PWD_NEVER_EXPIRES'
            SamAccountName=$u.SamAccountName
            Name=$u.Name
            Baseline='0 (humans); use gMSA/MSA for services'
            Severity= $(if ($privSamSet.Contains([string]$u.SamAccountName)) { 'CRITICAL' } else { 'HIGH' })
            IsPrivileged= $privSamSet.Contains([string]$u.SamAccountName)
        }
    }
    $pneObj = [pscustomobject]@{
        RiskId='PWD_NEVER_EXPIRES'
        Category='Credential Hygiene'
        Item='Enabled user accounts with PasswordNeverExpires'
        Severity='HIGH'
        Baseline='0 (humans); services should use gMSA/MSA'
        Observed=($pneDetails | Measure-Object).Count
        IsFinding=((($pneDetails | Measure-Object).Count) -gt 0)
        Recommendation='Eliminate non-expiring human passwords; migrate service accounts to gMSA; rotate credentials; enforce MFA for admins.'
    }

    # Disabled accounts stale (>180 days) based on whenChanged (best-effort)
    $disabledRetentionDays = 180
    $disabledOld = Get-ADUser -Filter { Enabled -eq $false } -Properties whenChanged,SamAccountName,Name -ErrorAction SilentlyContinue |
                   Where-Object { $_.whenChanged -lt (Get-Date).AddDays(-$disabledRetentionDays) }
    $disabledOldDetails = @()
    foreach ($u in $disabledOld) {
        $disabledOldDetails += [pscustomobject]@{
            RiskId='ACCT_DISABLED_STALE'
            SamAccountName=$u.SamAccountName
            Name=$u.Name
            whenChanged=$u.whenChanged
            Baseline="Review/remove if disabled > $disabledRetentionDays days"
            Severity='MEDIUM'
        }
    }
    $disabledOldObj = [pscustomobject]@{
        RiskId='ACCT_DISABLED_STALE'
        Category='Account Hygiene'
        Item="Disabled accounts not reviewed > $disabledRetentionDays days"
        Severity='MEDIUM'
        Baseline="0 (review/remove if disabled > $disabledRetentionDays days)"
        Observed=($disabledOldDetails | Measure-Object).Count
        IsFinding=((($disabledOldDetails | Measure-Object).Count) -gt 0)
        Recommendation='Remove or archive long-disabled accounts; verify business/legal retention; reduce directory clutter and attack surface.'
    }

    # MachineAccountQuota
    $maq = $null
    try {
        $maq = (Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Property 'ms-DS-MachineAccountQuota' | Select-Object -ExpandProperty ms-DS-MachineAccountQuota)
    } catch { }
    $maqFinding = $false
    if ($maq -ne $null -and [int]$maq -gt 0) { $maqFinding = $true }
    $maqObj = [pscustomobject]@{
        RiskId='DOMAIN_MAQ'
        Category='Domain Configuration'
        Item='ms-DS-MachineAccountQuota'
        Severity='HIGH'
        Baseline='0'
        Observed= $(if ($maq -ne $null) { [int]$maq } else { 'Unknown' })
        IsFinding=$maqFinding
        Recommendation='Set ms-DS-MachineAccountQuota to 0; delegate domain join to a controlled group/process; monitor computer object creation.'
    }

    # Duplicate passwords (requires DSInternals)
    $dupSummaryObj = [pscustomobject]@{
        RiskId='PWD_DUPLICATE'
        Category='Credential Hygiene'
        Item='Duplicate passwords (duplicate NT hashes)'
        Severity='CRITICAL'
        Baseline='0'
        Observed='Not evaluated (DSInternals not available)'
        IsFinding=$false
        Recommendation='Eliminate password reuse; enforce unique passwords; use password filters / banned password lists; monitor for duplicates.'
    }
    $dupDetails = @()

    if (Import-ADAuditModule -Name DSInternals) {
        try {
            $dcObj = Get-ADDomainController -Discover
            $dc = $dcObj.DNSHostName
            if (-not $dc) { $dc = $dcObj.HostName }
            if (-not $dc) { $dc = $dcObj.Name }
            $dc = [string]$dc

            $domain = Get-ADDomain
            $domainDN = $domain.DistinguishedName

            $replAccounts = Get-ADReplAccount -All -Server $dc -NamingContext $domainDN -ErrorAction Stop
            $hashGroups = @()

            foreach ($ra in $replAccounts) {
                $sam = $ra.SamAccountName
                $hex = _ToHex -Bytes $ra.NTHash
                if ($sam -and $hex) {
                    $hashGroups += [pscustomobject]@{ SamAccountName=$sam; NTHash=$hex }
                }
            }

            $dups = $hashGroups | Group-Object NTHash | Where-Object { $_.Count -gt 1 } |
                Sort-Object { @(($_.Group | Select-Object -ExpandProperty SamAccountName | Sort-Object))[0] }

            $dupGroupIndex = 0
            foreach ($g in $dups) {
                $dupGroupIndex++
                $members = @($g.Group | Select-Object -ExpandProperty SamAccountName | Sort-Object)
                $groupLabel = ('PWD-REUSE-{0:d3}' -f $dupGroupIndex)
                $samePasswordAccounts = [string]::Join('; ', $members)

                foreach ($m in $members) {
                    $isPrivileged = $privSamSet.Contains([string]$m)
                    $dupDetails += [pscustomobject]@{
                        RiskId='PWD_DUPLICATE'
                        PasswordGroup=$groupLabel
                        SharedCount=@($members).Count
                        SamAccountName=$m
                        SamePasswordAccounts=$samePasswordAccounts
                        IsPrivileged=$isPrivileged
                        Severity= $(if ($isPrivileged) { 'CRITICAL' } else { 'HIGH' })
                        Baseline='0'
                    }
                }
            }

            $dupDetails = @($dupDetails | Sort-Object PasswordGroup, SamAccountName)

            $dupCount = ($dups | Measure-Object).Count
            $dupSummaryObj = [pscustomobject]@{
                RiskId='PWD_DUPLICATE'
                Category='Credential Hygiene'
                Item='Duplicate passwords (duplicate NT hashes)'
                Severity='CRITICAL'
                Baseline='0'
                Observed="$dupCount duplicate-hash groups; $($dupDetails.Count) affected accounts"
                IsFinding=($dupDetails.Count -gt 0)
                Recommendation='Eliminate password reuse; prioritize privileged accounts; enforce unique passwords; rotate; consider banned password lists.'
            }
        } catch {
            # Keep default "Not evaluated" if anything fails
        }
    }

    # Build summary table
    $summary = @()
    $summary += $privSummary
    if ($daOverlapSummaryObj) { $summary += $daOverlapSummaryObj }
    $summary += $krbtgtObj
    $summary += $inactiveObj
    $summary += $pneObj
    $summary += $disabledOldObj
    $summary += $maqObj
    $summary += $dupSummaryObj

    # Write TXT report (with baseline table embedded)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("=== Active Directory High Risk Baseline Report ===")
    $lines.Add("Generated: $(Get-Date -Format o)")
    try {
        $d = Get-ADDomain
        $lines.Add("Domain:   $($d.DNSRoot)")
        $lines.Add("Forest:   $((Get-ADForest).Name)")
    } catch { }
    $lines.Add("")
    $lines.Add("Baseline (target values)")
    $lines.Add(('-' * 80))
    foreach ($k in $baseline.Keys) { $lines.Add(("{0}: {1}" -f $k, $baseline[$k])) }
    $lines.Add("")
    $lines.Add("Findings")
    $lines.Add(('-' * 80))

    $crit = $summary | Where-Object { $_.IsFinding -eq $true -and $_.Severity -eq 'CRITICAL' }
    $high = $summary | Where-Object { $_.IsFinding -eq $true -and $_.Severity -eq 'HIGH' }
    $med  = $summary | Where-Object { $_.IsFinding -eq $true -and $_.Severity -eq 'MEDIUM' }

    foreach ($item in ($crit | Sort-Object RiskId,Item)) {
        $lines.Add("[CRITICAL] $($item.Item) | Observed: $($item.Observed) | Baseline: $($item.Baseline)")
    }
    foreach ($item in ($high | Sort-Object RiskId,Item)) {
        $lines.Add("[HIGH]     $($item.Item) | Observed: $($item.Observed) | Baseline: $($item.Baseline)")
    }
    foreach ($item in ($med | Sort-Object RiskId,Item)) {
        $lines.Add("[MEDIUM]   $($item.Item) | Observed: $($item.Observed) | Baseline: $($item.Baseline)")
    }

    if (($crit | Measure-Object).Count -eq 0 -and ($high | Measure-Object).Count -eq 0 -and ($med | Measure-Object).Count -eq 0) {
        $lines.Add("[OK] No high-risk findings detected by this baseline.")
    }

    $lines.Add("")
    $lines.Add("Recommendations (per finding)")
    $lines.Add(('-' * 80))
    foreach ($item in ($summary | Where-Object { $_.IsFinding -eq $true } | Sort-Object Severity,RiskId,Item)) {
        $lines.Add("$($item.RiskId) [$($item.Severity)] $($item.Item)")
        $lines.Add("  Baseline: $($item.Baseline)")
        $lines.Add("  Observed: $($item.Observed)")
        $lines.Add("  Action:   $($item.Recommendation)")
        $lines.Add("")
    }

    $lines | Out-File -FilePath $txtPath -Encoding UTF8

    # Export CSVs (one per risk + overall summary)
    $summary | Select-Object RiskId,Category,Item,Severity,Baseline,Observed,IsFinding,Recommendation |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path $summaryCsv

    # Per-risk detail CSVs
    $privDetails  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'PRIVILEGED_GROUPS.csv')
    $inactiveDetails | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'INACTIVE_ACCOUNTS.csv')
    $pneDetails   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'PASSWORD_NEVER_EXPIRES.csv')
    $disabledOldDetails | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'DISABLED_STALE.csv')
    @($krbtgtObj) | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'KRBTGT.csv')
    @($maqObj)    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'MACHINE_ACCOUNT_QUOTA.csv')
    $dupDetails   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $riskOutDir 'DUPLICATE_PASSWORDS.csv')

    # HTML index (replaces XLSX requirement; no external modules)
$indexPath = Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'ad_high_risk_baseline_index.html'
$html = New-Object System.Collections.Generic.List[string]
$html.Add((Get-ADAuditReportHeader -Title 'AD High Risk Baseline Report'))
$html.Add("<div class='hero'><h1>Active Directory High Risk Baseline Report</h1>")
$domainMeta = ''
try {
    $d = Get-ADDomain
    $domainMeta = "Domain: <code>$($d.DNSRoot)</code> &mdash; Forest: <code>$((Get-ADForest).Name)</code> &mdash; "
} catch { }
$html.Add("<div class='meta'>${domainMeta}Generated: $(Get-Date -Format 'u')</div></div>")

$critCount = ($crit | Measure-Object).Count
$highCount = ($high | Measure-Object).Count
$medCount  = ($med  | Measure-Object).Count
$html.Add("<div class='stats'>")
$html.Add("<div class='stat'><div class='val'>$($critCount + $highCount + $medCount)</div><div class='lbl'>Total Findings</div></div>")
$html.Add("<div class='stat'><div class='val' style='color:var(--critical)'>$critCount</div><div class='lbl'>Critical</div></div>")
$html.Add("<div class='stat'><div class='val' style='color:var(--high)'>$highCount</div><div class='lbl'>High</div></div>")
$html.Add("<div class='stat'><div class='val' style='color:var(--medium)'>$medCount</div><div class='lbl'>Medium</div></div>")
$html.Add("</div>")

$html.Add('<h2>Baseline (target values)</h2>')
$html.Add('<table><thead><tr><th>Control</th><th>Baseline</th></tr></thead><tbody>')
foreach ($k in $baseline.Keys) {
    $html.Add("<tr><td>$([System.Security.SecurityElement]::Escape([string]$k))</td><td><code>$([System.Security.SecurityElement]::Escape([string]$baseline[$k]))</code></td></tr>")
}
$html.Add('</tbody></table>')

$html.Add('<h2>Evidence Files</h2><ul class="link-list">')
$html.Add("<li><a href='../Raw Data/Source/ad_high_risk_baseline.txt'>Executive TXT report (includes baseline + findings)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/Summary.csv'>Summary CSV</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/PRIVILEGED_GROUPS.csv'>Privileged group membership (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/accounts_domain_admins_group_overlap.csv'>Domain Admins group overlap (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/KRBTGT.csv'>krbtgt password age (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/INACTIVE_ACCOUNTS.csv'>Inactive enabled accounts (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/PASSWORD_NEVER_EXPIRES.csv'>Password never expires (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/DISABLED_STALE.csv'>Disabled stale accounts (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/MACHINE_ACCOUNT_QUOTA.csv'>MachineAccountQuota (detail)</a></li>")
$html.Add("<li><a href='../Raw Data/Source/HighRisk/DUPLICATE_PASSWORDS.csv'>Duplicate passwords (detail; requires DSInternals + replication privileges)</a></li>")
$html.Add('</ul>')

$html.Add('<h2>Finding Counts</h2>')
$html.Add('<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>')
$html.Add("<tr><td><span class='badge badge-critical'>CRITICAL</span></td><td>$critCount</td></tr>")
$html.Add("<tr><td><span class='badge badge-high'>HIGH</span></td><td>$highCount</td></tr>")
$html.Add("<tr><td><span class='badge badge-medium'>MEDIUM</span></td><td>$medCount</td></tr>")
$html.Add('</tbody></table>')

$html.Add((Get-ADAuditReportFooter))
$html | Out-File -Encoding UTF8 -FilePath $indexPath
Write-Both "    [+] High-risk AD baseline report generated: ad_high_risk_baseline.txt"
    Write-Both "    [+] High-risk CSVs generated in: $riskOutDir"
    if (Test-Path $indexPath) { Write-Both "    [+] High-risk HTML index generated: ad_high_risk_baseline_index.html" }
}

Function Get-KerberosUnconstrainedDelegation {
    # Finds accounts with unconstrained Kerberos delegation (excluding DCs which have it by design)
    # Unconstrained delegation allows an account to impersonate any user, making it a high-value attack target
    $count = 0
    $evidencePath = Get-EvidencePath 'unconstrained_delegation.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue

    # UserAccountControl flag 0x80000 = TRUSTED_FOR_DELEGATION (unconstrained)
    $filter = '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'
    $results = Get-ADObject -LDAPFilter $filter -Properties Name, SamAccountName, ObjectClass, userAccountControl, DistinguishedName

    foreach ($obj in $results) {
        Add-Content -Path $evidencePath -Value "$($obj.ObjectClass) $($obj.SamAccountName) ($($obj.Name)) has unconstrained Kerberos delegation - DN: $($obj.DistinguishedName)"
        $count++
    }

    if ($count -gt 0) {
        Write-Both "    [!] $count non-DC account(s) with unconstrained Kerberos delegation found (KB1200)"
        Write-Both "    [!] These accounts can impersonate ANY user who authenticates to them - high-priority remediation target"
        Write-Nessus-Finding "UnconstrainedDelegation" "KB1200" ([System.IO.File]::ReadAllText($evidencePath))
    }
    else {
        Write-Both "    [+] No non-DC accounts with unconstrained Kerberos delegation found"
    }
}

Function Get-GMSAStatus {
    # Identifies service accounts with SPNs that are NOT Group Managed Service Accounts (gMSA)
    # gMSA passwords are automatically rotated by AD, reducing credential theft risk
    $count = 0
    $gmsakount = 0
    $evidencePath = Get-EvidencePath 'gmsa_status.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue

    # Find gMSA accounts
    $gmsaAccounts = @(Get-ADServiceAccount -Filter * -Properties Name, SamAccountName, Enabled -ErrorAction SilentlyContinue)
    $gmsakount = ($gmsaAccounts | Measure-Object).Count

    # Find user accounts with SPNs set (likely service accounts)
    $svcAccounts = @(Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -Properties SamAccountName, Name, ServicePrincipalName)

    foreach ($svc in $svcAccounts) {
        $spnList = ($svc.ServicePrincipalName -join '; ')
        Add-Content -Path $evidencePath -Value "User account $($svc.SamAccountName) ($($svc.Name)) has SPNs: $spnList - consider migrating to gMSA"
        $count++
    }

    Write-Both "    [+] Found $gmsakount Group Managed Service Account(s) (gMSA)"
    if ($count -gt 0) {
        Write-Both "    [!] $count enabled user account(s) with SPNs (likely service accounts) are not using gMSA (KB1201)"
        Write-Both "    [!] These accounts use static passwords - consider migrating to gMSA for automatic password rotation"
        Write-Nessus-Finding "ServiceAccountsNotGMSA" "KB1201" ([System.IO.File]::ReadAllText($evidencePath))
    }
    else {
        Write-Both "    [+] No enabled user accounts with SPNs found (all service accounts may be using gMSA)"
    }
}

Function Get-TombstoneLifetime {
    # Checks the forest tombstone lifetime configuration
    # Low tombstone lifetime reduces the window for AD Recycle Bin recovery
    $configNC = (Get-ADRootDSE).configurationNamingContext
    $tombstoneObj = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime -ErrorAction SilentlyContinue
    $lifetime = $tombstoneObj.tombstoneLifetime

    if ($null -eq $lifetime) {
        $lifetime = 60  # Default if not explicitly set (Windows Server 2003+)
        Write-Both "    [!] Tombstone lifetime is not explicitly configured (defaults to 60 days). Consider setting to 180 days for better AD Recycle Bin retention (KB1202)"
        Write-Nessus-Finding "TombstoneLifetime" "KB1202" "Tombstone lifetime not explicitly set (defaults to 60 days)"
    }
    elseif ($lifetime -lt 180) {
        Write-Both "    [!] Tombstone lifetime is set to $lifetime days (recommended: 180 days minimum) (KB1202)"
        Write-Nessus-Finding "TombstoneLifetime" "KB1202" "Tombstone lifetime is $lifetime days (recommended minimum: 180)"
    }
    else {
        Write-Both "    [+] Tombstone lifetime is $lifetime days"
    }
}

Function Get-PrintSpoolerOnDCs {
    # Checks if Print Spooler service is running on domain controllers
    # PrintNightmare (CVE-2021-34527) and coercion attacks exploit the spooler service
    $count = 0
    $evidencePath = Get-EvidencePath 'dc_print_spooler.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue

    $dcList = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)

    foreach ($dc in $dcList) {
        try {
            $spooler = Get-ADAuditCimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -ComputerName $dc -UseWsmanFallback
            if ($spooler -and $spooler.State -eq 'Running') {
                Add-Content -Path $evidencePath -Value "Print Spooler is RUNNING on DC: $dc (StartMode: $($spooler.StartMode))"
                $count++
            }
            elseif ($spooler) {
                Write-Both "    [+] Print Spooler is $($spooler.State) on DC: $dc"
            }
        }
        catch {
            Write-Both "    [!] Could not query Print Spooler status on DC: $dc - $_"
        }
    }

    if ($count -gt 0) {
        Write-Both "    [!] Print Spooler is running on $count domain controller(s) - disable to mitigate PrintNightmare and coercion attacks (KB1203)"
        Write-Nessus-Finding "PrintSpoolerOnDC" "KB1203" ([System.IO.File]::ReadAllText($evidencePath))
    }
    else {
        Write-Both "    [+] Print Spooler is not running on any domain controller"
    }
}

Function Get-SMBSigningStatus {
    # Checks SMB signing enforcement on domain controllers
    # Missing SMB signing enables NTLM relay attacks
    $count = 0
    $evidencePath = Get-EvidencePath 'dc_smb_signing.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue

    $dcList = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)

    foreach ($dc in $dcList) {
        try {
            $regParams = @{
                ClassName    = 'StdRegProv'
                Namespace    = 'root/default'
                ComputerName = $dc
            }

            # Check RequireSecuritySignature (EnableSecuritySignature is the weaker setting)
            $requireSigning = $null
            try {
                $result = Invoke-CimMethod -ClassName StdRegProv -Namespace 'root/default' -MethodName GetDWORDValue -Arguments @{
                    hDefKey     = [uint32]2147483650  # HKLM
                    sSubKeyName = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
                    sValueName  = 'RequireSecuritySignature'
                } -CimSession (New-CimSession -ComputerName $dc -ErrorAction Stop) -ErrorAction Stop
                $requireSigning = $result.uValue
            }
            catch {
                # Fallback: try Get-SmbServerConfiguration if available
                try {
                    $smbConfig = Invoke-Command -ComputerName $dc -ScriptBlock { (Get-SmbServerConfiguration).RequireSecuritySignature } -ErrorAction Stop
                    $requireSigning = if ($smbConfig) { 1 } else { 0 }
                }
                catch {
                    Write-Both "    [!] Could not query SMB signing status on DC: $dc - $_"
                    continue
                }
            }

            if ($null -ne $requireSigning -and $requireSigning -ne 1) {
                Add-Content -Path $evidencePath -Value "SMB signing is NOT required on DC: $dc (RequireSecuritySignature = $requireSigning)"
                $count++
            }
            else {
                Write-Both "    [+] SMB signing is required on DC: $dc"
            }
        }
        catch {
            Write-Both "    [!] Could not query SMB signing status on DC: $dc - $_"
        }
    }

    if ($count -gt 0) {
        Write-Both "    [!] SMB signing is not enforced on $count domain controller(s) - enables NTLM relay attacks (KB1204)"
        Write-Nessus-Finding "SMBSigningNotRequired" "KB1204" ([System.IO.File]::ReadAllText($evidencePath))
    }
    else {
        Write-Both "    [+] SMB signing is required on all domain controllers"
    }
}

$outputdir = Join-Path -Path (Get-Item -Path '.').FullName -ChildPath $env:COMPUTERNAME
$script:outputdir = $outputdir
$starttime = Get-Date
$scriptname = $MyInvocation.MyCommand.Name
if (!(Test-Path "$outputdir")) { New-Item -ItemType Directory -Path $outputdir | Out-Null }

$script:HtmlReportsDir = Join-Path $outputdir 'HTML Reports'
$script:EvidenceFilesDir = Join-Path $outputdir 'Raw Data'
$script:LegacyArtifactsDir = Join-Path $script:EvidenceFilesDir 'Source'
$script:ReportDownloadsDir = $script:LegacyArtifactsDir  # Merged: Prepared now points to Source
if (!(Test-Path $script:HtmlReportsDir)) { New-Item -ItemType Directory -Path $script:HtmlReportsDir -Force | Out-Null }
if (!(Test-Path $script:EvidenceFilesDir)) { New-Item -ItemType Directory -Path $script:EvidenceFilesDir -Force | Out-Null }
if (!(Test-Path $script:LegacyArtifactsDir)) { New-Item -ItemType Directory -Path $script:LegacyArtifactsDir -Force | Out-Null }
Write-Both " _____ ____     _____       _ _ _
|  _  |    \   |  _  |_ _ _| |_| |_
|     |  |  |  |     | | | . | |  _|
|__|__|____/   |__|__|___|___|_|_|
6.0                     by phillips321 (Legacy Script)
$versionnum                  Converted for Powershell 7 and extended by Keberneth
"
$running = $false
Write-Both "[*] Script start time $starttime"

if (-not $script:ADAuditIsWindows) {
    Write-Both "[!] This script requires Windows because it depends on Windows Server/RSAT management modules."
    exit 1
}

$needsActiveDirectory = (
    $domainaudit -or $trusts -or $accounts -or $InactiveComputers -or
    $passwordpolicy -or $oldboxes -or $gpo -or $ouperms -or $laps -or
    $authpolsilos -or $insecurednszone -or $recentchanges -or $adcs -or
    $spn -or $asrep -or $acl -or $ldapsecurity -or $dataextract -or
    $delegatedpermissions -or $highrisk -or $overlappinggroups -or
    (($all -and 'domainaudit' -notin $exclude) -or
     ($all -and 'trusts' -notin $exclude) -or
     ($all -and 'accounts' -notin $exclude) -or
     ($all -and 'inactivecomputers' -notin $exclude) -or
     ($all -and 'passwordpolicy' -notin $exclude) -or
     ($all -and 'oldboxes' -notin $exclude) -or
     ($all -and 'gpo' -notin $exclude) -or
     ($all -and 'ouperms' -notin $exclude) -or
     ($all -and 'laps' -notin $exclude) -or
     ($all -and 'authpolsilos' -notin $exclude) -or
     ($all -and 'insecurednszone' -notin $exclude) -or
     ($all -and 'recentchanges' -notin $exclude) -or
     ($all -and 'adcs' -notin $exclude) -or
     ($all -and 'spn' -notin $exclude) -or
     ($all -and 'asrep' -notin $exclude) -or
     ($all -and 'acl' -notin $exclude) -or
     ($all -and 'ldapsecurity' -notin $exclude) -or
     ($all -and 'dataextract' -notin $exclude) -or
     ($all -and 'delegatedpermissions' -notin $exclude) -or
     ($all -and 'highrisk' -notin $exclude) -or
     ($all -and 'overlappinggroups' -notin $exclude)) -or
    ('domainaudit' -in $selectedChecks) -or ('trusts' -in $selectedChecks) -or
    ('accounts' -in $selectedChecks) -or ('inactivecomputers' -in $selectedChecks) -or
    ('passwordpolicy' -in $selectedChecks) -or ('oldboxes' -in $selectedChecks) -or
    ('gpo' -in $selectedChecks) -or ('ouperms' -in $selectedChecks) -or
    ('laps' -in $selectedChecks) -or ('authpolsilos' -in $selectedChecks) -or
    ('insecurednszone' -in $selectedChecks) -or ('recentchanges' -in $selectedChecks) -or
    ('adcs' -in $selectedChecks) -or ('spn' -in $selectedChecks) -or
    ('asrep' -in $selectedChecks) -or ('acl' -in $selectedChecks) -or
    ('ldapsecurity' -in $selectedChecks) -or ('dataextract' -in $selectedChecks) -or
    ('delegatedpermissions' -in $selectedChecks) -or ('highrisk' -in $selectedChecks) -or
    ('overlappinggroups' -in $selectedChecks)
)

$needsGroupPolicy = (
    $domainaudit -or $gpo -or $dataextract -or
    (($all -and 'domainaudit' -notin $exclude) -or ($all -and 'gpo' -notin $exclude) -or ($all -and 'dataextract' -notin $exclude)) -or
    ('domainaudit' -in $selectedChecks) -or ('gpo' -in $selectedChecks) -or ('dataextract' -in $selectedChecks)
)

$needsDnsServer = (
    $dnszone -or $insecurednszone -or
    (($all -and 'dnszone' -notin $exclude) -or ($all -and 'insecurednszone' -notin $exclude)) -or
    ('dnszone' -in $selectedChecks) -or ('insecurednszone' -in $selectedChecks)
)

$needsDSInternals = (
    $passwordpolicy -or $highrisk -or
    (($all -and 'passwordpolicy' -notin $exclude) -or ($all -and 'highrisk' -notin $exclude)) -or
    ('passwordpolicy' -in $selectedChecks) -or ('highrisk' -in $selectedChecks)
)

if ($needsActiveDirectory) {
    try {
        Import-ADAuditModule -Name ActiveDirectory -Required | Out-Null
    }
    catch {
        Write-Both "[!] ActiveDirectory module not installed or failed to load, exiting... $($_.Exception.Message)"
        exit 1
    }
}

if ($needsGroupPolicy) {
    try {
        Import-ADAuditModule -Name GroupPolicy -Required -PreferWindowsPowerShell | Out-Null
    }
    catch {
        Write-Both "[!] GroupPolicy module not available, GP-dependent checks will be skipped... $($_.Exception.Message)"
    }
}

if ($needsDnsServer) {
    try {
        Import-ADAuditModule -Name DnsServer -Required | Out-Null
    }
    catch {
        Write-Both "[!] DnsServer module not available, DNS-dependent checks will be skipped... $($_.Exception.Message)"
    }
}

if ($needsDSInternals) {
    if (-not (Import-ADAuditModule -Name DSInternals)) {
        Write-Both "[!] DSInternals module not installed, DSInternals-based checks will be skipped. Use -installdeps to install it."
    }
}

if (Test-Path "$outputdir\adaudit.nessus") { Remove-Item -LiteralPath "$outputdir\adaudit.nessus" -Force | Out-Null }
Write-Nessus-Header
Write-Both "[+] Outputting to $outputdir"
if ($needsActiveDirectory) {
    Write-Both "[*] Lang specific variables"
    Get-Variables
}
if ($installdeps) { $running = $true ; Write-Both "[*] Installing optionnal features"                           ; Install-Dependencies }
if ($hostdetails -or ($all -and 'hostdetails' -notin $exclude) -or 'hostdetails' -in $selectedChecks) { $running = $true ; Write-Both "[*] Device Information" ; Get-HostDetails }
if ($domainaudit -or ($all -and 'domainaudit' -notin $exclude) -or 'domainaudit' -in $selectedChecks) { $running = $true ; Write-Both "[*] Domain Audit" ; Get-LastWUDate ; Get-DCEval ; Get-TimeSource ; Get-PrivilegedGroupMembership ; Get-MachineAccountQuota; Get-DefaultDomainControllersPolicy ; Get-SMB1Support ; Get-FunctionalLevel ; Get-DCsNotOwnedByDA ; Get-ReplicationType ; Check-Shares ; Get-RecycleBinState ; Get-CriticalServicesStatus ; Get-RODC ; Get-KerberosUnconstrainedDelegation ; Get-TombstoneLifetime ; Get-PrintSpoolerOnDCs ; Get-SMBSigningStatus }
if ($trusts -or ($all -and 'trusts' -notin $exclude) -or 'trusts' -in $selectedChecks) { $running = $true ; Write-Both "[*] Domain Trust Audit" ; Get-DomainTrusts }
if ($accounts -or ($all -and 'accounts' -notin $exclude) -or 'accounts' -in $selectedChecks) { $running = $true ; Write-Both "[*] Accounts Audit" ; Get-InactiveAccounts ; Get-DisabledAccounts ; Get-LockedAccounts ; Get-AdminAccountChecks ; Get-NULLSessions ; Get-PrivilegedGroupAccounts ; Get-ProtectedUsers ; Get-DomainAdminsGroupOverlap ; Get-GMSAStatus }
if ($passwordpolicy -or ($all -and 'passwordpolicy' -notin $exclude) -or 'passwordpolicy' -in $selectedChecks) { $running = $true ; Write-Both "[*] Password Information Audit" ; Get-AccountPassDontExpire ; Get-UserPasswordNotChangedRecently ; Get-PasswordPolicy ; Get-PasswordQuality }
if ($InactiveComputers -or ($all -and 'inactivecomputers' -notin $exclude) -or 'inactivecomputers' -in $selectedChecks) {
    $running = $true
    Write-Both "[*] Inactive Computer Objects Audit"
    Get-InactiveComputerObjects
}
if ($all -or $accounts -or $overlappinggroups) {
    Write-Both "    [+] Running overlapping group membership analysis"
    Get-OverlappingGroupMemberships
}
if ($highrisk -or ($all -and 'highrisk' -notin $exclude) -or 'highrisk' -in $selectedChecks) { $running = $true ; Write-Both "[*] High-Risk AD Baseline Report" ; Get-HighRiskADBaselineReport }
if ($oldboxes -or ($all -and 'oldboxes' -notin $exclude) -or 'oldboxes' -in $selectedChecks) { $running = $true ; Write-Both "[*] Computer Objects Audit" ; Get-OldBoxes }
if ($gpo -or ($all -and 'gpo' -notin $exclude) -or 'gpo' -in $selectedChecks) { $running = $true ; Write-Both "[*] GPO audit (and checking SYSVOL for passwords)" ; Get-GPOtoFile ; Get-GPOsPerOU ; Get-SYSVOLXMLS; Get-GPOEnum }
if ($ouperms -or ($all -and 'ouperms' -notin $exclude) -or 'ouperms' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check Generic Group AD Permissions" ; Get-OUPerms }
if ($laps -or ($all -and 'laps' -notin $exclude) -or 'laps' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For Existence of LAPS in domain" ; Get-LAPSStatus }
if ($authpolsilos -or ($all -and 'authpolsilos' -notin $exclude) -or 'authpolsilos' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For Existence of Authentication Polices and Silos" ; Get-AuthenticationPoliciesAndSilos }
if ($insecurednszone -or ($all -and 'insecurednszone' -notin $exclude) -or 'insecurednszone' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For Existence DNS Zones allowing insecure updates" ; Get-DNSZoneInsecure }
if ($dnszone -or ($all -and 'dnszone' -notin $exclude) -or 'dnszone' -in $selectedChecks) {
    $running = $true
    Write-Both "[*] DNS Zone Report"
    Invoke-DNSZoneReport -OutputRoot $(if($DnsZoneOutputRoot){$DnsZoneOutputRoot}else{(Get-RawDataDir -BaseRoot $outputdir)}) -IncludeRecordCounts:$DnsIncludeRecordCounts -IncludeSystemZones:$DnsIncludeSystemZones
}
if ($recentchanges -or ($all -and 'recentchanges' -notin $exclude) -or 'recentchanges' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For newly created users and groups"                ; Get-RecentChanges }
if ($spn -or ($all -and 'spn' -notin $exclude) -or 'spn' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check high value kerberoastable user accounts"           ; Get-SPNs }
if ($asrep -or ($all -and 'asrep' -notin $exclude) -or 'asrep' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for accounts with kerberos pre-auth"               ; Get-ADUsersWithoutPreAuth }
if ($acl -or ($all -and 'acl' -notin $exclude) -or 'acl' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for dangerous ACL permissions on Computers, Users and Groups"  ; Find-DangerousACLPermissions }
if ($adcs -or ($all -and 'adcs' -notin $exclude) -or 'adcs' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for ADCS Vulnerabilities"                          ; Get-ADCSVulns }
if ($ldapsecurity -or ($all -and 'ldapsecurity' -notin $exclude) -or 'ldapsecurity' -in $selectedChecks) { 
    $running = $true 
    Write-Both "[*] Check for LDAP Security Issues" 
    Get-LDAPSecurity 
}
if ($dataextract -or ($all -and 'dataextract' -notin $exclude) -or 'dataextract' -in $selectedChecks) { $running = $true ; Write-Both "[*] AD Raw Data Extract"                          ; Export-ADAuditDataExtract }
if ($delegatedpermissions -or ($all -and 'delegatedpermissions' -notin $exclude) -or 'delegatedpermissions' -in $selectedChecks) {
    $running = $true
    if (-not $DelegatedOutputRoot) { $DelegatedOutputRoot = (Join-Path (Get-RawDataDir -BaseRoot $outputdir) 'DelegatedPermissions') }
    Write-Both "[*] Delegated Permissions Report"
    Invoke-DelegatedPermissionsReport -OutputRoot $DelegatedOutputRoot -IncludeSystemTrustees:$DelegIncludeSystemTrustees -IncludeDeny:$DelegIncludeDeny -IncludeInherited:$DelegIncludeInherited -Server $DelegServer
}
if (!$running) {
    Write-Both "[!] No arguments selected"
    Write-Both "[!] Other options are as follows, they can be used in combination"
    Write-Both "    -installdeps installs optionnal features (DSInternals)"
    Write-Both "    -hostdetails retrieves hostname and other useful audit info"
    Write-Both "    -domainaudit retrieves information about the AD such as functional level, delegation, spooler, SMB signing, tombstone"
    Write-Both "    -trusts retrieves information about any doman trusts"
    Write-Both "    -accounts identifies account issues such as expired, disabled, gMSA status, etc..."
    Write-Both "    -passwordpolicy retrieves password policy information"
    Write-Both "    -oldboxes identifies outdated OSs like 2000/2003/XP/Vista/7/2008 joined to the domain"
    Write-Both "    -gpo dumps the GPOs in XML and HTML for later analysis"
    Write-Both "    -ouperms checks generic OU permission issues"
    Write-Both "    -laps checks if LAPS is installed"
    Write-Both "    -authpolsilos checks for existence of authentication policies and silos"
    Write-Both "    -insecurednszone checks for insecure DNS zones"
    Write-Both "    -dnszone generates a DNS zone posture report (HTML/CSV/JSON) (alias: -dns-zone)"
    Write-Both "        Optional: -DnsIncludeRecordCounts -DnsIncludeSystemZones -DnsZoneOutputRoot <path>"
    Write-Both "    -recentchanges checks for newly created users and groups (last 30 days)"
    Write-Both "    -spn checks for kerberoastable high value accounts"
    Write-Both "    -asrep checks for accounts with kerberos pre-auth"
    Write-Both "    -acl checks for dangerous ACL permissions on Computers, Users and Groups"
    Write-Both "    -ADCS checks for ESC1,2,3,4 and 8"
    Write-Both "    -ldapsecurity checks for multiple LDAP issues"
    Write-Both "    -dataextract exports raw AD audit data (users/groups/computers/OUs/GPO reports/OU ACLs/FGPP/trusts) to .\<COMPUTERNAME>\Raw Data\ADExtract"
    Write-Both "    -delegatedpermissions generates an AD delegated permissions report (alias: -delegated-permissions)"
    Write-Both "        Optional: -DelegIncludeSystemTrustees -DelegIncludeDeny -DelegIncludeInherited -DelegServer <dc> -DelegatedOutputRoot <path>"
    Write-Both "    -all runs all checks, e.g. $scriptname -all"
    Write-Both "    -KeepLegacyArtifacts is retained for backward compatibility; raw data and evidence files are preserved in .\\<COMPUTERNAME>\\Raw Data by default"
}
Write-Nessus-Footer

# Sanitize .nessus XML characters in-place (no duplicate file)
$nessusPath = "$outputdir\adaudit.nessus"
if (Test-Path $nessusPath) {
    $nessusContent = Get-Content $nessusPath
    $nessusContent = $nessusContent -Replace "&", "&amp;"
    $nessusContent = $nessusContent -Replace ([char]8220), "&quot;"
    $nessusContent = $nessusContent -Replace ([char]8221), "&quot;"
    $nessusContent = $nessusContent -Replace "`'", "&apos;"
    $nessusContent = $nessusContent -Replace ([char]252), "u"
    $nessusContent | Out-File $nessusPath -Force
}

$endtime = Get-Date
Write-Both "[*] Script end time $endtime"


$oldEap = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
try {

function Invoke-ManagementReport {
    [CmdletBinding()]
    param(
        [string]$InputRoot,
        [string]$OutputHtml,
        [string]$OutputTxt,
        [string]$AuditHtml,
        [int]$TopFindings = 10
    )

    if (-not $InputRoot -or $InputRoot.Trim().Length -eq 0) {
        $InputRoot = Join-Path (Get-Location) $env:COMPUTERNAME
    }
    if (-not (Test-Path -Path $InputRoot)) {
        throw "InputRoot '$InputRoot' does not exist."
    }

    if (-not $OutputHtml) { $OutputHtml = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'Risk-Report.html' }
    if (-not $AuditHtml)  { $AuditHtml  = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'ADAudit-Results.html' }
    $outputHtmlDir = Split-Path -Path $OutputHtml -Parent
    if ($outputHtmlDir -and -not (Test-Path -LiteralPath $outputHtmlDir)) { New-Item -ItemType Directory -Path $outputHtmlDir -Force | Out-Null }
    $auditHtmlDir = Split-Path -Path $AuditHtml -Parent
    if ($auditHtmlDir -and -not (Test-Path -LiteralPath $auditHtmlDir)) { New-Item -ItemType Directory -Path $auditHtmlDir -Force | Out-Null }
    if (-not $PSBoundParameters.ContainsKey('OutputTxt') -or [string]::IsNullOrWhiteSpace($OutputTxt)) { $OutputTxt = $null }

    $ErrorActionPreference = 'Stop'

    # ---------------------------
    # Tunable baselines
    # ---------------------------
    $Baselines = @{
        DisabledUserAccounts = 20   # policy baseline for disabled user accounts (review/cleanup cadence)
    }

    # ---------------------------
    # Encoding helpers
    # ---------------------------
    function HtmlEncode([string]$s) {
        if ($null -eq $s) { return '' }
        if ('System.Web.HttpUtility' -as [type]) { return [System.Web.HttpUtility]::HtmlEncode($s) }
        return [System.Net.WebUtility]::HtmlEncode($s)
    }
    function HtmlAttrEncode([string]$s) {
        if ($null -eq $s) { return '' }
        if ('System.Web.HttpUtility' -as [type]) { return [System.Web.HttpUtility]::HtmlAttributeEncode($s) }
        return ([System.Net.WebUtility]::HtmlEncode($s) -replace '"','&quot;')
    }

    function Get-RelPath([string]$path) {
        if (-not $path) { return '' }
        try {
            $abs = [System.IO.Path]::GetFullPath($path)
            $rootAbs = [System.IO.Path]::GetFullPath($InputRoot)
            if ($abs.StartsWith($rootAbs, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $abs.Substring($rootAbs.Length).TrimStart('\','/')
            }
        } catch { }
        return [System.IO.Path]::GetFileName($path)
    }

    function Resolve-AuditArtifactPath([string]$Path) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

        $rawDataRoot   = Get-RawDataDir -BaseRoot $InputRoot
        $rawSourceRoot = Get-RawSourceDataDir -BaseRoot $InputRoot

        $candidateList = New-Object 'System.Collections.Generic.List[string]'
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

        function Add-Candidate([string]$Value) {
            if ([string]::IsNullOrWhiteSpace($Value)) { return }
            if ($seen.Add($Value)) { $candidateList.Add($Value) | Out-Null }
        }

        $isRooted = $false
        try { $isRooted = [System.IO.Path]::IsPathRooted($Path) } catch { $isRooted = $false }

        if ($isRooted) {
            Add-Candidate $Path
            try {
                $full = [System.IO.Path]::GetFullPath($Path)
                Add-Candidate $full

                $rootAbs = [System.IO.Path]::GetFullPath($InputRoot)
                if ($full.StartsWith($rootAbs, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $relative = $full.Substring($rootAbs.Length).TrimStart('\','/')
                    if (-not [string]::IsNullOrWhiteSpace($relative)) {
                        Add-Candidate (Join-Path $rawSourceRoot $relative)
                        Add-Candidate (Join-Path $rawDataRoot $relative)
                    }
                }
            } catch { }
        }
        else {
            Add-Candidate (Join-Path $InputRoot $Path)
            Add-Candidate (Join-Path $rawSourceRoot $Path)
            Add-Candidate (Join-Path $rawDataRoot $Path)
        }

        foreach ($candidate in $candidateList) {
            try {
                if (Test-Path -LiteralPath $candidate) {
                    return [System.IO.Path]::GetFullPath($candidate)
                }
            } catch { }
        }

        try { return [System.IO.Path]::GetFullPath($Path) } catch { return $Path }
    }

    # Extract only DOMAIN\account lines from pq_*.txt files (filters out headers/footers)
    function Get-PqAccountLines([string]$path) {
        $path = Resolve-AuditArtifactPath $path
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }
        try {
            return @((Get-Content -LiteralPath $path -ErrorAction Stop) |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -match '^[^=\-\s].*\\' })
        } catch { return @() }
    }

    function Get-NonHeaderLines([string]$path) {
        $path = Resolve-AuditArtifactPath $path
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }
        try {
            return (Get-Content -LiteralPath $path -ErrorAction Stop) |
                ForEach-Object {
                    $line = ([string]$_).Trim()
                    if ($line.StartsWith('@') -and $line.Length -gt 1) {
                        $line = $line.Substring(1).Trim()
                    }
                    $line
                } |
                Where-Object { $_ -and $_.Trim().Length -gt 0 }
        } catch { return @() }
    }

    function Get-CsvSafe([string]$path) {
        $path = Resolve-AuditArtifactPath $path
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }
        try { return Import-Csv -LiteralPath $path -ErrorAction Stop } catch { return @() }
    }

    # ---------------------------
    # Parsers
    # ---------------------------

    # accounts_disabled.txt parsing
    function Get-DisabledAccounts {
        param([string]$Path)

        $Path = Resolve-AuditArtifactPath $Path
        if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }

        $lines = @()
        try { $lines = Get-Content -LiteralPath $Path -ErrorAction Stop } catch { return @() }
        if (-not $lines -or $lines.Count -eq 0) { return @() }

        $results = New-Object 'System.Collections.Generic.List[object]'
        foreach ($ln in $lines) {
            if ($null -eq $ln) { continue }
            $t = ($ln -as [string]).Trim()
            if ($t.Length -eq 0) { continue }

            # skip headers/metadata
            if ($t -match '^[\s]*@') { continue }
            if ($t -match '^\s*Disabled user accounts\s*$') { continue }

            # Example:
            # Account $RON000-1LMLA83QPUGL (Exchange Online-ApplicationAccount) is disabled
            if ($t -match '^\s*Account\s+(?<Sam>\S+)\s+\((?<Display>.+?)\)\s+is\s+disabled\s*$') {
                $results.Add([PSCustomObject]@{
                    SamAccountName = $matches['Sam'].Trim()
                    DisplayName    = $matches['Display'].Trim()
                    Line           = $t
                }) | Out-Null
                continue
            }

            # fallback
            if ($t -match '^\s*Account\s+(?<Sam>\S+)\s+is\s+disabled\s*$') {
                $results.Add([PSCustomObject]@{
                    SamAccountName = $matches['Sam'].Trim()
                    DisplayName    = ''
                    Line           = $t
                }) | Out-Null
            }
        }

        return $results.ToArray()
    }

    # ASREP.txt parsing
    function Get-AsrepAccounts([string]$path) {
        $path = Resolve-AuditArtifactPath $path
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }

        $lines = @()
        try { $lines = Get-Content -LiteralPath $path -ErrorAction Stop } catch { return @() }

        $results = New-Object 'System.Collections.Generic.List[object]'

        foreach ($ln in $lines) {
            if (-not $ln) { continue }

            $t = $ln.TrimEnd()
            if ($t.Trim().Length -eq 0) { continue }

            if ($t -notmatch '^[^\s]') { continue }
            if ($t -match '^Accounts\s*\(') { continue }

            if ($t -match '^(?<Display>.+?)\s+\((?<Sam>[A-Za-z0-9._-]{1,64})\)\s*$') {
                $results.Add([PSCustomObject]@{
                    DisplayName    = $matches['Display'].Trim()
                    SamAccountName = $matches['Sam'].Trim()
                    Line           = $t
                }) | Out-Null
            }
        }

        return $results.ToArray()
    }

    # password_quality.txt parsing (reversible encryption section)
    function Get-ReversibleEncryptionAccounts {
        param([string]$Path)

        $Path = Resolve-AuditArtifactPath $Path
        if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return @() }

        $lines = @()
        try { $lines = Get-Content -LiteralPath $Path -ErrorAction Stop } catch { return @() }
        if (-not $lines -or $lines.Count -eq 0) { return @() }

        $startIdx = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if (($lines[$i] -as [string]) -match '^\s*Passwords of these accounts are stored using reversible encryption:\s*$') {
                $startIdx = $i + 1
                break
            }
        }
        if ($startIdx -lt 0 -or $startIdx -ge $lines.Count) { return @() }

        $results = New-Object 'System.Collections.Generic.List[string]'

        for ($j = $startIdx; $j -lt $lines.Count; $j++) {
            $ln = $lines[$j]
            if ($null -eq $ln) { continue }

            if ($ln -match '^\s*LM hashes of passwords of these accounts are present:\s*$') { break }

            $t = ($ln -as [string]).Trim()
            if ($t.Length -eq 0) { continue }
            if ($t -match ':\s*$') { continue }

            $results.Add($t) | Out-Null
        }

        return $results.ToArray()
    }

    # ---------------------------
    # Findings framework
    # ---------------------------
    $Findings = New-Object System.Collections.Generic.List[object]

    $SeverityScore = @{
        Critical    = 12
        High        = 8
        Medium      = 5
        Low         = 2
        Information = 0
    }

    function Normalize-Severity([string]$sev) {
        $s = ($sev -as [string])
        if (-not $s) { return 'Low' }
        $s = $s.Trim()
        switch -Regex ($s.ToUpperInvariant()) {
            '^CRIT'  { return 'Critical' }
            '^HIGH'  { return 'High' }
            '^MED'   { return 'Medium' }
            '^LOW'   { return 'Low' }
            '^INFO'  { return 'Information' }
            default  { return 'Low' }
        }
    }

    function Get-CanonicalTitle([string]$Title) {
        $t = ($Title -as [string])
        if (-not $t) { return '' }
        $t = $t.Trim()

        switch -Regex ($t) {
            '^Enabled accounts inactive >\s*180\s*days$' { return 'Observed inactive enabled accounts (>180 days)' }
            '^Inactive enabled accounts$'                { return 'Observed inactive enabled accounts (>180 days)' }

            '^Accounts with password set to not expire$' { return 'Enabled user accounts with PasswordNeverExpires' }
            '^Passwords set to never expire$'            { return 'Enabled user accounts with PasswordNeverExpires' }

            default { return $t }
        }
    }

    function Add-Finding {
        param(
            [string]$Severity,
            [string]$Title,
            [string]$Evidence,
            [string]$Path,
            [int]$ScoreOverride
        )

        $Severity = Normalize-Severity $Severity
        $Title = Get-CanonicalTitle $Title

        $score = [int]$SeverityScore[$Severity]
        if ($PSBoundParameters.ContainsKey('ScoreOverride')) {
            $score = [int]$ScoreOverride
        }

        $resolvedPath = $null
        if (-not [string]::IsNullOrWhiteSpace($Path)) {
            try { $resolvedPath = [System.IO.Path]::GetFullPath($Path) } catch { $resolvedPath = $Path }
        }

        $Findings.Add([PSCustomObject]@{
            Severity = $Severity
            Title    = $Title
            Evidence = $Evidence
            Link     = $resolvedPath
            Score    = $score
        }) | Out-Null
    }

    $dedup = New-Object 'System.Collections.Generic.HashSet[string]'
    function Add-FindingOnce {
        param(
            [string]$Severity,
            [string]$Title,
            [string]$Evidence,
            [string]$Path,
            [int]$ScoreOverride
        )
        $Severity = Normalize-Severity $Severity
        $Title = Get-CanonicalTitle $Title

        $pathKey = $null
        if (-not [string]::IsNullOrWhiteSpace($Path)) {
            try { $pathKey = [System.IO.Path]::GetFullPath($Path) } catch { $pathKey = $Path }
        }
        $k = '{0}|{1}|{2}' -f $Severity, (($Title -as [string]).Trim()), $pathKey
        if ($dedup.Add($k)) {
            Add-Finding -Severity $Severity -Title $Title -Evidence $Evidence -Path $Path -ScoreOverride $ScoreOverride
        }
    }

    function Score-Scaled([string]$Severity,[double]$Count,[int]$maxScale = 50) {
        $Severity = Normalize-Severity $Severity
        $base  = [int]$SeverityScore[$Severity]
        $c     = [Math]::Max([double]$Count, 0)
        $scale = [Math]::Min([Math]::Floor($c / 10), [Math]::Floor($maxScale / 10))
        return ($base + [int]$scale)
    }

    function Score-OverBaselineLog {
        param(
            [string]$Severity,
            [double]$Observed,
            [double]$Baseline,
            [int]$MaxAdd = 18,
            [double]$K = 5
        )

        $Severity = Normalize-Severity $Severity
        $base = [int]$SeverityScore[$Severity]

        if ($Baseline -le 0) { return $base }
        if ($Observed -le $Baseline) { return $base }

        $ratio = $Observed / $Baseline
        $add = [Math]::Ceiling($K * ([Math]::Log($ratio) / [Math]::Log(2)))
        $add = [Math]::Min([int]$add, [int]$MaxAdd)
        return ($base + [int]$add)
    }

    function Score-BaselineZeroLog {
        param(
            [string]$Severity,
            [double]$Observed,
            [int]$MaxAdd = 34,
            [double]$K = 10
        )

        $Severity = Normalize-Severity $Severity
        $base = [int]$SeverityScore[$Severity]

        $obs = [Math]::Max([double]$Observed, 0)
        if ($obs -le 0) { return $base }

        $add = [Math]::Ceiling($K * ([Math]::Log($obs + 1) / [Math]::Log(2)))
        $add = [Math]::Min([int]$add, [int]$MaxAdd)
        return ($base + [int]$add)
    }

    function DisplayOrDash($v) {
        if ($null -eq $v) { return '&mdash;' }
        $s = [string]$v
        if ([string]::IsNullOrWhiteSpace($s)) { return '&mdash;' }
        return (HtmlEncode $s)
    }

    function Get-SeverityRank([string]$Severity) {
        switch (Normalize-Severity $Severity) {
            'Critical'    { return 5 }
            'High'        { return 4 }
            'Medium'      { return 3 }
            'Low'         { return 2 }
            'Information' { return 1 }
            default       { return 0 }
        }
    }

    function New-Slug([string]$Value) {
        $slug = (($Value -as [string]) -replace '[^A-Za-z0-9]+','-').Trim('-').ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($slug)) { return 'finding' }
        return $slug
    }

    function New-FindingAnchor([object]$Finding) {
        return ('finding-' + (New-Slug ('{0}-{1}' -f $Finding.Title, $Finding.Link)))
    }

    function Get-FindingCategory([string]$Title) {
        switch -Regex ($Title) {
            'Domain Admins|Enterprise Admins|Schema Admins|Administrators|Operators|privileged|overlap|Delegated permissions' { return 'Privileged access' }
            'password|Password|KRBTGT|Kerberos|AS-REP|SPN|reversible|weak.*encryption|LM hashes|no password|dictionary|breach|DES-only|AES keys'  { return 'Authentication and password security' }
            'delegation|gMSA|service account'                                                         { return 'Delegation and service accounts' }
            'LAPS|LDAP|NTLM|cipher|SMB signing'                                                     { return 'Identity hardening' }
            'DNS'                                                                                    { return 'DNS security' }
            'computer|MachineAccountQuota'                                                           { return 'Computer hygiene' }
            'Print Spooler|tombstone'                                                                { return 'DC hardening' }
            'disabled|inactive'                                                                      { return 'Account hygiene' }
            'GPO|Group Policy'                                                                       { return 'Group policy' }
            'ACL'                                                                                    { return 'Access control' }
            default                                                                                  { return 'General' }
        }
    }

    function Get-FindingWhyItMatters([string]$Title) {
        switch -Regex ($Title) {
            'Duplicate passwords' {
                return 'Password reuse across privileged or service accounts can materially reduce the effort required to expand access after a single compromise.'
            }
            'KRBTGT password age' {
                return 'A stale KRBTGT password extends the lifetime of forged Kerberos tickets and weakens incident response after domain compromise.'
            }
            'AS-REP roastable|without Kerberos pre-auth' {
                return 'Accounts without Kerberos pre-auth can be targeted offline, allowing attackers to attempt password cracking without interacting further with the domain.'
            }
            'Kerberoastable SPNs|SPN' {
                return 'Service accounts with SPNs can be targeted for offline ticket cracking, especially when passwords are static, old, or weak.'
            }
            'reversible encryption' {
                return 'Reversible password storage materially weakens credential protection and should only exist for rare legacy compatibility requirements.'
            }
            'privileged group|Domain Admins|Enterprise Admins|Schema Admins|Administrators|Operators|overlap' {
                return 'Excessive or overlapping privilege expands blast radius and increases the probability of privileged misuse or lateral movement.'
            }
            'inactive|disabled stale|Inactive computer' {
                return 'Inactive objects increase attack surface, complicate review, and often indicate weak lifecycle controls.'
            }
            'PasswordNeverExpires|never expire' {
                return 'Passwords that never expire are frequently associated with unmanaged service accounts and create long-lived credential exposure.'
            }
            'MachineAccountQuota' {
                return 'Allowing standard users to join computers can be abused to create attack paths and should be tightly controlled.'
            }
            'weak Kerberos ciphers' {
                return 'Legacy Kerberos ciphers reduce cryptographic strength and should be retired in favor of AES-only configurations where possible.'
            }
            'LAPS' {
                return 'Overly broad local administrator password access or expired LAPS passwords weakens workstation and server credential hygiene.'
            }
            'LDAP security|NTLM' {
                return 'Weak LDAP or NTLM settings enable downgrade and relay scenarios and indicate incomplete hardening of identity protocols.'
            }
            'DNS zones allowing insecure updates' {
                return 'Insecure dynamic updates allow unauthenticated or weakly authenticated name changes and can enable spoofing or persistence.'
            }
            'unconstrained.*delegation' {
                return 'Accounts with unconstrained delegation can impersonate any user who authenticates to them, enabling credential theft and lateral movement across the domain.'
            }
            'gMSA|service account.*not.*gMSA' {
                return 'Service accounts using static passwords are vulnerable to credential theft and Kerberoasting. gMSA provides automatic password rotation managed by AD.'
            }
            'tombstone lifetime' {
                return 'A short tombstone lifetime reduces the AD Recycle Bin recovery window and can cause lingering objects during extended replication outages.'
            }
            'Print Spooler' {
                return 'The Print Spooler service on domain controllers exposes them to PrintNightmare and authentication coercion attacks that can lead to domain compromise.'
            }
            'SMB signing' {
                return 'Without required SMB signing, attackers can perform NTLM relay attacks to authenticate as the domain controller and escalate privileges.'
            }
            'weak.*encryption|legacy.*encryption' {
                return 'Accounts still configured with DES or RC4 Kerberos encryption are vulnerable to offline credential attacks. After an in-place AD upgrade the domain supports AES, but accounts whose passwords have not been reset continue to negotiate with the weaker ciphers stamped at their last password change.'
            }
            'LM hashes' {
                return 'LM hashes use weak DES-based encryption and can be cracked in seconds. Their presence indicates legacy password storage that should have been eliminated.'
            }
            'no password set' {
                return 'Accounts without passwords can be accessed without any authentication, providing trivial entry points for attackers.'
            }
            'dictionary|breach' {
                return 'Passwords found in known dictionaries or breach lists can be cracked instantly using widely available tools and wordlists.'
            }
            'default.*computer.*password|computer.*default' {
                return 'Computer accounts with default passwords have not completed domain join properly or have been reset, making them vulnerable to impersonation.'
            }
            'AES keys missing' {
                return 'Accounts missing Kerberos AES keys will fall back to weaker encryption (RC4/DES) for Kerberos authentication, increasing vulnerability to offline attacks.'
            }
            'DES-only' {
                return 'DES encryption is cryptographically broken and can be cracked in real-time. Accounts restricted to DES-only are critically vulnerable.'
            }
            'admin.*delegat|delegat.*admin' {
                return 'Administrative accounts allowed for delegation can be impersonated by services, creating privilege escalation paths if those services are compromised.'
            }
            'not required to have a password|password not required' {
                return 'The PASSWD_NOTREQD flag allows accounts to exist with empty passwords, bypassing the domain password policy entirely.'
            }
            default {
                return 'This finding indicates a deviation from common Active Directory hardening expectations and should be reviewed in context.'
            }
        }
    }

    function Get-FindingRecommendation([string]$Title) {
        switch -Regex ($Title) {
            'Duplicate passwords' {
                return 'Reset affected passwords, eliminate password reuse, prefer gMSA where applicable, and verify privileged accounts follow a separate credential standard.'
            }
            'KRBTGT password age' {
                return 'Plan and execute a controlled double KRBTGT rotation, validate ticket lifetimes, and document the ongoing rotation cadence.'
            }
            'AS-REP roastable|without Kerberos pre-auth' {
                return 'Re-enable Kerberos pre-auth unless a documented exception exists, and review service account usage and password quality.'
            }
            'Kerberoastable SPNs|SPN' {
                return 'Review each service account, prefer gMSA, require strong unique passwords, and enforce modern Kerberos encryption types.'
            }
            'reversible encryption' {
                return 'Disable reversible password storage, identify the legacy dependency, and reset affected account passwords after policy change.'
            }
            'privileged group|Domain Admins|Enterprise Admins|Schema Admins|Administrators|Operators|overlap' {
                return 'Reduce standing privilege, separate admin tiers, remove stale memberships, and require approval and periodic recertification for privileged access.'
            }
            'inactive|disabled stale|Inactive computer' {
                return 'Review ownership, disable or remove stale accounts and computer objects, and enforce a documented lifecycle and exception process.'
            }
            'PasswordNeverExpires|never expire' {
                return 'Minimize PasswordNeverExpires usage, migrate eligible services to gMSA, and maintain approved exceptions with regular review.'
            }
            'MachineAccountQuota' {
                return 'Set MachineAccountQuota to 0 unless there is a defined business need, and delegate computer join rights only to approved processes or groups.'
            }
            'weak Kerberos ciphers' {
                return 'Remove legacy cipher support where supported, validate application compatibility, and standardize on stronger Kerberos encryption.'
            }
            'LAPS' {
                return 'Restrict password readers to the minimum required set, rotate expired passwords, and validate LAPS policy application across managed systems.'
            }
            'LDAP security|NTLM' {
                return 'Harden LDAP signing and channel binding, reduce NTLM usage, and validate compatibility before enforcing stricter settings.'
            }
            'DNS zones allowing insecure updates' {
                return 'Change affected zones to secure-only dynamic updates and verify DHCP/DNS integration and update ownership.'
            }
            'unconstrained.*delegation' {
                return 'Remove unconstrained delegation, migrate to constrained delegation or resource-based constrained delegation, and audit all delegation settings regularly.'
            }
            'gMSA|service account.*not.*gMSA' {
                return 'Migrate eligible service accounts to Group Managed Service Accounts (gMSA) for automatic password rotation. Document exceptions for accounts that cannot be migrated.'
            }
            'tombstone lifetime' {
                return 'Set the tombstone lifetime to at least 180 days via ADSI Edit (CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration) to ensure adequate Recycle Bin retention.'
            }
            'Print Spooler' {
                return 'Disable the Print Spooler service on all domain controllers. DCs should not serve as print servers. Use Group Policy to enforce: Set Spooler service to Disabled.'
            }
            'SMB signing' {
                return 'Enable SMB signing on all DCs via Group Policy: "Microsoft network server: Digitally sign communications (always)" = Enabled. Validate client compatibility before enforcement.'
            }
            'weak.*encryption|legacy.*encryption' {
                return 'Force a password change for affected user accounts. For computer accounts use Reset-ComputerMachinePassword or rejoin the domain. For service accounts rotate the password or migrate to gMSA. Set msDS-SupportedEncryptionTypes to 24 (AES128+AES256) on all accounts via Group Policy or directly: Set-ADUser <account> -Replace @{''msDS-SupportedEncryptionTypes''=24}. Verify with Get-ADUser <account> -Properties msDS-SupportedEncryptionTypes.'
            }
            'LM hashes' {
                return 'Disable LM hash storage via Group Policy (Network security: Do not store LAN Manager hash value on next password change = Enabled). Force password changes for all affected accounts to eliminate stored LM hashes.'
            }
            'no password set' {
                return 'Set passwords on all affected accounts immediately. Review why these accounts were created without passwords and enforce the domain password policy.'
            }
            'dictionary|breach' {
                return 'Force immediate password changes for all affected accounts. Implement Azure AD Password Protection or a third-party banned-password filter to prevent dictionary passwords from being set.'
            }
            'default.*computer.*password|computer.*default' {
                return 'Rejoin affected computers to the domain to trigger machine account password rotation. Investigate why the machine account password was not updated during the join process.'
            }
            'AES keys missing' {
                return 'Force a password change or reset for affected accounts. The new password hash will include AES keys. For computer accounts use Reset-ComputerMachinePassword. For service accounts consider migrating to gMSA.'
            }
            'DES-only' {
                return 'Remove the DES restriction from affected accounts: Set-ADUser <account> -Replace @{''msDS-SupportedEncryptionTypes''=24}. Clear the "Use Kerberos DES encryption types for this account" checkbox in account properties. Force a password change after the update.'
            }
            'admin.*delegat|delegat.*admin' {
                return 'Mark sensitive administrative accounts as "Account is sensitive and cannot be delegated" in account properties, or add them to the Protected Users group. Review which services need delegation and use constrained delegation with specific target SPNs.'
            }
            'not required to have a password|password not required' {
                return 'Clear the PASSWD_NOTREQD flag on affected accounts: Set-ADUser <account> -PasswordNotRequired $false. Then force a password change to ensure a proper password is set. Review why the flag was enabled.'
            }
            default {
                return 'Review the affected configuration, identify the owning team, and document a remediation plan with validation after implementation.'
            }
        }
    }

    function Get-FindingSourceLabel([string]$Path) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return 'Embedded evidence' }
        try {
            return [System.IO.Path]::GetFileName($Path)
        } catch {
            return $Path
        }
    }

    function Get-EvidencePreviewLines([string]$Path, [int]$MaxLines = 10) {
        $preview = New-Object 'System.Collections.Generic.List[string]'
        $Path = Resolve-AuditArtifactPath $Path
        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return @() }

        $ext = ''
        try { $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant() } catch { }

        switch ($ext) {
            '.csv' {
                try {
                    $rows = Import-Csv -LiteralPath $Path -ErrorAction Stop | Select-Object -First $MaxLines
                    foreach ($row in $rows) {
                        $parts = @()
                        foreach ($prop in ($row.PSObject.Properties | Where-Object { $_.Value -ne $null -and ([string]$_.Value).Trim().Length -gt 0 } | Select-Object -First 4)) {
                            $parts += ('{0}={1}' -f $prop.Name, ([string]$prop.Value))
                        }
                        if ($parts.Count -gt 0) {
                            $preview.Add(($parts -join ' | ')) | Out-Null
                        }
                    }
                } catch { }
            }
            '.txt' {
                try {
                    $lines = Get-Content -LiteralPath $Path -ErrorAction Stop |
                        Where-Object { $_ -and $_.Trim().Length -gt 0 -and ($_ -notmatch '^[\s]*@') } |
                        Select-Object -First $MaxLines
                    foreach ($line in $lines) {
                        $preview.Add(([string]$line).Trim()) | Out-Null
                    }
                } catch { }
            }
            '.html' {
                $preview.Add('Detailed HTML companion report generated for this check.') | Out-Null
            }
            default {
                $preview.Add(('Source: {0}' -f (Get-FindingSourceLabel $Path))) | Out-Null
            }
        }

        return $preview.ToArray()
    }

    function Get-CompanionHtmlReports([string]$Root, [string[]]$Exclude = @()) {
        $items = New-Object 'System.Collections.Generic.List[object]'
        $seen  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

        $excludeMap = @{}
        foreach ($p in $Exclude) {
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                try { $excludeMap[[System.IO.Path]::GetFullPath($p)] = $true } catch { }
            }
        }

        $candidates = New-Object 'System.Collections.Generic.List[System.IO.FileInfo]'

        $htmlRoot = Get-HtmlReportsDir -BaseRoot $Root
        if (Test-Path -LiteralPath $htmlRoot) {
            foreach ($f in (Get-ChildItem -Path $htmlRoot -File -Filter '*.html' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.source\.html$' })) {
                $candidates.Add($f) | Out-Null
            }
        }

        foreach ($f in (Get-ChildItem -Path $Root -File -Filter '*.html' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.source\.html$' })) {
            $candidates.Add($f) | Out-Null
        }

        $delegIndex = Get-ChildItem -Path (Join-Path (Get-RawDataDir -BaseRoot $Root) 'DelegatedPermissions') -Recurse -File -Filter 'index.html' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($delegIndex) { $candidates.Add($delegIndex) | Out-Null }

        $dnsAudit = Get-ChildItem -Path $Root -Recurse -File -Filter 'DNSAudit-*.html' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '\.source\.html$' } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($dnsAudit) { $candidates.Add($dnsAudit) | Out-Null }

        $dnsReco = Get-ChildItem -Path $Root -Recurse -File -Filter 'DNS-Recommendations-*.html' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '\.source\.html$' } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($dnsReco) { $candidates.Add($dnsReco) | Out-Null }

        foreach ($file in $candidates) {
            if (-not $file) { continue }

            $full = $null
            try { $full = [System.IO.Path]::GetFullPath($file.FullName) } catch { $full = $file.FullName }
            if ($excludeMap.ContainsKey($full)) { continue }
            if (-not $seen.Add($full)) { continue }

            $title = switch -Regex ($file.Name) {
                '^GPOReport\.html$'                      { 'Group Policy report' ; break }
                '^overlapping_group_memberships\.html$'  { 'Overlapping group membership report' ; break }
                '^multiple_nested_paths\.html$'          { 'Multiple nested paths report' ; break }
                '^dangerousACLs\.html$'                 { 'Dangerous ACL report' ; break }
                '^ad_high_risk_baseline_index\.html$'   { 'High-risk baseline report' ; break }
                '^index\.html$'                         { 'Delegated permissions report' ; break }
                '^DNSAudit-.*\.html$'                   { 'DNS audit report' ; break }
                '^DNS-Recommendations-.*\.html$'        { 'DNS recommendations report' ; break }
                default                                 { ($file.BaseName -replace '[-_]+',' ') }
            }

            $items.Add([pscustomobject]@{
                Title    = $title
                FullPath = $full
            }) | Out-Null
        }

        return $items.ToArray()
    }

    function Ensure-DirectoryPath([string]$Path) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return }
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }

    function Get-NormalizedAbsolutePath([string]$Path) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
        try { return [System.IO.Path]::GetFullPath($Path) } catch { return $Path }
    }

    function Get-RelativeHref([string]$FromFile, [string]$ToPath) {
        if ([string]::IsNullOrWhiteSpace($ToPath)) { return '' }

        try {
            $fromDir = Split-Path -Path $FromFile -Parent
            if ([string]::IsNullOrWhiteSpace($fromDir)) { $fromDir = Split-Path -Path (Get-NormalizedAbsolutePath $FromFile) -Parent }
            $fromAbs = [System.IO.Path]::GetFullPath($fromDir)
            $targetAbs = [System.IO.Path]::GetFullPath($ToPath)

            $baseUri = New-Object System.Uri(($fromAbs.TrimEnd('\') + '\'))
            $targetUri = New-Object System.Uri($targetAbs)
            return ([System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($targetUri).ToString()) -replace '\\','/')
        } catch {
            return [System.IO.Path]::GetFileName($ToPath)
        }
    }

    function Format-PreviewValue($Value) {
        if ($null -eq $Value) { return '' }
        if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
        return [string]$Value
    }

    function New-PreviewTableHtml {
        param(
            [object[]]$Rows,
            [string[]]$Columns,
            [int]$MaxRows = 250
        )

        if (-not $Rows -or $Rows.Count -eq 0) {
            return "<div class='result-empty'>No detailed rows were available for this finding.</div>"
        }

        $displayRows = @($Rows | Select-Object -First $MaxRows)
        $availableColumns = @()
        try { $availableColumns = @($displayRows[0].PSObject.Properties.Name) } catch { $availableColumns = @() }

        if (-not $Columns -or $Columns.Count -eq 0) {
            $Columns = @($availableColumns | Select-Object -First 8)
        } else {
            $Columns = @($Columns | Where-Object { $_ -in $availableColumns })
            if ($Columns.Count -eq 0) {
                $Columns = @($availableColumns | Select-Object -First 8)
            }
        }

        if (-not $Columns -or $Columns.Count -eq 0) {
            return "<div class='result-empty'>Detailed rows were detected, but no displayable columns were available.</div>"
        }

        $headHtml = ($Columns | ForEach-Object { "<th>$(HtmlEncode ([string]$_))</th>" }) -join ''
        $rowHtml = New-Object 'System.Collections.Generic.List[string]'

        foreach ($row in $displayRows) {
            $cellHtml = New-Object 'System.Collections.Generic.List[string]'
            foreach ($col in $Columns) {
                $val = $null
                try {
                    if ($row.PSObject.Properties[$col]) {
                        $val = $row.PSObject.Properties[$col].Value
                    } else {
                        $val = $row.$col
                    }
                } catch { $val = $null }

                $cellHtml.Add("<td>$(HtmlEncode (Format-PreviewValue $val))</td>") | Out-Null
            }
            $rowHtml.Add("<tr>$($cellHtml -join '')</tr>") | Out-Null
        }

        $note = if ($Rows.Count -gt $displayRows.Count) {
            "Showing the first $($displayRows.Count) of $($Rows.Count) rows. Use the download link for the complete result."
        } else {
            "Rows: $($Rows.Count)"
        }

        return @"
<div class="result-note">$(HtmlEncode $note)</div>
<div class="result-scroll">
  <table class="result-table">
    <thead>
      <tr>$headHtml</tr>
    </thead>
    <tbody>
      $($rowHtml -join "`n")
    </tbody>
  </table>
</div>
"@
    }

    function New-PreviewTextHtml {
        param(
            [string[]]$Lines,
            [int]$MaxLines = 300
        )

        if (-not $Lines -or $Lines.Count -eq 0) {
            return "<div class='result-empty'>No detailed lines were available for this finding.</div>"
        }

        $displayLines = @($Lines | Select-Object -First $MaxLines)
        $note = if ($Lines.Count -gt $displayLines.Count) {
            "Showing the first $($displayLines.Count) of $($Lines.Count) lines. Use the download link for the complete result."
        } else {
            "Lines: $($Lines.Count)"
        }

        $content = HtmlEncode (($displayLines | ForEach-Object { [string]$_ }) -join "`r`n")
        return @"
<div class="result-note">$(HtmlEncode $note)</div>
<div class="result-scroll">
  <pre class="result-pre">$content</pre>
</div>
"@
    }

    function Get-CsvDownloadName {
        param(
            [string]$Name,
            [string]$Fallback = 'result.csv'
        )

        if ([string]::IsNullOrWhiteSpace($Name)) { return $Fallback }

        $base = ''
        try { $base = [System.IO.Path]::GetFileNameWithoutExtension($Name) } catch { $base = $Name }
        if ([string]::IsNullOrWhiteSpace($base)) { $base = 'result' }
        return ('{0}.csv' -f $base)
    }

    function Convert-LinesToTableRows {
        param(
            [string[]]$Lines,
            [string]$PrimaryColumn = 'Result'
        )

        $rows = New-Object 'System.Collections.Generic.List[object]'
        if (-not $Lines) { return @() }

        $lineNumber = 1
        foreach ($line in $Lines) {
            if ($null -eq $line) { continue }
            $text = ([string]$line).Trim()
            if ($text.Length -eq 0) { continue }

            $rows.Add([pscustomobject]@{
                Line = $lineNumber
                $PrimaryColumn = $text
            }) | Out-Null

            $lineNumber++
        }

        return $rows.ToArray()
    }

    function Get-TextFindingTableData {
        param(
            [object]$Finding,
            [object]$Definition,
            [string]$SourcePath
        )

        $SourcePath = Resolve-AuditArtifactPath $SourcePath
        $title = Get-CanonicalTitle $Finding.Title
        $rows = @()
        $columns = @()
        $lines = if ($SourcePath) { @(Get-NonHeaderLines $SourcePath) } else { @() }

        switch -Regex ($title) {
            '^Inactive computer accounts \(>90 days\)$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                foreach ($line in $lines) {
                    if ($line -match '^Computer\s+(?<Name>\S+)\s+\((?<DNSHostName>.*?)\)\s+OS:\s+(?<OperatingSystem>.*?)\s+last logon:\s+(?<LastLogon>.+)$') {
                        $tmp.Add([pscustomobject]@{
                            Name            = $matches['Name'].Trim()
                            DNSHostName     = $matches['DNSHostName'].Trim()
                            OperatingSystem = $matches['OperatingSystem'].Trim()
                            LastLogon       = $matches['LastLogon'].Trim()
                        }) | Out-Null
                    }
                }
                $rows = $tmp.ToArray()
                $columns = @('Name','DNSHostName','OperatingSystem','LastLogon')
                break
            }

            '^Domain controllers allow weak Kerberos ciphers$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                $current = [ordered]@{}
                foreach ($line in $lines) {
                    $t = ([string]$line).Trim()
                    if ($t -match '^Link:') { continue }

                    if ($t -match '^Decimal Value:\s*(?<Value>.+)$') {
                        $current['DecimalValue'] = $matches['Value'].Trim()
                        continue
                    }
                    if ($t -match '^Hex Value:\s*(?<Value>.+)$') {
                        $current['HexValue'] = $matches['Value'].Trim()
                        continue
                    }
                    if ($t -match '^Supported Encryption Types:\s*(?<Value>.+)$') {
                        $current['SupportedEncryptionTypes'] = $matches['Value'].Trim()
                        if ($current.Contains('DomainController')) {
                            $tmp.Add([pscustomobject]@{
                                DomainController          = [string]$current['DomainController']
                                DecimalValue              = [string]$current['DecimalValue']
                                HexValue                  = [string]$current['HexValue']
                                SupportedEncryptionTypes  = [string]$current['SupportedEncryptionTypes']
                            }) | Out-Null
                        }
                        $current = [ordered]@{}
                        continue
                    }

                    if (-not $t.Contains(':')) {
                        if ($current.Contains('DomainController')) {
                            $tmp.Add([pscustomobject]@{
                                DomainController          = [string]$current['DomainController']
                                DecimalValue              = [string]$current['DecimalValue']
                                HexValue                  = [string]$current['HexValue']
                                SupportedEncryptionTypes  = [string]$current['SupportedEncryptionTypes']
                            }) | Out-Null
                        }
                        $current = [ordered]@{ DomainController = $t }
                    }
                }

                if ($current.Contains('DomainController')) {
                    $tmp.Add([pscustomobject]@{
                        DomainController          = [string]$current['DomainController']
                        DecimalValue              = [string]$current['DecimalValue']
                        HexValue                  = [string]$current['HexValue']
                        SupportedEncryptionTypes  = [string]$current['SupportedEncryptionTypes']
                    }) | Out-Null
                }

                $rows = $tmp.ToArray()
                $columns = @('DomainController','DecimalValue','HexValue','SupportedEncryptionTypes')
                break
            }

            '^Kerberoastable SPNs present \(review high-value service accounts\)$' {
                $rows = @(
                    $lines |
                    Where-Object { $_ -and $_ -notmatch '^No high value kerberoastable user accounts identified\.$' } |
                    ForEach-Object {
                        [pscustomobject]@{ AccountName = ([string]$_).Trim() }
                    }
                )
                $columns = @('AccountName')
                break
            }

            '^LAPS password read rights widely delegated$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                foreach ($line in $lines) {
                    if ($line -match '^(?<Trustee>.+?) can read password attribute of (?<ObjectDN>.+)$') {
                        $tmp.Add([pscustomobject]@{
                            Trustee  = $matches['Trustee'].Trim()
                            ObjectDN = $matches['ObjectDN'].Trim()
                        }) | Out-Null
                    }
                }
                $rows = $tmp.ToArray()
                $columns = @('Trustee','ObjectDN')
                break
            }

            '^LAPS passwords expired$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                foreach ($line in $lines) {
                    if ($line -match '^(?<Computer>.+?) password is expired since (?<Expiration>.+)$') {
                        $tmp.Add([pscustomobject]@{
                            Computer   = $matches['Computer'].Trim()
                            Expiration = $matches['Expiration'].Trim()
                        }) | Out-Null
                    }
                }
                $rows = $tmp.ToArray()
                $columns = @('Computer','Expiration')
                break
            }

            '^LDAP security misconfiguration detected$' {
                $rows = @(Convert-LinesToTableRows -Lines $lines -PrimaryColumn 'Issue')
                $columns = @('Issue')
                break
            }

            '^NTLM restrictions require hardening$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                foreach ($line in $lines) {
                    if ($line -match '^NTLM restricted by GPO \[(?<GPO>.+?)\] with value \[(?<Value>.+?)\]$') {
                        $tmp.Add([pscustomobject]@{
                            Type  = 'RestrictedByGPO'
                            GPO   = $matches['GPO'].Trim()
                            Value = $matches['Value'].Trim()
                        }) | Out-Null
                        continue
                    }
                    if ($line -match '^NTLM audit GPO \[(?<GPO>.+?)\] with value \[(?<Value>.+?)\]$') {
                        $tmp.Add([pscustomobject]@{
                            Type  = 'AuditByGPO'
                            GPO   = $matches['GPO'].Trim()
                            Value = $matches['Value'].Trim()
                        }) | Out-Null
                        continue
                    }
                    if ($line -match '^NTLM auth exceptions (?<Value>.+)$') {
                        $tmp.Add([pscustomobject]@{
                            Type  = 'Exceptions'
                            GPO   = ''
                            Value = $matches['Value'].Trim()
                        }) | Out-Null
                        continue
                    }

                    $tmp.Add([pscustomobject]@{
                        Type  = 'Detail'
                        GPO   = ''
                        Value = ([string]$line).Trim()
                    }) | Out-Null
                }
                $rows = $tmp.ToArray()
                $columns = @('Type','GPO','Value')
                break
            }

            '^DNS zones allowing insecure updates$' {
                $tmp = New-Object 'System.Collections.Generic.List[object]'
                foreach ($line in $lines) {
                    if ($line -match '^The DNS Zone (?<ZoneName>.+?) on DNS server (?<DnsServer>.+?) allows insecure updates \((?<DynamicUpdate>.+)\)$') {
                        $tmp.Add([pscustomobject]@{
                            ZoneName      = $matches['ZoneName'].Trim()
                            DnsServer     = $matches['DnsServer'].Trim()
                            DynamicUpdate = $matches['DynamicUpdate'].Trim()
                        }) | Out-Null
                    }
                }
                $rows = $tmp.ToArray()
                $columns = @('ZoneName','DnsServer','DynamicUpdate')
                break
            }

            '^Delegated permissions risks detected$|^Delegated permissions recommendations available$' {
                $rows = @(Convert-LinesToTableRows -Lines $lines -PrimaryColumn 'Note')
                $columns = @('Note')
                break
            }
        }

        if (-not $rows -or $rows.Count -eq 0) {
            $rows = @(Convert-LinesToTableRows -Lines $lines -PrimaryColumn 'Result')
            $columns = @('Result')
        }

        return [pscustomobject]@{
            Rows    = @($rows)
            Columns = @($columns)
            Lines   = @($lines)
        }
    }

    function Get-FindingArtifactDefinition {
        param([object]$Finding)

        $title = Get-CanonicalTitle $Finding.Title
        $sourceRoot  = Get-RawSourceDataDir -BaseRoot $InputRoot
        $highRiskDir = Resolve-AuditArtifactPath (Join-Path $InputRoot 'HighRisk')
        $htmlRoot = Get-HtmlReportsDir -BaseRoot $InputRoot
        $sourcePath = Resolve-AuditArtifactPath (Get-NormalizedAbsolutePath $Finding.Link)
        $sourceExt = ''
        try { $sourceExt = [System.IO.Path]::GetExtension($sourcePath).ToLowerInvariant() } catch { }

        $definition = [ordered]@{
            Type        = 'auto'
            SourcePath  = $sourcePath
            DownloadName = if ($sourcePath) { [System.IO.Path]::GetFileName($sourcePath) } else { ('{0}.txt' -f (New-Slug $title)) }
            ButtonText  = 'Download Result'
            Columns     = @()
            FilterColumn = $null
            FilterValue  = $null
        }

        switch -Regex ($title) {
            '^Domain Admins group overlap \(extra group memberships\)$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'accounts_domain_admins_group_overlap.csv'
                $definition.DownloadName = 'accounts_domain_admins_group_overlap.csv'
                $definition.Columns = @('SamAccountName','Name','Enabled','ExtraGroupCount','ExtraGroups','Tier1GroupsFound','Flags')
                break
            }
            '^Domain Admins$|^Domain Admins membership size$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'Domain_Admins.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'Domain Admins'
                break
            }
            '^Enterprise Admins$|^Enterprise Admins membership size$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'Enterprise_Admins.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'Enterprise Admins'
                break
            }
            '^Schema Admins$|^Schema Admins membership size$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'Schema_Admins.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'Schema Admins'
                break
            }
            '^BUILTIN\\Administrators$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'BUILTIN_Administrators.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'BUILTIN\Administrators'
                break
            }
            '^BUILTIN\\Account Operators$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'BUILTIN_Account_Operators.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'BUILTIN\Account Operators'
                break
            }
            '^BUILTIN\\Server Operators$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'BUILTIN_Server_Operators.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'BUILTIN\Server Operators'
                break
            }
            '^BUILTIN\\Backup Operators$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'BUILTIN_Backup_Operators.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'BUILTIN\Backup Operators'
                break
            }
            '^BUILTIN\\Print Operators$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'BUILTIN_Print_Operators.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass')
                $definition.FilterColumn = 'Group'
                $definition.FilterValue = 'BUILTIN\Print Operators'
                break
            }
            '^Large privileged group membership$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
                $definition.DownloadName = 'PRIVILEGED_GROUPS.csv'
                $definition.Columns = @('Group','MemberSam','MemberName','ObjectClass','Baseline','Severity')
                break
            }
            '^Observed inactive enabled accounts \(>180 days\)$|^Inactive enabled accounts$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'INACTIVE_ACCOUNTS.csv'
                $definition.DownloadName = 'INACTIVE_ACCOUNTS.csv'
                $definition.Columns = @('SamAccountName','Name','LastLogonDate','WhenCreated','IsPrivileged')
                break
            }
            '^Enabled user accounts with PasswordNeverExpires$|^Accounts with password set to not expire$|^Passwords set to never expire$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'PASSWORD_NEVER_EXPIRES.csv'
                $definition.DownloadName = 'PASSWORD_NEVER_EXPIRES.csv'
                break
            }
            '^Disabled stale accounts$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'DISABLED_STALE.csv'
                $definition.DownloadName = 'DISABLED_STALE.csv'
                break
            }
            '^Duplicate passwords detected$|^Duplicate passwords' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'DUPLICATE_PASSWORDS.csv'
                $definition.DownloadName = 'DUPLICATE_PASSWORDS.csv'
                $definition.Columns = @('PasswordGroup','SharedCount','SamAccountName','SamePasswordAccounts','IsPrivileged','Severity','Baseline')
                break
            }
            '^KRBTGT password age is high$|^krbtgt password age$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'KRBTGT.csv'
                $definition.DownloadName = 'KRBTGT.csv'
                break
            }
            '^ms-DS-MachineAccountQuota$|^MachineAccountQuota permits user-created computers$' {
                $definition.Type = 'csv'
                $definition.SourcePath = Join-Path $highRiskDir 'MACHINE_ACCOUNT_QUOTA.csv'
                $definition.DownloadName = 'MACHINE_ACCOUNT_QUOTA.csv'
                break
            }
            '^Passwords stored using reversible encryption$' {
                $definition.Type = 'reversible'
                $definition.SourcePath = Join-Path $InputRoot 'password_quality.txt'
                $definition.DownloadName = 'reversible_encryption_accounts.txt'
                break
            }
            '^Accounts without Kerberos pre-auth \(AS-REP roastable\)$' {
                $definition.Type = 'asrep'
                $definition.SourcePath = Join-Path $InputRoot 'ASREP.txt'
                $definition.DownloadName = 'ASREP.txt'
                break
            }
            '^Disabled user accounts present \(review and cleanup\)$' {
                $definition.Type = 'disabled-accounts'
                $definition.SourcePath = Join-Path $InputRoot 'accounts_disabled.txt'
                $definition.DownloadName = 'accounts_disabled.txt'
                break
            }
            '^Domain controllers allow weak Kerberos ciphers$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'dcs_weak_kerberos_ciphersuite.txt'
                $definition.DownloadName = 'dcs_weak_kerberos_ciphersuite.txt'
                break
            }
            '^Kerberoastable SPNs present \(review high-value service accounts\)$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'SPNs.txt'
                $definition.DownloadName = 'SPNs.txt'
                break
            }
            '^Inactive computer accounts \(>90 days\)$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'computers_inactive_90days.txt'
                $definition.DownloadName = 'computers_inactive_90days.txt'
                break
            }
            '^LAPS password read rights widely delegated$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'laps_read-extendedrights.txt'
                $definition.DownloadName = 'laps_read-extendedrights.txt'
                break
            }
            '^LAPS passwords expired$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'laps_expired-passwords.txt'
                $definition.DownloadName = 'laps_expired-passwords.txt'
                break
            }
            '^LDAP security misconfiguration detected$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'LDAPSecurity.txt'
                $definition.DownloadName = 'LDAPSecurity.txt'
                break
            }
            '^NTLM restrictions require hardening$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'ntlm_restrictions.txt'
                $definition.DownloadName = 'ntlm_restrictions.txt'
                break
            }
            '^DNS zones allowing insecure updates$' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $InputRoot 'insecure_dns_zones.txt'
                $definition.DownloadName = 'insecure_dns_zones.txt'
                break
            }
            '^Delegated permissions risks detected$|^Delegated permissions recommendations available$' {
                $definition.Type = 'text'
                if ($sourcePath) { $definition.DownloadName = [System.IO.Path]::GetFileName($sourcePath) }
                break
            }
            '^Group Policy report available$' {
                $definition.Type = 'html'
                $definition.SourcePath = Join-Path $htmlRoot 'GPOReport.html'
                $definition.DownloadName = 'GPOReport.html'
                $definition.ButtonText = 'Open Report'
                break
            }
            '^Overlapping group membership report available$' {
                $definition.Type = 'html'
                $definition.SourcePath = Join-Path $htmlRoot 'overlapping_group_memberships.html'
                $definition.DownloadName = 'overlapping_group_memberships.html'
                $definition.ButtonText = 'Open Report'
                break
            }
            '^Multiple nested paths report available$' {
                $definition.Type = 'html'
                $definition.SourcePath = Join-Path $htmlRoot 'multiple_nested_paths.html'
                $definition.DownloadName = 'multiple_nested_paths.html'
                $definition.ButtonText = 'Open Report'
                break
            }
            '^Dangerous ACL report available$' {
                $definition.Type = 'html'
                $definition.SourcePath = Join-Path $htmlRoot 'dangerousACLs.html'
                $definition.DownloadName = 'dangerousACLs.html'
                $definition.ButtonText = 'Open Report'
                break
            }
            '^Delegated permissions report available$|^DNS audit report available$|^DNS recommendations report available$|^High-risk baseline report available$' {
                $definition.Type = 'html'
                if ($sourcePath) { $definition.DownloadName = [System.IO.Path]::GetFileName($sourcePath) }
                $definition.ButtonText = 'Open Report'
                break
            }
            'unconstrained.*delegation' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $sourceRoot 'unconstrained_delegation.txt'
                $definition.DownloadName = 'unconstrained_delegation.txt'
                break
            }
            'gMSA|service account.*not.*gMSA' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $sourceRoot 'gmsa_status.txt'
                $definition.DownloadName = 'gmsa_status.txt'
                break
            }
            'Print Spooler' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $sourceRoot 'dc_print_spooler.txt'
                $definition.DownloadName = 'dc_print_spooler.txt'
                break
            }
            'SMB signing' {
                $definition.Type = 'text'
                $definition.SourcePath = Join-Path $sourceRoot 'dc_smb_signing.txt'
                $definition.DownloadName = 'dc_smb_signing.txt'
                break
            }
        }

        if ($definition.Type -eq 'auto') {
            switch ($sourceExt) {
                '.csv'  { $definition.Type = 'csv' }
                '.txt'  { $definition.Type = 'text' }
                '.html' { $definition.Type = 'html'; $definition.ButtonText = 'Open Report' }
                default { $definition.Type = 'text' }
            }
        }

        $definition.SourcePath = Resolve-AuditArtifactPath (Get-NormalizedAbsolutePath $definition.SourcePath)
        return [pscustomobject]$definition
    }

    function Copy-DownloadFile([string]$SourcePath, [string]$DestinationPath) {
        if ([string]::IsNullOrWhiteSpace($SourcePath) -or [string]::IsNullOrWhiteSpace($DestinationPath)) { return $false }
        if (-not (Test-Path -LiteralPath $SourcePath)) { return $false }

        try {
            Ensure-DirectoryPath (Split-Path -Path $DestinationPath -Parent)
            Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop
            return $true
        } catch {
            return $false
        }
    }

    function Publish-CommonDownloadArtifacts {
        param(
            [string]$Root,
            [string]$DownloadRoot
        )

        Ensure-DirectoryPath $DownloadRoot
        Ensure-DirectoryPath (Join-Path $DownloadRoot 'HighRisk')
    }

    function New-FindingResultPresentation {
        param(
            [object]$Finding,
            [string]$AuditReportPath,
            [string]$DownloadRoot
        )

        $definition = Get-FindingArtifactDefinition -Finding $Finding
        $sourcePath = $definition.SourcePath
        $downloadPath = $null
        $downloadHref = ''
        $downloadLabel = ''
        $resultsHtml = "<div class='result-empty'>Detailed result data was not available for this finding.</div>"
        $buttonText = if ($definition.ButtonText) { [string]$definition.ButtonText } else { 'Download Result' }
        $openInNewTab = $false

        switch ($definition.Type) {
            'html' {
                if ($sourcePath -and (Test-Path -LiteralPath $sourcePath)) {
                    $downloadPath = $sourcePath
                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = "<div class='result-empty'>This finding is backed by a companion HTML report. Use the button below to open the full report.</div>"
                    $openInNewTab = $true
                }
            }

            'csv' {
                $rows = if ($sourcePath) { @(Get-CsvSafe $sourcePath) } else { @() }
                $filtered = $false
                if ($rows.Count -gt 0 -and $definition.FilterColumn -and $definition.FilterValue) {
                    $rows = @(
                        $rows | Where-Object {
                            $_.PSObject.Properties[$definition.FilterColumn] -and
                            ([string]$_.PSObject.Properties[$definition.FilterColumn].Value).Trim() -eq [string]$definition.FilterValue
                        }
                    )
                    $filtered = $true
                }

                if ($rows.Count -gt 0) {
                    if ($filtered) {
                        $downloadPath = Join-Path $DownloadRoot $definition.DownloadName
                        Ensure-DirectoryPath (Split-Path -Path $downloadPath -Parent)
                        $rows | Export-Csv -LiteralPath $downloadPath -NoTypeInformation -Encoding UTF8
                    }
                    else {
                        $downloadPath = $sourcePath
                    }

                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = New-PreviewTableHtml -Rows $rows -Columns $definition.Columns -MaxRows 250
                }
                elseif ($sourcePath -and (Test-Path -LiteralPath $sourcePath)) {
                    $resultsHtml = "<div class='result-empty'>The source CSV exists, but no rows matched this finding after filtering.</div>"
                }
            }

            'text' {
                $tableData = Get-TextFindingTableData -Finding $Finding -Definition $definition -SourcePath $sourcePath
                $rows = @($tableData.Rows)

                if ($rows.Count -gt 0) {
                    $downloadPath = Join-Path $DownloadRoot (Get-CsvDownloadName -Name $definition.DownloadName -Fallback ('{0}.csv' -f (New-Slug $Finding.Title)))
                    Ensure-DirectoryPath (Split-Path -Path $downloadPath -Parent)
                    $rows | Export-Csv -LiteralPath $downloadPath -NoTypeInformation -Encoding UTF8

                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = New-PreviewTableHtml -Rows $rows -Columns $tableData.Columns -MaxRows 250
                }
                elseif ($sourcePath -and (Test-Path -LiteralPath $sourcePath)) {
                    $downloadPath = $sourcePath
                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = "<div class='result-empty'>A source text file exists for this finding, but no detailed rows could be parsed into a table.</div>"
                }
            }

            'disabled-accounts' {
                $rows = if ($sourcePath) { @(Get-DisabledAccounts -Path $sourcePath) } else { @() }
                if ($rows.Count -gt 0) {
                    $downloadPath = Join-Path $DownloadRoot (Get-CsvDownloadName -Name $definition.DownloadName -Fallback 'accounts_disabled.csv')
                    Ensure-DirectoryPath (Split-Path -Path $downloadPath -Parent)
                    $rows | Export-Csv -LiteralPath $downloadPath -NoTypeInformation -Encoding UTF8

                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = New-PreviewTableHtml -Rows $rows -Columns @('SamAccountName','DisplayName') -MaxRows 250
                }
            }

            'asrep' {
                $rows = if ($sourcePath) { @(Get-AsrepAccounts -Path $sourcePath) } else { @() }
                if ($rows.Count -gt 0) {
                    $downloadPath = Join-Path $DownloadRoot (Get-CsvDownloadName -Name $definition.DownloadName -Fallback 'ASREP.csv')
                    Ensure-DirectoryPath (Split-Path -Path $downloadPath -Parent)
                    $rows | Export-Csv -LiteralPath $downloadPath -NoTypeInformation -Encoding UTF8

                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = New-PreviewTableHtml -Rows $rows -Columns @('SamAccountName','DisplayName') -MaxRows 250
                }
            }

            'reversible' {
                $lines = if ($sourcePath) { @(Get-ReversibleEncryptionAccounts -Path $sourcePath) } else { @() }
                if ($lines.Count -gt 0) {
                    $rows = @(
                        $lines | ForEach-Object {
                            [pscustomobject]@{ Account = ([string]$_).Trim() }
                        }
                    )

                    $downloadPath = Join-Path $DownloadRoot (Get-CsvDownloadName -Name $definition.DownloadName -Fallback 'reversible_encryption_accounts.csv')
                    Ensure-DirectoryPath (Split-Path -Path $downloadPath -Parent)
                    $rows | Export-Csv -LiteralPath $downloadPath -NoTypeInformation -Encoding UTF8

                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                    $resultsHtml = New-PreviewTableHtml -Rows $rows -Columns @('Account') -MaxRows 250
                }
            }

            default {
                if ($sourcePath -and (Test-Path -LiteralPath $sourcePath)) {
                    $downloadPath = $sourcePath
                    $downloadHref = Get-RelativeHref -FromFile $AuditReportPath -ToPath $downloadPath
                    $downloadLabel = [System.IO.Path]::GetFileName($downloadPath)
                }
            }
        }

        return [pscustomobject]@{
            DownloadHref  = $downloadHref
            DownloadLabel = $downloadLabel
            DownloadText  = $buttonText
            ResultsHtml   = $resultsHtml
            OpenInNewTab  = $openInNewTab
            ResolvedSourcePath = $sourcePath
        }
    }

    function Write-AuditHtmlReport {
        [CmdletBinding()]
        param(
            [string]$Path,
            [object[]]$Items,
            [hashtable]$Counts,
            [string]$ComputerName,
            [string]$GeneratedOn,
            [string]$ManagementReportPath,
            [object[]]$CompanionReports
        )

        $severityOrder = @('Critical','High','Medium','Low','Information')
        $totalCount = if ($Items) { $Items.Count } else { 0 }
        $managementRel = Get-RelativeHref -FromFile $Path -ToPath $ManagementReportPath

        $priorityItems = @(
            $Items |
            Where-Object { (Normalize-Severity $_.Severity) -in @('Critical','High') } |
            Sort-Object -Property @{Expression={ Get-SeverityRank $_.Severity }; Descending=$true}, @{Expression='Score';Descending=$true}, @{Expression='Title';Descending=$false} |
            Select-Object -First 8
        )

        $countCards = New-Object 'System.Collections.Generic.List[string]'
        foreach ($sev in $severityOrder) {
            $count = 0
            if ($Counts.ContainsKey($sev)) { $count = [int]$Counts[$sev] }
            $countCards.Add(@"
<div class="metric sev-$sev">
  <div class="metric-label">$sev</div>
  <div class="metric-value">$count</div>
</div>
"@) | Out-Null
        }

        $priorityHtml = @()
        if ($priorityItems.Count -gt 0) {
            foreach ($item in $priorityItems) {
                $anchor = New-FindingAnchor $item
                $priorityHtml += @"
<li>
  <span class="badge sev-$(Normalize-Severity $item.Severity)">$(Normalize-Severity $item.Severity)</span>
  <a class="priority-title" href="#$anchor">$(HtmlEncode $item.Title)</a>
  <span class="priority-evidence">$(HtmlEncode $item.Evidence)</span>
</li>
"@
            }
        } else {
            $priorityHtml += '<li>No high-priority findings were identified from the collected results.</li>'
        }

        $findingIndexHtml = New-Object 'System.Collections.Generic.List[string]'
        foreach ($sev in $severityOrder) {
            $bucket = @(
                $Items |
                Where-Object { (Normalize-Severity $_.Severity) -eq $sev } |
                Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Title';Descending=$false}
            )

            if ($bucket.Count -eq 0) { continue }

            $indexRows = New-Object 'System.Collections.Generic.List[string]'
            foreach ($item in $bucket) {
                $anchor = New-FindingAnchor $item
                $indexRows.Add("<li><a href='#$(HtmlAttrEncode $anchor)'>$(HtmlEncode $item.Title)</a></li>") | Out-Null
            }

            $findingIndexHtml.Add(@"
<details class="index-detail">
  <summary>$sev ($($bucket.Count))</summary>
  <ol>
    $($indexRows -join "`n")
  </ol>
</details>
"@) | Out-Null
        }

        if ($findingIndexHtml.Count -eq 0) {
            $findingIndexHtml.Add('<div class="empty">No finding index entries were available.</div>') | Out-Null
        }

        $sectionHtml = New-Object 'System.Collections.Generic.List[string]'
        foreach ($sev in $severityOrder) {
            $bucket = @(
                $Items |
                Where-Object { (Normalize-Severity $_.Severity) -eq $sev } |
                Sort-Object -Property @{Expression='Score';Descending=$true}, @{Expression='Title';Descending=$false}
            )

            $bucketHtml = New-Object 'System.Collections.Generic.List[string]'
            if ($bucket.Count -eq 0) {
                $bucketHtml.Add('<div class="empty">No findings in this severity band.</div>') | Out-Null
            }
            else {
                foreach ($item in $bucket) {
                    $sevNorm = Normalize-Severity $item.Severity
                    $anchor  = New-FindingAnchor $item
                    $category = Get-FindingCategory $item.Title

                    $downloadHref = ''
                    $downloadLabel = ''
                    $downloadText = 'Download Result'
                    $resultPanelHtml = "<div class='result-empty'>Detailed result data was not available for this finding.</div>"
                    $downloadModeAttrs = ''

                    if ($item.PSObject.Properties['DownloadHref'] -and $item.DownloadHref) { $downloadHref = [string]$item.DownloadHref }
                    if ($item.PSObject.Properties['DownloadLabel'] -and $item.DownloadLabel) { $downloadLabel = [string]$item.DownloadLabel }
                    if ($item.PSObject.Properties['DownloadText'] -and $item.DownloadText) { $downloadText = [string]$item.DownloadText }
                    if ($item.PSObject.Properties['ResultsHtml'] -and $item.ResultsHtml) { $resultPanelHtml = [string]$item.ResultsHtml }
                    if ($item.PSObject.Properties['OpenInNewTab'] -and $item.OpenInNewTab) {
                        $downloadModeAttrs = " target='_blank' rel='noopener'"
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($downloadLabel)) {
                        $downloadModeAttrs = " download='" + (HtmlAttrEncode $downloadLabel) + "'"
                    }

                    $downloadHtml = if (-not [string]::IsNullOrWhiteSpace($downloadHref)) {
                        @"
<a class="download-link" href="$(HtmlAttrEncode $downloadHref)"$downloadModeAttrs>$(HtmlEncode $downloadText)</a>
<div class="download-name mono">$(HtmlEncode $downloadLabel)</div>
"@
                    } else {
                        "<span class='mono'>No downloadable result file was generated for this finding.</span>"
                    }

                    $bucketHtml.Add(@"
<details class="finding sev-$sevNorm" data-sev="$sevNorm" data-category="$(HtmlAttrEncode $category)" id="$anchor">
  <summary>
    <div class="finding-head">
      <div class="finding-title-wrap">
        <span class="badge sev-$sevNorm">$sevNorm</span>
        <span class="category">$(HtmlEncode $category)</span>
        <span class="finding-title">$(HtmlEncode $item.Title)</span>
      </div>
      <div class="finding-summary">$(HtmlEncode $item.Evidence)</div>
    </div>
  </summary>
  <div class="finding-body">
    <div class="finding-grid">
      <div class="panel">
        <h4>What was observed</h4>
        <p>$(HtmlEncode $item.Evidence)</p>
      </div>
      <div class="panel">
        <h4>Why it matters</h4>
        <p>$(HtmlEncode (Get-FindingWhyItMatters $item.Title))</p>
      </div>
      <div class="panel">
        <h4>Recommended action</h4>
        <p>$(HtmlEncode (Get-FindingRecommendation $item.Title))</p>
      </div>
      <div class="panel">
        <h4>Download Result</h4>
        <div class="download-wrap">
          $downloadHtml
        </div>
      </div>
    </div>
    <div class="panel evidence">
      <h4>Result details</h4>
      $resultPanelHtml
    </div>
  </div>
</details>
"@) | Out-Null
                }
            }

            $sectionHtml.Add(@"
<section class="severity-section" id="section-$(New-Slug $sev)">
  <div class="section-header">
    <h2>$sev</h2>
    <div class="section-count">$($bucket.Count) findings</div>
  </div>
  $($bucketHtml -join "`n")
</section>
"@) | Out-Null
        }

        $companionHtml = New-Object 'System.Collections.Generic.List[string]'
        if ($CompanionReports -and $CompanionReports.Count -gt 0) {
            foreach ($report in $CompanionReports) {
                $reportHref = ''
                if ($report.PSObject.Properties['FullPath'] -and $report.FullPath) {
                    $reportHref = Get-RelativeHref -FromFile $Path -ToPath $report.FullPath
                }
                elseif ($report.PSObject.Properties['RelativePath'] -and $report.RelativePath) {
                    $reportHref = [string]$report.RelativePath
                }

                if ($reportHref) {
                    $companionHtml.Add("<li><a href='$(HtmlAttrEncode $reportHref)'>$(HtmlEncode $report.Title)</a></li>") | Out-Null
                }
            }
        }
        if ($companionHtml.Count -eq 0) {
            $companionHtml.Add('<li>No additional HTML companion reports were detected.</li>') | Out-Null
        }

        $css = @"
<style>
:root{
  --bg:#f5f7fb;
  --panel:#ffffff;
  --text:#1b2430;
  --muted:#5f6b7a;
  --line:#d9e0ea;
  --shadow:0 10px 24px rgba(15,23,42,.08);
  --critical:#c62828;
  --high:#ef6c00;
  --medium:#0277bd;
  --low:#2e7d32;
  --information:#6c757d;
  --critical-soft:#fdecec;
  --high-soft:#fff2e5;
  --medium-soft:#e8f4fd;
  --low-soft:#edf8ee;
  --information-soft:#f2f4f6;
  --result-panel:#ffffff;
}
body[data-theme="dark"]{
  --bg:#0f172a;
  --panel:#111827;
  --text:#e5e7eb;
  --muted:#94a3b8;
  --line:#334155;
  --shadow:0 10px 24px rgba(0,0,0,.35);
  --critical:#f87171;
  --high:#fb923c;
  --medium:#60a5fa;
  --low:#4ade80;
  --information:#cbd5e1;
  --critical-soft:rgba(248,113,113,.15);
  --high-soft:rgba(251,146,60,.14);
  --medium-soft:rgba(96,165,250,.14);
  --low-soft:rgba(74,222,128,.14);
  --information-soft:rgba(203,213,225,.12);
  --result-panel:#0b1220;
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family:Segoe UI,Arial,sans-serif;
  background:var(--bg);
  color:var(--text);
}
a{color:#0f5cb8;text-decoration:none}
body[data-theme="dark"] a{color:#93c5fd}
a:hover{text-decoration:underline}
.container{max-width:1280px;margin:0 auto;padding:28px 22px 48px}
.hero{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:18px;
  box-shadow:var(--shadow);
  padding:24px;
}
.hero-top{
  display:flex;
  justify-content:space-between;
  gap:20px;
  flex-wrap:wrap;
  align-items:flex-start;
}
.hero-actions{
  display:flex;
  flex-direction:column;
  align-items:flex-end;
  gap:12px;
}
.theme-toggle{
  border:1px solid var(--line);
  background:var(--panel);
  color:var(--text);
  border-radius:999px;
  padding:10px 14px;
  font-size:13px;
  font-weight:700;
  cursor:pointer;
}
.theme-toggle:hover{transform:translateY(-1px)}
h1{margin:0 0 8px;font-size:28px}
.meta{color:var(--muted);font-size:14px;line-height:1.6}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:22px}
.metric{
  border:1px solid var(--line);
  border-radius:14px;
  padding:14px 16px;
  background:var(--panel);
}
.metric-label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700}
.metric-value{font-size:30px;font-weight:800;margin-top:6px}
.metric.sev-Critical{background:var(--critical-soft)}
.metric.sev-High{background:var(--high-soft)}
.metric.sev-Medium{background:var(--medium-soft)}
.metric.sev-Low{background:var(--low-soft)}
.metric.sev-Information{background:var(--information-soft)}
.layout{display:grid;grid-template-columns:280px minmax(0,1fr);gap:20px;margin-top:20px}
.sidebar{
  position:sticky;top:18px;align-self:start;
  background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;
}
.sidebar h3,.content h2{margin-top:0}
.sidebar ul{list-style:none;padding:0;margin:0}
.sidebar li{margin:10px 0}
.index-group{margin-top:18px;padding-top:18px;border-top:1px solid var(--line)}
.index-group h4{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.index-detail{border:1px solid var(--line);border-radius:12px;padding:8px 10px;background:#f8fafc;margin-bottom:10px}
body[data-theme="dark"] .index-detail{background:var(--result-panel)}
.index-detail summary{cursor:pointer;font-weight:700;list-style:none}
.index-detail summary::-webkit-details-marker{display:none}
.index-detail ol{margin:10px 0 0 18px;padding:0;max-height:260px;overflow:auto}
.index-detail li{margin:6px 0}
.index-detail a{color:var(--text)}
.badge{
  display:inline-flex;
  align-items:center;
  border-radius:999px;
  padding:4px 10px;
  font-size:12px;
  font-weight:800;
  letter-spacing:.02em;
  margin-right:8px;
  border:1px solid transparent;
}
.badge.sev-Critical{background:var(--critical-soft);color:var(--critical);border-color:rgba(198,40,40,.25)}
.badge.sev-High{background:var(--high-soft);color:var(--high);border-color:rgba(239,108,0,.25)}
.badge.sev-Medium{background:var(--medium-soft);color:var(--medium);border-color:rgba(2,119,189,.25)}
.badge.sev-Low{background:var(--low-soft);color:var(--low);border-color:rgba(46,125,50,.25)}
.badge.sev-Information{background:var(--information-soft);color:var(--information);border-color:rgba(108,117,125,.25)}
.category{
  display:inline-flex;
  align-items:center;
  border-radius:999px;
  padding:4px 10px;
  font-size:12px;
  font-weight:700;
  color:var(--muted);
  background:#f4f6f9;
  border:1px solid var(--line);
  margin-right:8px;
}
body[data-theme="dark"] .category{background:#1f2937}
.toolbar{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:18px;
  box-shadow:var(--shadow);
  padding:16px;
  margin-bottom:18px;
}
.toolbar-row{
  display:flex;
  gap:12px;
  flex-wrap:wrap;
  align-items:flex-end;
}
label{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
select,input{
  width:100%;
  min-height:42px;
  border:1px solid var(--line);
  border-radius:10px;
  padding:10px 12px;
  background:var(--panel);
  color:var(--text);
}
.filter{min-width:220px;flex:1}
.section-header{
  display:flex;justify-content:space-between;align-items:center;gap:12px;
  margin:0 0 12px;
}
.section-header h2{margin:0;font-size:24px}
.section-count{color:var(--muted);font-size:14px;font-weight:700}
.finding{
  background:var(--panel);
  border:1px solid var(--line);
  border-left:6px solid var(--information);
  border-radius:16px;
  box-shadow:var(--shadow);
  margin-bottom:14px;
  overflow:hidden;
}
.finding.sev-Critical{border-left-color:var(--critical)}
.finding.sev-High{border-left-color:var(--high)}
.finding.sev-Medium{border-left-color:var(--medium)}
.finding.sev-Low{border-left-color:var(--low)}
.finding.sev-Information{border-left-color:var(--information)}
.finding summary{
  list-style:none;
  cursor:pointer;
  padding:18px 18px 16px;
}
.finding summary::-webkit-details-marker{display:none}
.finding-head{display:flex;flex-direction:column;gap:10px}
.finding-title-wrap{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.finding-title{font-size:18px;font-weight:800}
.finding-summary{color:var(--muted);line-height:1.5}
.finding-body{padding:0 18px 18px}
.finding-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.panel{
  background:#f8fafc;
  border:1px solid var(--line);
  border-radius:12px;
  padding:14px;
}
body[data-theme="dark"] .panel{background:var(--result-panel)}
.panel h4{margin:0 0 8px;font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.panel p{margin:0;line-height:1.55}
.panel.evidence{margin-top:12px}
.priority{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;margin-bottom:18px}
.priority ul{margin:0;padding-left:18px}
.priority li{margin:10px 0;line-height:1.5}
.priority-title{font-weight:700;color:var(--text)}
.priority-evidence{display:block;color:var(--muted);margin-top:4px}
.empty{background:var(--panel);border:1px dashed var(--line);border-radius:14px;padding:16px;color:var(--muted)}
.companion{background:var(--panel);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:18px;margin-top:18px}
.companion ul{margin:0;padding-left:18px}
.mono{font-family:Consolas,Menlo,Monaco,monospace}
.download-wrap{display:flex;flex-direction:column;gap:10px}
.download-link{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:40px;
  padding:10px 14px;
  border-radius:10px;
  border:1px solid var(--line);
  background:var(--panel);
  color:var(--text);
  font-weight:700;
  max-width:220px;
}
.download-name{font-size:13px;color:var(--muted);word-break:break-word}
.result-note{font-size:13px;color:var(--muted);margin-bottom:10px}
.result-scroll{
  max-height:360px;
  overflow:auto;
  border:1px solid var(--line);
  border-radius:10px;
  background:var(--panel);
}
.result-table{
  width:100%;
  border-collapse:collapse;
  font-size:13px;
}
.result-table th,.result-table td{
  border-bottom:1px solid var(--line);
  padding:10px 12px;
  vertical-align:top;
  text-align:left;
}
.result-table th{
  position:sticky;
  top:0;
  background:#eef2f7;
  z-index:1;
}
body[data-theme="dark"] .result-table th{background:#0b1220}
.result-pre{
  margin:0;
  padding:12px;
  white-space:pre-wrap;
  word-break:break-word;
  font-family:Consolas,Menlo,Monaco,monospace;
  color:var(--text);
}
.result-empty{color:var(--muted);line-height:1.5}
@media (max-width: 980px){
  .layout{grid-template-columns:1fr}
  .sidebar{position:static}
  .hero-actions{align-items:flex-start}
}
</style>
"@

        $js = @"
<script>
(function(){
  function q(sel){return document.querySelector(sel);}
  function qa(sel){return Array.prototype.slice.call(document.querySelectorAll(sel));}
  function findings(){return qa('.finding');}

  function applyTheme(theme){
    document.body.setAttribute('data-theme', theme);
    var btn = q('#themeToggle');
    if (btn) {
      btn.innerText = theme === 'dark' ? 'Light mode' : 'Dark mode';
      btn.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
    }
    try { localStorage.setItem('adaudit-theme', theme); } catch (e) {}
  }

  function applyFilters(){
    var sev = q('#severityFilter').value;
    var query = (q('#searchFilter').value || '').toLowerCase().trim();
    var visible = 0;

    findings().forEach(function(item){
      var itemSev = item.getAttribute('data-sev');
      var text = (item.innerText || '').toLowerCase();
      var show = (sev === 'All' || itemSev === sev) && (!query || text.indexOf(query) >= 0);
      item.style.display = show ? '' : 'none';
      if(show){ visible++; }
    });

    var el = q('#visibleFindings');
    if (el) { el.value = visible; }
  }

  var btn = q('#themeToggle');
  if (btn) {
    btn.addEventListener('click', function(){
      var next = document.body.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      applyTheme(next);
    });
  }

  var storedTheme = null;
  try { storedTheme = localStorage.getItem('adaudit-theme'); } catch (e) {}
  applyTheme(storedTheme === 'dark' ? 'dark' : 'light');

  q('#severityFilter').addEventListener('change', applyFilters);
  q('#searchFilter').addEventListener('input', applyFilters);
  applyFilters();
})();
</script>
"@

        $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ADAudit - Audit Results</title>
$css
</head>
<body data-theme="light">
<div class="container">
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>Active Directory Audit Results</h1>
        <div class="meta">
          Target: <span class="mono">$(HtmlEncode $ComputerName)</span><br>
          Generated: $(HtmlEncode $GeneratedOn)<br>
          Report style: HTML audit summary with severity-based findings and embedded evidence<br>
          Finding details include in-report result previews with per-finding downloads.<br>
          Downloaded evidence is written to the <span class="mono">Raw Data</span> folder for technician handoff and follow-up work.
        </div>
      </div>
      <div class="hero-actions">
        <button type="button" class="theme-toggle" id="themeToggle" aria-pressed="false">Dark mode</button>
        <div class="meta">
          Total findings: <b>$totalCount</b><br>
          Risk report: <a href="$(HtmlAttrEncode $managementRel)">$(HtmlEncode ([System.IO.Path]::GetFileName($ManagementReportPath)))</a>
        </div>
      </div>
    </div>

    <div class="metrics">
      $($countCards -join "`n")
    </div>
  </section>

  <div class="layout">
    <aside class="sidebar">
      <h3>Navigate</h3>
      <ul>
        <li><a href="#priority-actions">Priority actions</a></li>
        <li><a href="#section-critical">Critical findings</a></li>
        <li><a href="#section-high">High findings</a></li>
        <li><a href="#section-medium">Medium findings</a></li>
        <li><a href="#section-low">Low findings</a></li>
        <li><a href="#section-information">Information</a></li>
        <li><a href="#companion-reports">Companion reports</a></li>
      </ul>
      <div class="index-group">
        <h4>Finding index</h4>
        $($findingIndexHtml -join "`n")
      </div>
    </aside>

    <main class="content">
      <section class="priority" id="priority-actions">
        <div class="section-header">
          <h2>Priority actions</h2>
          <div class="section-count">Highest-severity findings first</div>
        </div>
        <ul>
          $($priorityHtml -join "`n")
        </ul>
      </section>

      <section class="toolbar">
        <div class="toolbar-row">
          <div class="filter">
            <label for="severityFilter">Severity</label>
            <select id="severityFilter">
              <option>All</option>
              <option>Critical</option>
              <option>High</option>
              <option>Medium</option>
              <option>Low</option>
              <option>Information</option>
            </select>
          </div>
          <div class="filter">
            <label for="searchFilter">Search</label>
            <input id="searchFilter" type="text" placeholder="Search findings, evidence, result details, category">
          </div>
          <div class="filter">
            <label>Visible findings</label>
            <input type="text" value="$totalCount" id="visibleFindings" readonly>
          </div>
        </div>
      </section>

      $($sectionHtml -join "`n")

      <section class="companion" id="companion-reports">
        <div class="section-header">
          <h2>Companion reports</h2>
          <div class="section-count">Additional HTML outputs detected</div>
        </div>
        <ul>
          $($companionHtml -join "`n")
        </ul>
      </section>
    </main>
  </div>
</div>
$js
</body>
</html>
"@

        Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
    }

    # ---------------------------
    # Baseline parsing (authoritative)
    # ---------------------------
    $baselinePath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'ad_high_risk_baseline.txt')

    $baselineHasDA        = $false
    $baselineHasEA        = $false
    $baselineHasSA        = $false
    $baselineHasDAOverlap = $false

    $baselineHasInactive180 = $false
    $baselineHasPNE         = $false

    if ($baselinePath -and (Test-Path -LiteralPath $baselinePath)) {
        $lines = Get-Content -LiteralPath $baselinePath -ErrorAction SilentlyContinue
        $inFindings = $false

        foreach ($ln in $lines) {
            if (-not $ln) { continue }
            if ($ln -match '^\s*Findings\s*$') { $inFindings = $true; continue }
            if (-not $inFindings) { continue }

            if ($ln -match '^\s*\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*(.+?)\s*\|\s*Observed:\s*(.+?)\s*\|\s*Baseline:\s*(.+?)\s*$') {
                $sevRaw  = $matches[1]
                $title   = $matches[2].Trim()
                $obs     = $matches[3].Trim()
                $base    = $matches[4].Trim()
                $sev     = Normalize-Severity $sevRaw

                # suppress baseline duplicate-password line (keep only HighRisk\DUPLICATE_PASSWORDS.csv)
                if ($title -match '^\s*Duplicate passwords\b') { continue }

                if ($title -match '^Enabled accounts inactive >\s*180\s*days$') { $baselineHasInactive180 = $true }
                if ($title -match '^Enabled user accounts with PasswordNeverExpires$') { $baselineHasPNE = $true }

                $evidence = "Observed: $obs | Baseline: $base"
                $score = [int]$SeverityScore[$sev]

                switch -Regex ($title) {

                    '^krbtgt password age$' {
                        $obsDays = 0
                        if ($obs -match '\(([0-9]+)\s*days\)') { $obsDays = [int]$matches[1] }
                        elseif ($obs -match '([0-9]+)') { $obsDays = [int]$matches[1] }

                        $baseDays = 0
                        if ($base -match '([0-9]+)') { $baseDays = [int]$matches[1] }

                        if ($obsDays -gt 0 -and $baseDays -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsDays -Baseline $baseDays -MaxAdd 22 -K 5
                        }
                    }

                    '^Domain Admins$' {
                        $baselineHasDA = $true
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }
                        $baseCount = 0
                        if ($base -match '([0-9]+)') { $baseCount = [int]$matches[1] }
                        if ($obsCount -gt 0 -and $baseCount -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsCount -Baseline $baseCount -MaxAdd 18 -K 4
                        }
                    }

                    '^Enterprise Admins$' { $baselineHasEA = $true }

                    '^Schema Admins$' {
                        $baselineHasSA = $true
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }

                        $baseCount = 0
                        if ($base -match '^\s*0\b') { $baseCount = 0 }
                        elseif ($base -match '([0-9]+)') { $baseCount = [int]$matches[1] }

                        if ($obsCount -gt 0) {
                            if ($baseCount -le 0) {
                                $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $obsCount -MaxAdd 28 -K 8
                                $sev = 'Critical'
                            } else {
                                $score = Score-OverBaselineLog -Severity $sev -Observed $obsCount -Baseline $baseCount -MaxAdd 18 -K 4
                            }
                        }
                    }

                    '^Domain Admins group overlap' {
                        $baselineHasDAOverlap = $true
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }
                        if ($obsCount -gt 0) {
                            $sev = 'Critical'
                            $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $obsCount -MaxAdd 34 -K 10
                        }
                    }

                    '^Enabled accounts inactive >\s*180\s*days$' {
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }
                        if ($obsCount -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsCount -Baseline 1 -MaxAdd 14 -K 3
                        }
                    }

                    '^Enabled user accounts with PasswordNeverExpires$' {
                        $obsCount = 0
                        if ($obs -match '([0-9]+)') { $obsCount = [int]$matches[1] }
                        if ($obsCount -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsCount -Baseline 1 -MaxAdd 14 -K 3
                        }
                    }

                    '^ms-DS-MachineAccountQuota$' {
                        $obsVal = 0
                        if ($obs -match '([0-9]+)') { $obsVal = [int]$matches[1] }
                        if ($obsVal -gt 0) {
                            $score = Score-OverBaselineLog -Severity $sev -Observed $obsVal -Baseline 1 -MaxAdd 16 -K 4
                        }
                    }

                    default { $score = [int]$SeverityScore[$sev] }
                }

                Add-FindingOnce $sev $title $evidence $baselinePath $score
            }
        }
    }

    # ---------------------------
    # Domain stats from ADExtract (optional)
    # ---------------------------
    $UsersCount  = $null
    $GroupsCount = $null
    $OUsCount    = $null
    try {
        $adExtract = Resolve-AuditArtifactPath (Join-Path (Get-RawDataDir -BaseRoot $InputRoot) 'ADExtract')
        if ($adExtract -and (Test-Path -LiteralPath $adExtract)) {
            $usersCsv  = Get-ChildItem -Path $adExtract -Recurse -File -Filter '*-Users.csv'  | Select-Object -First 1
            $groupsCsv = Get-ChildItem -Path $adExtract -Recurse -File -Filter '*-Groups.csv' | Select-Object -First 1
            $ousCsv    = Get-ChildItem -Path $adExtract -Recurse -File -Filter '*-OUs.csv'    | Select-Object -First 1
            if ($usersCsv)  { $UsersCount  = (Get-CsvSafe $usersCsv.FullName).Count }
            if ($groupsCsv) { $GroupsCount = (Get-CsvSafe $groupsCsv.FullName).Count }
            if ($ousCsv)    { $OUsCount    = (Get-CsvSafe $ousCsv.FullName).Count }
        }
    } catch { }

    # ---------------------------
    # HighRisk CSVs
    # ---------------------------
    $highRiskDir = Resolve-AuditArtifactPath (Join-Path $InputRoot 'HighRisk')
    if ($highRiskDir -and (Test-Path -LiteralPath $highRiskDir)) {
        $hrFiles = @{
            DUPLICATE_PASSWORDS     = Join-Path $highRiskDir 'DUPLICATE_PASSWORDS.csv'
            KRBTGT                  = Join-Path $highRiskDir 'KRBTGT.csv'
            PRIVILEGED_GROUPS       = Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv'
            INACTIVE_ACCOUNTS       = Join-Path $highRiskDir 'INACTIVE_ACCOUNTS.csv'
            PASSWORD_NEVER_EXPIRES  = Join-Path $highRiskDir 'PASSWORD_NEVER_EXPIRES.csv'
            DISABLED_STALE          = Join-Path $highRiskDir 'DISABLED_STALE.csv'
            MACHINE_ACCOUNT_QUOTA   = Join-Path $highRiskDir 'MACHINE_ACCOUNT_QUOTA.csv'
            Summary                 = Join-Path $highRiskDir 'Summary.csv'
        }

        $dupRows = Get-CsvSafe $hrFiles.DUPLICATE_PASSWORDS
        if ($dupRows.Count -gt 0) {
            Add-FindingOnce 'Critical' 'Duplicate passwords detected' "Affected accounts in shared-password groups: $($dupRows.Count)" $hrFiles.DUPLICATE_PASSWORDS (Score-Scaled 'Critical' $dupRows.Count 100)
        }

        $krbtgt = Get-CsvSafe $hrFiles.KRBTGT
        if ($krbtgt.Count -gt 0) {
            $ageVal = 0
            try {
                $first = $krbtgt | Select-Object -First 1
                # Also try Observed column which may contain "date (N days)" format
                $raw = @($first.AgeDays, $first.PasswordAgeDays) |
                    Where-Object { $_ -ne $null -and $_ -ne '' } |
                    Select-Object -First 1
                if (-not $raw -and $first.Observed -and $first.Observed -ne 'Unknown') {
                    if ($first.Observed -match '\((\d+)\s*days?\)') { $raw = $Matches[1] }
                }
                if ($raw) { $ageVal = [int](([string]$raw) -replace '[^0-9]','') }
            } catch { $ageVal = 0 }

            if ($ageVal -gt 180) {
                $sev = if ($ageVal -ge 365) { 'High' } else { 'Medium' }
                Add-FindingOnce $sev 'KRBTGT password age is high' "Estimated age (days): $ageVal" $hrFiles.KRBTGT (Score-Scaled $sev ([Math]::Max($ageVal,1) / 30))
            }
        }

        $privRows = Get-CsvSafe $hrFiles.PRIVILEGED_GROUPS
        if ($privRows.Count -gt 0) {
            $sev = if ($privRows.Count -ge 20) { 'High' } elseif ($privRows.Count -ge 10) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Large privileged group membership' "Rows: $($privRows.Count)" $hrFiles.PRIVILEGED_GROUPS (Score-Scaled $sev $privRows.Count)
        }

        # Keep ONLY baseline inactive >180 days (renamed), suppress HighRisk\INACTIVE_ACCOUNTS.csv
        if (-not $baselineHasInactive180) {
            $inactiveRows = Get-CsvSafe $hrFiles.INACTIVE_ACCOUNTS
            if ($inactiveRows.Count -gt 0) {
                $sev = if ($inactiveRows.Count -ge 200) { 'High' } elseif ($inactiveRows.Count -ge 50) { 'Medium' } else { 'Low' }
                Add-FindingOnce $sev 'Inactive enabled accounts' "Accounts inactive: $($inactiveRows.Count)" $hrFiles.INACTIVE_ACCOUNTS (Score-Scaled $sev $inactiveRows.Count)
            }
        }

        # Keep ONLY baseline PasswordNeverExpires, suppress HighRisk\PASSWORD_NEVER_EXPIRES.csv
        if (-not $baselineHasPNE) {
            $pneRows = Get-CsvSafe $hrFiles.PASSWORD_NEVER_EXPIRES
            if ($pneRows.Count -gt 0) {
                $sev = if ($pneRows.Count -ge 50) { 'High' } elseif ($pneRows.Count -ge 10) { 'Medium' } else { 'Low' }
                Add-FindingOnce $sev 'Passwords set to never expire' "Accounts: $($pneRows.Count)" $hrFiles.PASSWORD_NEVER_EXPIRES (Score-Scaled $sev $pneRows.Count)
            }
        }

        $dsRows = Get-CsvSafe $hrFiles.DISABLED_STALE
        if ($dsRows.Count -gt 0) {
            $sev = if ($dsRows.Count -ge 200) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Disabled stale accounts' "Accounts: $($dsRows.Count)" $hrFiles.DISABLED_STALE (Score-Scaled $sev $dsRows.Count)
        }

        $maqRows = Get-CsvSafe $hrFiles.MACHINE_ACCOUNT_QUOTA
        if ($maqRows.Count -gt 0) {
            $quota = 10
            try {
                $firstRow = $maqRows | Select-Object -First 1
                $quotaCol = ($firstRow | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -match 'quota|Machine|Account' } | Select-Object -ExpandProperty Name -First 1)
                if ($quotaCol) { $quota = [int]$firstRow.$quotaCol }
            } catch { $quota = 10 }

            $sev = if ($quota -gt 10) { 'High' } elseif ($quota -gt 0) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'MachineAccountQuota permits user-created computers' "Quota: $quota" $hrFiles.MACHINE_ACCOUNT_QUOTA (Score-Scaled $sev $quota)
        }
    }

    # ---------------------------
    # Text-based checks
    # ---------------------------
    $weakKerbPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'dcs_weak_kerberos_ciphersuite.txt')
    $weakKerbLines = Get-NonHeaderLines $weakKerbPath
    if ($weakKerbLines.Count -gt 0) {
        Add-FindingOnce 'High' 'Domain controllers allow weak Kerberos ciphers' "DCs flagged: $($weakKerbLines.Count)" $weakKerbPath (Score-Scaled 'High' $weakKerbLines.Count)
    }

    # ---------------------------
    # Disabled user accounts (accounts_disabled.txt) - UPDATED SCORING
    # ---------------------------
    $disabledPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'accounts_disabled.txt')
    $disabled = @(Get-DisabledAccounts -Path $disabledPath)
    $disabledUnique = @(
        $disabled |
        Select-Object -ExpandProperty SamAccountName -Unique |
        Where-Object { $_ -and $_.Trim().Length -gt 0 }
    )
    $disabledCount = $disabledUnique.Count

    if ($disabledCount -gt 0) {
        $base = [int]$Baselines.DisabledUserAccounts

        # Risk-class behavior:
        # - Medium by default (lifecycle control)
        # - Escalate to High when volume is large (governance failure signal)
        $sev = 'Medium'
        if ($disabledCount -ge 200) { $sev = 'High' }

        $preview = if ($disabledUnique.Count -le 10) {
            ($disabledUnique -join ', ')
        } else {
            (($disabledUnique | Select-Object -First 10) -join ', ') + ', ...'
        }

        # Stronger scaling than before (so 256 with baseline 20 is not "Low + small bump")
        # Example for 256: High base(8) + ceil(4*log2(12.8))=8+15 => 23 (capped by MaxAdd 20, not hit)
        $score = Score-OverBaselineLog -Severity $sev -Observed $disabledCount -Baseline ([Math]::Max($base,1)) -MaxAdd 20 -K 4

        Add-FindingOnce $sev 'Disabled user accounts present (review and cleanup)' ("Disabled accounts: $disabledCount (Baseline: <= $base) | Example: $preview") $disabledPath $score
    }

    # ---------------------------
    # Password quality (reversible encryption) - try split file first, fall back to combined
    # ---------------------------
    $pqRevPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_reversible_encryption.txt')
    $pqPath    = Resolve-AuditArtifactPath (Join-Path $InputRoot 'password_quality.txt')
    $revAccounts = @(Get-ReversibleEncryptionAccounts -Path $(if ($pqRevPath) { $pqRevPath } else { $pqPath }))
    if ($revAccounts.Count -eq 0 -and $pqRevPath -ne $pqPath) {
        $revAccounts = @(Get-ReversibleEncryptionAccounts -Path $pqPath)
    }
    $revCount = $revAccounts.Count
    if ($revCount -gt 0) {
        $preview = if ($revCount -le 10) {
            ($revAccounts -join ', ')
        } else {
            (($revAccounts | Select-Object -First 10) -join ', ') + ', ...'
        }
        $revEvidencePath = if ($pqRevPath) { $pqRevPath } else { $pqPath }
        $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $revCount -MaxAdd 34 -K 10
        Add-FindingOnce 'Critical' 'Passwords stored using reversible encryption' "Accounts: $revCount | Example: $preview" $revEvidencePath $score
    }

    # ---------------------------
    # Password quality split files - additional category findings
    # ---------------------------
    # LM hashes present
    $pqLmPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_lm_hashes.txt')
    $pqLmLines = Get-PqAccountLines $pqLmPath
    if ($pqLmLines.Count -gt 0) {
        $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $pqLmLines.Count -MaxAdd 34 -K 10
        Add-FindingOnce 'Critical' 'LM hashes of passwords present in AD' "Accounts: $($pqLmLines.Count)" $pqLmPath $score
    }

    # Accounts with no password set - cross-reference with Users.csv to check enabled/disabled
    $pqNoPwdPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_no_password.txt')
    $pqNoPwdLines = Get-PqAccountLines $pqNoPwdPath
    if ($pqNoPwdLines.Count -gt 0) {
        # Extract SamAccountNames from DOMAIN\user format
        $noPwdSams = @($pqNoPwdLines | ForEach-Object { ($_ -split '\\', 2)[-1].Trim() } | Where-Object { $_ })

        # Try to determine how many are enabled via Users.csv (userAccountControl bit 0x2 = disabled)
        $enabledNoPwd = 0
        $disabledNoPwd = $pqNoPwdLines.Count
        try {
            $adExtractDir = Resolve-AuditArtifactPath (Join-Path (Get-RawDataDir -BaseRoot $InputRoot) 'ADExtract')
            if ($adExtractDir -and (Test-Path -LiteralPath $adExtractDir)) {
                $uCsv = Get-ChildItem -Path $adExtractDir -Recurse -File -Filter '*-Users.csv' | Select-Object -First 1
                if ($uCsv) {
                    $allUserRows = Get-CsvSafe $uCsv.FullName
                    $noPwdSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($s in $noPwdSams) { $noPwdSet.Add($s) | Out-Null }
                    $enabledNoPwd = 0
                    foreach ($row in $allUserRows) {
                        $sam = $row.SamAccountName
                        if (-not $sam -or -not $noPwdSet.Contains($sam)) { continue }
                        $uac = 0
                        try { $uac = [int]$row.userAccountControl } catch {}
                        if (($uac -band 2) -eq 0) { $enabledNoPwd++ }
                    }
                    $disabledNoPwd = $pqNoPwdLines.Count - $enabledNoPwd
                }
            }
        } catch {}

        if ($enabledNoPwd -gt 0) {
            # Enabled accounts with no password = Critical
            $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $enabledNoPwd -MaxAdd 34 -K 10
            Add-FindingOnce 'Critical' 'Accounts with no password set (ENABLED)' "Enabled: $enabledNoPwd of $($pqNoPwdLines.Count) total" $pqNoPwdPath $score
        }
        if ($disabledNoPwd -gt 0 -and $enabledNoPwd -eq 0) {
            # All disabled = Low severity (common for shared mailboxes / service accounts)
            Add-FindingOnce 'Low' 'Accounts with no password set (all disabled)' "Disabled accounts: $disabledNoPwd" $pqNoPwdPath (Score-Scaled 'Low' $disabledNoPwd)
        } elseif ($disabledNoPwd -gt 0 -and $enabledNoPwd -gt 0) {
            Add-FindingOnce 'Low' 'Accounts with no password set (disabled)' "Disabled accounts: $disabledNoPwd (review and cleanup)" $pqNoPwdPath (Score-Scaled 'Low' $disabledNoPwd)
        }
    }

    # Dictionary passwords found
    $pqDictPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_dictionary_passwords.txt')
    $pqDictLines = Get-PqAccountLines $pqDictPath
    if ($pqDictLines.Count -gt 0) {
        $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $pqDictLines.Count -MaxAdd 34 -K 10
        Add-FindingOnce 'Critical' 'Passwords found in dictionary/breach list' "Accounts: $($pqDictLines.Count)" $pqDictPath $score
    }

    # Default computer passwords
    $pqDefCompPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_default_computer_passwords.txt')
    $pqDefCompLines = Get-PqAccountLines $pqDefCompPath
    if ($pqDefCompLines.Count -gt 0) {
        $sev = if ($pqDefCompLines.Count -ge 5) { 'Critical' } else { 'High' }
        $score = Score-BaselineZeroLog -Severity $sev -Observed $pqDefCompLines.Count -MaxAdd 20 -K 8
        Add-FindingOnce $sev 'Computer accounts with default passwords' "Accounts: $($pqDefCompLines.Count)" $pqDefCompPath $score
    }

    # Missing Kerberos AES keys
    $pqAesPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_missing_aes_keys.txt')
    $pqAesLines = Get-PqAccountLines $pqAesPath
    if ($pqAesLines.Count -gt 0) {
        Add-FindingOnce 'Medium' 'Kerberos AES keys missing from accounts' "Accounts: $($pqAesLines.Count)" $pqAesPath (Score-Scaled 'Medium' $pqAesLines.Count)
    }

    # DES-only encryption accounts
    $pqDesPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_des_only.txt')
    $pqDesLines = Get-PqAccountLines $pqDesPath
    if ($pqDesLines.Count -gt 0) {
        $score = Score-BaselineZeroLog -Severity 'Critical' -Observed $pqDesLines.Count -MaxAdd 34 -K 10
        Add-FindingOnce 'Critical' 'Accounts restricted to DES-only encryption' "Accounts: $($pqDesLines.Count)" $pqDesPath $score
    }

    # Admin accounts allowed delegation
    $pqAdminDelegPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_admin_delegation.txt')
    $pqAdminDelegLines = Get-PqAccountLines $pqAdminDelegPath
    if ($pqAdminDelegLines.Count -gt 0) {
        $sev = if ($pqAdminDelegLines.Count -ge 5) { 'Critical' } else { 'High' }
        Add-FindingOnce $sev 'Administrative accounts allowed to be delegated' "Accounts: $($pqAdminDelegLines.Count)" $pqAdminDelegPath (Score-Scaled $sev $pqAdminDelegLines.Count)
    }

    # Password not required flag
    $pqPwdNotReqPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'pq_password_not_required.txt')
    $pqPwdNotReqLines = Get-PqAccountLines $pqPwdNotReqPath
    if ($pqPwdNotReqLines.Count -gt 0) {
        $score = Score-BaselineZeroLog -Severity 'High' -Observed $pqPwdNotReqLines.Count -MaxAdd 20 -K 8
        Add-FindingOnce 'High' 'Accounts not required to have a password' "Accounts: $($pqPwdNotReqLines.Count)" $pqPwdNotReqPath $score
    }

    # ---------------------------
    # AS-REP roastable
    # ---------------------------
    $asrepPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'ASREP.txt')
    $asrepAccounts = @(Get-AsrepAccounts -path $asrepPath)
    $asrepCount = @($asrepAccounts).Count
    if ($asrepCount -gt 0) {
        $sev = 'Critical'
        $score = if ($asrepCount -eq 1) { [int]$SeverityScore.Critical }
        else { Score-BaselineZeroLog -Severity $sev -Observed $asrepCount -MaxAdd 34 -K 10 }

        $samList = @($asrepAccounts | Select-Object -ExpandProperty SamAccountName -Unique)
        $samPreview = if ($samList.Count -le 10) { ($samList -join ', ') }
        else { (($samList | Select-Object -First 10) -join ', ') + ', ...' }

        Add-FindingOnce $sev 'Accounts without Kerberos pre-auth (AS-REP roastable)' "Accounts: $asrepCount | Users: $samPreview" $asrepPath $score
    }

    $spnPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'SPNs.txt')
    $spnLines = Get-NonHeaderLines $spnPath
    if ($spnLines.Count -gt 0) {
        Add-FindingOnce 'Medium' 'Kerberoastable SPNs present (review high-value service accounts)' "Lines: $($spnLines.Count)" $spnPath (Score-Scaled 'Medium' $spnLines.Count)
    }

    # Inactive computer objects (>90 days)
    $inactiveCompsPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'computers_inactive_90days.txt')
    $inactiveCompsLines = Get-NonHeaderLines $inactiveCompsPath
    if ($inactiveCompsLines.Count -gt 0) {
        $obs = $inactiveCompsLines.Count
        $base = 5
        $sev = if ($obs -ge 200) { 'High' } elseif ($obs -ge 50) { 'Medium' } else { 'Low' }
        $score = Score-OverBaselineLog -Severity $sev -Observed $obs -Baseline $base -MaxAdd 14 -K 3
        Add-FindingOnce $sev 'Inactive computer accounts (>90 days)' "Computers inactive: $obs (Baseline: <= $base)" $inactiveCompsPath $score
    }

    # Suppress accounts_passdontexpire.txt when baseline already provides PasswordNeverExpires
    $pndePath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'accounts_passdontexpire.txt')
    if (-not $baselineHasPNE) {
        $pndeLines = Get-NonHeaderLines $pndePath
        if ($pndeLines.Count -gt 0) {
            $sev = if ($pndeLines.Count -ge 50) { 'High' } elseif ($pndeLines.Count -ge 10) { 'Medium' } else { 'Low' }
            Add-FindingOnce $sev 'Accounts with password set to not expire' "Accounts: $($pndeLines.Count)" $pndePath (Score-Scaled $sev $pndeLines.Count)
        }
    }

    $lapsRightsPath  = Resolve-AuditArtifactPath (Join-Path $InputRoot 'laps_read-extendedrights.txt')
    $lapsExpiredPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'laps_expired-passwords.txt')
    if (($lapsRightsPath -and (Test-Path -LiteralPath $lapsRightsPath)) -or ($lapsExpiredPath -and (Test-Path -LiteralPath $lapsExpiredPath))) {
        $rightsCount  = (Get-NonHeaderLines $lapsRightsPath).Count
        $expiredCount = (Get-NonHeaderLines $lapsExpiredPath).Count
        if ($rightsCount -gt 0)  { Add-FindingOnce 'High'   'LAPS password read rights widely delegated' "Readers: $rightsCount" $lapsRightsPath (Score-Scaled 'High' $rightsCount) }
        if ($expiredCount -gt 0) { Add-FindingOnce 'Medium' 'LAPS passwords expired' "Computers flagged: $expiredCount" $lapsExpiredPath (Score-Scaled 'Medium' $expiredCount) }
    }

    $ldapSecPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'LDAPSecurity.txt')
    if ((Get-NonHeaderLines $ldapSecPath).Count -gt 0) {
        Add-FindingOnce 'High' 'LDAP security misconfiguration detected' 'See LDAPSecurity.txt for details' $ldapSecPath $SeverityScore.High
    }

    $ntlmRestrictPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'ntlm_restrictions.txt')
    if ((Get-NonHeaderLines $ntlmRestrictPath).Count -gt 0) {
        Add-FindingOnce 'Medium' 'NTLM restrictions require hardening' 'Review NTLM configuration and restrictions' $ntlmRestrictPath $SeverityScore.Medium
    }

    $dnsInsecureZonesPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'insecure_dns_zones.txt')
    $dnsInsecureLines = Get-NonHeaderLines $dnsInsecureZonesPath
    if ($dnsInsecureLines.Count -gt 0) {
        Add-FindingOnce 'High' 'DNS zones allowing insecure updates' "Zones flagged: $($dnsInsecureLines.Count)" $dnsInsecureZonesPath (Score-Scaled 'High' $dnsInsecureLines.Count)
    }

    # Unconstrained Kerberos delegation
    $unconstrainedPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'unconstrained_delegation.txt')
    $unconstrainedLines = Get-NonHeaderLines $unconstrainedPath
    if ($unconstrainedLines.Count -gt 0) {
        $sev = if ($unconstrainedLines.Count -ge 3) { 'Critical' } else { 'High' }
        Add-FindingOnce $sev 'Accounts with unconstrained Kerberos delegation' "Accounts: $($unconstrainedLines.Count)" $unconstrainedPath (Score-Scaled $sev $unconstrainedLines.Count)
    }

    # gMSA status
    $gmsaPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'gmsa_status.txt')
    $gmsaLines = Get-NonHeaderLines $gmsaPath
    if ($gmsaLines.Count -gt 0) {
        $sev = if ($gmsaLines.Count -ge 10) { 'Medium' } else { 'Low' }
        Add-FindingOnce $sev 'Service accounts not using gMSA' "Accounts with static passwords: $($gmsaLines.Count)" $gmsaPath (Score-Scaled $sev $gmsaLines.Count)
    }

    # Print Spooler on DCs
    $spoolerPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'dc_print_spooler.txt')
    $spoolerLines = Get-NonHeaderLines $spoolerPath
    if ($spoolerLines.Count -gt 0) {
        Add-FindingOnce 'High' 'Print Spooler running on domain controllers' "DCs affected: $($spoolerLines.Count)" $spoolerPath (Score-Scaled 'High' $spoolerLines.Count)
    }

    # SMB signing on DCs
    $smbSignPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'dc_smb_signing.txt')
    $smbSignLines = Get-NonHeaderLines $smbSignPath
    if ($smbSignLines.Count -gt 0) {
        Add-FindingOnce 'High' 'SMB signing not enforced on domain controllers' "DCs affected: $($smbSignLines.Count)" $smbSignPath (Score-Scaled 'High' $smbSignLines.Count)
    }

    # Delegated Permissions
    $delegRoot = Resolve-AuditArtifactPath (Join-Path (Get-RawDataDir -BaseRoot $InputRoot) 'DelegatedPermissions')
    if ($delegRoot -and (Test-Path -LiteralPath $delegRoot)) {
        $repFolder = Get-ChildItem -Path $delegRoot -Directory | Sort-Object Name | Select-Object -Last 1
        if ($repFolder) {
            $riskTxt = Join-Path $repFolder.FullName 'ADAudit_RiskAssessment.txt'
            $recTxt  = Join-Path $repFolder.FullName 'ADAudit_Recommendations.txt'

            $riskLines = Get-NonHeaderLines $riskTxt
            if ($riskLines.Count -gt 0) {
                $highCount = ($riskLines | Where-Object { $_ -match '(CRITICAL|HIGH)' }).Count
                $sev = if ($highCount -gt 0) { 'High' } else { 'Medium' }
                Add-FindingOnce $sev 'Delegated permissions risks detected' "High/Critical items: $highCount" $riskTxt (Score-Scaled $sev $highCount)
            }

            if ($recTxt -and (Test-Path -LiteralPath $recTxt)) {
                Add-FindingOnce 'Low' 'Delegated permissions recommendations available' 'See recommendations file' $recTxt $SeverityScore.Low
            }
        }
    }

    # Admin group text files (suppressed if baseline includes)
    $daPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'domain_admins.txt')
    $eaPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'enterprise_admins.txt')
    $saPath = Resolve-AuditArtifactPath (Join-Path $InputRoot 'schema_admins.txt')

    if (-not $baselineHasDA) {
        $daCount = (Get-NonHeaderLines $daPath).Count
        if ($daCount -gt 0) {
            $sev = if ($daCount -gt 10) { 'High' } elseif ($daCount -gt 5) { 'Medium' } else { 'Low' }
            $daBase = 5
            Add-FindingOnce $sev 'Domain Admins membership size' "Members: $daCount (Baseline: <= $daBase)" $daPath (Score-OverBaselineLog -Severity $sev -Observed $daCount -Baseline $daBase -MaxAdd 18 -K 4)
        }
    }

    if (-not $baselineHasEA) {
        $eaCount = (Get-NonHeaderLines $eaPath).Count
        if ($eaCount -gt 0) {
            $sev = if ($eaCount -gt 5) { 'High' } elseif ($eaCount -gt 2) { 'Medium' } else { 'Low' }
            $eaBase = 2
            Add-FindingOnce $sev 'Enterprise Admins membership size' "Members: $eaCount (Baseline: <= $eaBase)" $eaPath (Score-OverBaselineLog -Severity $sev -Observed $eaCount -Baseline $eaBase -MaxAdd 16 -K 4)
        }
    }

    if (-not $baselineHasSA) {
        $saCount = (Get-NonHeaderLines $saPath).Count
        if ($saCount -gt 0) {
            $sev = if ($saCount -gt 5) { 'High' } elseif ($saCount -gt 2) { 'Medium' } else { 'Low' }
            $saBase = 1
            Add-FindingOnce $sev 'Schema Admins membership size' "Members: $saCount (Baseline: <= $saBase except during schema change)" $saPath (Score-OverBaselineLog -Severity $sev -Observed $saCount -Baseline $saBase -MaxAdd 18 -K 4)
        }
    }

    # Companion HTML outputs
    $gpoReportPath = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'GPOReport.html'
    if (Test-Path $gpoReportPath) {
        Add-FindingOnce 'Information' 'Group Policy report available' 'Detailed GPO export generated as HTML.' $gpoReportPath $SeverityScore.Information
    }

    $overlapHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'overlapping_group_memberships.html'
    if (Test-Path $overlapHtmlPath) {
        Add-FindingOnce 'Information' 'Overlapping group membership report available' 'Detailed overlapping membership report generated as HTML.' $overlapHtmlPath $SeverityScore.Information
    }

    $nestedPathHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'multiple_nested_paths.html'
    if (Test-Path $nestedPathHtmlPath) {
        Add-FindingOnce 'Information' 'Multiple nested paths report available' 'Report showing target groups reachable via multiple nesting chains from a single direct group.' $nestedPathHtmlPath $SeverityScore.Information
    }

    $dangerousAclHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $InputRoot) 'dangerousACLs.html'
    if (Test-Path $dangerousAclHtmlPath) {
        Add-FindingOnce 'Information' 'Dangerous ACL report available' 'Detailed ACL findings generated as HTML.' $dangerousAclHtmlPath $SeverityScore.Information
    }

    $delegatedIndexPath = Get-ChildItem -Path (Join-Path (Get-RawDataDir -BaseRoot $InputRoot) 'DelegatedPermissions') -Recurse -File -Filter 'index.html' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($delegatedIndexPath) {
        Add-FindingOnce 'Information' 'Delegated permissions report available' 'Detailed delegated permissions HTML report generated.' $delegatedIndexPath.FullName $SeverityScore.Information
    }

    $dnsAuditHtmlPath = Get-ChildItem -Path $InputRoot -Recurse -File -Filter 'DNSAudit-*.html' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '\.source\.html$' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($dnsAuditHtmlPath) {
        Add-FindingOnce 'Information' 'DNS audit report available' 'Detailed DNS audit HTML report generated.' $dnsAuditHtmlPath.FullName $SeverityScore.Information
    }

    $dnsRecoHtmlPath = Get-ChildItem -Path $InputRoot -Recurse -File -Filter 'DNS-Recommendations-*.html' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '\.source\.html$' } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($dnsRecoHtmlPath) {
        Add-FindingOnce 'Information' 'DNS recommendations report available' 'Supplementary DNS recommendations HTML report generated.' $dnsRecoHtmlPath.FullName $SeverityScore.Information
    }

    # ---------------------------
    # Prepare report download artifacts and in-report result previews
    # ---------------------------
    $htmlReportsDirLocal = Get-HtmlReportsDir -BaseRoot $InputRoot
    $downloadsDirLocal = Get-HtmlDownloadsDir -BaseRoot $InputRoot
    Publish-CommonDownloadArtifacts -Root $InputRoot -DownloadRoot $downloadsDirLocal

    foreach ($finding in $Findings) {
        $presentation = New-FindingResultPresentation -Finding $finding -AuditReportPath $AuditHtml -DownloadRoot $downloadsDirLocal
        $finding | Add-Member -NotePropertyName DownloadHref -NotePropertyValue $presentation.DownloadHref -Force
        $finding | Add-Member -NotePropertyName DownloadLabel -NotePropertyValue $presentation.DownloadLabel -Force
        $finding | Add-Member -NotePropertyName DownloadText -NotePropertyValue $presentation.DownloadText -Force
        $finding | Add-Member -NotePropertyName ResultsHtml -NotePropertyValue $presentation.ResultsHtml -Force
        $finding | Add-Member -NotePropertyName OpenInNewTab -NotePropertyValue $presentation.OpenInNewTab -Force
        if ($presentation.ResolvedSourcePath) {
            $finding.Link = $presentation.ResolvedSourcePath
        }
    }

    # ---------------------------
    # Totals
    # ---------------------------
    $sevCounts = @{
        Critical    = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Critical'    }).Count
        High        = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'High'        }).Count
        Medium      = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Medium'      }).Count
        Low         = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Low'         }).Count
        Information = ($Findings | Where-Object { (($_.Severity -as [string]).Trim()) -ieq 'Information' }).Count
    }

    $TotalScore = 0
    foreach ($f in $Findings) { $TotalScore += [int]$f.Score }

    # ---------------------------
    # Score matrix + banding
    # ---------------------------
    $ScoreBands = @(
        [PSCustomObject]@{
            Level   = 'Low'
            Range   = '0 - 49'
            Meaning = 'Minor control gaps or baseline drift. Address during routine maintenance and continue monitoring.'
        }
        [PSCustomObject]@{
            Level   = 'Medium'
            Range   = '50 - 99'
            Meaning = 'Noticeable control gaps. Plan remediation in the next hardening cycle and track to closure.'
        }
        [PSCustomObject]@{
            Level   = 'High'
            Range   = '100 - 149'
            Meaning = 'Major control gaps. Prioritize remediation and validate that administrative controls are applied consistently.'
        }
        [PSCustomObject]@{
            Level   = 'Critical'
            Range   = '150+'
            Meaning = 'Significant control gaps or privileged configuration drift. Treat as a priority workstream with defined owners and timelines.'
        }
    )

    function Get-ScoreBand([int]$score) {
        if ($score -ge 150) { return 'Critical' }
        elseif ($score -ge 100) { return 'High' }
        elseif ($score -ge 50) { return 'Medium' }
        else { return 'Low' }
    }

    $OverallLevel = Get-ScoreBand $TotalScore

    $bandNow = $OverallLevel
    $scoreMatrixRows = foreach ($b in $ScoreBands) {
        $isActive = ($b.Level -eq $bandNow)
        $cls = if ($isActive) { "matrix-row active sev-$($b.Level)" } else { "matrix-row sev-$($b.Level)" }
@"
<tr class="$cls">
  <td><span class="pill sev-$($b.Level)">$($b.Level)</span></td>
  <td class="mono">$($b.Range)</td>
  <td class="matrix-meaning">$(HtmlEncode $b.Meaning)</td>
</tr>
"@
    }

    # ---------------------------
    # HTML output
    # ---------------------------
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
    $computerName = Split-Path -Path $InputRoot -Leaf

    $domainInfoBlock = ''
    try {
        if ($baselinePath -and (Test-Path -LiteralPath $baselinePath)) {
            $domainInfoBlock = (Get-Content -LiteralPath $baselinePath -ErrorAction SilentlyContinue) -join "`n"
        }
    } catch { }

    $sortedFindings = $Findings | Sort-Object -Property @{Expression={ Get-SeverityRank $_.Severity };Descending=$true}, @{Expression='Score';Descending=$true}, @{Expression='Title';Descending=$false}

    $companionReports = Get-CompanionHtmlReports -Root $InputRoot -Exclude @($AuditHtml, $OutputHtml)
    Write-AuditHtmlReport -Path $AuditHtml -Items $sortedFindings -Counts $sevCounts -ComputerName $computerName -GeneratedOn $now -ManagementReportPath $OutputHtml -CompanionReports $companionReports

    $auditRel = [System.IO.Path]::GetFileName($AuditHtml)
    $tableRows = foreach ($f in $sortedFindings) {
        $sev      = Normalize-Severity $f.Severity
        $score    = [int]$f.Score
        $anchorId = New-FindingAnchor $f
        $auditRef = '{0}#{1}' -f $auditRel, $anchorId
        $sourceLabel = Get-FindingSourceLabel $f.Link
@"
<tr data-sev="$sev" data-score="$score">
  <td><span class="pill sev-$sev">$sev</span></td>
  <td class="title">$(HtmlEncode $f.Title)</td>
  <td class="evidence">$(HtmlEncode $f.Evidence)</td>
  <td class="score">$score</td>
  <td class="source"><a href="$(HtmlAttrEncode $auditRef)" title="$(HtmlAttrEncode $sourceLabel)"><span class="mono">Audit details</span></a></td>
</tr>
"@
    }

    $meaning = switch ($OverallLevel) {
        'Critical' { 'The overall score indicates significant gaps relative to the defined baselines. Prioritize remediation for the highest-severity items and confirm governance for privileged access and password controls.' }
        'High'     { 'The overall score indicates material gaps relative to the defined baselines. Prioritize remediation and validate that controls are applied consistently across the environment.' }
        'Medium'   { 'The overall score indicates moderate gaps relative to the defined baselines. Plan remediation in the next hardening cycle and track progress to closure.' }
        Default    { 'The overall score indicates minor gaps relative to the defined baselines. Address as part of routine maintenance and continue monitoring.' }
    }

    $nextSteps = switch ($OverallLevel) {
        'Critical' { @(
            'Assign owners for Critical findings and define target dates for remediation.'
            'Review privileged group membership (Domain Admins / Schema Admins / built-in administrators) and ensure membership is justified, documented, and reviewed regularly.'
            'Reduce standing privilege and align with tiering (Tier 0 vs Tier 1 separation). Avoid Tier0+Tier1 overlap.'
            'Address password control items (duplicate passwords, PasswordNeverExpires usage, KRBTGT rotation policy) and confirm they align with operational requirements.'
            'Disable reversible password encryption and remediate affected accounts (password reset + policy review).'
            'Re-run the assessment after remediation to confirm closure and reduce configuration drift.'
        ) }
        'High' { @(
            'Prioritize High findings and track remediation to closure.'
            'Validate privileged access governance (membership reviews, approvals, and change tracking).'
            'Reduce standing privilege and align with tiering (Tier 0 vs Tier 1 separation).'
            'Standardize account lifecycle controls (inactive accounts, disabled account review cadence).'
            'Re-run the assessment after changes to confirm improvements.'
        ) }
        'Medium' { @(
            'Plan remediation for Medium findings in the next hardening cycle.'
            'Ensure baseline expectations and exception handling are documented and reviewed periodically.'
            'Re-run the assessment on a regular cadence to monitor drift.'
        ) }
        Default { @(
            'Address Low findings through routine maintenance.'
            'Continue periodic reviews of privileged access and baseline drift.'
            'Re-run the assessment after major changes.'
        ) }
    }
    $nextStepsHtml = ($nextSteps | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join "`n"

    $css = @"
<style>
:root{
  --bg:#0b1220; --text:#e8edf6; --muted:#b7c0d6; --line:rgba(255,255,255,.10);
  --shadow:0 10px 30px rgba(0,0,0,.35); --radius:14px;
  --critical-bg:rgba(255,77,79,.18); --high-bg:rgba(255,169,64,.18);
  --medium-bg:rgba(105,177,255,.18); --low-bg:rgba(149,222,100,.18);
  --info-bg:rgba(160,160,160,.18);
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
  background: radial-gradient(1200px 700px at 20% 10%, rgba(105,177,255,.18), transparent 60%),
              radial-gradient(1200px 700px at 80% 0%, rgba(255,169,64,.16), transparent 55%),
              var(--bg);
  color:var(--text);
}
a{color:#cfe1ff;text-decoration:none} a:hover{text-decoration:underline}
.container{max-width:1200px;margin:0 auto;padding:28px 20px 60px}
.header{
  background: linear-gradient(135deg, rgba(255,255,255,.08), rgba(255,255,255,.02));
  border:1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow);
  padding:22px 22px 18px;
}
.h-title{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;flex-wrap:wrap}
h1{font-size:22px;margin:0 0 6px;letter-spacing:.2px}
.meta{color:var(--muted);font-size:13px}
.badge{
  display:inline-flex;align-items:center;gap:10px;
  padding:10px 12px;border-radius:999px;border:1px solid var(--line);
  background: rgba(255,255,255,.06); font-weight:700;
}
.badge .grade{font-size:13px;color:var(--muted);font-weight:600}
.badge .value{font-size:15px}
.badge.Critical{background:var(--critical-bg)} .badge.High{background:var(--high-bg)}
.badge.Medium{background:var(--medium-bg)} .badge.Low{background:var(--low-bg)} .badge.Information{background:var(--info-bg)}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px;margin-top:14px}
.card{
  background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
  border:1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow);
  padding:14px 14px 12px; min-height:88px;
}
.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em}
.card .v{font-size:22px;font-weight:800;margin-top:6px}
.card .s{margin-top:4px;color:var(--muted);font-size:12px}
.span-3{grid-column:span 3} .span-4{grid-column:span 4}
.pill{
  display:inline-flex;align-items:center;justify-content:center;
  padding:4px 10px;border-radius:999px;font-weight:800;font-size:12px;
  border:1px solid var(--line);
  min-width:86px;
}
.sev-Critical{background:var(--critical-bg)} .sev-High{background:var(--high-bg)}
.sev-Medium{background:var(--medium-bg)} .sev-Low{background:var(--low-bg)} .sev-Information{background:var(--info-bg)}
.section{margin-top:18px} .section h2{margin:0 0 10px;font-size:16px}
.callout{border:1px solid var(--line);border-radius: var(--radius);padding:14px;background: rgba(255,255,255,.05)}
.callout p{margin:0;line-height:1.4} .callout ul{margin:10px 0 0 18px} .callout li{margin:6px 0}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between;margin:10px 0}
.filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
select,input{
  background:rgba(255,255,255,.06);
  color:var(--text);
  border:1px solid var(--line);
  border-radius:10px;
  padding:8px 10px;
  outline:none;
}
input{min-width:240px}
small{color:var(--muted)}
select option{ background:#0b1220; color:#ffffff; }
table{width:100%;border-collapse:collapse;border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;background:rgba(255,255,255,.03)}
th,td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em;background: rgba(255,255,255,.05);cursor:pointer;user-select:none}
tr:hover td{background:rgba(255,255,255,.04)}
td.score{font-weight:800} td.title{font-weight:700}
.mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace}
td.source .mono{font-size:12px;color:#d7e6ff}
pre{white-space:pre-wrap;background:rgba(0,0,0,.25);border:1px solid var(--line);border-radius: var(--radius);padding:12px;color:#dbe6ff;overflow:auto}
.footer{margin-top:16px;color:var(--muted);font-size:12px}
.matrix-wrap{margin-top:10px}
table.matrix{ table-layout:fixed; }
table.matrix th, table.matrix td{ padding:14px 18px; }
table.matrix th{ cursor:default; }
table.matrix th:nth-child(1), table.matrix td:nth-child(1){ width:18%; padding-left:22px; }
table.matrix th:nth-child(2), table.matrix td:nth-child(2){ width:18%; text-align:center; }
table.matrix th:nth-child(3), table.matrix td:nth-child(3){ width:64%; padding-left:22px; }
.matrix-row.active td{background:rgba(255,255,255,.06)}
</style>
"@

    $js = @"
<script>
(function(){
  function q(sel){return document.querySelector(sel);}
  function qa(sel){return Array.prototype.slice.call(document.querySelectorAll(sel));}
  function rows(){return qa('#findings-body tr');}

  function applyFilters(){
    var sev = q('#sevFilter').value;
    var s = (q('#search').value || '').toLowerCase().trim();
    var visible = 0;

    rows().forEach(function(r){
      var rsev = r.getAttribute('data-sev');
      var text = (r.innerText || '').toLowerCase();
      var okSev = (sev === 'All') || (rsev === sev);
      var okSearch = (!s) || (text.indexOf(s) >= 0);
      var show = okSev && okSearch;
      r.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    q('#visibleCount').innerText = visible;
  }

  var sortCol = null;
  var sortAsc = false;
  var order = ['Critical','High','Medium','Low','Information'];

  function sortBy(col){
    sortAsc = (sortCol === col) ? !sortAsc : true;
    sortCol = col;

    var arr = rows().slice().sort(function(a,b){
      var ka, kb;
      if(col === 'severity'){
        ka = order.indexOf(a.getAttribute('data-sev'));
        kb = order.indexOf(b.getAttribute('data-sev'));
      } else if(col === 'score'){
        ka = parseInt(a.getAttribute('data-score') || '0',10);
        kb = parseInt(b.getAttribute('data-score') || '0',10);
      } else if(col === 'title'){
        ka = (a.querySelector('.title') || {}).innerText || '';
        kb = (b.querySelector('.title') || {}).innerText || '';
      } else {
        ka = a.innerText; kb = b.innerText;
      }
      if(ka < kb) return sortAsc ? -1 : 1;
      if(ka > kb) return sortAsc ? 1 : -1;
      return 0;
    });

    var tbody = q('#findings-body');
    arr.forEach(function(r){tbody.appendChild(r);});
    applyFilters();
  }

  q('#sevFilter').addEventListener('change', applyFilters);
  q('#search').addEventListener('input', applyFilters);
  qa('th[data-sort]').forEach(function(th){
    th.addEventListener('click', function(){ sortBy(th.getAttribute('data-sort')); });
  });

  applyFilters();
  sortBy('score'); sortBy('score');
})();
</script>
"@

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD Audit - Risk Report</title>
$css
</head>
<body>
<div class="container">
  <div class="header">
    <div class="h-title">
      <div>
        <h1>Active Directory Audit - Risk Report</h1>
        <div class="meta">Target: <span class="mono">$(HtmlEncode $computerName)</span> | Generated: $(HtmlEncode $now) | <a href="$(HtmlAttrEncode ([System.IO.Path]::GetFileName($AuditHtml)))">Detailed audit report</a></div>
        <div class="meta" style="margin-top:4px">Script: <span class="mono">$versionnum</span> | Run by: <span class="mono">$(HtmlEncode "$env:USERDOMAIN\$env:USERNAME")</span> | Start: $(HtmlEncode "$starttime") | End: $(HtmlEncode "$endtime")</div>
      </div>
      <div class="badge $OverallLevel">
        <div>
          <div class="grade">Overall Risk</div>
          <div class="value">$OverallLevel</div>
        </div>
        <div style="width:1px;height:28px;background:var(--line)"></div>
        <div>
          <div class="grade">Score</div>
          <div class="value">$TotalScore</div>
        </div>
      </div>
    </div>

    <div class="grid">
      <div class="card span-3"><div class="k">Critical findings</div><div class="v">$($sevCounts.Critical)</div><div class="s">Immediate remediation</div></div>
      <div class="card span-3"><div class="k">High findings</div><div class="v">$($sevCounts.High)</div><div class="s">Prioritize</div></div>
      <div class="card span-3"><div class="k">Medium findings</div><div class="v">$($sevCounts.Medium)</div><div class="s">Plan hardening</div></div>
      <div class="card span-3"><div class="k">Low findings</div><div class="v">$($sevCounts.Low)</div><div class="s">Maintain baseline</div></div>

      <div class="card span-4"><div class="k">Users</div><div class="v">$(DisplayOrDash $UsersCount)</div><div class="s">From ADExtract (if present)</div></div>
      <div class="card span-4"><div class="k">Groups</div><div class="v">$(DisplayOrDash $GroupsCount)</div><div class="s">From ADExtract (if present)</div></div>
      <div class="card span-4"><div class="k">OUs</div><div class="v">$(DisplayOrDash $OUsCount)</div><div class="s">From ADExtract (if present)</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Interpretation</h2>
    <div class="callout">
      <p><b>What this means:</b> $(HtmlEncode $meaning)</p>

      <div class="matrix-wrap">
        <p style="margin-top:12px"><b>Score matrix:</b> The total score is mapped to a risk level as follows (current score highlighted).</p><br>
        <table class="matrix">
          <thead>
            <tr>
              <th>Level</th>
              <th>Score range</th>
              <th>Interpretation</th>
            </tr>
          </thead>
          <tbody>
            $(($scoreMatrixRows -join "`n"))
          </tbody>
        </table>
      </div>

      <p style="margin-top:12px"><b>Recommended next steps:</b></p>
      <ul>
        $nextStepsHtml
      </ul>

      <div class="footer">Note: This score is an index based on the findings included in this report and the collected audit data embedded into the generated HTML reports. Validate scope and collection completeness.</div>
    </div>
  </div>

  <div class="section">
    <h2>Findings by Category</h2>
    <table style="width:100%;border-collapse:collapse;margin-bottom:18px">
      <thead><tr><th style="text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)">Category</th><th style="text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)">Critical</th><th style="text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)">High</th><th style="text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)">Medium</th><th style="text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)">Low</th><th style="text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)">Total</th></tr></thead>
      <tbody>
$(
    $catGroups = $Findings | ForEach-Object { [pscustomobject]@{ Category = (Get-FindingCategory $_.Title); Severity = (Normalize-Severity $_.Severity) } } | Group-Object Category | Sort-Object @{Expression={($_.Group | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object).Count};Descending=$true}, @{Expression={($_.Group | Where-Object { $_.Severity -eq 'High' } | Measure-Object).Count};Descending=$true}, Name
    foreach ($cg in $catGroups) {
        $cc = ($cg.Group | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object).Count
        $ch = ($cg.Group | Where-Object { $_.Severity -eq 'High' } | Measure-Object).Count
        $cm = ($cg.Group | Where-Object { $_.Severity -eq 'Medium' } | Measure-Object).Count
        $cl = ($cg.Group | Where-Object { $_.Severity -eq 'Low' } | Measure-Object).Count
        $ct = $cg.Count
        "<tr><td style='padding:6px 10px;border-bottom:1px solid var(--line)'>$(HtmlEncode $cg.Name)</td><td style='text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)'>$(if($cc -gt 0){"<span class='pill sev-Critical'>$cc</span>"}else{'-'})</td><td style='text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)'>$(if($ch -gt 0){"<span class='pill sev-High'>$ch</span>"}else{'-'})</td><td style='text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)'>$(if($cm -gt 0){"<span class='pill sev-Medium'>$cm</span>"}else{'-'})</td><td style='text-align:center;padding:6px 10px;border-bottom:1px solid var(--line)'>$(if($cl -gt 0){"<span class='pill sev-Low'>$cl</span>"}else{'-'})</td><td style='text-align:center;padding:6px 10px;border-bottom:1px solid var(--line);font-weight:700'>$ct</td></tr>"
    }
)
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Findings</h2>
    <div class="toolbar">
      <div class="filters">
        <label>
          <small>Severity</small><br>
          <select id="sevFilter">
            <option>All</option>
            <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
            <option>Information</option>
          </select>
        </label>
        <label>
          <small>Search</small><br>
          <input id="search" type="text" placeholder="Search title/evidence/source...">
        </label>
      </div>
      <div>
        <small>Visible: <span id="visibleCount">0</span> / $($Findings.Count)</small>
      </div>
    </div>

    <table id="findings">
      <thead>
        <tr>
          <th data-sort="severity">Severity</th>
          <th data-sort="title">Finding</th>
          <th>Evidence</th>
          <th data-sort="score">Score</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody id="findings-body">
        $(($tableRows -join "`n"))
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Baseline and Notes</h2>
    <pre>$(HtmlEncode $domainInfoBlock)</pre>
  </div>

  <div class="footer">
    Generated by the Risk Report script. Review the linked ADAudit-Results.html findings for remediation actions.<br>
    This report summarizes configuration and baseline observations. It should be reviewed alongside operational context and existing compensating controls.
  </div>
</div>

$js
</body>
</html>
"@

    Set-Content -LiteralPath $OutputHtml -Value $html -Encoding UTF8

    if ($OutputTxt) {
        # ---------------------------
        # Optional TXT output
        # ---------------------------
        $top = ($Findings | Sort-Object -Property @{Expression='Score';Descending=$true}) | Select-Object -First $TopFindings

        $txt = @()
        $txt += "Active Directory Audit - Risk Report"
        $txt += "Target: $computerName"
        $txt += "Generated: $now"
        $txt += "Overall risk level: $OverallLevel (Score=$TotalScore)"
        $txt += "Score matrix: Low=0-49; Medium=50-99; High=100-149; Critical=150+"
        if ($UsersCount)  { $txt += "Users: $UsersCount" }
        if ($GroupsCount) { $txt += "Groups: $GroupsCount" }
        if ($OUsCount)    { $txt += "OUs: $OUsCount" }
        $txt += ""
        $txt += "Top findings:"
        foreach ($f in $top) { $txt += "- [$($f.Severity)] $($f.Title) - $($f.Evidence) (source: $($f.Link))" }
        $txt += ""
        $txt += "See HTML report for linked detailed findings."

        Set-Content -LiteralPath $OutputTxt -Value ($txt -join "`r`n") -Encoding UTF8
        Write-Host "[+] Executive TXT summary written:" (Get-RelPath $OutputTxt)
    }

    Write-Host "[+] Audit results written:" (Get-RelPath $AuditHtml)
    Write-Host "[+] Risk report written:" (Get-RelPath $OutputHtml)
}

function Get-RelativeReportHref {
    [CmdletBinding()]
    param(
        [string]$FromFile,
        [string]$ToPath
    )

    if ([string]::IsNullOrWhiteSpace($FromFile) -or [string]::IsNullOrWhiteSpace($ToPath)) { return '' }

    try {
        $fromDir = Split-Path -Path $FromFile -Parent
        $fromAbs = [System.IO.Path]::GetFullPath($fromDir)
        $targetAbs = [System.IO.Path]::GetFullPath($ToPath)

        $baseUri = New-Object System.Uri(($fromAbs.TrimEnd('\') + '\'))
        $targetUri = New-Object System.Uri($targetAbs)
        return ([System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($targetUri).ToString()) -replace '\\','/')
    } catch {
        return [System.IO.Path]::GetFileName($ToPath)
    }
}

function Get-CompanionHtmlReportTitle {
    [CmdletBinding()]
    param([string]$FileName)

    switch -Regex ($FileName) {
        '^GPOReport\.html$'                     { return 'Group Policy report' }
        '^overlapping_group_memberships\.html$' { return 'Overlapping group membership report' }
        '^multiple_nested_paths\.html$'        { return 'Multiple nested paths report' }
        '^dangerousACLs\.html$'                { return 'Dangerous ACL report' }
        '^ad_high_risk_baseline_index\.html$'  { return 'High-risk baseline report' }
        '^index\.html$'                        { return 'Delegated permissions report' }
        '^DNSAudit-.*\.html$'                  { return 'DNS audit report' }
        '^DNS-Recommendations-.*\.html$'       { return 'DNS recommendations report' }
        default                                { return ($FileName -replace '\.html$','' -replace '[-_]+',' ') }
    }
}

function Get-CompanionHtmlShellCandidates {
    [CmdletBinding()]
    param([string]$Root)

    $items = New-Object 'System.Collections.Generic.List[System.IO.FileInfo]'
    $seen  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    function Add-File([System.IO.FileInfo]$File) {
        if (-not $File) { return }
        $full = $null
        try { $full = [System.IO.Path]::GetFullPath($File.FullName) } catch { $full = $File.FullName }
        if ($seen.Add($full)) { $items.Add($File) | Out-Null }
    }

    $htmlRoot = Get-HtmlReportsDir -BaseRoot $Root
    if (Test-Path -LiteralPath $htmlRoot) {
        foreach ($file in (Get-ChildItem -LiteralPath $htmlRoot -File -Filter '*.html' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @('Risk-Report.html','ADAudit-Results.html') -and $_.Name -notmatch '\.source\.html$' })) {
            Add-File $file
        }
    }

    foreach ($file in (Get-ChildItem -Path (Join-Path (Get-RawDataDir -BaseRoot $Root) 'DelegatedPermissions') -Recurse -File -Filter 'index.html' -ErrorAction SilentlyContinue)) {
        Add-File $file
    }

    foreach ($file in (Get-ChildItem -Path $Root -Recurse -File -Include 'DNSAudit-*.html','DNS-Recommendations-*.html' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.source\.html$' })) {
        Add-File $file
    }

    return $items.ToArray()
}

function Update-CompanionHtmlReports {
    [CmdletBinding()]
    param([string]$Root)

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return }

    $auditPath = Join-Path (Get-HtmlReportsDir -BaseRoot $Root) 'ADAudit-Results.html'

    foreach ($file in (Get-CompanionHtmlShellCandidates -Root $Root)) {
        $targetPath = $file.FullName
        $rawHtml = ''
        try { $rawHtml = Get-Content -LiteralPath $targetPath -Raw -ErrorAction Stop } catch { continue }
        if ([string]::IsNullOrWhiteSpace($rawHtml)) { continue }
        if ($rawHtml -match 'adaudit-companion-wrapper') { continue }

        $bodyHtml = $rawHtml
        if ($rawHtml -match '(?is)<body[^>]*>(?<body>.*)</body>') {
            $bodyHtml = $matches['body']
        }

        $styleBlocks = @(
            [regex]::Matches($rawHtml, '(?is)<style[^>]*>.*?</style>') |
            ForEach-Object { $_.Value }
        )

        $sourcePath = Join-Path $file.DirectoryName (([System.IO.Path]::GetFileNameWithoutExtension($file.Name)) + '.source.html')
        if (Test-Path -LiteralPath $sourcePath) {
            Remove-Item -LiteralPath $sourcePath -Force -ErrorAction SilentlyContinue
        }

        Move-Item -LiteralPath $targetPath -Destination $sourcePath -Force -ErrorAction SilentlyContinue

        $title = Get-CompanionHtmlReportTitle -FileName $file.Name
        $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
        $auditHref = if (Test-Path -LiteralPath $auditPath) { Get-RelativeReportHref -FromFile $targetPath -ToPath $auditPath } else { '' }
        $sourceHref = Get-RelativeReportHref -FromFile $targetPath -ToPath $sourcePath

        $wrapper = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="adaudit-companion-wrapper" content="1">
<title>ADAudit - $title</title>
$($styleBlocks -join "`n")
<style>
:root{
  --bg:#f5f7fb;
  --panel:#ffffff;
  --text:#1b2430;
  --muted:#5f6b7a;
  --line:#d9e0ea;
  --shadow:0 10px 24px rgba(15,23,42,.08);
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family:Segoe UI,Arial,sans-serif;
  background:var(--bg);
  color:var(--text);
}
a{color:#0f5cb8;text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1280px;margin:0 auto;padding:28px 22px 48px}
.hero,.panel{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:18px;
  box-shadow:var(--shadow);
}
.hero{padding:24px}
.panel{padding:22px;margin-top:20px}
.hero-top{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;align-items:flex-start}
.meta{color:var(--muted);font-size:14px;line-height:1.6}
.actions{display:flex;gap:10px;flex-wrap:wrap}
.btn{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:40px;
  padding:10px 14px;
  border-radius:10px;
  border:1px solid var(--line);
  background:var(--panel);
  color:var(--text);
  font-weight:700;
}
.embedded-report{margin-top:8px}
.embedded-report table{border-collapse:collapse;width:100%}
.embedded-report th,.embedded-report td{border:1px solid var(--line);padding:8px 10px;vertical-align:top;text-align:left}
.embedded-report th{background:#eef2f7}
.embedded-report pre{
  white-space:pre-wrap;
  word-break:break-word;
  background:#f8fafc;
  border:1px solid var(--line);
  border-radius:12px;
  padding:14px;
}
.embedded-report code{
  font-family:Consolas,Menlo,Monaco,monospace;
  background:#f3f4f6;
  padding:2px 4px;
  border-radius:4px;
}
.embedded-report details{
  border:1px solid var(--line);
  border-radius:12px;
  padding:12px;
  margin:12px 0;
  background:#fafcff;
}
.embedded-report summary{cursor:pointer;font-weight:700}
.embedded-report h1,.embedded-report h2,.embedded-report h3,.embedded-report h4{margin-top:0}
</style>
</head>
<body>
<div class="container">
  <section class="hero">
    <div class="hero-top">
      <div>
        <h1>$title</h1>
        <div class="meta">
          Companion HTML report generated by ADAudit.<br>
          Generated wrapper: $generated
        </div>
      </div>
      <div class="actions">
        $(if ($auditHref) { "<a class='btn' href='$auditHref'>Back to ADAudit-Results</a>" } else { '' })
        <a class="btn" href="$sourceHref" target="_blank" rel="noopener">Open original HTML</a>
      </div>
    </div>
  </section>

  <section class="panel">
    <div class="embedded-report">
      $bodyHtml
    </div>
  </section>
</div>
</body>
</html>
"@

        Set-Content -LiteralPath $targetPath -Value $wrapper -Encoding UTF8
    }
}

function Get-LegacyArtifactCandidates {
    [CmdletBinding()]
    param(
        [string]$Root
    )

    $items = New-Object 'System.Collections.Generic.List[System.IO.FileInfo]'
    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return @() }

    $rootExts = @('.txt','.csv','.xml','.json','.nessus')
    $highRiskExts = @('.txt','.csv','.json')

    foreach ($file in (Get-ChildItem -LiteralPath $Root -File -ErrorAction SilentlyContinue | Where-Object { $rootExts -contains $_.Extension.ToLowerInvariant() })) {
        $items.Add($file) | Out-Null
    }

    $highRiskDir = Join-Path $Root 'HighRisk'
    if (Test-Path -LiteralPath $highRiskDir) {
        foreach ($file in (Get-ChildItem -LiteralPath $highRiskDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $highRiskExts -contains $_.Extension.ToLowerInvariant() })) {
            $items.Add($file) | Out-Null
        }
    }

    return @($items | Sort-Object FullName -Unique)
}

function Remove-EmptyAuditDirectories {
    [CmdletBinding()]
    param(
        [string]$Root,
        [string[]]$Exclude = @()
    )

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return }

    $excludeMap = @{}
    foreach ($path in $Exclude) {
        if (-not [string]::IsNullOrWhiteSpace($path)) {
            try { $excludeMap[[System.IO.Path]::GetFullPath($path)] = $true } catch { }
        }
    }

    foreach ($dir in (Get-ChildItem -Path $Root -Recurse -Directory -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
        $full = $null
        try { $full = [System.IO.Path]::GetFullPath($dir.FullName) } catch { $full = $dir.FullName }
        if ($excludeMap.ContainsKey($full)) { continue }

        try {
            if (-not (Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue)) {
                Remove-Item -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }
}

function Remove-LegacyAuditArtifacts {
    [CmdletBinding()]
    param(
        [string]$Root
    )

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return }

    $removed = 0
    foreach ($file in (Get-LegacyArtifactCandidates -Root $Root)) {
        try {
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            $removed++
        } catch { }
    }

    Remove-EmptyAuditDirectories -Root $Root -Exclude @((Get-HtmlReportsDir -BaseRoot $Root), (Get-RawDataDir -BaseRoot $Root))

    if ($removed -gt 0) {
        Write-Host "[+] Removed raw TXT/CSV/XML/JSON/NESSUS audit artifacts from the output tree."
    }
}

function Move-LegacyAuditArtifacts {
    [CmdletBinding()]
    param(
        [string]$Root,
        [string]$ArchiveRoot
    )

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return }
    if ([string]::IsNullOrWhiteSpace($ArchiveRoot)) { $ArchiveRoot = Get-RawSourceDataDir -BaseRoot $Root }

    if (-not (Test-Path -LiteralPath $ArchiveRoot)) {
        New-Item -ItemType Directory -Path $ArchiveRoot -Force | Out-Null
    }

    $rootAbs = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $moved = 0

    foreach ($file in (Get-LegacyArtifactCandidates -Root $Root)) {
        try {
            $full = [System.IO.Path]::GetFullPath($file.FullName)
            $relative = $full.Substring($rootAbs.Length).TrimStart('\','/')
            $destination = Join-Path $ArchiveRoot $relative
            $destinationDir = Split-Path -Path $destination -Parent
            if ($destinationDir -and -not (Test-Path -LiteralPath $destinationDir)) {
                New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
            }

            Move-Item -LiteralPath $file.FullName -Destination $destination -Force -ErrorAction Stop
            $moved++
        } catch { }
    }

    Remove-EmptyAuditDirectories -Root $Root -Exclude @((Get-HtmlReportsDir -BaseRoot $Root), $ArchiveRoot)

    if ($moved -gt 0) {
        Write-Host "[+] Moved raw TXT/CSV/XML/JSON/NESSUS audit artifacts to:" $ArchiveRoot
    }
}

function Move-RootHtmlReports {
    [CmdletBinding()]
    param(
        [string]$Root,
        [string]$Destination
    )

    if ([string]::IsNullOrWhiteSpace($Root) -or -not (Test-Path -LiteralPath $Root)) { return }
    if ([string]::IsNullOrWhiteSpace($Destination)) { $Destination = Get-HtmlReportsDir -BaseRoot $Root }

    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    foreach ($file in (Get-ChildItem -LiteralPath $Root -File -Filter '*.html' -ErrorAction SilentlyContinue)) {
        $destFile = Join-Path $Destination $file.Name
        try {
            $srcFull = [System.IO.Path]::GetFullPath($file.FullName)
            $destFull = [System.IO.Path]::GetFullPath($destFile)
            if ($srcFull -ieq $destFull) { continue }
            Move-Item -LiteralPath $file.FullName -Destination $destFile -Force -ErrorAction Stop
        } catch { }
    }
}

Move-RootHtmlReports -Root $outputdir -Destination (Get-HtmlReportsDir -BaseRoot $outputdir)
Move-LegacyAuditArtifacts -Root $outputdir -ArchiveRoot (Get-RawSourceDataDir -BaseRoot $outputdir)
Invoke-ManagementReport -InputRoot $outputdir -OutputHtml (Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'Risk-Report.html') -AuditHtml (Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'ADAudit-Results.html')
Update-CompanionHtmlReports -Root $outputdir

# <<< add cleanup here (absolute last action) >>>
$__htmlReportsDir = Get-HtmlReportsDir -BaseRoot $outputdir
$__remove = @(
    'ad_high_risk_baseline_index.source.html'
    'GPOReport.html'
    'overlapping_group_memberships.source.html'
)
foreach ($name in $__remove) {
    $p = Join-Path $__htmlReportsDir $name
    if (Test-Path -LiteralPath $p) {
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    }
}
}
finally {
    $ErrorActionPreference = $oldEap
}

<#
    .NOTES
        Author       : phillips321.co.uk
        Creation Date: 16/08/2018
        Script Name  : ADAudit.ps1
    .SYNOPSIS
        PowerShell Script to perform a quick AD audit
    .DESCRIPTION
        o Compatibility :
            * PowerShell v2.0 (PowerShell 5.0 needed if you intend to use DSInternals PowerShell module)
            * Tested on Windows Server 2008R2/2012/2012R2/2016/2019/2022
            * All languages (you may need to adjust $AdministratorTranslation variable)
        o Requirements :
            * ActiveDirectory PowerShell module (installed with RSAT tools)
            * DnsServer PowerShell module (installed with DNS Server role)
            * AdmPwd.PS PowerShell module (optional, installed with LAPS)
            * DSInternals and NuGet PowerShell module, installed by script if -installdeps switch is used)
              Offline installation help using ADAudit-run.ps1 script
        o Changelog :
            [X] Version 7.1.1 - 24/12/2025
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
    [switch]$passwordpolicy = $false,
    [switch]$ntds = $false,
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
    [switch]$all = $false,
    [string[]]$exclude = @(),
    [string]$select
)

$selectedChecks = @()
if ($select) { $selectedChecks = $select.Split(',') }

$versionnum = "v7.1.2"
$AdministratorTranslation = @("Administrator", "Administrateur", "Administrador")#If missing put the default Administrator name for your own language here

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
    #Writes to console screen and output file
    Write-Host "$args"
    Add-Content -Path "$outputdir\consolelog.txt" -Value "$args"
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
        Import-Module ActiveDirectory -ErrorAction Stop
        Import-Module DnsServer -ErrorAction Stop
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

    $globalInsecureZonesFile = "$outputdir\insecure_dns_zones.txt"
    if (Test-Path $globalInsecureZonesFile) {
        Remove-Item $globalInsecureZonesFile -Force
    }

    $totalcount = 0

    foreach ($dnsServer in $dcList) {

        Write-Both "    [*] Checking potential DNS server: $dnsServer"

        # Optional: check remote OS version to skip 2008 if needed
        $skipServer = $false
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $dnsServer -ErrorAction Stop
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
        if ($OSVersion -like "Windows Server 2019*" -or $OSVersion -like "Windows Server 2022*") {
            $output = (Get-Acl "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$object").Access | Where-Object { ($_.IdentityReference -eq "$AuthenticatedUsers") -or ($_.IdentityReference -eq "$EveryOne") -or ($_.IdentityReference -like "*\$DomainUsers") -or ($_.IdentityReference -eq "BUILTIN\$Users") } | Where-Object { ($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'GenericExecute') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.ActiveDirectoryRights -ne 'ListObject') -and ($_.ActiveDirectoryRights -ne 'ListChildren') -and ($_.ActiveDirectoryRights -ne 'ListChildren, ReadProperty, ListObject') -and ($_.ActiveDirectoryRights -ne 'ReadProperty, GenericExecute') -and ($_.AccessControlType -ne 'Deny') }
        }
        else {
            $output = (Get-Acl AD:$object).Access                                                                    | Where-Object { ($_.IdentityReference -eq "$AuthenticatedUsers") -or ($_.IdentityReference -eq "$EveryOne") -or ($_.IdentityReference -like "*\$DomainUsers") -or ($_.IdentityReference -eq "BUILTIN\$Users") } | Where-Object { ($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'GenericExecute') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.ActiveDirectoryRights -ne 'ListObject') -and ($_.ActiveDirectoryRights -ne 'ListChildren') -and ($_.ActiveDirectoryRights -ne 'ListChildren, ReadProperty, ListObject') -and ($_.ActiveDirectoryRights -ne 'ReadProperty, GenericExecute') -and ($_.AccessControlType -ne 'Deny') }
        }
        if ($output -ne $null) {
            $count++
            Add-Content -Path "$outputdir\ou_permissions.txt" -Value "OU: $object"
            Add-Content -Path "$outputdir\ou_permissions.txt" -Value "[!] Rights: $($output.IdentityReference) $($output.ActiveDirectoryRights) $($output.AccessControlType)"
        }
    }
    Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] Issue identified, see $outputdir\ou_permissions.txt"
        Write-Nessus-Finding "OUPermissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\ou_permissions.txt"))
    }
}
Function Get-LAPSStatus {
    #Check for presence of LAPS in domain
    try {
        Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$((Get-ADDomain).DistinguishedName)" -ErrorAction Stop | Out-Null
        Write-Both "    [+] LAPS Installed in domain"
    }
    catch {
        Write-Both "    [!] LAPS Not Installed in domain (KB258)"
        Write-Nessus-Finding "LAPSMissing" "KB258" "LAPS Not Installed in domain"
    }
    if (Get-Module -ListAvailable -Name AdmPwd.PS) {
        Import-Module AdmPwd.PS
        $count = 0
        $missingComputers = (Get-ADComputer -Filter { ms-Mcs-AdmPwd -notlike "*" }).Name
        $totalcount = ($missingComputers | Measure-Object | Select-Object Count).count
        if ($totalcount -gt 0) {
            $missingComputers | Add-Content -Path $outputdir\laps_missing-computers.txt
            Write-Both "    [!] Some computers/servers don't have LAPS password set, see $outputdir\laps_missing-computers.txt"
            Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText("$outputdir\laps_missing-computers.txt"))
        }
        $count = 0
        $computersList = (Get-ADComputer -Filter { ms-Mcs-AdmPwdExpirationTime -like "*" } -Properties ms-Mcs-AdmPwdExpirationTime | select Name, ms-Mcs-AdmPwdExpirationTime)
        foreach ($computer in $computersList ) {
            $expiration = [datetime]::FromFileTime($computer.'ms-Mcs-AdmPwdExpirationTime')
            $today = Get-Date
            if ($expiration -lt $today) {
                $count++
"@$($computer.Name) password is expired since $expiration" | Add-Content -Path $outputdir\laps_expired-passwords.txt
            }
        }
        if ($count -gt 0) {
            Write-Both "    [!] Some computers/servers have LAPS password expired, see $outputdir\laps_expired-passwords.txt"
            Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText("$outputdir\laps_expired-passwords.txt"))
        }
        Get-ADOrganizationalUnit -Filter * | Find-AdmPwdExtendedRights -PipelineVariable OU | foreach {
            $_.ExtendedRightHolders | foreach {
                if ($_ -ne $System) {
"@$_ can read password attribute of $($Ou.ObjectDN)" | Add-Content -Path $outputdir\laps_read-extendedrights.txt
                }
            }
        }
        Write-Both "    [!] LAPS extended rights exported, see $outputdir\laps_read-extendedrights.txt"
        Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText("$outputdir\laps_read-extendedrights.txt"))

    }
    else {
        Write-Both "    [!] LAPS PowerShell module is not installed, can't run LAPS checks on this DC"
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
        Add-Content -Path "$outputdir\accounts_userPrivileged.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts in privileged groups, see accounts_userPrivileged.txt (KB426)"
        Write-Nessus-Finding "AdminSDHolders" "KB426" ([System.IO.File]::ReadAllText("$outputdir\accounts_userPrivileged.txt"))
    }
}
Function Get-ProtectedUsers {
    #Lists users in "Protected Users" group (2012R2 and above)
    $DomainLevel = (Get-ADDomain).domainMode
    if ($DomainLevel -eq "Windows2012Domain" -or $DomainLevel -eq "Windows2012R2Domain" -or $DomainLevel -eq "Windows2016Domain") {
        #Checking for 2012 or above domain functional level
        $ProtectedUsersSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-525"
        $ProtectedUsers = (Get-ADGroup -Identity $ProtectedUsersSID).SamAccountName
        $count = 0
        $protectedaccounts = (Get-ADGroup $ProtectedUsers -Properties members).Members
        $totalcount = ($protectedaccounts | Measure-Object | Select-Object Count).count
        foreach ($members in $protectedaccounts) {
            if ($totalcount -eq 0) { break }
            Write-Progress -Activity "Searching for protected users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
            $account = Get-ADObject $members -Properties SamAccountName
            Add-Content -Path "$outputdir\accounts_protectedusers.txt" -Value "$($account.SamAccountName) ($($account.Name))"
            $count++
        }
        Write-Progress -Activity "Searching for protected users..." -Status "Ready" -Completed
        if ($count -gt 0) {
            Write-Both "    [!] There are $count accounts in the 'Protected Users' group, see accounts_protectedusers.txt"
            Write-Nessus-Finding "ProtectedUsers" "KB549" ([System.IO.File]::ReadAllText("$outputdir\accounts_protectedusers.txt"))
        }
    }
    else { Write-Both "    [-] Not Windows 2012 Domain Functional level or above, skipping Get-ProtectedUsers check." }
}
Function Get-AuthenticationPoliciesAndSilos {
    #Lists any authentication policies and silos (2012R2 and above)
    if ([single](Get-WinVersion) -ge [single]6.3) {
        #NT6.2 or greater detected so running this script
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
}
Function Get-MachineAccountQuota {
    #Get number of machines a user can add to a domain
    $MachineAccountQuota = (Get-ADDomain | select -ExpandProperty DistinguishedName | Get-ADObject -Property 'ms-DS-MachineAccountQuota' | select -ExpandProperty ms-DS-MachineAccountQuota)
    if ($MachineAccountQuota -gt 0) {
        Write-Both "    [!] Domain users can add $MachineAccountQuota devices to the domain! (KB251)"
        Write-Nessus-Finding "DomainAccountQuota" "KB251" "Domain users can add $MachineAccountQuota devices to the domain"
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
            Write-Both "    [!] Lockout threshold is less than 5, currently set to $($finegrainedpolicy).LockoutThreshold) (KB263)"
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
        Add-Content -Path "$outputdir\accounts_with_old_passwords.txt" -Value "User $($account.SamAccountName) ($($account.Name)) has not changed their password since $datelastchanged"
        $count++
    }
    Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count accounts with passwords older than 90days, see accounts_with_old_passwords.txt (KB550)"
        Write-Nessus-Finding "AccountsWithOldPasswords" "KB550" ([System.IO.File]::ReadAllText("$outputdir\accounts_with_old_passwords.txt"))
    }
    $krbtgtPasswordDate = (Get-ADUser -Filter { SamAccountName -eq "krbtgt" } -Properties PasswordLastSet).PasswordLastSet
    if ($krbtgtPasswordDate -lt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] krbtgt password not changed since $krbtgtPasswordDate! (KB253)"
        Write-Nessus-Finding "krbtgtPasswordNotChanged" "KB253" "krbtgt password not changed since $krbtgtPasswordDate"
    }
}
Function Get-GPOtoFile {
    #Outputs complete GPO report
    if (Test-Path "$outputdir\GPOReport.html") { Remove-Item "$outputdir\GPOReport.html" -Recurse }
    Get-GPOReport -All -ReportType HTML -Path "$outputdir\GPOReport.html"
    Write-Both "    [+] GPO Report saved to GPOReport.html"
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
        Add-Content -Path "$outputdir\ous_inheritedGPOs.txt" -Value "$($ouobject.Name) Inherits these GPOs: $combinedgpos"
        $count++
    }
    Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Ready" -Completed
    Write-Both "    [+] Inherited GPOs saved to ous_inheritedGPOs.txt"
}
Function Get-NTDSdit {
    #Dumps NTDS.dit, SYSTEM and SAM for password cracking
    if (Test-Path "$outputdir\ntds.dit") { Remove-Item "$outputdir\ntds.dit" -Recurse }
    $outputdirntds = '\"' + $outputdir + '\ntds.dit\"'
    $command = "ntdsutil `"ac in ntds`" `"ifm`" `"cr fu $outputdirntds `" q q"
    $hide = cmd.exe /c "$command" 2>&1
    Write-Both "    [+] NTDS.dit, SYSTEM & SAM saved to output folder"
    Write-Both "    [+] Use secretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL -outputfile customer"
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
    #Lists accounts not used in past 180 days plus some checks for admin accounts
    $count = 0
    $progresscount = 0
    $inactiveaccounts = Search-ADaccount -AccountInactive -Timespan (New-TimeSpan -Days 180) -UsersOnly | Where-Object { $_.Enabled -eq $true }
    $totalcount = ($inactiveaccounts | Measure-Object | Select-Object Count).count

    if ($totalcount -gt 0) {
        # Header (overwrite any existing file)
"@Accounts inactive (no logon) for the past 180 days" | Set-Content -Path "$outputdir\accounts_inactive.txt"
    }

    foreach ($account in $inactiveaccounts) {
        if ($totalcount -eq 0) { break }
        $progresscount++
        Write-Progress -Activity "Searching for inactive users..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
        if ($account.Enabled) {
            if ($account.LastLogonDate) {
                $userlastused = $account.LastLogonDate
            }
            else {
                $userlastused = "Never"
            }
            Add-Content -Path "$outputdir\accounts_inactive.txt" -Value "User $($account.SamAccountName) ($($account.Name)) has not logged on since $userlastused"
            $count++
        }
    }
    Write-Progress -Activity "Searching for inactive users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count inactive user accounts(180days), see accounts_inactive.txt (KB500)"
        Write-Nessus-Finding "InactiveAccounts" "KB500" ([System.IO.File]::ReadAllText("$outputdir\accounts_inactive.txt"))
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
Function Get-DisabledAccounts {
    #Lists disabled accounts
    $disabledaccounts = Search-ADaccount -AccountDisabled -UsersOnly
    $count = 0
    $totalcount = ($disabledaccounts | Measure-Object | Select-Object Count).count
    foreach ($account in $disabledaccounts) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for disabled users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\accounts_disabled.txt" -Value "Account $($account.SamAccountName) ($($account.Name)) is disabled"
        $count++
    }
    Write-Progress -Activity "Searching for disabled users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count disabled user accounts, see accounts_disabled.txt (KB501)"
        Write-Nessus-Finding "DisabledAccounts" "KB501" ([System.IO.File]::ReadAllText("$outputdir\accounts_disabled.txt"))
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
        Add-Content -Path "$outputdir\accounts_locked.txt" -Value "Account $($account.SamAccountName) ($($account.Name)) is locked"
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
        Add-Content -Path "$outputdir\accounts_passdontexpire.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts that don't expire, see accounts_passdontexpire.txt (KB254)"
        Write-Nessus-Finding "AccountsThatDontExpire" "KB254" ([System.IO.File]::ReadAllText("$outputdir\accounts_passdontexpire.txt"))
    }
}
Function Get-OldBoxes {
    #Lists 2000/2003/XP/Vista/7/2008 machines
    $count = 0
    $oldboxes = Get-ADComputer -Filter { OperatingSystem -Like "*2003*" -and Enabled -eq "true" -or OperatingSystem -Like "*XP*" -and Enabled -eq "true" -or OperatingSystem -Like "*2000*" -and Enabled -eq "true" -or OperatingSystem -like '*Windows 7*' -and Enabled -eq "true" -or OperatingSystem -like '*vista*' -and Enabled -eq "true" -or OperatingSystem -like '*2008*' -and Enabled -eq "true" } -Property OperatingSystem
    $totalcount = ($oldboxes | Measure-Object | Select-Object Count).count
    foreach ($machine in $oldboxes) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for 2000/2003/XP/Vista/7/2008 devices joined to the domain..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\machines_old.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address)"
        $count++
    }
    Write-Progress -Activity "Searching for 2000/2003/XP/Vista/7/2008 devices joined to the domain..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] We found $count machines running 2000/2003/XP/Vista/7/2008! see machines_old.txt (KB3/37/38/KB259)"
        Write-Nessus-Finding "OldBoxes" "KB259" ([System.IO.File]::ReadAllText("$outputdir\machines_old.txt"))
    }
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
                Add-Content -Path "$outputdir\dcs_not_owned_by_da.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address), owned by $($machine.ntsecuritydescriptor.Owner)"
                $count++
            }
        }
        Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Ready" -Completed
    }
    if ($count -gt 0) {
        Write-Both "    [!] We found $count DCs not owned by Domains Admins group! see dcs_not_owned_by_da.txt"
        Write-Nessus-Finding "DCsNotByDA" "KB547" ([System.IO.File]::ReadAllText("$outputdir\dcs_not_owned_by_da.txt"))
    }
}
Function Get-HostDetails {
    #Gets basic information about the host
    Write-Both "    [+] Device Name:  $env:ComputerName"
    Write-Both "    [+] Domain Name:  $env:UserDomain"
    Write-Both "    [+] User Name  :  $env:UserName"
    Write-Both "    [+] NT Version :  $(Get-WinVersion)"
    $IPAddresses = [net.dns]::GetHostAddresses("") | select -ExpandProperty IP*
    foreach ($ip in $IPAddresses) {
        if ($ip -ne "::1") {
            Write-Both "    [+] IP Address :  $ip"
        }
    }
}
Function Get-FunctionalLevel {
    #Gets the functional level for domain and forest
    $DomainLevel = (Get-ADDomain).domainMode
    if ($DomainLevel -eq "Windows2000Domain" -and [single](Get-WinVersion) -gt 5.0) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2003InterimDomain" -and [single](Get-WinVersion) -gt 5.1) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2003Domain" -and [single](Get-WinVersion) -gt 5.2) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2008Domain" -and [single](Get-WinVersion) -gt 6.0) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2008R2Domain" -and [single](Get-WinVersion) -gt 6.1) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2012Domain" -and [single](Get-WinVersion) -gt 6.2) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2012R2Domain" -and [single](Get-WinVersion) -gt 6.3) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2016Domain" -and [single](Get-WinVersion) -gt 10.0) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    $ForestLevel = (Get-ADForest).ForestMode
    if ($ForestLevel -eq "Windows2000Forest" -and [single](Get-WinVersion) -gt 5.0) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2003InterimForest" -and [single](Get-WinVersion) -gt 5.1) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2003Forest" -and [single](Get-WinVersion) -gt 5.2) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2008Forest" -and [single](Get-WinVersion) -gt 6.0) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2008R2Forest" -and [single](Get-WinVersion) -gt 6.1) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2012Forest" -and [single](Get-WinVersion) -gt 6.2) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2012R2Forest" -and [single](Get-WinVersion) -gt 6.3) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2016Forest" -and [single](Get-WinVersion) -gt 10.0) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
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
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyInteractiveLogonRight $($member.Name.'#text')"
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
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyRemoteInteractiveLogonRight $($member.Name.'#text')"
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
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyNetworkLogonRight $($member.Name.'#text')"
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
                Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
            }
        }
    }
    else {
        foreach ($record in $DenyNTLM) {
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
        }
    }
    #Output for NTLM exceptions
    if ($NTLMAuthExceptions.count -ne 0) {
        foreach ($record in $NTLMAuthExceptions) {
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM auth exceptions $($record)"
        }
    }
    #Output for NTLM audit
    if ($AuditNTLM.count -eq 0) {
        Write-Both "    [!] No GPO enables NTLM audit authentication!"
    }
    else {
        foreach ($record in $DenyNTLM) {
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM audit GPO [$($record.gpo)] with value [$($record.value)]"
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
            Add-Content -Path "$outputdir\schema_admins.txt" -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
        }
    }
    if (($EnterpriseMembers | measure).count -ne 0) {
        Write-Both "    [!] Enterprise Admins not empty!!!"
        foreach ($member in $EnterpriseMembers) {
            Add-Content -Path "$outputdir\enterprise_admins.txt" -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
        }
    }
    foreach ($member in $DomainAdminsMembers) {
        Add-Content -Path "$outputdir\domain_admins.txt" -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
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
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2003' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2003"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2003' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2008 !(R2)' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2008"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2008 !(R2)' } | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2008 R2' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2008 R2" ; $ADs | Where-Object { $_.OperatingSystem -Match '2008 R2' }    | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2012 !(R2)' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2012"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2012 !(R2)' } | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2012 R2' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2012 R2" ; $ADs | Where-Object { $_.OperatingSystem -Match '2012 R2' }    | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2016' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2016"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2016' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2019' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2019"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2019' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2022' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2022"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2022' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
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
            Add-Content -Path "$outputdir\sites_no_gc.txt" -Value "$($Site.Name)"
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
    27 = "DES_CBC_MD5, DES_CBC_MD5, AES 128, AES 256"
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
        Add-Content -Path "$outputdir\dcs_weak_kerberos_ciphersuite.txt" -Value "$($DC.DNSHostName)`nDecimal Value: $encType`nHex Value: $hexValue`nSupported Encryption Types: $supportedTypes`n"
    }
}

if ($WeakKerberos) {
    Add-Content -Path "$outputdir\dcs_weak_kerberos_ciphersuite.txt" -Value "`nLink: https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797`n"
    Write-Both "    [!] You have DCs with RC4 or DES allowed for Kerberos!!!"
    Write-Nessus-Finding "WeakKerberosEncryption" "KB995" ([System.IO.File]::ReadAllText("$outputdir\dcs_weak_kerberos_ciphersuite.txt"))
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
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeInteractiveLogonRight $($member.Name.'#text')"
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
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeBatchLogonRight $($member.Name.'#text')"
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
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRemoteInteractiveLogonRight $($member.Name.'#text')"
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
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeBackupPrivilege $($member.Name.'#text')"
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
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRestorePrivilege $($member.Name.'#text')"
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
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeLoadDriverPrivilege $($member.Name.'#text')"
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
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeShutdownPrivilege $($member.Name.'#text')"
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
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRemoteShutdownPrivilege $($member.Name.'#text')"
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
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeSystemTimePrivilege $($member.Name.'#text')"
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
"@User Created within the last 30 days" | Set-Content -Path "$outputdir\new_users.txt"
        foreach ($newUser in $newUsers ) { Add-Content -Path "$outputdir\new_users.txt" -Value "Account $($newUser.SamAccountName) was created $($newUser.whenCreated)" }
        Write-Both "    [!] $totalcountUsers new users were created last 30 days, see $outputdir\new_users.txt"
    }
    if ($totalcountGroups -gt 0) {
        foreach ($newGroup in $newGroups ) { Add-Content -Path $outputdir\new_groups.txt -Value "Group $($newGroup.SamAccountName) was created $($newGroup.whenCreated)" }
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
    $objectName = "DFSR-GlobalSettings"
    $searcher = [ADSISearcher] "(objectClass=msDFSR-GlobalSettings)"
    $objectExists = $searcher.FindOne() -ne $null
    if ($objectExists) {
        $services = @("dns", "netlogon", "kdc", "w32time", "ntds", "dfsr")
    }
    else {
        $services = @("dns", "netlogon", "kdc", "w32time", "ntds", "ntfrs")
    }
    foreach ($DC in $dcList) {
        foreach ($service in $services) {
            $checkService = Get-Service $service -ComputerName $DC -ErrorAction SilentlyContinue
            $serviceName = $checkService.Name
            $serviceStatus = $checkService.Status
            if (!($serviceStatus)) {
                Write-Both "        [!] Service $($service) cannot be checked on $DC!"
            }
            elseif ($serviceStatus -ne "Running") {
                Write-Both "        [!] Service $($service) is not running on $DC!"
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

        $startMode = (Get-WmiObject -ComputerName $DC -Class Win32_Service -Property StartMode -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue).StartMode
        if (!($startMode)) {
            Write-Both "        [!] Windows Update service cannot be checked on $DC!"
        }
        elseif ($startMode -eq "Disabled") {
            Write-Both "        [!] Windows Update service is disabled on $DC!"
        }
    }
    $progresscount = 0
    $totalcount = ($dcList | Measure-Object | Select-Object Count).count
    foreach ($DC in $dcList) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for last Windows Update installation on all DCs..." -Status "Currently searching on $DC" -PercentComplete ($progresscount / $totalcount * 100)
        try {
            $lastHotfix = (Get-HotFix -ComputerName $DC | Where-Object { $_.InstalledOn -ne $null } | Sort-Object -Descending InstalledOn  | Select-Object -First 1).InstalledOn
            if ($lastHotfix -lt $lastMonth) {
                Write-Both "        [!] Windows is not up to date on $DC, last install: $($lastHotfix)"
            }
            else {
                Write-Both "        [+] Windows is up to date on $DC, last install: $($lastHotfix)"
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
    #Install DSInternals
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor
        [Net.SecurityProtocolType]::Tls12
        $count = 0
        $totalcount = 3
        Write-Progress -Activity "Installing dependencies..." -Status "Currently installing NuGet Package Provider" -PercentComplete ($count / $totalcount * 100)
        #if (!(Get-PackageProvider -ListAvailable -Name Nuget -ErrorAction SilentlyContinue)) { Install-PackageProvider -Name NuGet -Force | Out-Null }
        $count++
        Write-Progress -Activity "Installing dependencies..." -Status "Currently adding PSGallery to trusted Repositories" -PercentComplete ($count / $totalcount * 100)
        if ((Get-PSRepository -Name PSGallery).InstallationPolicy -eq "Untrusted") { Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted }
        $count++
        Write-Progress -Activity "Installing dependencies..." -Status "Currently installing module DSInternals" -PercentComplete ($count / $totalcount * 100)
        #if (!(Get-Module -ListAvailable -Name DSInternals)) { Install-Module -Name DSInternals -Force }
        Write-Progress -Activity "Installing dependencies..." -Status "Ready" -Completed
        Import-Module DSInternals
    }
    else {
        Write-Both "    [!] PowerShell 5 or greater is needed, see https://www.microsoft.com/en-us/download/details.aspx?id=54616"
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
    if (Get-Module -ListAvailable -Name DSInternals) {
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
                $passwordQualityPath = Join-Path $outputdir 'password_quality.txt'

                $accounts |
                    Test-PasswordQuality -IncludeDisabledAccounts |
                    Out-File -FilePath $passwordQualityPath

                if (Test-Path $passwordQualityPath) {
                    Write-Both "    [!] Password quality test done, see $passwordQualityPath"

                    # Post-process the DSInternals report to clarify why accounts are marked as Kerberoastable
                    try {
                        Add-KerberoastExplanationToPasswordQualityReport `
                            -ReportPath $passwordQualityPath `
                            -DomainController $dc
                    }
                    catch {
                        Write-Both "    [*] Failed to append Kerberoast clarification to password quality report: $($_.Exception.Message)"
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


Function Check-Shares {
    #Check SYSVOL and NETLOGON share exists
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    Write-Both "    [+] Checking SYSVOL and NETLOGON shares on all DCs"
    foreach ($DC in $dcList) {
        $shareList = (Get-WmiObject -Class Win32_Share -ComputerName $DC -ErrorAction SilentlyContinue)
        if (!($shareList)) {
            Write-Both "        [!] Cannot test shares on $DC!"
        }
        else {
            $sysvolShare = ($shareList | ? { $_ -match 'SYSVOL' }   | measure).Count
            $netlogonShare = ($shareList | ? { $_ -match 'NETLOGON' } | measure).Count
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
    foreach ($line in $certutil_lines) {
        if ($line.StartsWith("Template[")) {
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
                if ($detail -like "*TemplatePropCommonName =*") {
                    $TemplatePropCommonName = $detail.Split("=")[1].Trim()
                }
                if ($detail -like "*CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1*") {
                    $SuppliesSubjectCheck = $true
                }
                if ($detail -like "*Client Authentication*") {
                    $ClientAuthCheck = $true
                }
                if ($detail -match "^\s*Allow Enroll\s+.*\\Authenticated Users\s*$|^\s*Allow Enroll\s+.*\\Domain Users\s*$") {
                    $AllowEnrollCheck = $true
                }
                if ($detail -like "2.5.29.37.0 Any Purpose") {
                    $AnyPurposeCheck = $true
                }
                if ($detail -match "^\s*Allow Write\s+.*\\Authenticated Users\s*$|^\s*Allow Write\s+.*\\Domain Users\s*$") {
                    $AllowWriteCheck = $true
                }
                # Check for Allow Full Control
                if ($detail -match "^\s*Allow Full Control\s+.*\\Authenticated Users\s*$|^\s*Allow Full Control\s+.*\\Domain Users\s*$") {
                    $AllowFullControl = $true
                }
                if ($detail -like "Certificate Request Agent (1.3.6.1.4.1.311.20.2.1)") {
                    $CertificateRequestAgentCheck = $true
                }
                # Create object with details. Objectg name is TemplatePropCommonName
                $template = New-Object -TypeName PSObject -Property @{
"@SuppliesSubjectCheck"         = $SuppliesSubjectCheck
"@ClientAuthCheck"              = $ClientAuthCheck
"@AllowEnrollCheck"             = $AllowEnrollCheck
"@AnyPurposeCheck"              = $AnyPurposeCheck
"@AllowWriteCheck"              = $AllowWriteCheck
"@AllowFullControl"             = $AllowFullControl
"@TemplatePropCommonName"       = $TemplatePropCommonName
"@CertificateRequestAgentCheck" = $CertificateRequestAgentCheck
                }
            }
            $templates += $template
            $current_template = $line + ","
        }
        else {
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

    $template_path = $outputdir + "\vulnerable_templates.txt"
    $web_enrollmeent_path = $outputdir + "\web_enrollment.txt"

    foreach ($template in $ESC1) {
        $ESC1line = "ESC1 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC1line
        Write-Both '    [!]'$ESC1line
    }
    foreach ($template in $ESC2) {
        $ESC2line = "ESC2 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC2line
        Write-Both '    [!]'$ESC2line
    }
    foreach ($template in $ESC3) {
        $ESC3line = "ESC3 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC3line
        Write-Both '    [!]'$ESC3line
    }
    foreach ($template in $ESC4) {
        $ESC4line = "ESC4 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC4line
        Write-Both '    [!]'$ESC4line
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
            Add-Content -Path $web_enrollmeent_path -Value "ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
            Write-Both "    [!] ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
        }
        else {
            Write-Both "    [+] ESC8 not vulnerable"
        }
    }
    if (Test-Path "$outputdir\web_enrollment.txt") {
        Write-Nessus-Finding "Active Directory Certificate Service Web Enrollment Enabled in HTTP" "KB1095" ([System.IO.File]::ReadAllText("$outputdir\web_enrollment.txt"))
    }
    if (Test-Path "$outputdir\vulnerable_templates.txt") {
        Write-Nessus-Finding "Active Directory Certificate Service Vulnerable Templates" "KB1096" ([System.IO.File]::ReadAllText("$outputdir\vulnerable_templates.txt"))
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

    Import-Module ActiveDirectory -ErrorAction Stop

    # If no DC specified, let AD pick one
    if (-not $Server) {
        try {
            $Server = (Get-ADDomainController -Discover -ErrorAction Stop).HostName
        }
        catch {
            throw "Unable to discover a domain controller. Specify -Server explicitly or check network/credentials."
        }
    }

    Write-both "    [+] Using domain controller: $Server"

    # Default/high-value groups we care about
    $default_groups = @(
"@Domain Admins",
"@Enterprise Admins",
"@Schema Admins",
"@Domain Controllers",
"@Backup Operators",
"@Account Operators",
"@Server Operators",
"@Print Operators",
"@Remote Desktop Users",
"@Network Configuration Operators",
"@Exchange Organization Admins",
"@Exchange View-Only Admins",
"@Exchange Recipient Admins",
"@Exchange Servers",
"@Exchange Trusted Subsystem",
"@Exchange Public Folder Admins",
"@Exchange UM Management"
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
            Write-both "    [*] Skipping non-existent group '$group' on $Server."
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
    $spnFile = Join-Path $outputdir 'SPNs.txt'
    New-Item -Path $spnFile -ItemType File -Force | Out-Null
    Clear-Content -Path $spnFile -ErrorAction SilentlyContinue

    Write-both "    [+] Enumerating SPN-bearing user accounts from DC: $Server"

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
        Write-both "    [+] No high value kerberoastable user accounts identified."
        Add-Content -Path $spnFile -Value "No high value kerberoastable user accounts identified."
    }
    else {
        foreach ($user in $high_value_users) {
            $kerbuser = '    [!]' + $user.Name + ' in groups: ' + $user.Group
            Write-both $kerbuser
            Add-Content -Path $spnFile -Value $user.Name
        }
    }

    # Safe ReadAllText regardless of DC vs jump server
    $spnContent = [System.IO.File]::ReadAllText($spnFile)
    Write-Nessus-Finding "Kerberoast Attack - Services Configured With a Weak Password" "KB611" $spnContent
}

function Get-ADUsersWithoutPreAuth {
    try {
        $asrepUsers = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true -and Enabled -eq $true' `
                                 -Properties SamAccountName, Name, userAccountControl
    }
    catch { $asrepUsers = @() }

    if (-not $asrepUsers -or $asrepUsers.Count -eq 0) {
        $asrepUsers = Get-ADUser -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
                                 -Properties SamAccountName, Name, userAccountControl
    }

    $asrepUsers = $asrepUsers | Select-Object SamAccountName, Name, userAccountControl

    if (-not $asrepUsers -or $asrepUsers.Count -eq 0) {
        Write-Both "    [+] No ASREP Accounts"
        return
    }

    $asrepPath = Join-Path $outputdir 'ASREP.txt'
    $header = @(
        'AS-REP Roastable accounts detected (DONT_REQ_PREAUTH set).',
        '',
        'To list all vulnerable accounts:',
        '  Get-ADUser -Filter ''DoesNotRequirePreAuth -eq $true -and Enabled -eq $true'' | Select SamAccountName, Enabled',
        '  # Or LDAP bitwise (server-side):',
        '  Get-ADUser -LDAPFilter ''(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'' | Select SamAccountName, Enabled',
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
    $header | Set-Content -Path $asrepPath -Encoding UTF8

    foreach ($user in $asrepUsers) {
        $display = ("{0} ({1})" -f $user.Name, $user.SamAccountName)
        Write-Both ("    [!] AS-REP Roastable user: {0}" -f $display)

        @(
            $display,
            '      # Verify vulnerable bit (non-zero means vulnerable):',
            "      (Get-ADUser $($user.SamAccountName) -Properties userAccountControl).userAccountControl -band 0x00400000",
            '      # Mitigate (clear bit 0x00400000):',
            "      `$u = Get-ADUser $($user.SamAccountName) -Properties userAccountControl",
            "      Set-ADUser $($user.SamAccountName) -Replace @{userAccountControl = (`$u.userAccountControl -band (-bnot 0x00400000))}",
            '      # Optional: force password reset (use compliant password):',
            "      Set-ADAccountPassword -Identity $($user.SamAccountName) -Reset -NewPassword (Read-Host -AsSecureString)",
            ''
        ) | Add-Content -Path $asrepPath
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
            Write-both "    [+] LDAP signing is enabled on $computerName"
        }
        else {
            Write-both "    [!] Issue identified LDAP signing is not enabled on $computerName, the registry value is currently set to $ldapSigning."
            Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAP signing is not enabled on $computerName, the registry key does not exist"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enabled on $computerName, the registry key does not exist"
        }
    }
    catch {
        Write-both "    [!] Issue identified LDAP signing is not enabled on $computerName, the registry key does not exist."
        Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAP signing is not enabled on $computerName, the registry key does not exist"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enabled on $computerName, the registry key does not exist"
    }

    # Check if LDAPS is configured
    $serverAuthOid = '1.3.6.1.5.5.7.3.1'
    $ldapsCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
        $_.Extensions -like "System.Security.Cryptography.Oid*" -and
        $_.Extensions.Oid.Value -eq $serverAuthOid
    }

    if ($ldapsCert) {
        Write-both "    [+] LDAPS is configured on $computerName"
    }
    else {
        Write-both "    [!] Issue identified LDAPS is not configured on $computerName, LDAPs certificates are not configured"
        Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAPS is not configured on $computerName, LDAPs certificates are not configured"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS is not configured on $computerName, LDAPs certificates are not configured"
    }


    # Check if LDAPS Channel binding is enabled
    try {
        $ldapsBinding = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction Stop).LdapEnforceChannelBinding

        if ($ldapsBinding -eq 2) {
            Write-both "    [+] LDAPS channel binding is enabled on $computerName"
        }
        else {
            Write-both "    [!] Issue identified LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
            Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
        }
    }
    catch {
        Write-both "    [!] Issue identified LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
        Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
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

        Write-both "    [!] Issue identified LDAP null session allowed on server $Server`:$Port"
        Add-Content -Path $outputdir\LDAPSecurity.txt -Value "null session allowed on server $Server`:$Port"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP null session allowed on server $Server`:$Port"
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        Write-both "    [+] LDAP null session not allowed on server $Server`:$Port"
    }
    catch {
        Write-both "Error occurred: $_"
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
            Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
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
    if ($computerResults) {
        $computerResults | ConvertTo-Html -Property @{ Label = "Type"; Expression = { "Computer" } }, @{ Label = "Computer Name"; Expression = { $_.ObjectName } }, @{ Label = "Allowed Group"; Expression = { $_.IdentityReference } }, AccessControlType, ActiveDirectoryRights | Out-File -Encoding UTF8 $outputdir\dangerousACLs.html -Append
        $computerResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType | Out-File $outputdir\dangerousACL_Computer.txt -Encoding UTF8
        Write-Both "    [!] Issue identified, vulnerable ACL on Computer, see $outputdir\dangerousACL_Computer.txt"
        Write-Nessus-Finding "Weak Computer Permissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\dangerousACL_Computer.txt"))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any computer."
    }

    if ($groupResults) {
        $groupResults | ConvertTo-Html -Property @{ Label = "Type"; Expression = { "Group" } }, @{ Label = "Group Name"; Expression = { $_.ObjectName } }, @{ Label = "Allowed Group"; Expression = { $_.IdentityReference } }, AccessControlType, ActiveDirectoryRights | Out-File -Encoding UTF8 $outputdir\dangerousACLs.html -Append
        $groupResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType, ActiveDirectoryRights | Out-File $outputdir\dangerousACL_Groups.txt
        Write-Both "    [!] Issue identified, vulnerable ACL on Group, see $outputdir\dangerousACL_Groups.txt"
        Write-Nessus-Finding "Weak Group Permissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\dangerousACL_Groups.txt"))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any group."
    }
    if ($userResults) {
        $userResults | ConvertTo-Html -Property @{ Label = "Type"; Expression = { "User" } }, @{ Label = "User"; Expression = { $_.ObjectName } }, @{ Label = "Allowed Group"; Expression = { $_.IdentityReference } }, AccessControlType, ActiveDirectoryRights | Out-File -Encoding UTF8 $outputdir\dangerousACLs.html -Append
        $userResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType, ActiveDirectoryRights | Out-File $outputdir\dangerousACLUsers.txt
        Write-Both "    [!] Issue identified, vulnerable ACL on User, see $outputdir\dangerousACLUsers.txt"
        Write-Nessus-Finding "Weak User Permissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\dangerousACLUsers.txt"))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any user."
    }
}
#region AD raw data extract (Get-ADAuditData style)
function New-ZipFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, Position=0)]
        [string]$Path,
        [Parameter(Mandatory=$True, Position=1)]
        [ValidateScript({Test-Path $_ -PathType 'Container'})]
        [string]$Source
    )
    try {
        $rel = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release -ErrorAction Stop).Release
        if ($rel -ge 394802) {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
            [System.IO.Compression.ZipFile]::CreateFromDirectory($Source, $Path, [System.IO.Compression.CompressionLevel]::Optimal, $true)
            return $true
        }
    } catch { }
    return $false
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
        [ValidateScript({Test-Path $_ -PathType 'Container'})]
        [string]$Path = (Join-Path $outputdir 'ADExtract'),
        [Parameter(Mandatory=$false)]
        [string]$SearchBase = (Get-ADRootDSE | Select-Object -ExpandProperty defaultNamingContext)
    )

    try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Both "    [!] ActiveDirectory module missing. $_"; return }
    try { Import-Module GroupPolicy -ErrorAction Stop } catch { Write-Both "    [!] GroupPolicy module missing. $_"; return }

    $domainInfo = Get-ADDomain -Current LocalComputer
    $domainDN   = $domainInfo.DistinguishedName
    $outRoot    = Join-Path $Path $domainDN

    if (Test-Path $outRoot) { Remove-Item $outRoot -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $outRoot | Out-Null

    $log = Join-Path $outRoot 'consoleOutput.txt'
"@Starting AD data extract at $(Get-Date -Format G)" | Out-File -FilePath $log -Encoding utf8
"@Path parameter: '$outRoot'" | Out-File -FilePath $log -Append -Encoding utf8
"@SearchBase parameter: '$SearchBase'" | Out-File -FilePath $log -Append -Encoding utf8

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

    # Users
    $delimiter='|'; $eol="`r`n"
    $userProps = @('accountExpirationDate','adminCount','canonicalName','cn','comment','company','department','description','displayName',
        'distinguishedName','employeeID','employeeNumber','employeeType','givenName','info','LastLogonDate','mail','managedObjects',
        'manager','memberOf','middleName','msDS-AllowedToDelegateTo','msDS-PSOApplied','msDS-ResultantPSO',
        'msDS-User-Account-Control-Computed','msDS-UserPasswordExpiryTimeComputed','name','objectSid','PasswordExpired',
        'PasswordLastSet','primaryGroupID','sAMAccountName','servicePrincipalName','sIDHistory','sn','title','uid','uidNumber',
        'userAccountControl','userWorkstations','whenChanged','whenCreated')
    $userHeader = $userProps + @('relativeIdentifier')
    $users = Get-ADUser -SearchBase $SearchBase -Filter * -Properties $userProps
    $w = [System.IO.StreamWriter](Join-Path $outRoot "$($domainInfo.DNSRoot)-Users.csv")
    $w.Write(($userHeader -join $delimiter) + $eol)
    foreach ($u in $users) {
        $managed = ($u.managedObjects | ForEach-Object { ((($_ -split ',')[0]) -replace '^CN=','') }) -join ', '
        $memberof = ($u.memberOf | ForEach-Object { ((($_ -split ',')[0]) -replace '^CN=','') }) -join ', '
        $psoApplied = (($u.'msDS-PSOApplied' -join ';') -replace ",CN=Password Settings Container,CN=System,$domainDN",'') -replace 'CN=',''
        $psoRes = (($u.'msDS-ResultantPSO' -join ';') -replace ",CN=Password Settings Container,CN=System,$domainDN",'') -replace 'CN=',''
        $line = @(
            [string]$u.accountExpirationDate
            $u.adminCount
            (Remove-InvalidFileNameChars $u.canonicalName)
            (Remove-InvalidFileNameChars $u.cn)
            (Remove-InvalidFileNameChars $u.comment)
            $u.company
            $u.department
            (Remove-InvalidFileNameChars $u.description)
            (Remove-InvalidFileNameChars $u.displayName)
            $u.distinguishedName
            $u.employeeID
            $u.employeeNumber
            $u.employeeType
            (Remove-InvalidFileNameChars $u.givenName)
            (Remove-InvalidFileNameChars $u.info)
            [string]$u.LastLogonDate
            $u.mail
            $managed
            $u.manager
            $memberof
            (Remove-InvalidFileNameChars $u.middleName)
            ($u.'msDS-AllowedToDelegateTo' -join ';')
            $psoApplied
            $psoRes
            (ConvertFrom-UACComputed $u.'msDS-User-Account-Control-Computed')
            (ConvertFrom-PasswordExpiration $u.'msDS-UserPasswordExpiryTimeComputed')
            (Remove-InvalidFileNameChars $u.name)
            $u.objectSid
            $u.PasswordExpired
            [string]$u.PasswordLastSet
            $u.primaryGroupID
            $u.sAMAccountName
            ($u.servicePrincipalName -join ';')
            ($u.sIDHistory -join ';')
            (Remove-InvalidFileNameChars $u.sn)
            $u.title
            ($u.uid -join ';')
            $u.uidNumber
            (ConvertFrom-UAC $u.userAccountControl)
            $u.userWorkstations
            [string]$u.whenChanged
            [string]$u.whenCreated
            (($u.SID.Value).Split('-')[-1])
        ) -join $delimiter
        $w.Write($line + $eol)
    }
    $w.Close()

    # Groups
    $groupProps = @('CN','description','displayName','distinguishedName','GroupCategory','GroupScope','ManagedBy','memberOf','msDS-PSOApplied','name','objectSID','sAMAccountName','whenCreated','whenChanged')
    $groupHeader = $groupProps + @('relativeIdentifier')
    $groups = Get-ADGroup -SearchBase $SearchBase -Filter * -Properties $groupProps
    $w = [System.IO.StreamWriter](Join-Path $outRoot "$($domainInfo.DNSRoot)-Groups.csv")
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
    $w.Close()

    # Computers
    $computerProps = @('cn','description','displayName','distinguishedName','LastLogonDate','name','objectSid','operatingSystem','operatingSystemServicePack','operatingSystemVersion','primaryGroupID','PasswordLastSet','userAccountControl','whenCreated','whenChanged')
    $computers = Get-ADComputer -SearchBase $SearchBase -Filter * -Properties $computerProps
    $computers | Select-Object $computerProps | ForEach-Object {
        $_.userAccountControl = ConvertFrom-UAC $_.userAccountControl
        $_
    } | ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-Computers.csv") -Append

    # OUs
    $ouProps = @('CanonicalName','Description','DisplayName','DistinguishedName','ManagedBy','Name','whenChanged','whenCreated')
    Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter * -Properties $ouProps |
        Select-Object CanonicalName,Description,DisplayName,DistinguishedName,ManagedBy,Name,whenChanged,whenCreated |
        ForEach-Object {
            $_.CanonicalName = Remove-InvalidFileNameChars $_.CanonicalName
            $_.Description   = Remove-InvalidFileNameChars $_.Description
            $_.DisplayName   = Remove-InvalidFileNameChars $_.DisplayName
            $_.Name          = Remove-InvalidFileNameChars $_.Name
            $_
        } | ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-OUs.csv") -Append

    # GPO Reports + inheritance
    $gpRoot = Join-Path $outRoot 'GroupPolicy'
    New-Item -ItemType Directory -Path (Join-Path $gpRoot 'Reports') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $gpRoot 'Inheritance') -Force | Out-Null

    $gpos = Get-GPO -All
    foreach ($gpo in $gpos) {
        $name = Remove-InvalidFileNameChars $gpo.DisplayName
        Get-GPOReport -Guid $gpo.Id -ReportType Html -Path (Join-Path (Join-Path $gpRoot 'Reports') "$name.html")
    }

    $domainGPI = Get-GPInheritance -Target $domainDN
    $domainGPI | Select-Object Name,ContainerType,Path,GpoInheritanceBlocked | Format-List |
        Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$domainDN.txt")
    $domainGPI | Select-Object -ExpandProperty InheritedGpoLinks |
        Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$domainDN.txt") -Append

    $adOUs = Get-ADOrganizationalUnit -SearchBase $SearchBase -Filter *
    foreach ($ou in $adOUs) {
        $fn = Remove-InvalidFileNameChars $ou.DistinguishedName
        $gpi = Get-GPInheritance -Target $ou.DistinguishedName
        $gpi | Select-Object Name,ContainerType,Path,GpoInheritanceBlocked | Format-List |
            Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$fn.txt")
        $gpi | Select-Object -ExpandProperty InheritedGpoLinks |
            Out-File -FilePath (Join-Path (Join-Path $gpRoot 'Inheritance') "$fn.txt") -Append
    }

    # OU ACLs (full dump)
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
        $csvPath = Join-Path (Join-Path $outRoot 'OU\ACLs') "$fn.csv"
        Get-Acl -Path "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$ouDN" |
            Select-Object -ExpandProperty Access |
            Select-Object @{n='organizationalUnit';e={$ouDN}},
                @{n='objectTypeName';e={ if ($_.ObjectType -eq [Guid]::Empty) {'All'} else { $schemaIDGUID[$_.ObjectType] } }},
                @{n='inheritedObjectTypeName';e={ $schemaIDGUID[$_.InheritedObjectType] }}, * |
            ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
            Out-File -FilePath $csvPath -Append
    }

    # Confidentiality bit
    try {
        Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$domainDN" -LDAPFilter '(searchFlags:1.2.840.113556.1.4.803:=128)' |
            Select-Object DistinguishedName,Name |
            ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
            Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-confidentialBit.csv") -Append
    } catch {
"@Problem exporting confidentiality bit: $_" | Out-File -FilePath $log -Append -Encoding utf8
    }

    # Default password policy + FGPP
    Get-ADDefaultDomainPasswordPolicy |
        Select-Object ComplexityEnabled,DistinguishedName,LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,
            MinPasswordAge,MinPasswordLength,PasswordHistoryCount,ReversibleEncryptionEnabled |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-defaultDomainPasswordPolicy.csv") -Append

    Get-ADFineGrainedPasswordPolicy -Filter * -Properties appliesTo |
        Select-Object ComplexityEnabled,DistinguishedName,LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,
            MinPasswordAge,MinPasswordLength,
            @{Name='msDS-PSOAppliesTo';Expression={(($_.appliesTo -split "," | Select-String -AllMatches "CN=") -join ", ") -replace "CN=" -replace "" }},
            Name,PasswordHistoryCount,Precedence,ReversibleEncryptionEnabled |
        ConvertTo-Csv -Delimiter '|' -NoTypeInformation | ForEach-Object { $_ -replace '"','' } |
        Out-File -FilePath (Join-Path $outRoot "$($domainInfo.DNSRoot)-fgppDetails.csv") -Append

    # Trusts (Get-ADTrust if available, else netdom text)
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
#endregion AD raw data extract

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
        $rootLeaf = Split-Path -Path $Root -Leaf

        # If Root already ends with the hostname, do not append it again
        if ($rootLeaf -ieq $safeServer) {
            $base = $Root
        }
        else {
            $base = Join-Path -Path $Root -ChildPath $safeServer
        }

        Ensure-Folder $base | Out-Null
        $reports = Join-Path -Path $base -ChildPath 'DNS-Reports'
        Ensure-Folder $reports
    }

    # ----------------------------
    # Detect target DNS server (no args)
    # ----------------------------
    function Get-TargetDnsServer {
        $localOk = Safe-Get -Context "Detect: Get-DnsServer local" -Default $false -Script {
            Import-Module DnsServer -ErrorAction Stop
            $null = Get-DnsServer -ComputerName $env:COMPUTERNAME -ErrorAction Stop
            $true
        }
        if ($localOk) { return $env:COMPUTERNAME }

        $dnsIps = Safe-Get -Context "Detect: Get-DnsClientServerAddress" -Default @() -Script {
            $addrs = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop
            $active = $addrs | Where-Object { $_.InterfaceAlias -and $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 }
            ($active | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
        }

        if (-not $dnsIps -or $dnsIps.Count -eq 0) {
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

    Import-Module DnsServer -ErrorAction Stop

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
            $g = $groups | Where-Object Name -eq $t | Select-Object -First 1
            if ($g) { return [int]$g.Count }
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
    $recCss = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 18px; }
.small { color: #555; font-size: 0.95em; }
table { border-collapse: collapse; width: 100%; margin-top: 8px; }
th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
th { background: #f3f3f3; }
.pri-high { background: #ffd6d6; }
.pri-medium { background: #fff2cc; }
.pri-low { background: #d9ead3; }
</style>
"@

    $recRowsHtml = ($recommendations | ForEach-Object {
        $cls = switch ($_.Priority) { 'High' { 'pri-high' } 'Medium' { 'pri-medium' } default { 'pri-low' } }
        "<tr class='$cls'><td>$($_.Priority)</td><td>$($_.Area)</td><td>$($_.Topic)</td><td>$($_.Evidence)</td><td>$($_.Recommendation)</td></tr>"
    }) -join "`r`n"

@"
$recCss
<h1>DNS Recommendations Report</h1>
<div class="small">
<b>Target DNS server:</b> $ComputerName<br/>
<b>Generated:</b> $($serverPosture.Generated)
</div>

<h2>Disclaimer</h2>
<div class="small">
$($RecommendationDisclaimer.Trim() -replace "`r?`n","<br/>")
</div>

<h2>Recommendations</h2>
<table>
<tr><th>Priority</th><th>Area</th><th>Topic</th><th>Evidence</th><th>Recommendation</th></tr>
$recRowsHtml
</table>
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
    $css = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 18px; }
h1,h2 { margin-bottom: 6px; }
.small { color: #555; font-size: 0.95em; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.9em; }
.high { background: #ffd6d6; border: 1px solid #c40000; }
.medium { background: #fff2cc; border: 1px solid #b38f00; }
.low { background: #d9ead3; border: 1px solid #2d7d2d; }
table { border-collapse: collapse; width: 100%; margin-top: 8px; }
th, td { border: 1px solid #ddd; padding: 8px; vertical-align: top; }
th { background: #f3f3f3; position: sticky; top: 0; }
</style>
"@

    $serverSummaryHtml = @"
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>TargetDnsServer</td><td>$($serverPosture.TargetDnsServer)</td></tr>
<tr><td>Generated</td><td>$($serverPosture.Generated)</td></tr>
<tr><td>RunAs</td><td>$($serverPosture.RunAs)</td></tr>
<tr><td>PowerShellVersion</td><td>$($serverPosture.PowerShellVersion)</td></tr>
<tr><td>OSVersion</td><td>$($serverPosture.OSVersion)</td></tr>
<tr><td>DnsServerModuleVersion</td><td>$($serverPosture.DnsServerModuleVersion)</td></tr>
<tr><td>Recursion</td><td>$($serverPosture.Recursion)</td></tr>
<tr><td>Forwarders</td><td>$($serverPosture.Forwarders)</td></tr>
<tr><td>ScavengingEnabled</td><td>$($serverPosture.ScavengingEnabled)</td></tr>
</table>
"@

    $serverRiskHtml = @"
<div class="small">
<b>Server risk:</b>
<span class="badge $($serverRisk.RiskLevel.ToLower())">$($serverRisk.RiskLevel)</span>
Score=$($serverRisk.RiskScore)<br/>
<b>Issues:</b> $([string]::Join(' | ', $serverRisk.Issues))<br/>
<b>Recommendations:</b> $([string]::Join(' | ', $serverRisk.Recommendations))
</div>
"@

    $zonesTable = $rows |
        Sort-Object -Property @{Expression="RiskScore";Descending=$true}, @{Expression="ZoneName";Descending=$false} |
        Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate,
                      ZoneTransferType, SecureSecondaries, Notify, NotifyServers, SecondaryServers,
                      AgingEnabled, NoRefreshInterval, RefreshInterval,
                      TotalRecords, RiskLevel, RiskScore, RiskFactors, Issues, Recommendations, Notes

    $zonesHtml = ($zonesTable | ConvertTo-Html -Fragment) `
        -replace '<td>High</td>','<td><span class="badge high">High</span></td>' `
        -replace '<td>Medium</td>','<td><span class="badge medium">Medium</span></td>' `
        -replace '<td>Low</td>','<td><span class="badge low">Low</span></td>'

    $findingsHtml = (($topFindings | Select-Object Name, Count) | ConvertTo-Html -Fragment)

@"
$css
<h1>DNS Audit Report</h1>
<div class="small">
<b>Target DNS server:</b> $ComputerName<br/>
<b>Zones:</b> Total=$totalZones, High=$high, Medium=$medium, Low=$low<br/>
<b>Recommendations report:</b> DNS-Recommendations-$timestamp.html
</div>

<h2>Server posture</h2>
$serverSummaryHtml
$serverRiskHtml

<h2>Top findings</h2>
$findingsHtml

<h2>Zone details</h2>
$zonesHtml
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

    # Embedded from Deligated_Permissions.ps1 (working version)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory -ErrorAction Stop

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
"@CN=Users,$domainNC",
"@CN=Computers,$domainNC",
"@CN=System,$domainNC",
"@CN=Managed Service Accounts,$domainNC"
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
    $index.Add('<!doctype html>')
    $index.Add('<html><head><meta charset="utf-8" />')
    $index.Add('<title>AD Delegated Permissions Report</title>')
    $index.Add('<style>body{font-family:Segoe UI,Arial,sans-serif} code{background:#f3f3f3;padding:2px 4px;border-radius:3px}</style>')
    $index.Add('</head><body>')
    $index.Add('<h1>AD Delegated Permissions Report</h1>')
    $index.Add("<p>Generated: $(Get-Date -Format 'u')</p>")
    $index.Add('<h2>Scopes</h2><ul>')
    foreach ($dn in $scopes) {
      $safe = ($dn -replace '[=,]','_') -replace '[^\w\.-]','_'
      $index.Add("<li><code>$dn</code> - <a href='OUs/ADAudit_$safe.csv'>CSV</a> | <a href='OUs/ADAudit_$safe.txt'>TXT</a></li>")
    }
    $index.Add('</ul>')
    $index.Add('<h2>Summary</h2><ul>')
    $index.Add("<li><a href='All/ADAudit_AllScopes_$ts.csv'>Master CSV</a></li>")
    $index.Add("<li><a href='All/ADAudit_HighRisk_$ts.csv'>High-Risk CSV</a></li>")
    $index.Add("<li><a href='ADAudit_RiskAssessment.txt'>Risk Assessment</a></li>")
    $index.Add("<li><a href='ADAudit_Recommendations.txt'>Recommendations</a></li>")
    $index.Add('</ul></body></html>')
    $indexPath = Join-Path $base 'index.html'
    $index | Out-File -Encoding UTF8 -FilePath $indexPath
    Write-Host "Index: $indexPath"
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

    $riskOutDir = Join-Path $outputdir 'HighRisk'
    New-Item -ItemType Directory -Path $riskOutDir -Force | Out-Null

    $txtPath = Join-Path $outputdir 'ad_high_risk_baseline.txt'
    $summaryCsv = Join-Path $riskOutDir 'Summary.csv'
    $indexPath = Join-Path $outputdir 'ad_high_risk_baseline_index.html'

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
            RiskId      = $gd.RiskId
            Category    = 'Privileged Group Membership'
            Item        = $gd.Name
            Severity    = $gd.Severity
            Baseline    = $gd.Baseline
            Observed    = $cnt
            IsFinding   = $isFinding
            Recommendation = 'Minimize permanent membership; use JIT/PIM where possible; keep Tier0 separate; monitor changes.'
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
    $inactiveDays = 180
    $inactiveUsers = Search-ADAccount -AccountInactive -Timespan (New-TimeSpan -Days $inactiveDays) -UsersOnly -ErrorAction SilentlyContinue |
                     Where-Object { $_.Enabled -eq $true }
    $inactiveDetails = @()
    foreach ($u in $inactiveUsers) {
        $inactiveDetails += [pscustomobject]@{
            RiskId='ACCT_INACTIVE'
            SamAccountName=$u.SamAccountName
            Name=$u.Name
            LastLogonDate=$u.LastLogonDate
            Enabled=$u.Enabled
            Baseline="Disable if inactive > $inactiveDays days"
            Severity='HIGH'
            IsPrivileged= $privSamSet.Contains([string]$u.SamAccountName)
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

    if (Get-Module -ListAvailable -Name DSInternals) {
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

            $dups = $hashGroups | Group-Object NTHash | Where-Object { $_.Count -gt 1 }
            foreach ($g in $dups) {
                $members = ($g.Group | Select-Object -ExpandProperty SamAccountName | Sort-Object)
                foreach ($m in $members) {
                    $dupDetails += [pscustomobject]@{
                        RiskId='PWD_DUPLICATE'
                        NTHash=$g.Name
                        SamAccountName=$m
                        IsPrivileged=$privSamSet.Contains([string]$m)
                        Severity= $(if ($privSamSet.Contains([string]$m)) { 'CRITICAL' } else { 'HIGH' })
                        Baseline='0'
                    }
                }
            }

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


    # Windows Update / Patch Tuesday compliance (local machine)
    # Baseline: Latest monthly cumulative update installed for the current Patch Tuesday cycle.
    # NOTE: This check is best-effort and depends on Windows Update history being available on the host.
    $wuSummaryObj = [pscustomobject]@{
        RiskId='WIN_UPDATE'
        Category='Patch Management'
        Item='Windows cumulative update (Patch Tuesday) - latest cycle'
        Severity='HIGH'
        Baseline='Latest monthly cumulative update installed (current Patch Tuesday cycle)'
        Observed='Not evaluated'
        IsFinding=$false
        Recommendation='Install the latest monthly cumulative update. Verify servicing stack prerequisites. Ensure update compliance monitoring is in place.'
    }
    $wuReportPath = Join-Path $riskOutDir 'WINDOWS_UPDATE.txt'

    function _Get-SecondTuesday {
        param([datetime]$MonthDate)
        $first = Get-Date -Year $MonthDate.Year -Month $MonthDate.Month -Day 1
        $offset = ([int][System.DayOfWeek]::Tuesday - [int]$first.DayOfWeek + 7) % 7
        $firstTuesday = $first.AddDays($offset)
        return $firstTuesday.AddDays(7)
    }

    function _Get-TargetPatchMonth {
        $now = Get-Date
        $pt = _Get-SecondTuesday -MonthDate $now
        if ($now -ge $pt) { return $now } else { return $now.AddMonths(-1) }
    }

    try {
        $monthsBack = 6
        $cutoffDate = (Get-Date).AddMonths(-[math]::Abs($monthsBack)).Date

        $session = New-Object -ComObject "Microsoft.Update.Session"
        $searcher = $session.CreateUpdateSearcher()
        $historyCount = $searcher.GetTotalHistoryCount()
        $history = $searcher.QueryHistory(0, $historyCount)

        # Exclude Defender signatures and MSRT, keep entries after cutoff
        $filtered = $history | Where-Object {
            $_.Date -gt $cutoffDate -and (
                $_.Title -notmatch '(?i)\bDefender\b' -and
                $_.Title -notmatch '(?i)Security Intelligence' -and
                $_.Title -notmatch '(?i)Antivirus' -and
                $_.Title -notmatch '(?i)\bMalicious Software Removal Tool\b' -and
                $_.Title -notmatch '(?i)\bMSRT\b'
            )
        }

        $latestRelevant = $filtered | Sort-Object Date -Descending | Select-Object -First 1
        $latestRelevantDate = $null
        if ($latestRelevant) { $latestRelevantDate = $latestRelevant.Date }

        $target = _Get-TargetPatchMonth
        $targetPrefix = $target.ToString('yyyy-MM')
        $targetPatchTuesday = _Get-SecondTuesday -MonthDate $target

        # Match monthly Cumulative Update for Windows Server by yyyy-MM prefix in title.
        # Many CUs are titled like: "2025-12 Cumulative Update for Microsoft server operating system version ..."
        $cuPattern = "(?i)^" + [Regex]::Escape($targetPrefix) + "\s+Cumulative Update.*(Windows Server|Microsoft\s+server)"
        $targetMonthCU = $history | Where-Object { $_.Title -match $cuPattern } | Sort-Object Date -Descending | Select-Object -First 1

        $daysSinceLast = $null
        if ($latestRelevantDate) { $daysSinceLast = [int]((New-TimeSpan -Start $latestRelevantDate -End (Get-Date)).TotalDays) }

        if ($targetMonthCU) {
            # Compliant: do not create a missing-update report file
            if (Test-Path $wuReportPath) { Remove-Item -Force $wuReportPath -ErrorAction SilentlyContinue }
            $wuSummaryObj = [pscustomobject]@{
                RiskId='WIN_UPDATE'
                Category='Patch Management'
                Item='Windows cumulative update (Patch Tuesday) - latest cycle'
                Severity='HIGH'
                Baseline='Latest monthly cumulative update installed (current Patch Tuesday cycle)'
                Observed= $(if ($latestRelevantDate) { "Compliant. Latest relevant update: $latestRelevantDate ($daysSinceLast days ago). Target CU found: $($targetMonthCU.Title) on $($targetMonthCU.Date)." } else { "Compliant. Target CU found: $($targetMonthCU.Title) on $($targetMonthCU.Date)." })
                IsFinding=$false
                Recommendation='No action required for this check.'
            }
        } else {
            # Not compliant: create a report file with details
            $notUpdatedMsg = $(if ($latestRelevantDate) { "$daysSinceLast days since last relevant update." } else { "No relevant updates found in history within last $monthsBack months." })
            $wuSummaryObj = [pscustomobject]@{
                RiskId='WIN_UPDATE'
                Category='Patch Management'
                Item='Windows cumulative update (Patch Tuesday) - latest cycle'
                Severity='HIGH'
                Baseline="Install monthly CU for $targetPrefix (Patch Tuesday: $($targetPatchTuesday.ToString('yyyy-MM-dd')))"
                Observed= "Missing $targetPrefix CU. Latest relevant update: $(if ($latestRelevantDate) { $latestRelevantDate } else { 'Unknown' }). $notUpdatedMsg"
                IsFinding=$true
                Recommendation='Install the latest monthly cumulative update, then reboot if required. Verify WSUS/WUfB configuration and servicing stack prerequisites.'
            }

            $r = New-Object System.Collections.Generic.List[string]
            $r.Add("=== Windows Update / Patch Tuesday Compliance ===")
            $r.Add("Generated: $(Get-Date -Format o)")
            $r.Add("Computer:  $env:COMPUTERNAME")
            $r.Add("")
            $r.Add("Baseline:")
            $r.Add("  - Latest monthly cumulative update installed for the current Patch Tuesday cycle.")
            $r.Add("")
            $r.Add("Target cycle:")
            $r.Add("  - Target month (yyyy-MM): $targetPrefix")
            $r.Add("  - Patch Tuesday date:      $($targetPatchTuesday.ToString('yyyy-MM-dd'))")
            $r.Add("")
            $r.Add("Status:")
            $r.Add("  - Target cumulative update found: NO")
            if ($latestRelevantDate) {
                $r.Add("  - Latest relevant update installed: $latestRelevantDate ($daysSinceLast days ago)")
            } else {
                $r.Add("  - Latest relevant update installed: Unknown")
            }
            $r.Add("")
            $r.Add("Recent update history (last $monthsBack months; excluding Defender/MSRT):")
            $r.Add(('-' * 80))
            foreach ($u in ($filtered | Sort-Object Date -Descending)) {
                $r.Add(("{0} | {1}" -f ($u.Date.ToString('yyyy-MM-dd')), $u.Title))
            }
            $r | Out-File -FilePath $wuReportPath -Encoding UTF8
        }
    } catch {
        # If Windows Update history cannot be queried, keep "Not evaluated" and do not create report.
    }


    # Build summary table
    $summary = @()
    $summary += $privSummary
    $summary += $krbtgtObj
    $summary += $inactiveObj
    $summary += $pneObj
    $summary += $disabledOldObj
    $summary += $maqObj
    $summary += $dupSummaryObj
    $summary += $wuSummaryObj

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
$indexPath = Join-Path $outputdir 'ad_high_risk_baseline_index.html'
$html = New-Object System.Collections.Generic.List[string]
$html.Add('<!doctype html>')
$html.Add('<html><head><meta charset="utf-8" />')
$html.Add('<title>AD High Risk Baseline Report</title>')
$html.Add('<style>body{font-family:Segoe UI,Arial,sans-serif} table{border-collapse:collapse} td,th{border:1px solid #ddd;padding:6px 10px} th{background:#f3f3f3} code{background:#f3f3f3;padding:2px 4px;border-radius:3px}</style>')
$html.Add('</head><body>')
$html.Add('<h1>Active Directory High Risk Baseline Report</h1>')
$html.Add("<p>Generated: $(Get-Date -Format 'u')</p>")
try {
    $d = Get-ADDomain
    $html.Add("<p>Domain: <code>$($d.DNSRoot)</code><br/>Forest: <code>$((Get-ADForest).Name)</code></p>")
} catch { }

$html.Add('<h2>Baseline (target values)</h2>')
$html.Add('<table><thead><tr><th>Control</th><th>Baseline</th></tr></thead><tbody>')
foreach ($k in $baseline.Keys) {
    $html.Add("<tr><td>$([System.Security.SecurityElement]::Escape([string]$k))</td><td>$([System.Security.SecurityElement]::Escape([string]$baseline[$k]))</td></tr>")
}
$html.Add('</tbody></table>')

$html.Add('<h2>Reports</h2><ul>')
$html.Add("<li><a href='ad_high_risk_baseline.txt'>Executive TXT report (includes baseline + findings)</a></li>")
$html.Add("<li><a href='HighRisk/Summary.csv'>Summary CSV</a></li>")
$html.Add("<li><a href='HighRisk/PRIVILEGED_GROUPS.csv'>Privileged group membership (detail)</a></li>")
$html.Add("<li><a href='HighRisk/KRBTGT.csv'>krbtgt password age (detail)</a></li>")
$html.Add("<li><a href='HighRisk/INACTIVE_ACCOUNTS.csv'>Inactive enabled accounts (detail)</a></li>")
$html.Add("<li><a href='HighRisk/PASSWORD_NEVER_EXPIRES.csv'>Password never expires (detail)</a></li>")
$html.Add("<li><a href='HighRisk/DISABLED_STALE.csv'>Disabled stale accounts (detail)</a></li>")
$html.Add("<li><a href='HighRisk/MACHINE_ACCOUNT_QUOTA.csv'>MachineAccountQuota (detail)</a></li>")
$html.Add("<li><a href='HighRisk/DUPLICATE_PASSWORDS.csv'>Duplicate passwords (detail; requires DSInternals + replication privileges)</a></li>")
if (Test-Path (Join-Path $riskOutDir 'WINDOWS_UPDATE.txt')) { $html.Add("<li><a href='HighRisk/WINDOWS_UPDATE.txt'>Windows Update compliance (detail)</a></li>") }
$html.Add('</ul>')

$html.Add('<h2>Finding Counts</h2>')
$html.Add('<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>')
$html.Add("<tr><td>CRITICAL</td><td>$((($crit | Measure-Object).Count))</td></tr>")
$html.Add("<tr><td>HIGH</td><td>$((($high | Measure-Object).Count))</td></tr>")
$html.Add("<tr><td>MEDIUM</td><td>$((($med | Measure-Object).Count))</td></tr>")
$html.Add('</tbody></table>')

$html.Add('</body></html>')
$html | Out-File -Encoding UTF8 -FilePath $indexPath
Write-Both "    [+] High-risk AD baseline report generated: ad_high_risk_baseline.txt"
    Write-Both "    [+] High-risk CSVs generated in: $riskOutDir"
    if (Test-Path $indexPath) { Write-Both "    [+] High-risk HTML index generated: ad_high_risk_baseline_index.html" }
}

$outputdir = (Get-Item -Path ".\").FullName + "\" + $env:computername
$starttime = Get-Date
$scriptname = $MyInvocation.MyCommand.Name
if (!(Test-Path "$outputdir")) { New-Item -ItemType Directory -Path $outputdir | Out-Null }
Write-Both " _____ ____     _____       _ _ _
|  _  |    \   |  _  |_ _ _| |_| |_
|     |  |  |  |     | | | . | |  _|
|__|__|____/   |__|__|___|___|_|_|
6.0                     by phillips321
$versionnum                  modified by Keberneth
"
$running = $false
Write-Both "[*] Script start time $starttime"
if (Get-Module -ListAvailable -Name ActiveDirectory) { Import-Module ActiveDirectory }else { Write-Both "[!] ActiveDirectory module not installed, exiting..." ; exit }
if (Get-Module -ListAvailable -Name ServerManager) { Import-Module ServerManager }else { Write-Both "[!] ServerManager module not installed, exiting..."   ; exit }
if (Get-Module -ListAvailable -Name GroupPolicy) { Import-Module GroupPolicy }else { Write-Both "[!] GroupPolicy module not installed, exiting..."     ; exit }
if (Get-Module -ListAvailable -Name DSInternals) { Import-Module DSInternals }else { Write-Both "[!] DSInternals module not installed, use -installdeps to force install" }
if (Test-Path "$outputdir\adaudit.nessus") { Remove-Item -recurse "$outputdir\adaudit.nessus" | Out-Null }
Write-Nessus-Header
Write-Host "[+] Outputting to $outputdir"
Write-Both "[*] Lang specific variables"
Get-Variables
if ($installdeps) { $running = $true ; Write-Both "[*] Installing optionnal features"                           ; Install-Dependencies }
if ($hostdetails -or ($all -and 'hostdetails' -notin $exclude) -or 'hostdetails' -in $selectedChecks) { $running = $true ; Write-Both "[*] Device Information" ; Get-HostDetails }
if ($domainaudit -or ($all -and 'domainaudit' -notin $exclude) -or 'domainaudit' -in $selectedChecks) { $running = $true ; Write-Both "[*] Domain Audit" ; Get-LastWUDate ; Get-DCEval ; Get-TimeSource ; Get-PrivilegedGroupMembership ; Get-MachineAccountQuota; Get-DefaultDomainControllersPolicy ; Get-SMB1Support ; Get-FunctionalLevel ; Get-DCsNotOwnedByDA ; Get-ReplicationType ; Check-Shares ; Get-RecycleBinState ; Get-CriticalServicesStatus ; Get-RODC }
if ($trusts -or ($all -and 'trusts' -notin $exclude) -or 'trusts' -in $selectedChecks) { $running = $true ; Write-Both "[*] Domain Trust Audit" ; Get-DomainTrusts }
if ($accounts -or ($all -and 'accounts' -notin $exclude) -or 'accounts' -in $selectedChecks) { $running = $true ; Write-Both "[*] Accounts Audit" ; Get-InactiveAccounts ; Get-DisabledAccounts ; Get-LockedAccounts ; Get-AdminAccountChecks ; Get-NULLSessions ; Get-PrivilegedGroupAccounts ; Get-ProtectedUsers }
if ($passwordpolicy -or ($all -and 'passwordpolicy' -notin $exclude) -or 'passwordpolicy' -in $selectedChecks) { $running = $true ; Write-Both "[*] Password Information Audit" ; Get-AccountPassDontExpire ; Get-UserPasswordNotChangedRecently ; Get-PasswordPolicy ; Get-PasswordQuality }

if ($highrisk -or ($all -and 'highrisk' -notin $exclude) -or 'highrisk' -in $selectedChecks) { $running = $true ; Write-Both "[*] High-Risk AD Baseline Report" ; Get-HighRiskADBaselineReport }
if ($ntds -or ($all -and 'ntds' -notin $exclude) -or 'ntds' -in $selectedChecks) { $running = $true ; Write-Both "[*] Trying to save NTDS.dit, please wait..." ; Get-NTDSdit }
if ($oldboxes -or ($all -and 'oldboxes' -notin $exclude) -or 'oldboxes' -in $selectedChecks) { $running = $true ; Write-Both "[*] Computer Objects Audit" ; Get-OldBoxes }
if ($gpo -or ($all -and 'gpo' -notin $exclude) -or 'gpo' -in $selectedChecks) { $running = $true ; Write-Both "[*] GPO audit (and checking SYSVOL for passwords)" ; Get-GPOtoFile ; Get-GPOsPerOU ; Get-SYSVOLXMLS; Get-GPOEnum }
if ($ouperms -or ($all -and 'ouperms' -notin $exclude) -or 'ouperms' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check Generic Group AD Permissions" ; Get-OUPerms }
if ($laps -or ($all -and 'laps' -notin $exclude) -or 'laps' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For Existence of LAPS in domain" ; Get-LAPSStatus }
if ($authpolsilos -or ($all -and 'authpolsilos' -notin $exclude) -or 'authpolsilos' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For Existence of Authentication Polices and Silos" ; Get-AuthenticationPoliciesAndSilos }
if ($insecurednszone -or ($all -and 'insecurednszone' -notin $exclude) -or 'insecurednszone' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For Existence DNS Zones allowing insecure updates" ; Get-DNSZoneInsecure }
if ($dnszone -or ($all -and 'dnszone' -notin $exclude) -or 'dnszone' -in $selectedChecks) {
    $running = $true
    Write-Both "[*] DNS Zone Report"
    Invoke-DNSZoneReport -OutputRoot $(if($DnsZoneOutputRoot){$DnsZoneOutputRoot}else{$outputdir}) -IncludeRecordCounts:$DnsIncludeRecordCounts -IncludeSystemZones:$DnsIncludeSystemZones
}
if ($recentchanges -or ($all -and 'recentchanges' -notin $exclude) -or 'recentchanges' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check For newly created users and groups"                ; Get-RecentChanges }
if ($spn -or ($all -and 'spn' -notin $exclude) -or 'spn' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check high value kerberoastable user accounts"           ; Get-SPNs }
if ($asrep -or ($all -and 'asrep' -notin $exclude) -or 'asrep' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for accounts with kerberos pre-auth"               ; Get-ADUsersWithoutPreAuth }
if ($acl -or ($all -and 'acl' -notin $exclude) -or 'acl' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for dangerous ACL permissions on Computers, Users and Groups"  ; Find-DangerousACLPermissions }
if ($adcs -or ($all -and 'adcs' -notin $exclude) -or 'adcs' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for ADCS Vulnerabilities"                          ; Get-ADCSVulns }
if ($ldapsecurity -or ($all -and 'ldapecurity' -notin $exclude) -or 'adcs' -in $selectedChecks) { $running = $true ; Write-Both "[*] Check for LDAP Security Issues"                          ; Get-LDAPSecurity }
if ($dataextract -or ($all -and 'dataextract' -notin $exclude) -or 'dataextract' -in $selectedChecks) { $running = $true ; Write-Both "[*] AD Raw Data Extract"                          ; Export-ADAuditDataExtract }
if ($delegatedpermissions -or ($all -and 'delegatedpermissions' -notin $exclude) -or 'delegatedpermissions' -in $selectedChecks) {
    $running = $true
    if (-not $DelegatedOutputRoot) { $DelegatedOutputRoot = (Join-Path $outputdir 'DelegatedPermissions') }
    Write-Both "[*] Delegated Permissions Report"
    Invoke-DelegatedPermissionsReport -OutputRoot $DelegatedOutputRoot -IncludeSystemTrustees:$DelegIncludeSystemTrustees -IncludeDeny:$DelegIncludeDeny -IncludeInherited:$DelegIncludeInherited -Server $DelegServer
}
if (!$running) {
    Write-Both "[!] No arguments selected"
    Write-Both "[!] Other options are as follows, they can be used in combination"
    Write-Both "    -installdeps installs optionnal features (DSInternals)"
    Write-Both "    -hostdetails retrieves hostname and other useful audit info"
    Write-Both "    -domainaudit retrieves information about the AD such as functional level"
    Write-Both "    -trusts retrieves information about any doman trusts"
    Write-Both "    -accounts identifies account issues such as expired, disabled, etc..."
    Write-Both "    -passwordpolicy retrieves password policy information"
    Write-Both "    -ntds dumps the NTDS.dit file using ntdsutil"
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
    Write-Both "    -dataextract exports raw AD audit data (users/groups/computers/OUs/GPO reports/OU ACLs/FGPP/trusts) to .\<COMPUTERNAME>\ADExtract"
    Write-Both "    -delegatedpermissions generates an AD delegated permissions report (alias: -delegated-permissions)"
    Write-Both "        Optional: -DelegIncludeSystemTrustees -DelegIncludeDeny -DelegIncludeInherited -DelegServer <dc> -DelegatedOutputRoot <path>"
    Write-Both "    -all runs all checks, e.g. $scriptname -all"
    Write-Both "    -exclude allows you to exclude specific checks when using -all, e.g. $scriptname -all -exclude hostdetails,ntds"
    Write-Both "    -select allows you to exclude specific checks when using -all, e.g. $scriptname -all `"-gpo,ntds,acl`""
}
Write-Nessus-Footer

#Dirty fix for .nessus characters (will do this properly or as a function later. Will need more characters adding here...)
$originalnessusoutput = Get-Content $outputdir\adaudit.nessus
$nessusoutput = $originalnessusoutput -Replace "&", "&amp;"
$nessusoutput = $nessusoutput -Replace ([char]8220), "&quot;"
$nessusoutput = $nessusoutput -Replace ([char]8221), "&quot;"
$nessusoutput = $nessusoutput -Replace "`'", "&apos;"
$nessusoutput = $nessusoutput -Replace ([char]252), "u"
$nessusoutput | Out-File $outputdir\adaudit-replaced.nessus

$endtime = Get-Date
Write-Both "[*] Script end time $endtime"

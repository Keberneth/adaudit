<#
    .SYNOPSIS
        ADAudit check: AD Raw Data Extract

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -dataextract). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-DataExtractCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select dataextract [options]

    .NOTES
        Entry point: Invoke-DataExtractCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory, GroupPolicy.
#>
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
    # Keys MUST be [int64] to match the [int64] lookup below. Hashtable key equality is
    # type-sensitive, and the literals 0/16/8388608/... parse as Int32 while 2147483648
    # parses as Int64, so a bare table made every Int32 key un-findable via an Int64 key.
    $uacComputed = @{
        ([int64]0)        = 'Refer to userAccountControl Field'
        ([int64]16)       = 'Locked Out'
        ([int64]8388608)  = 'Password Expired'
        ([int64]8388624)  = 'Locked Out - Password Expired'
        ([int64]67108864) = 'Partial Secrets Account'
        ([int64]2147483648) = 'Use AES Keys'
    }
    if ($null -eq $Value) { return "Unknown User Account Type - No Value Available" }
    $key = [int64]$Value
    if ($uacComputed.ContainsKey($key)) { return [string]$uacComputed[$key] }
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
    # trustAttributes is a bitmask (MS-ADTS), so decode each flag rather than
    # doing an exact key lookup (which mislabels any combined value as "Unknown").
    $trustAttribute = [ordered]@{
        0x1   = 'Non-Transitive'
        0x2   = 'Up-level Only'
        0x4   = 'Quarantined Domain (SID Filtering Enabled)'
        0x8   = 'Forest Transitive'
        0x10  = 'Cross-Organization (Selective Authentication)'
        0x20  = 'Within Forest'
        0x40  = 'Treat As External'
        0x80  = 'Uses RC4 Encryption'
        0x200 = 'Cross-Organization No TGT Delegation'
        0x400 = 'PIM (PAM) Trust'
        0x800 = 'Cross-Organization Enable TGT Delegation'
    }
    if ($null -eq $Value) { return "Unknown Trust Attribute - No Value Available" }
    $val = [int]$Value
    if ($val -eq 0) { return 'Non-Verifiable / No attributes set' }
    $matched = foreach ($bit in $trustAttribute.Keys) { if ($val -band $bit) { $trustAttribute[$bit] } }
    if (-not $matched) { return "Unknown Trust Attribute - $Value" }
    return ($matched -join ', ')
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

function Invoke-DataExtractCheck {
    Export-ADAuditDataExtract
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select dataextract @args
}
<#
    .SYNOPSIS
        ADAudit check: Domain Audit

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -domainaudit). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-DomainAuditCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select domainaudit [options]

    .NOTES
        Entry point: Invoke-DomainAuditCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory, GroupPolicy.
#>
Function Get-MachineAccountQuota {
    #Get number of machines a user can add to a domain
    $MachineAccountQuota = (Get-ADDomain | select -ExpandProperty DistinguishedName | Get-ADObject -Property 'ms-DS-MachineAccountQuota' | select -ExpandProperty ms-DS-MachineAccountQuota)
    if ($null -eq $MachineAccountQuota) {
        # Attribute unset: SAM still applies the documented default of 10
        Write-Both "    [!] ms-DS-MachineAccountQuota is not set; domain users can add the default 10 devices to the domain! (KB251)"
        Write-Nessus-Finding "DomainAccountQuota" "KB251" "ms-DS-MachineAccountQuota is not set; domain users can add the default 10 devices to the domain"
    }
    elseif ($MachineAccountQuota -gt 0) {
        Write-Both "    [!] Domain users can add $MachineAccountQuota devices to the domain! (KB251)"
        Write-Nessus-Finding "DomainAccountQuota" "KB251" "Domain users can add $MachineAccountQuota devices to the domain"
    }
}

Function Get-SMB1Support {
    # Check whether the DCs still support the SMBv1 server. This is a per-host
    # setting on each DC, so we query the DCs rather than the host running the
    # script (which, on a jump server, would report the jump server's SMBv1).
    $dcList = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
    if (-not $dcList -or $dcList.Count -eq 0) {
        Register-ADAuditNotAssessed -Name 'Get-SMB1Support' -Switch 'domainaudit' -Reason "No domain controllers enumerated; cannot assess SMBv1 support."
        return
    }

    foreach ($dc in $dcList) {
        $enabled = $null
        # Preferred: Get-SmbServerConfiguration over WinRM (version-agnostic, authoritative).
        try {
            $enabled = Invoke-Command -ComputerName $dc -ScriptBlock { [bool](Get-SmbServerConfiguration).EnableSMB1Protocol } -ErrorAction Stop
        }
        catch {
            # Fallback: SMB1 REG_DWORD (0 = disabled). Absent is ambiguous on modern OS.
            $reg = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ValueName 'SMB1'
            if (-not $reg.Success) {
                Register-ADAuditNotAssessed -Name 'Get-SMB1Support' -Switch 'domainaudit' -Target $dc -RequiresRemotePS -Reason "SMBv1 status needs Get-SmbServerConfiguration over WinRM or the SMB1 registry value; neither was reachable on ${dc}: $($reg.Error)"
                continue
            }
            if ($null -eq $reg.Value) {
                Register-ADAuditNotAssessed -Name 'Get-SMB1Support' -Switch 'domainaudit' -Target $dc -Reason "The SMB1 registry value is not set on $dc and WinRM was unavailable, so SMBv1 server state is ambiguous (cannot confirm enabled or disabled)."
                continue
            }
            $enabled = ($reg.Value -ne 0)
        }

        if ($enabled) {
            Write-Both "    [!] SMBv1 is enabled on $dc! (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled on $dc"
        }
        else {
            Write-Both "    [+] SMBv1 is disabled on $dc"
        }
    }
}

Function Get-DCsNotOwnedByDA {
    #Searches for DC objects not owned by the Domain Admins group
    $count = 0
    $progresscount = 0
    $domaincontrollers = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } -Property ntSecurityDescriptor, OperatingSystem, OperatingSystemServicePack, OperatingSystemVersion, IPv4Address
    $totalcount = ($domaincontrollers | Measure-Object | Select-Object Count).count
    if ($totalcount -gt 0) {
        foreach ($machine in $domaincontrollers) {
            $progresscount++
            Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Currently identified $count" -PercentComplete ($progresscount / $totalcount * 100)
            $owner = $machine.ntSecurityDescriptor.Owner
            if ($null -eq $owner) {
                Write-Both "    [!] Could not read owner of DC object $($machine.Name); skipping."
            }
            elseif ($owner -ne "$env:UserDomain\$DomainAdmins") {
                Add-Content -Path (Get-EvidencePath 'dcs_not_owned_by_da.txt') -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersion), $($machine.IPv4Address), owned by $owner"
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
        $otherDCs = @($ADs | Where-Object { $_.OperatingSystem -notmatch '2019|2022|2025' })
        if ($otherDCs.Count -gt 0) { Write-Both "        [+] Domain controllers with other/older OS"    ; $otherDCs | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
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
    #FSMO role placement. Co-location (one DC holding all roles) is normal and
    #supported, so this is informational only - not a warning. The -adhealth
    #check ('FSMO role holders') validates each holder's writability, DNS,
    #reachability, replication and the forest-root PDC time source.
    $fsmoHolders = @($ADs | Where-Object { @($_.OperationMasterRoles).Count -gt 0 })
    if ($fsmoHolders.Count -eq 1) {
        Write-Both "    [i] All FSMO roles are held by a single DC ($($fsmoHolders[0].Hostname)). Normal/supported in a single-domain forest; noted for documentation and DR. Run -adhealth to validate each FSMO holder."
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

Function Get-ReplicationType {
    #Retrieve replication mechanism (FRS or DFSR)
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
                $checkService = Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName $DC -Filter "Name='$service'" -UseWsmanFallback
                if (-not $checkService) {
                    Register-ADAuditNotAssessed -Name 'Get-CriticalServicesStatus' -Switch 'domainaudit' -Target "$DC/$service" -RequiresRemotePS -Reason "Service query returned no data (DC unreachable over CIM/DCOM or WinRM); service state unknown, not confirmed running."
                    continue
                }

                $serviceStatus = [string]$checkService.State
                if (-not $serviceStatus) {
                    Register-ADAuditNotAssessed -Name 'Get-CriticalServicesStatus' -Switch 'domainaudit' -Target "$DC/$service" -RequiresRemotePS -Reason "Service state was empty (DC unreachable over CIM/DCOM or WinRM)."
                }
                elseif ($serviceStatus -ne "Running") {
                    Write-Both "        [!] Service $service is not running on $DC!"
                }
            }
            catch {
                Register-ADAuditNotAssessed -Name 'Get-CriticalServicesStatus' -Switch 'domainaudit' -Target "$DC/$service" -RequiresRemotePS -Reason "Could not query service over CIM/DCOM or WinRM: $($_.Exception.Message)"
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
            $wuService = Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName $DC -Filter "Name='wuauserv'" -UseWsmanFallback
            $startMode = $wuService.StartMode
            if (-not $startMode) {
                Register-ADAuditNotAssessed -Name 'Get-LastWUDate' -Switch 'domainaudit' -Target $DC -RequiresRemotePS -Reason "Windows Update service start mode could not be read (DC unreachable over CIM/DCOM or WinRM)."
            }
            elseif ($startMode -eq "Disabled") {
                Write-Both "        [!] Windows Update service is disabled on $DC!"
            }
        }
        catch {
            Register-ADAuditNotAssessed -Name 'Get-LastWUDate' -Switch 'domainaudit' -Target $DC -RequiresRemotePS -Reason "Could not query Windows Update service over CIM/DCOM or WinRM: $($_.Exception.Message)"
        }
    }

    $progresscount = 0
    $totalcount = ($dcList | Measure-Object | Select-Object -ExpandProperty Count)
    foreach ($DC in $dcList) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for last Windows Update installation on all DCs..." -Status "Currently searching on $DC" -PercentComplete ($progresscount / $totalcount * 100)
        try {
            $lastHotfix = (Get-HotFix -ComputerName $DC | Where-Object { $_.InstalledOn -ne $null } | Sort-Object -Descending InstalledOn | Select-Object -First 1).InstalledOn
            if ($null -eq $lastHotfix) {
                # No dated hotfix data returned - do NOT treat as "not up to date" ($null -lt $date is $true)
                Write-Both "        [!] Could not determine last update date on $DC (no dated hotfix data returned)"
            }
            elseif ($lastHotfix -lt $lastMonth) {
                Write-Both "        [!] Windows is not up to date on $DC, last install: $lastHotfix"
            }
            else {
                Write-Both "        [+] Windows is up to date on $DC, last install: $lastHotfix"
            }
        }
        catch {
            Register-ADAuditNotAssessed -Name 'Get-LastWUDate' -Switch 'domainaudit' -Target $DC -RequiresRemotePS -Reason "Could not read installed hotfixes (Get-HotFix over RPC failed): $($_.Exception.Message)"
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
        $ntpSource = $null
        try {
            $ntpSource = (w32tm /query /source /computer:$DC 2>&1 | Out-String).Trim()
        }
        catch {
            Register-ADAuditNotAssessed -Name 'Get-TimeSource' -Switch 'domainaudit' -Target $DC -RequiresRemotePS -Reason "w32tm could not query the time source (RPC to W32Time failed): $($_.Exception.Message)"
            continue
        }
        # Reject error codes (e.g. 0x800706BA) and error text instead of printing them as a "source".
        if ([string]::IsNullOrWhiteSpace($ntpSource) -or $ntpSource -match '0x[0-9A-Fa-f]{6,8}' -or $ntpSource -match 'error') {
            Register-ADAuditNotAssessed -Name 'Get-TimeSource' -Switch 'domainaudit' -Target $DC -RequiresRemotePS -Reason "Could not determine NTP source ('$ntpSource'). w32tm needs RPC to the W32Time service on the DC."
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

Function Check-Shares {
    #Check SYSVOL and NETLOGON share exists
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    Write-Both "    [+] Checking SYSVOL and NETLOGON shares on all DCs"
    $assessed = 0
    foreach ($DC in $dcList) {
        $shareList = $null
        try {
            $shareList = @(Get-ADAuditCimInstance -ClassName Win32_Share -ComputerName $DC -UseWsmanFallback)
        }
        catch {
            Register-ADAuditNotAssessed -Name 'Check-Shares' -Switch 'domainaudit' -Target $DC -RequiresRemotePS -Reason "Could not enumerate shares over CIM/DCOM or WinRM: $($_.Exception.Message)"
            continue
        }

        if (-not $shareList -or $shareList.Count -eq 0) {
            Register-ADAuditNotAssessed -Name 'Check-Shares' -Switch 'domainaudit' -Target $DC -RequiresRemotePS -Reason "Share enumeration returned no data (DC unreachable over CIM/WinRM); SYSVOL/NETLOGON presence is unknown, not confirmed present."
            continue
        }

        $assessed++
        $sysvolShare = ($shareList | Where-Object { $_.Name -eq 'SYSVOL' } | Measure-Object).Count
        $netlogonShare = ($shareList | Where-Object { $_.Name -eq 'NETLOGON' } | Measure-Object).Count
        if ($sysvolShare -eq 0) { Write-Both "        [!] SYSVOL share is missing on $DC!" }
        if ($netlogonShare -eq 0) { Write-Both "        [!] NETLOGON share is missing on $DC!" }
    }

    if ($assessed -eq 0 -and $dcList.Count -gt 0) {
        Register-ADAuditNotAssessed -Name 'Check-Shares' -Switch 'domainaudit' -RequiresRemotePS -Reason "SYSVOL/NETLOGON shares could not be checked on ANY domain controller ($($dcList.Count) total). Requires CIM/DCOM or WinRM to the DCs. Posture is unknown, not 'all shares present'."
    }
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

Function Get-TombstoneLifetime {
    # Checks the forest tombstone lifetime configuration
    # Low tombstone lifetime reduces the window for AD Recycle Bin recovery
    try {
        $configNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $tombstoneObj = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime -ErrorAction Stop
    }
    catch {
        # A FAILED read is not the same as "not configured" - do not emit a (false) finding.
        Register-ADAuditNotAssessed -Name 'Get-TombstoneLifetime' -Switch 'domainaudit' -Reason "Could not read the tombstoneLifetime configuration object: $($_.Exception.Message)"
        return
    }
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
    $assessed = 0
    $evidencePath = Get-EvidencePath 'dc_print_spooler.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue

    $dcList = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)

    foreach ($dc in $dcList) {
        try {
            $spooler = Get-ADAuditCimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -ComputerName $dc -UseWsmanFallback
            if (-not $spooler) {
                Register-ADAuditNotAssessed -Name 'Get-PrintSpoolerOnDCs' -Switch 'domainaudit' -Target $dc -RequiresRemotePS -Reason "Win32_Service query returned no data for the Spooler service (DC unreachable over CIM/DCOM or WinRM); spooler state unknown."
                continue
            }
            $assessed++
            if ($spooler.State -eq 'Running') {
                Add-Content -Path $evidencePath -Value "Print Spooler is RUNNING on DC: $dc (StartMode: $($spooler.StartMode))"
                $count++
            }
            else {
                Write-Both "    [+] Print Spooler is $($spooler.State) on DC: $dc"
            }
        }
        catch {
            Register-ADAuditNotAssessed -Name 'Get-PrintSpoolerOnDCs' -Switch 'domainaudit' -Target $dc -RequiresRemotePS -Reason "Could not query Print Spooler over CIM/DCOM or WinRM: $($_.Exception.Message)"
        }
    }

    if ($count -gt 0) {
        Write-Both "    [!] Print Spooler is running on $count domain controller(s) - disable to mitigate PrintNightmare and coercion attacks (KB1203)"
        Write-Nessus-Finding "PrintSpoolerOnDC" "KB1203" ([System.IO.File]::ReadAllText($evidencePath))
    }
    elseif ($assessed -eq 0) {
        Register-ADAuditNotAssessed -Name 'Get-PrintSpoolerOnDCs' -Switch 'domainaudit' -RequiresRemotePS -Reason "Print Spooler state could not be queried on ANY domain controller ($($dcList.Count) total). Requires CIM/DCOM or WinRM to the DCs; from a non-DC host with those blocked the spooler posture is unknown, not 'not running'."
    }
    else {
        Write-Both "    [+] Print Spooler is not running on any of the $assessed assessed domain controller(s) (of $($dcList.Count) total)"
    }
}

Function Get-SMBSigningStatus {
    # Checks SMB signing enforcement on domain controllers
    # Missing SMB signing enables NTLM relay attacks
    $count = 0
    $evidencePath = Get-EvidencePath 'dc_smb_signing.txt'
    Remove-Item -LiteralPath $evidencePath -Force -ErrorAction SilentlyContinue

    $dcList = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
    $assessed = 0

    foreach ($dc in $dcList) {
        # Primary: read the DC's registry via StdRegProv, DCOM first then WSMan/WinRM.
        $reg = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ValueName 'RequireSecuritySignature'
        $requireSigning = $null

        if ($reg.Success) {
            $requireSigning = $reg.Value   # $null here means the value is not set on the DC
            $assessed++
        }
        else {
            # Fallback: Get-SmbServerConfiguration over WinRM
            try {
                $smbConfig = Invoke-Command -ComputerName $dc -ScriptBlock { (Get-SmbServerConfiguration).RequireSecuritySignature } -ErrorAction Stop
                $requireSigning = if ($smbConfig) { 1 } else { 0 }
                $assessed++
            }
            catch {
                Register-ADAuditNotAssessed -Name 'Get-SMBSigningStatus' -Switch 'domainaudit' -Target $dc -RequiresRemotePS -Reason "SMB signing posture needs the DC's registry (StdRegProv over CIM/DCOM/WinRM) or Get-SmbServerConfiguration over WinRM; neither was reachable: $($reg.Error)"
                continue
            }
        }

        if ($null -eq $requireSigning) {
            # Reached the DC but the value is not present. The effective default varies
            # by OS/policy, so do not assert "required" and do not score it.
            Register-ADAuditNotAssessed -Name 'Get-SMBSigningStatus' -Switch 'domainaudit' -Target $dc -Reason "RequireSecuritySignature is not set in the registry on $dc; the effective value depends on OS default/policy and could not be confirmed."
        }
        elseif ($requireSigning -ne 1) {
            Add-Content -Path $evidencePath -Value "SMB signing is NOT required on DC: $dc (RequireSecuritySignature = $requireSigning)"
            $count++
        }
        else {
            Write-Both "    [+] SMB signing is required on DC: $dc"
        }
    }

    if ($count -gt 0) {
        Write-Both "    [!] SMB signing is not enforced on $count domain controller(s) - enables NTLM relay attacks (KB1204)"
        Write-Nessus-Finding "SMBSigningNotRequired" "KB1204" ([System.IO.File]::ReadAllText($evidencePath))
    }
    elseif ($assessed -eq 0) {
        Register-ADAuditNotAssessed -Name 'Get-SMBSigningStatus' -Switch 'domainaudit' -RequiresRemotePS -Reason "SMB signing could not be queried on ANY domain controller ($($dcList.Count) total). Requires remote registry (CIM/DCOM/WinRM) or Get-SmbServerConfiguration over WinRM. Posture is unknown, not 'enforced'."
    }
    else {
        Write-Both "    [+] SMB signing is required on all of the $assessed of $($dcList.Count) domain controller(s) assessed"
    }
}

function Invoke-DomainAuditCheck {
    Invoke-AuditStep -Name 'Get-LastWUDate' -Switch 'domainaudit' -Body { Get-LastWUDate }
    Invoke-AuditStep -Name 'Get-DCEval' -Switch 'domainaudit' -Body { Get-DCEval }
    Invoke-AuditStep -Name 'Get-TimeSource' -Switch 'domainaudit' -Body { Get-TimeSource }
    Invoke-AuditStep -Name 'Get-PrivilegedGroupMembership' -Switch 'domainaudit' -Body { Get-PrivilegedGroupMembership }
    Invoke-AuditStep -Name 'Get-MachineAccountQuota' -Switch 'domainaudit' -Body { Get-MachineAccountQuota }
    Invoke-AuditStep -Name 'Get-DefaultDomainControllersPolicy' -Switch 'domainaudit' -Body { Get-DefaultDomainControllersPolicy }
    Invoke-AuditStep -Name 'Get-SMB1Support' -Switch 'domainaudit' -Body { Get-SMB1Support }
    Invoke-AuditStep -Name 'Get-FunctionalLevel' -Switch 'domainaudit' -Body { Get-FunctionalLevel }
    Invoke-AuditStep -Name 'Get-DCsNotOwnedByDA' -Switch 'domainaudit' -Body { Get-DCsNotOwnedByDA }
    Invoke-AuditStep -Name 'Get-ReplicationType' -Switch 'domainaudit' -Body { Get-ReplicationType }
    Invoke-AuditStep -Name 'Check-Shares' -Switch 'domainaudit' -Body { Check-Shares }
    Invoke-AuditStep -Name 'Get-RecycleBinState' -Switch 'domainaudit' -Body { Get-RecycleBinState }
    Invoke-AuditStep -Name 'Get-CriticalServicesStatus' -Switch 'domainaudit' -Body { Get-CriticalServicesStatus }
    Invoke-AuditStep -Name 'Get-RODC' -Switch 'domainaudit' -Body { Get-RODC }
    Invoke-AuditStep -Name 'Get-KerberosUnconstrainedDelegation' -Switch 'domainaudit' -Body { Get-KerberosUnconstrainedDelegation }
    Invoke-AuditStep -Name 'Get-TombstoneLifetime' -Switch 'domainaudit' -Body { Get-TombstoneLifetime }
    Invoke-AuditStep -Name 'Get-PrintSpoolerOnDCs' -Switch 'domainaudit' -Body { Get-PrintSpoolerOnDCs }
    Invoke-AuditStep -Name 'Get-SMBSigningStatus' -Switch 'domainaudit' -Body { Get-SMBSigningStatus }
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select domainaudit @args
}
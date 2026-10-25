<#
    .SYNOPSIS
        ADAudit check: Check for dangerous ACL permissions on Computers, Users and Groups

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -acl). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-DangerousAclCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select acl [options]

    .NOTES
        Entry point: Invoke-DangerousAclCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
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

function Get-ADAuditAceSid {
    param($Ace, [hashtable]$Cache)
    try {
        $identity = $Ace.IdentityReference
        if ([string]$identity -match '^S-1-') { return [string]$identity }
        $key = [string]$identity
        if ($null -ne $Cache -and $Cache.ContainsKey($key)) { return $Cache[$key] }
        $sid = $identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($null -ne $Cache -and $sid) { $Cache[$key] = $sid }
        return $sid
    } catch { return $null }
}

function Export-ADAuditSecurityCsv {
    param($Rows, [string[]]$Columns, [string]$Path)
    $items = @($Rows | Where-Object { $null -ne $_ })
    if ($items.Count -gt 0) {
        $items | Select-Object -Property $Columns | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $Path
    } else {
        # Preserve the schema for empty results; a zero-byte file is ambiguous.
        (($Columns | ForEach-Object { '"' + ($_ -replace '"','""') + '"' }) -join ',') | Set-Content -Encoding UTF8 -LiteralPath $Path
    }
}

function Get-ADAuditDangerousAceCapability {
    # This identifies an applicable allow ACE, not effective access through a complete token.
    # Retain that distinction in the evidence: other ACEs and group memberships matter.
    param($Ace, [switch]$IncludeDescendants)
    if ([string]$Ace.AccessControlType -ne 'Allow') { return }
    if (-not $IncludeDescendants -and ([string]$Ace.PropagationFlags -match 'InheritOnly')) { return }
    $rights = [int]$Ace.ActiveDirectoryRights
    $guid = [string]$Ace.ObjectType
    $allProperties = (-not $guid -or $guid -eq [guid]::Empty.ToString())
    if (($rights -band 983551) -eq 983551) { 'GenericAll'; return }
    if (($rights -band 262144) -ne 0) { 'WriteDacl' }
    if (($rights -band 524288) -ne 0) { 'WriteOwner' }
    if (($rights -band 131112) -eq 131112) { 'GenericWrite' }
    elseif (($rights -band 32) -ne 0 -and $allProperties) { 'WriteAllProperties' }
    elseif (($rights -band 32) -ne 0 -and $guid -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2') { 'WriteGroupMembership' }
    if (($rights -band 256) -ne 0 -and ($allProperties -or $guid -eq '00299570-246d-11d0-a768-00aa006e0529')) { 'ResetPasswordOrAllExtendedRights' }
    if (($rights -band 65536) -ne 0) { 'Delete' }
}

function Find-DangerousACLPermissions {
    #Specify the ACLs and Groups to check against
    $coverage = [System.Collections.Generic.List[object]]::new()
    $sidCache = @{}
    # Build the low-privilege identity list dynamically. The literal 'DOMAIN\Domain Users'
    # placeholder never matched a real IdentityReference (e.g. 'CONTOSO\Domain Users'),
    # so the whole check silently found nothing. Use the locale-correct script variables
    # populated by Get-Variables and qualify Domain Users with the real NetBIOS name.
    $domain = Get-ADDomain -ErrorAction Stop
    $nbDomain  = if ($domain.NetBIOSName) { $domain.NetBIOSName } else { $env:USERDOMAIN }
    $authUsers = if ($script:AuthenticatedUsers) { $script:AuthenticatedUsers } else { 'NT AUTHORITY\Authenticated Users' }
    $everyone  = if ($script:EveryOne)           { $script:EveryOne }           else { 'Everyone' }
    $domUsers  = if ($script:DomainUsers)         { $script:DomainUsers }         else { 'Domain Users' }
    $groupsToCheck = @($authUsers, $everyone, "$nbDomain\$domUsers")
    $domainSid = $domain.DomainSID.Value
    $broadSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545',"$domainSid-513","$domainSid-515")

    # Find dangerous permissions on Computers
    Write-ADAuditProgress -Activity 'ACL: computers' -Status 'Enumerating directory objects' -PercentComplete -1
    $computers = @(Get-ADObject -Filter { objectClass -eq 'computer' -and objectCategory -eq 'computer' } -Properties Name -ResultPageSize 2000 -ErrorAction Stop)
    $ci = 0
    $ciFailed = 0
    $computerResults = foreach ($computer in $computers) {
        try {
            Write-ADAuditProgress -Activity 'ACL: computers' -Status "Reading computer $($ci + 1)/$($computers.Count); $ci reads finished, ${ciFailed} unreadable" -PercentComplete ($ci / [math]::Max(1,$computers.Count) * 100)
            $acl = Get-ADObjectAclSafe -DistinguishedName $computer.DistinguishedName
        }
        catch {
            Write-Warning "Could not retrieve ACL for computer '$computer': $_"
            Register-ADAuditNotAssessed -Name 'Dangerous ACL' -Switch 'acl' -Target $computer.DistinguishedName -Reason "ACL read failed: $($_.Exception.Message)"
            $coverage.Add([pscustomobject]@{ObjectType='Computer'; DistinguishedName=$computer.DistinguishedName; Status='NotAssessed'})
            $ciFailed++
            continue
        } finally {
            $ci++
            Write-ADAuditProgress -Activity 'ACL: computers' -Status "${ci}/$($computers.Count) ACL reads finished; ${ciFailed} unreadable" -PercentComplete ($ci / [math]::Max(1,$computers.Count) * 100)
        }
        $coverage.Add([pscustomobject]@{ObjectType='Computer'; DistinguishedName=$computer.DistinguishedName; Status='Assessed'})

        $dangerousRules = $acl.Access | Where-Object {
            ((Get-ADAuditAceSid $_ -Cache $sidCache) -in $broadSids -or [string]$_.IdentityReference -in $groupsToCheck) -and
            @(Get-ADAuditDangerousAceCapability $_).Count -gt 0
        }

        if ($dangerousRules) {
            foreach ($rule in $dangerousRules) {
                [PSCustomObject]@{
                    ObjectType            = 'Computer'
                    ObjectName            = $computer
                    IdentityReference     = $rule.IdentityReference
                    AccessControlType     = $rule.AccessControlType
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights
                    DistinguishedName     = $computer.DistinguishedName
                    TrusteeSid            = Get-ADAuditAceSid $rule -Cache $sidCache
                    ObjectTypeGuid        = [string]$rule.ObjectType
                    InheritanceType       = [string]$rule.InheritanceType
                    IsInherited           = $rule.IsInherited
                    Capability            = @(Get-ADAuditDangerousAceCapability $rule) -join '; '
                    Status                = 'PotentialExposure'
                    Severity              = 'High'
                }
            }
        }
    }

    # Find dangerous permissions on groups
    Write-ADAuditProgress -Activity 'ACL: groups' -Status 'Enumerating directory objects' -PercentComplete -1
    $groups = @(Get-ADObject -Filter { objectClass -eq 'group' -and objectCategory -eq 'group' } -Properties Name -ResultPageSize 2000 -ErrorAction Stop)
    $gi = 0
    $giFailed = 0
    $groupResults = foreach ($group in $groups) {
        try {
            Write-ADAuditProgress -Activity 'ACL: groups' -Status "Reading group $($gi + 1)/$($groups.Count); $gi reads finished, ${giFailed} unreadable" -PercentComplete ($gi / [math]::Max(1,$groups.Count) * 100)
            $acl = Get-ADObjectAclSafe -DistinguishedName $group.DistinguishedName
        }
        catch {
            Write-Warning "Could not retrieve ACL for group '$group': $_"
            Register-ADAuditNotAssessed -Name 'Dangerous ACL' -Switch 'acl' -Target $group.DistinguishedName -Reason "ACL read failed: $($_.Exception.Message)"
            $coverage.Add([pscustomobject]@{ObjectType='Group'; DistinguishedName=$group.DistinguishedName; Status='NotAssessed'})
            $giFailed++
            continue
        } finally {
            $gi++
            Write-ADAuditProgress -Activity 'ACL: groups' -Status "${gi}/$($groups.Count) ACL reads finished; ${giFailed} unreadable" -PercentComplete ($gi / [math]::Max(1,$groups.Count) * 100)
        }
        $coverage.Add([pscustomobject]@{ObjectType='Group'; DistinguishedName=$group.DistinguishedName; Status='Assessed'})

        $dangerousRules = $acl.Access | Where-Object {
            ((Get-ADAuditAceSid $_ -Cache $sidCache) -in $broadSids -or [string]$_.IdentityReference -in $groupsToCheck) -and
            @(Get-ADAuditDangerousAceCapability $_).Count -gt 0
        }

        if ($dangerousRules) {
            foreach ($rule in $dangerousRules) {
                [PSCustomObject]@{
                    ObjectType            = 'Group'
                    ObjectName            = $group
                    IdentityReference     = $rule.IdentityReference
                    AccessControlType     = $rule.AccessControlType
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights
                    DistinguishedName     = $group.DistinguishedName
                    TrusteeSid            = Get-ADAuditAceSid $rule -Cache $sidCache
                    ObjectTypeGuid        = [string]$rule.ObjectType
                    InheritanceType       = [string]$rule.InheritanceType
                    IsInherited           = $rule.IsInherited
                    Capability            = @(Get-ADAuditDangerousAceCapability $rule) -join '; '
                    Status                = 'PotentialExposure'
                    Severity              = 'High'
                }
            }
        }
    }
    # Find dangerous permissions on users
    Write-ADAuditProgress -Activity 'ACL: users' -Status 'Enumerating directory objects' -PercentComplete -1
    $users = @(Get-ADObject -Filter { objectClass -eq 'user' -and objectCategory -eq 'person' } -Properties Name -ResultPageSize 2000 -ErrorAction Stop)
    $ui = 0
    $uiFailed = 0

    $userResults = foreach ($user in $users) {
        try {
            Write-ADAuditProgress -Activity 'ACL: users' -Status "Reading user $($ui + 1)/$($users.Count); $ui reads finished, ${uiFailed} unreadable" -PercentComplete ($ui / [math]::Max(1,$users.Count) * 100)
            $acl = Get-ADObjectAclSafe -DistinguishedName $user.DistinguishedName
        }
        catch {
            Write-Warning "Could not retrieve ACL for user '$user': $_"
            Register-ADAuditNotAssessed -Name 'Dangerous ACL' -Switch 'acl' -Target $user.DistinguishedName -Reason "ACL read failed: $($_.Exception.Message)"
            $coverage.Add([pscustomobject]@{ObjectType='User'; DistinguishedName=$user.DistinguishedName; Status='NotAssessed'})
            $uiFailed++
            continue
        } finally {
            $ui++
            Write-ADAuditProgress -Activity 'ACL: users' -Status "${ui}/$($users.Count) ACL reads finished; ${uiFailed} unreadable" -PercentComplete ($ui / [math]::Max(1,$users.Count) * 100)
        }
        $coverage.Add([pscustomobject]@{ObjectType='User'; DistinguishedName=$user.DistinguishedName; Status='Assessed'})
        if ($acl) {
            $dangerousRules = $acl.Access | Where-Object {
            ((Get-ADAuditAceSid $_ -Cache $sidCache) -in $broadSids -or [string]$_.IdentityReference -in $groupsToCheck) -and
            @(Get-ADAuditDangerousAceCapability $_).Count -gt 0
        }
            if ($dangerousRules) {
                foreach ($rule in $dangerousRules) {
                    [PSCustomObject]@{
                        ObjectType            = 'User'
                        ObjectName            = $user
                        IdentityReference     = $rule.IdentityReference
                        AccessControlType     = $rule.AccessControlType
                        ActiveDirectoryRights = $rule.ActiveDirectoryRights
                        DistinguishedName     = $user.DistinguishedName
                        TrusteeSid            = Get-ADAuditAceSid $rule -Cache $sidCache
                        ObjectTypeGuid        = [string]$rule.ObjectType
                        InheritanceType       = [string]$rule.InheritanceType
                        IsInherited           = $rule.IsInherited
                        Capability            = @(Get-ADAuditDangerousAceCapability $rule) -join '; '
                        Status                = 'PotentialExposure'
                        Severity              = 'High'
                    }
                }
            }
        }
    }

    Write-ADAuditProgress -Activity 'ACL: evidence export' -Status 'Writing findings and coverage' -PercentComplete -1
    # Output results
    Export-ADAuditSecurityCsv -Rows (@($computerResults) + @($groupResults) + @($userResults)) -Columns @('ObjectType','ObjectName','DistinguishedName','IdentityReference','TrusteeSid','AccessControlType','ActiveDirectoryRights','ObjectTypeGuid','InheritanceType','IsInherited','Capability','Status','Severity') -Path (Get-EvidencePath 'dangerous_acls.csv')
    $coverage | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Get-EvidencePath 'dangerous_acl_coverage.csv')
    Write-Both '    [*] ACL scope: broad built-in groups only; reported allow ACEs are potential exposure, not a complete effective-access calculation. Review deny ACEs and nested/custom trustee groups.'
    $dangerousAclHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'dangerousACLs.html'
    $hasAnyAcl = $false

    if ($computerResults) {
        $hasAnyAcl = $true
        $computerResults | Format-List ObjectType,DistinguishedName,IdentityReference,AccessControlType,ActiveDirectoryRights,ObjectTypeGuid,InheritanceType,Capability,Status | Out-File (Get-EvidencePath 'dangerousACL_Computer.txt') -Encoding UTF8 -Width 4096
        Write-Both '    [!] Potential broad-group permission exposure on computers; validate effective access. See dangerous_acls.csv.'
        Write-Nessus-Finding "Weak Computer Permissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dangerousACL_Computer.txt'))) 'High'
    }
    else {
        Write-Both "    [*] No matching broad-group allow ACEs found on assessed computers. Assessed: $(@($coverage | Where-Object { $_.ObjectType -eq 'Computer' -and $_.Status -eq 'Assessed' }).Count)/$($computers.Count)."
    }

    if ($groupResults) {
        $hasAnyAcl = $true
        $groupResults | Format-List ObjectType,DistinguishedName,IdentityReference,AccessControlType,ActiveDirectoryRights,ObjectTypeGuid,InheritanceType,Capability,Status | Out-File (Get-EvidencePath 'dangerousACL_Groups.txt') -Encoding UTF8 -Width 4096
        Write-Both '    [!] Potential broad-group permission exposure on groups; validate effective access. See dangerous_acls.csv.'
        Write-Nessus-Finding "Weak Group Permissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dangerousACL_Groups.txt'))) 'High'
    }
    else {
        Write-Both "    [*] No matching broad-group allow ACEs found on assessed groups. Assessed: $(@($coverage | Where-Object { $_.ObjectType -eq 'Group' -and $_.Status -eq 'Assessed' }).Count)/$($groups.Count)."
    }
    if ($userResults) {
        $hasAnyAcl = $true
        $userResults | Format-List ObjectType,DistinguishedName,IdentityReference,AccessControlType,ActiveDirectoryRights,ObjectTypeGuid,InheritanceType,Capability,Status | Out-File (Get-EvidencePath 'dangerousACLUsers.txt') -Encoding UTF8 -Width 4096
        Write-Both '    [!] Potential broad-group permission exposure on users; validate effective access. See dangerous_acls.csv.'
        Write-Nessus-Finding "Weak User Permissions" "KB551" ([System.IO.File]::ReadAllText((Get-EvidencePath 'dangerousACLUsers.txt'))) 'High'
    }
    else {
        Write-Both "    [*] No matching broad-group allow ACEs found on assessed users. Assessed: $(@($coverage | Where-Object { $_.ObjectType -eq 'User' -and $_.Status -eq 'Assessed' }).Count)/$($users.Count)."
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
                [void]$sb.AppendLine("<tr><td><span class='badge badge-high'>$title</span></td><td><code>$([System.Net.WebUtility]::HtmlEncode([string]$r.ObjectName))</code></td><td>$([System.Net.WebUtility]::HtmlEncode([string]$r.IdentityReference))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$r.AccessControlType))</td><td>$([System.Net.WebUtility]::HtmlEncode([string]$r.ActiveDirectoryRights))</td></tr>")
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

function Invoke-DangerousAclCheck {
    Write-ADAuditProgress -Activity 'Dangerous ACL permissions' -Status 'Starting collection' -PercentComplete -1
    try {
        Find-DangerousACLPermissions
    } finally {
        Write-ADAuditProgress -Activity 'Dangerous ACL permissions' -Completed
    }
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select acl @args
}

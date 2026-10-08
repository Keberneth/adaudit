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

function Find-DangerousACLPermissions {
    #Specify the ACLs and Groups to check against
    $dangerousAces = @('GenericAll', 'GenericWrite', 'ForceChangePassword', 'WriteDacl', 'WriteOwner', 'Delete')
    # Build the low-privilege identity list dynamically. The literal 'DOMAIN\Domain Users'
    # placeholder never matched a real IdentityReference (e.g. 'CONTOSO\Domain Users'),
    # so the whole check silently found nothing. Use the locale-correct script variables
    # populated by Get-Variables and qualify Domain Users with the real NetBIOS name.
    $nbDomain  = try { (Get-ADDomain).NetBIOSName } catch { $env:USERDOMAIN }
    $authUsers = if ($script:AuthenticatedUsers) { $script:AuthenticatedUsers } else { 'NT AUTHORITY\Authenticated Users' }
    $everyone  = if ($script:EveryOne)           { $script:EveryOne }           else { 'Everyone' }
    $domUsers  = if ($script:DomainUsers)         { $script:DomainUsers }         else { 'Domain Users' }
    $groupsToCheck = @($authUsers, $everyone, "$nbDomain\$domUsers")

    # Find dangerous permissions on Computers
    $computers = Get-ADObject -Filter { objectClass -eq 'computer' -and objectCategory -eq 'computer' } -Properties Name -ResultPageSize 2000
    $ci = 0
    $computerResults = foreach ($computer in $computers) {
        try {
            $acl = Get-ADObjectAclSafe -DistinguishedName $computer.DistinguishedName
        }
        catch {
            Write-Warning "Could not retrieve ACL for computer '$computer': $_"
            continue
        }

        $dangerousRules = $acl.Access | Where-Object {
            ([string]$_.IdentityReference -in $groupsToCheck) -and
            ((($_.ActiveDirectoryRights.ToString()) -split ',\s*') | Where-Object { $_ -in $dangerousAces })
        }

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
        $ci++
        Write-Progress -Activity "Searching for dangerous ACL permissions on computers" -Status "Computers searched: $ci/$($computers.Count)" -PercentComplete ($ci / $computers.Count * 100)
    }

    # Find dangerous permissions on groups
    $groups = Get-ADObject -Filter { objectClass -eq 'group' -and objectCategory -eq 'group' } -Properties Name -ResultPageSize 2000
    $gi = 0
    $groupResults = foreach ($group in $groups) {
        try {
            $acl = Get-ADObjectAclSafe -DistinguishedName $group.DistinguishedName
        }
        catch {
            Write-Warning "Could not retrieve ACL for group '$group': $_"
            continue
        }

        $dangerousRules = $acl.Access | Where-Object {
            ([string]$_.IdentityReference -in $groupsToCheck) -and
            ((($_.ActiveDirectoryRights.ToString()) -split ',\s*') | Where-Object { $_ -in $dangerousAces })
        }

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
        $gi++
        Write-Progress -Activity "Searching for dangerous ACL permissions on groups" -Status "Groups searched: $gi/$($groups.Count)" -PercentComplete ($gi / $groups.Count * 100)
    }
    # Find dangerous permissions on users
    $users = Get-ADObject -Filter { objectClass -eq 'user' -and objectCategory -eq 'person' } -Properties Name -ResultPageSize 2000
    $ui = 0

    $userResults = foreach ($user in $users) {
        try {
            $acl = Get-ADObjectAclSafe -DistinguishedName $user.DistinguishedName
        }
        catch {
            Write-Warning "Could not retrieve ACL for user '$user': $_"
            continue
        }
        if ($acl) {
            $dangerousRules = $acl.Access | Where-Object {
            ([string]$_.IdentityReference -in $groupsToCheck) -and
            ((($_.ActiveDirectoryRights.ToString()) -split ',\s*') | Where-Object { $_ -in $dangerousAces })
        }
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
        }
        $ui++
        Write-Progress -Activity "Searching for dangerous ACL permissions on users" -Status "Users searched: $ui/$($users.Count)" -PercentComplete ($ui / $users.Count * 100)
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
    Find-DangerousACLPermissions
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select acl @args
}
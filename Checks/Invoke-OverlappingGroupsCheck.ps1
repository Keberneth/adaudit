<#
    .SYNOPSIS
        ADAudit check: Overlapping group membership analysis

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -overlappinggroups). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-OverlappingGroupsCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select overlappinggroups [options]

    .NOTES
        Entry point: Invoke-OverlappingGroupsCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
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

    function _Enc([string]$s) {
        if ($null -eq $s) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($s)
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
        [void]$sb.AppendLine((Get-ADAuditPrimaryNav -Active 'overlap'))
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
            [void]$sb.AppendLine("<summary>$(_Enc $ug.Name) &mdash; $(_Enc $disp) ($($userRows.Count) target group(s) with overlap)</summary>")
            [void]$sb.AppendLine("<div class='detail-body'><p><code>$(_Enc $dn)</code></p>")
            [void]$sb.AppendLine("<table><thead><tr><th>Target Group</th><th>Overlap Type</th><th>Direct Entry Groups</th><th>Contributing Groups</th><th>Common Groups</th><th>Paths</th></tr></thead><tbody>")

            foreach ($r in ($userRows | Sort-Object TargetGroup)) {
                $pathsHtml = ($r.Paths -split '\s\|\s' | ForEach-Object { "<div><code>$(_Enc $_)</code></div>" }) -join ''
                [void]$sb.AppendLine("<tr><td>$(_Enc $r.TargetGroup)</td><td>$($r.OverlapType)</td><td>$(_Enc $r.DirectEntryGroups)</td><td>$(_Enc $r.ContributingGroups)</td><td>$(_Enc $r.CommonGroups)</td><td>$pathsHtml</td></tr>")
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
        [void]$sb2.AppendLine((Get-ADAuditPrimaryNav -Active 'overlap'))
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
            [void]$sb2.AppendLine("<summary>$(_Enc $ug.Name) &mdash; $(_Enc $disp) ($($userRows.Count) target group(s) with multiple paths)</summary>")
            [void]$sb2.AppendLine("<div class='detail-body'><p><code>$(_Enc $dn)</code></p>")
            [void]$sb2.AppendLine("<table><thead><tr><th>Target Group</th><th>Overlap Type</th><th>Direct Entry Groups</th><th>Contributing Groups</th><th>Common Groups</th><th>Paths</th></tr></thead><tbody>")

            foreach ($r in ($userRows | Sort-Object TargetGroup)) {
                $pathsHtml = ($r.Paths -split '\s\|\s' | ForEach-Object { "<div><code>$(_Enc $_)</code></div>" }) -join ''
                [void]$sb2.AppendLine("<tr><td>$(_Enc $r.TargetGroup)</td><td>$($r.OverlapType)</td><td>$(_Enc $r.DirectEntryGroups)</td><td>$(_Enc $r.ContributingGroups)</td><td>$(_Enc $r.CommonGroups)</td><td>$pathsHtml</td></tr>")
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

function Invoke-OverlappingGroupsCheck {
    Get-OverlappingGroupMemberships
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select overlappinggroups @args
}
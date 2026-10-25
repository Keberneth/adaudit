<#
    .SYNOPSIS
        ADAudit check: GPO audit (and checking SYSVOL for passwords)

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -gpo). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-GroupPolicyCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select gpo [options]

    .NOTES
        Entry point: Invoke-GroupPolicyCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory, GroupPolicy.
#>
Function Get-GPOtoFile {
    #Outputs complete GPO report
    $gpoHtmlPath = Join-Path (Get-HtmlReportsDir -BaseRoot $outputdir) 'GPOReport.html'
    if (Test-Path $gpoHtmlPath) { Remove-Item $gpoHtmlPath -Recurse }
    Write-ADAuditProgress -Activity 'GPO: complete HTML export' -Status 'Waiting for GroupPolicy report generation' -PercentComplete -1
    Get-GPOReport -All -ReportType HTML -Path $gpoHtmlPath
    Write-Both "    [+] GPO Report saved to HTML Reports\GPOReport.html"
    if (Test-Path "$outputdir\GPOReport.xml") { Remove-Item "$outputdir\GPOReport.xml" -Recurse }
    Write-ADAuditProgress -Activity 'GPO: complete XML export' -Status 'Waiting for GroupPolicy report generation' -PercentComplete -1
    Get-GPOReport -All -ReportType XML -Path "$outputdir\GPOReport.xml"
    Write-Both "    [+] GPO Report saved to GPOReport.xml, now run Grouper offline using the following command (KB499)"
    Write-Both "    [+]     PS>Import-Module Grouper.psm1 ; Invoke-AuditGPOReport -Path C:\GPOReport.xml -Level 3"
}

Function Get-GPOsPerOU {
    # Lists every OU and the GPOs that apply to it. Computed from the gPLink / gPOptions
    # attributes directly (domain root -> ... -> OU), because under PowerShell 7 the
    # GroupPolicy module's Get-GPInheritance returns deserialized link objects without
    # DisplayName or GpoId, which produced bare comma lists / "(none)" for every OU.
    $gpoNames = @{}
    try {
        foreach ($g in @(Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName -ErrorAction Stop)) {
            $gpoNames[([string]$g.Name).ToUpperInvariant()] = [string]$g.displayName
        }
    } catch {
        Write-Both "    [!] Could not enumerate GPO containers: $($_.Exception.Message)"
    }
    function _Get-GpLinks {
        # Returns @{ Links = [list of @{Name; Enforced; Disabled}]; Block = bool } for one container.
        param([string]$Dn)
        $out = @{ Links = @(); Block = $false }
        try {
            $o = Get-ADObject -Identity $Dn -Properties gPLink, gPOptions -ErrorAction Stop
            $out.Block = (([int]$(if ($o.gPOptions) { $o.gPOptions } else { 0 })) -band 1) -ne 0
            foreach ($m in [regex]::Matches([string]$o.gPLink, '\[LDAP://(?<dn>[^;\]]+);(?<opt>\d+)\]')) {
                $guid = ''
                if ($m.Groups['dn'].Value -match '(?i)cn=(\{[0-9a-f-]+\})') { $guid = $matches[1].ToUpperInvariant() }
                $opt = [int]$m.Groups['opt'].Value
                $nm = if ($guid -and $gpoNames.ContainsKey($guid)) { $gpoNames[$guid] } else { "GPO $guid" }
                $out.Links += @{ Name = $nm; Enforced = (($opt -band 2) -ne 0); Disabled = (($opt -band 1) -ne 0) }
            }
        } catch { }
        return $out
    }
    $count = 0
    $ousgpos = @(Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue)
    $totalcount = $ousgpos.Count
    $domainDn = (Get-ADDomain).DistinguishedName
    $linkCache = @{}
    $outPath = Get-EvidencePath 'ous_inheritedGPOs.txt'
    Set-Content -Path $outPath -Value @(
        'Candidate GPO links per OU. This is link inventory, not resultant policy.',
        'Site/local policies, disabled GPO sections, security/WMI filters and final setting precedence are not evaluated.',
        'Enforced links are marked [enforced]; "blocks inheritance" means gPOptions=1 on that OU, so only enforced links from above apply.',
        '---------------------------------------------------------------------------------------------------'
    ) -Encoding UTF8
    foreach ($ouobject in $ousgpos) {
        if ($totalcount -eq 0) { break }
        Write-ADAuditProgress -Activity "GPO: candidate links per OU" -Status "$count/$totalcount OUs processed" -PercentComplete ($count / $totalcount * 100)
        # Chain of containers from the domain root down to this OU
        $chain = New-Object System.Collections.Generic.List[string]
        $cur = [string]$ouobject.DistinguishedName
        while ($cur -and $cur -ne $domainDn -and $cur -match '^(OU|CN)=[^,]+,(?<parent>.+)$') { $chain.Insert(0, $cur); $cur = $matches['parent'] }
        $chain.Insert(0, $domainDn)
        $applied = New-Object System.Collections.Generic.List[string]
        $enforcedAbove = New-Object System.Collections.Generic.List[string]
        $blocked = $false
        foreach ($dn in $chain) {
            if (-not $linkCache.ContainsKey($dn)) { $linkCache[$dn] = _Get-GpLinks -Dn $dn }
            $info = $linkCache[$dn]
            if ($info.Block -and $dn -ne $domainDn) {
                # Block inheritance: drop everything from above except enforced links
                $applied.Clear(); foreach ($e in $enforcedAbove) { $applied.Add($e) }
                $blocked = $true
            }
            foreach ($l in $info.Links) {
                if ($l.Disabled) { continue }
                $label = if ($l.Enforced) { "$($l.Name) [enforced]" } else { $l.Name }
                if (-not $applied.Contains($label)) { $applied.Add($label) }
                if ($l.Enforced -and -not $enforcedAbove.Contains($label)) { $enforcedAbove.Add($label) }
            }
        }
        $text = if ($applied.Count) { $applied -join '; ' } else { '(no GPO applies)' }
        Add-Content -Path $outPath -Value "$($ouobject.DistinguishedName)$(if ($blocked) { ' [blocks inheritance]' }) : $text" -Encoding UTF8
        $count++
    }
    Write-ADAuditProgress -Activity "GPO: candidate links per OU" -Status "Ready" -Completed
    Write-Both "    [+] Inherited GPOs saved to ous_inheritedGPOs.txt"
}

Function Get-SYSVOLXMLS {
    #Finds XML files in SYSVOL (thanks --> https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
    $sysvolRoot = "\\$Env:USERDNSDOMAIN\SYSVOL"
    if (-not (Test-Path -LiteralPath $sysvolRoot -ErrorAction SilentlyContinue)) {
        Register-ADAuditNotAssessed -Name 'Get-SYSVOLXMLS' -Switch 'gpo' -Target $sysvolRoot -RequiresRemotePS -Reason "SYSVOL is not reachable from this host (SMB/DFS access to a DC required); the GPP cpassword scan could not run. Note: 'zero files' would NOT mean 'no GPP passwords'."
        return
    }
    $scanErrors = @()
    Write-ADAuditProgress -Activity 'GPO: SYSVOL enumeration' -Status 'Discovering preference XML files over SMB' -PercentComplete -1
    $XMLFiles = @(Get-ChildItem -Path $sysvolRoot -Recurse -ErrorAction SilentlyContinue -ErrorVariable +scanErrors -Include 'Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml')
    foreach ($scanError in $scanErrors) { Register-ADAuditNotAssessed -Name 'SYSVOL preference password scan' -Switch 'gpo' -Target $sysvolRoot -Reason $scanError.Exception.Message }
    $count = 0
    if ($XMLFiles) {
        $progresscount = 0
        $totalcount = ($XMLFiles | Measure-Object | Select-Object Count).count
        foreach ($File in $XMLFiles) {
            if ($totalcount -eq 0) { break }
            $progresscount++
            Write-ADAuditProgress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Reading file $progresscount/$totalcount; $count files with cpassword identified" -PercentComplete ($progresscount / $totalcount * 100)
            $Filename = Split-Path $File -Leaf
            $Distinguishedname = (Split-Path (Split-Path (Split-Path( Split-Path (Split-Path $File -Parent) -Parent ) -Parent ) -Parent) -Leaf).Substring(1).TrimEnd('}')
            [xml]$Xml = Get-Content ($File)
            if ($Xml.InnerXml -match 'cpassword="[^"]+"') {
                if (!(Test-Path "$outputdir\sysvol")) { New-Item -ItemType Directory -Path "$outputdir\sysvol" | Out-Null }
                Write-Both "    [!] cpassword found in file, copying to output folder (KB329)"
                Write-Both "        $File"
                Copy-Item -Path $File -Destination $outputdir\sysvol\$Distinguishedname.$Filename
                $count++
            }
        }
        Write-ADAuditProgress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Ready" -Completed
    }
    if ($count -eq 0) {
        Write-Both "    ...cpassword not found in $($XMLFiles.count) collected XML files; collection errors: $($scanErrors.Count)."
    }
    else {
        $GPOxml = (Get-Content "$outputdir\sysvol\*.xml" -ErrorAction SilentlyContinue)
        Write-Nessus-Finding "GPOPasswordStorage" "KB329" "$GPOxml"
    }
}

function ConvertTo-ADAuditGpoSettingRows {
    param([xml]$Xml, [string]$GpoName, [string]$GpoId, [string]$GpoStatus)
    foreach ($node in $Xml.SelectNodes("//*[local-name()='Computer']//*[local-name()='SecurityOptions' or local-name()='UserRightsAssignment']")) {
        $name = $node.SelectSingleNode("*[local-name()='KeyName' or local-name()='Name']")
        if (-not $name) { continue }
        if ($name.InnerText -notmatch 'NoLMHash|LmCompatibilityLevel|RestrictNTLM|AuditNTLM|AuditReceivingNTLM|DCAllowedNTLM|SupportedEncryptionTypes|SeDeny.*LogonRight|SeMachineAccountPrivilege') { continue }
        $value = $node.SelectSingleNode("*[local-name()='SettingNumber' or local-name()='SettingBoolean' or local-name()='SettingString']")
        $members = @($node.SelectNodes("*[local-name()='Member']") | ForEach-Object { $_.InnerText })
        [pscustomobject]@{
            GpoName=$GpoName; GpoId=$GpoId; GpoStatus=$GpoStatus; Setting=$name.InnerText
            Value=$(if ($value) { $value.InnerText } elseif ($members.Count) { $members -join '; ' } else { $node.InnerText })
            Assessment='Configuration inventory only; effective application not verified'
        }
    }
}

Function Get-GPOEnum {
    $rows = [System.Collections.Generic.List[object]]::new()
    Write-ADAuditProgress -Activity 'GPO: configuration inventory' -Status 'Enumerating policies' -PercentComplete -1
    $policies = @(Get-GPO -All -ErrorAction Stop | Sort-Object DisplayName)
    $policyIndex = 0
    foreach ($gpo in $policies) {
        Write-ADAuditProgress -Activity 'GPO: configuration inventory' -Status "Reading policy $($policyIndex + 1)/$($policies.Count): $($gpo.DisplayName)" -PercentComplete ($policyIndex / [math]::Max(1,$policies.Count) * 100)
        $policyIndex++
        try {
            [xml]$xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
            foreach ($row in @(ConvertTo-ADAuditGpoSettingRows -Xml $xml -GpoName $gpo.DisplayName -GpoId $gpo.Id -GpoStatus ([string]$gpo.GpoStatus))) { $rows.Add($row) }
        } catch { Register-ADAuditNotAssessed -Name 'GPO configuration inventory' -Switch 'gpo' -Target $gpo.DisplayName -Reason $_.Exception.Message }
    }
    $rows | Export-Csv -LiteralPath (Get-EvidencePath 'gpo_security_settings.csv') -NoTypeInformation -Encoding UTF8
    $policyEvidence = @(
        'Status: PolicyEvidenceOnly - GPO configuration does not establish effective protection.'
        'Disabled sections, links, security/WMI filtering and precedence must be checked with resultant policy on the target.'
        'See gpo_security_settings.csv for all observed values, including disabled policies and value zero.'
        'See ntlm_dc_settings.csv for directly observed DC registry settings; missing/inaccessible settings remain unknown.'
    )
    $policyEvidence | Set-Content -LiteralPath (Get-EvidencePath 'ntlm_restrictions.txt') -Encoding UTF8
    $rows | Where-Object { $_.Setting -match 'SeDeny.*LogonRight' } | Format-Table GpoName,GpoStatus,Setting,Value -AutoSize | Out-String -Width 300 |
        Set-Content -LiteralPath (Get-EvidencePath 'admin_logon_restrictions.txt') -Encoding UTF8
    Register-ADAuditNotAssessed -Name 'Effective administrative logon restrictions' -Switch 'gpo' -Reason 'GPO settings are inventoried, but resultant policy for member servers and workstations is not collected. Presence or absence in a GPO is not a domain-wide protection verdict.'
}

function Get-ADAuditNtlmDcSettings {
    $rows = [System.Collections.Generic.List[object]]::new()
    $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop)
    if ($dcs.Count -eq 0) { Register-ADAuditNotAssessed -Name 'DC NTLM configuration' -Switch 'gpo' -Reason 'No domain controllers returned.'; return }
    $dcIndex = 0
    foreach ($dc in $dcs) {
        Write-ADAuditProgress -Activity 'GPO: observed NTLM configuration' -Status "DC $($dcIndex + 1)/$($dcs.Count): $($dc.HostName)" -PercentComplete ($dcIndex / [math]::Max(1,$dcs.Count) * 100)
        $dcIndex++
        foreach ($setting in @(
            @{Name='LmCompatibilityLevel'; Key='SYSTEM\CurrentControlSet\Control\Lsa'},
            @{Name='NoLMHash'; Key='SYSTEM\CurrentControlSet\Control\Lsa'},
            @{Name='RestrictNTLMInDomain'; Key='SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'}
        )) {
            $result = Get-ADAuditRemoteRegistryDword -ComputerName $dc.HostName -SubKey $setting.Key -ValueName $setting.Name
            $status = 'Observed'; $severity = 'Information'; $reason = 'Observed configuration; evaluate approved exceptions and application compatibility.'
            if (-not $result.Success -or $null -eq $result.Value) {
                $status = 'NotAssessed'; $reason = if (-not $result.Success) { $result.Error } else { 'Value not explicitly configured; OS defaults and effective policy were not established.' }
                Register-ADAuditNotAssessed -Name 'DC NTLM configuration' -Switch 'gpo' -Target ($dc.HostName + '/' + $setting.Name) -Reason $reason
            } elseif ($setting.Name -eq 'LmCompatibilityLevel') {
                if ($result.Value -notin 0..5) {
                    $status='NotAssessed'; $reason='Unrecognized LAN Manager authentication level.'
                    Register-ADAuditNotAssessed -Name 'DC NTLM configuration' -Switch 'gpo' -Target $dc.HostName -Reason $reason
                } elseif ($result.Value -lt 5) { $status='Finding'; $severity='Medium'; $reason='Configured LAN Manager level does not refuse both LM and NTLMv1. Audit client dependencies, then evaluate level 5.' }
            } elseif ($setting.Name -eq 'NoLMHash' -and $result.Value -eq 0) {
                $status='Finding'; $severity='High'; $reason='LM hash storage is explicitly permitted. Enable NoLMHash and plan password changes; configuration alone does not prove existing hashes.'
            }
            $row = [pscustomobject]@{ Target=$dc.HostName; Setting=$setting.Name; Value=$result.Value; Status=$status; Severity=$severity; Reason=$reason }
            $rows.Add($row)
            if ($status -eq 'Finding') { Write-Nessus-Finding 'DC NTLM configuration' 'KB1311' ($row | ConvertTo-Json -Compress) $severity }
        }
    }
    $rows | Export-Csv -LiteralPath (Get-EvidencePath 'ntlm_dc_settings.csv') -NoTypeInformation -Encoding UTF8
}

function Invoke-GroupPolicyCheck {
    Write-ADAuditProgress -Activity 'Group Policy checks' -Status 'Starting collection' -PercentComplete -1
    try {
        Invoke-AuditStep -Name 'Get-GPOtoFile' -Switch 'gpo' -Body { Get-GPOtoFile }
        Invoke-AuditStep -Name 'Get-GPOsPerOU' -Switch 'gpo' -Body { Get-GPOsPerOU }
        Invoke-AuditStep -Name 'Get-SYSVOLXMLS' -Switch 'gpo' -Body { Get-SYSVOLXMLS }
        Invoke-AuditStep -Name 'Get-GPOEnum' -Switch 'gpo' -Body { Get-GPOEnum }
        Invoke-AuditStep -Name 'Get-ADAuditNtlmDcSettings' -Switch 'gpo' -Body { Get-ADAuditNtlmDcSettings }
    } finally {
        Write-ADAuditProgress -Activity 'Group Policy checks' -Completed
    }
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select gpo @args
}

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
    Get-GPOReport -All -ReportType HTML -Path $gpoHtmlPath
    Write-Both "    [+] GPO Report saved to HTML Reports\GPOReport.html"
    if (Test-Path "$outputdir\GPOReport.xml") { Remove-Item "$outputdir\GPOReport.xml" -Recurse }
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
        'Effective Group Policy per OU (links applied, in processing order: domain -> parent OUs -> OU).',
        'Enforced links are marked [enforced]; "blocks inheritance" means gPOptions=1 on that OU, so only enforced links from above apply.',
        '---------------------------------------------------------------------------------------------------'
    ) -Encoding UTF8
    foreach ($ouobject in $ousgpos) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Currently identified $count OUs" -PercentComplete ($count / $totalcount * 100)
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
    Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Ready" -Completed
    Write-Both "    [+] Inherited GPOs saved to ous_inheritedGPOs.txt"
}

Function Get-SYSVOLXMLS {
    #Finds XML files in SYSVOL (thanks --> https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
    $sysvolRoot = "\\$Env:USERDNSDOMAIN\SYSVOL"
    if (-not (Test-Path -LiteralPath $sysvolRoot -ErrorAction SilentlyContinue)) {
        Register-ADAuditNotAssessed -Name 'Get-SYSVOLXMLS' -Switch 'gpo' -Target $sysvolRoot -RequiresRemotePS -Reason "SYSVOL is not reachable from this host (SMB/DFS access to a DC required); the GPP cpassword scan could not run. Note: 'zero files' would NOT mean 'no GPP passwords'."
        return
    }
    $XMLFiles = Get-ChildItem -Path $sysvolRoot -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml'
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
            if ($Xml.InnerXml -match 'cpassword="[^"]+"') {
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
        Write-Nessus-Finding "GPOPasswordStorage" "KB329" "$GPOxml"
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
        #Look for GPO that hardens NTLM. Only count the GPO when the configured
        #VALUE actually hardens: NoLMHash=Disabled or LmCompatibilityLevel 0-2
        #configure the key without restricting anything. When the value cannot
        #be parsed (e.g. localized display text), keep the previous behavior
        #and count it rather than raise a false 'not restricted' finding.
        $permissionindex = $GPOreport.IndexOf('NoLMHash</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'NoLMHash' }
            $noLmHardens = $true
            try {
                if ($value.Display.DisplayBoolean) { $noLmHardens = ([string]$value.Display.DisplayBoolean -ieq 'true') }
                elseif ($value.SettingNumber)      { $noLmHardens = ([int]$value.SettingNumber -ne 0) }
            } catch { }
            if ($noLmHardens) {
                $obj = New-Object -TypeName PSObject
                $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
                $obj | Add-Member -MemberType NoteProperty -Name Value -Value "NoLMHash $($value.Display.DisplayBoolean)"
                $HardenNTLM += $obj
            }
        }
        $permissionindex = $GPOreport.IndexOf('LmCompatibilityLevel</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'LmCompatibilityLevel' }
            $lmHardens = $true
            try {
                if ($value.SettingNumber) { $lmHardens = ([int]$value.SettingNumber -ge 3) }
                elseif ($value.Display.DisplayString) {
                    # Levels 0-2 (English): 'Send LM & NTLM ...' / 'Send NTLM response only'
                    $lmDisplay = [string]$value.Display.DisplayString
                    if ($lmDisplay -like 'Send LM *' -or $lmDisplay -ieq 'Send NTLM response only') { $lmHardens = $false }
                }
            } catch { }
            if ($lmHardens) {
                $obj = New-Object -TypeName PSObject
                $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
                $obj | Add-Member -MemberType NoteProperty -Name Value -Value "LmCompatibilityLevel $($value.Display.DisplayString)"
                $HardenNTLM += $obj
            }
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
            # Independent checks (not elseif): a single GPO can enable several weak ciphers
            # and/or leave several AES types off; the previous elseif chain reported only the
            # first match and hid the rest.
            if (($EncryptionTypes | Where-Object { $_.Name -eq 'DES_CBC_CRC' }             | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_CRC for Kerberos!" }
            if (($EncryptionTypes | Where-Object { $_.Name -eq 'DES_CBC_MD5' }             | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_MD5 for Kerberos!" }
            if (($EncryptionTypes | Where-Object { $_.Name -eq 'RC4_HMAC_MD5' }            | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled RC4_HMAC_MD5 for Kerberos!" }
            if (($EncryptionTypes | Where-Object { $_.Name -eq 'AES128_HMAC_SHA1' }        | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] GPO [$($GPO.DisplayName)] does not enable AES128_HMAC_SHA1 for Kerberos!" }
            if (($EncryptionTypes | Where-Object { $_.Name -eq 'AES256_HMAC_SHA1' }        | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] GPO [$($GPO.DisplayName)] does not enable AES256_HMAC_SHA1 for Kerberos!" }
            if (($EncryptionTypes | Where-Object { $_.Name -eq 'Future encryption types' } | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] GPO [$($GPO.DisplayName)] does not enable future encryption types for Kerberos!" }
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
        Write-Both "    [!] No GPO configures Kerberos SupportedEncryptionTypes, so the OS default applies and weak ciphers (RC4, and on some systems DES) may still be permitted. Explicitly configure AES-only where application compatibility allows."
    }
    #Output for deny NTLM
    # Always record an explicit status line so the risk report can tell "NTLM is not
    # restricted" (a finding) apart from "NTLM is restricted" (evidence, not a finding)
    # and apart from "the GPO check never ran" (no file at all). Previously the file was
    # only written when restrictions EXISTED, so the risk report flagged hardened domains.
    $ntlmEvidence = Get-EvidencePath 'ntlm_restrictions.txt'
    if ($DenyNTLM.count -eq 0 -and $HardenNTLM.count -eq 0) {
        Write-Both "    [!] No GPO denies NTLM authentication!"
        Write-Both "    [!] No GPO explicitely restricts LM or NTLMv1!"
        Add-Content -Path $ntlmEvidence -Value "Status: NotRestricted - no GPO denies NTLM and no GPO restricts LM/NTLMv1 across the domain."
    }
    else {
        Add-Content -Path $ntlmEvidence -Value "Status: Restricted - one or more GPOs deny or harden NTLM (details below)."
        if ($DenyNTLM.count -eq 0) {
            Write-Both "    [+] NTLM authentication hardening implemented, but NTLM not denied"
            foreach ($record in $HardenNTLM) {
                Write-Both "        [-] $($record.value)"
                Add-Content -Path $ntlmEvidence -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
            }
        }
        else {
            foreach ($record in $DenyNTLM) {
                Add-Content -Path $ntlmEvidence -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
            }
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

function Invoke-GroupPolicyCheck {
    Invoke-AuditStep -Name 'Get-GPOtoFile' -Switch 'gpo' -Body { Get-GPOtoFile }
    Invoke-AuditStep -Name 'Get-GPOsPerOU' -Switch 'gpo' -Body { Get-GPOsPerOU }
    Invoke-AuditStep -Name 'Get-SYSVOLXMLS' -Switch 'gpo' -Body { Get-SYSVOLXMLS }
    Invoke-AuditStep -Name 'Get-GPOEnum' -Switch 'gpo' -Body { Get-GPOEnum }
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select gpo @args
}
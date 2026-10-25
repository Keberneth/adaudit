<# Read-only review of assigned authentication policy configuration for privileged users. #>
function Get-ADAuditAuthenticationPolicyState {
    param($Policy, $Silo, [bool]$HasAssignment)
    if (-not $HasAssignment) { return [pscustomobject]@{Status='Missing'; Detail='No policy/silo assignment was found. Other sign-in restrictions were not evaluated.'} }
    if ($null -eq $Policy) { return [pscustomobject]@{Status='NotAssessed'; Detail='Assigned policy could not be resolved, or the silo has no user policy.'} }
    if (-not $Policy.Enforce -or ($null -ne $Silo -and -not $Silo.Enforce)) { return [pscustomobject]@{Status='AuditOnly'; Detail='Assigned policy or silo is not enforced; audit mode does not restrict authentication.'} }
    if (-not $Policy.UserAllowedToAuthenticateFrom -and -not $Policy.UserAllowedToAuthenticateTo) { return [pscustomobject]@{Status='AssignedUnrestricted'; Detail='An enforced policy is assigned, but no user source/target restriction is configured. TGT lifetime alone does not prove host containment.'} }
    [pscustomobject]@{Status='ConfiguredRestriction'; Detail='An enforced assigned policy contains a source/target restriction. Review the access-control expression, silo membership and Kerberos prerequisites; this is configuration evidence, not an end-to-end sign-in test.'}
}
function Get-AuthenticationPoliciesAndSilos {
    $evidence = Get-EvidencePath 'auth_policies_silos.txt'
    Remove-Item -LiteralPath $evidence -ErrorAction SilentlyContinue
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        if (-not (Test-ADAuditFunctionalLevelAtLeast -Mode $domain.DomainMode -MinimumMode 'Windows2012R2Domain')) {
            Register-ADAuditNotAssessed -Name 'Authentication policy coverage' -Switch 'authpolsilos' -Reason "DFL $($domain.DomainMode) does not support this feature. Assess other privileged sign-in restrictions; raising DFL requires a separate compatibility plan."
            return
        }
        $policies = @(Get-ADAuthenticationPolicy -Filter * -Properties * -ErrorAction Stop)
        $silos = @(Get-ADAuthenticationPolicySilo -Filter * -Properties * -ErrorAction Stop)
    } catch { Register-ADAuditNotAssessed -Name 'Authentication policy inventory' -Switch 'authpolsilos' -Reason $_.Exception.Message; return }
    $policyMap = @{}; $siloMap = @{}
    foreach ($p in $policies) { $policyMap[[string]$p.DistinguishedName] = $p }
    foreach ($s in $silos) { $siloMap[[string]$s.DistinguishedName] = $s }
    $principals = @{}
    # Scope is stated explicitly: recursive members of DA and domain BUILTIN Administrators.
    foreach ($groupSid in @("$($domain.DomainSID.Value)-512",'S-1-5-32-544')) {
        try {
            foreach ($member in @(Get-ADGroupMember -Identity $groupSid -Recursive -ErrorAction Stop)) {
                if ($member.objectClass -eq 'user') { $principals[[string]$member.SID] = $member }
            }
        } catch { Register-ADAuditNotAssessed -Name 'Authentication policy privileged scope' -Switch 'authpolsilos' -Target $groupSid -Reason "Recursive membership failed: $($_.Exception.Message)" }
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($member in $principals.Values) {
        try {
            $user = Get-ADUser -Identity $member.DistinguishedName -Properties msDS-AssignedAuthNPolicy,msDS-AssignedAuthNPolicySilo,Enabled -ErrorAction Stop
            $policyDN = [string]$user.'msDS-AssignedAuthNPolicy'
            $siloDN = [string]$user.'msDS-AssignedAuthNPolicySilo'
            $silo = $null; $policy = $null
            if ($siloDN) {
                $silo = $siloMap[$siloDN]
                if (-not $silo) { throw "Assigned silo $siloDN was not resolved." }
                $policyDN = [string]$silo.UserAuthenticationPolicy
            }
            if ($policyDN) { $policy = $policyMap[$policyDN] }
            $state = Get-ADAuditAuthenticationPolicyState -Policy $policy -Silo $silo -HasAssignment ([bool]($policyDN -or $siloDN))
            $rows.Add([pscustomobject]@{Account=$user.SamAccountName; SID=[string]$user.SID; Enabled=$user.Enabled; Policy=$policyDN; Silo=$siloDN; Status=$state.Status; Detail=$state.Detail})
            if ($state.Status -eq 'NotAssessed') { Register-ADAuditNotAssessed -Name 'Authentication policy assignment' -Switch 'authpolsilos' -Target $user.DistinguishedName -Reason $state.Detail }
        } catch {
            Register-ADAuditNotAssessed -Name 'Authentication policy assignment' -Switch 'authpolsilos' -Target $member.DistinguishedName -Reason $_.Exception.Message
            $rows.Add([pscustomobject]@{Account=$member.SamAccountName; SID=[string]$member.SID; Enabled=$null; Policy=''; Silo=''; Status='NotAssessed'; Detail=$_.Exception.Message})
        }
    }
    Export-ADAuditSecurityCsv -Rows $rows -Columns @('Account','SID','Enabled','Policy','Silo','Status','Detail') -Path (Get-EvidencePath 'auth_policy_coverage.csv')
    $policies | Select-Object Name,DistinguishedName,Enforce,UserAllowedToAuthenticateFrom,UserAllowedToAuthenticateTo,UserTGTLifetimeMins | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Get-EvidencePath 'auth_policy_inventory.csv')
    $silos | Select-Object Name,DistinguishedName,Enforce,UserAuthenticationPolicy,Members | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Get-EvidencePath 'auth_silo_inventory.csv')
    $gaps = @($rows | Where-Object { $_.Enabled -eq $true -and $_.Status -in @('Missing','AuditOnly','AssignedUnrestricted') })
    if ($gaps.Count -gt 0) {
        @('Scope: enabled user members of Domain Admins and domain BUILTIN Administrators (recursive). This is authentication-policy configuration coverage; other sign-in controls may exist.'; $gaps | ForEach-Object { "$($_.Account): $($_.Status). $($_.Detail)" }; 'Review intended Tier 0 isolation, pilot policies in audit mode, validate allowed and rejected authentication, then enforce. Plan emergency access before changing restrictions.') | Set-Content -LiteralPath $evidence -Encoding UTF8
        Write-Nessus-Finding 'Privileged authentication policy coverage requires review' 'KB549' ([IO.File]::ReadAllText($evidence)) 'Medium'
    }
    Write-Both "    [*] Authentication policies=$($policies.Count); silos=$($silos.Count); privileged user assignments reviewed=$($rows.Count); enabled-user configuration gaps=$($gaps.Count). See auth_policy_coverage.csv for per-account state and scope."
}
function Invoke-AuthPoliciesCheck { Get-AuthenticationPoliciesAndSilos }
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select authpolsilos @args
}

<#
    .SYNOPSIS
        ADAudit check: Delegated Permissions Report

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -delegatedpermissions). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-DelegatedPermissionsCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select delegatedpermissions [options]

    .NOTES
        Entry point: Invoke-DelegatedPermissionsCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory.
#>
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

    # System.Web is needed later for HtmlEncode in the HTML index. Loading
    # it once up front avoids a per-call Add-Type and keeps strict-mode happy.
    try { [void][System.Web.HttpUtility] } catch { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue }

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
    # Both helpers run once per ACE; the same trustees and scope DNs recur
    # constantly, so memoize to avoid thousands of duplicate LDAP queries.
    $principalTypeCache = @{}
    function Get-PrincipalType {
      param([string]$Identity)
      if ($principalTypeCache.ContainsKey($Identity)) { return $principalTypeCache[$Identity] }
      $ptResult = $null
      try {
        # Trustees arrive as 'DOMAIN\name', 'BUILTIN\name', a raw SID ('S-1-5-...'), or a
        # DN. Build the filter from the right component: sAMAccountName is the part after
        # the last backslash, a SID must match objectSid, and a DN must match
        # distinguishedName. The previous filter compared the whole 'DOMAIN\name' string
        # against sAMAccountName/DN/SID and so never matched a domain trustee.
        $name = ($Identity -split '\\')[-1]
        $filter =
          if ($Identity -match '^S-\d-\d+') { "(objectSid=$Identity)" }
          elseif ($Identity -match '^(CN|OU|DC)=') { "(distinguishedName=$Identity)" }
          else { "(sAMAccountName=$name)" }
        $obj = if ($Server) {
          Get-ADObject -Server $Server -LDAPFilter $filter -Properties objectClass -ErrorAction Stop
        } else {
          Get-ADObject -LDAPFilter $filter -Properties objectClass -ErrorAction Stop
        }
        if ($obj.objectClass -contains 'group')          { $ptResult = 'Group' }
        elseif ($obj.objectClass -contains 'user')       { $ptResult = 'User' }
        elseif ($obj.objectClass -contains 'computer')   { $ptResult = 'Computer' }
        elseif ($obj.objectClass -contains 'foreignSecurityPrincipal') { $ptResult = 'FSP' }
      } catch {}
      if (-not $ptResult) {
        $ptResult = if ($Identity -match '^S-\d-\d+') { 'SID' } else { 'WellKnownOrExternal' }
      }
      $principalTypeCache[$Identity] = $ptResult
      return $ptResult
    }

    # Canonical path helper
    $canonicalCache = @{}
    function Get-Canonical {
      param([string]$Dn)
      if ($canonicalCache.ContainsKey($Dn)) { return $canonicalCache[$Dn] }
      $cn = try {
        $p = @{ Identity=$Dn; Properties='CanonicalName'; ErrorAction='Stop' }
        if ($Server) { $p['Server'] = $Server }
        (Get-ADObject @p).CanonicalName
      } catch { $null }
      $canonicalCache[$Dn] = $cn
      return $cn
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
      # NOTE: Per-scope .txt files are no longer written here. They previously
      # duplicated the same data already in the per-scope .csv (and we ended up
      # with 73+ pairs of .txt/.csv files in OUs/, which made the report folder
      # hard to navigate). A single consolidated, sectioned summary is written
      # instead - see ADAudit_PerScopeSummary.txt later in this function.
    }

    # De-duplicate identical ACE rows to reduce noise
    $records = @($records |
      Sort-Object ScopeDN,Trustee,AccessControlType,ActiveDirectoryRights,AppliesToClass,AppliesToProperty,InheritanceType,IsInherited,ObjectTypeGuid,InheritedObjectGuid -Unique)

    # ------- Analytics and risk outputs (always generated) -------

    # Windows LAPS + legacy LAPS attributes
    $lapsAttributes = @('ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime','msLAPS-Password','msLAPS-PasswordExpirationTime','msLAPS-EncryptedPassword','msLAPS-EncryptedPasswordHistory','msLAPS-EncryptedDSRMPassword','msLAPS-EncryptedDSRMPasswordHistory')

    $overDelegations = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'GenericAll|WriteDacl|DeleteTree'
    }
    $accountOperators = $records | Where-Object { $_.Trustee -eq 'BUILTIN\Account Operators' }
    $printOperators   = $records | Where-Object { $_.Trustee -eq 'BUILTIN\Print Operators' }
    # Trustee values carry a 'DOMAIN\' or 'BUILTIN\' prefix, so compare the name part
    # after the last backslash - otherwise these matches never fire (e.g. the real value
    # is 'CONTOSO\Exchange Trusted Subsystem', not the bare name).
    $exchangePattern  = 'Exchange Trusted Subsystem','Organization Management','Exchange Windows Permissions'
    $exchangeDelegations = $records | Where-Object { (($_.Trustee -split '\\')[-1]) -in $exchangePattern }
    $serviceAcctDelegations = $records | Where-Object {
      $name = ($_.Trustee -split '\\')[-1]
      ($name -match '^(svc|sa)[\-_]') -or ($_.Trustee -match 'DomainJoin') -or ($name -match '\bDJ\b')
    }
    $unknownSids = @($records | Where-Object { $_.TrusteeType -eq 'SID' } | Select-Object -Expand Trustee | Sort-Object -Unique)
    $membershipControl = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'WriteProperty' -and $_.AppliesToProperty -eq 'member'
    }
    $preWin2k  = $records | Where-Object { (($_.Trustee -split '\\')[-1]) -eq 'Pre-Windows 2000 Compatible Access' }
    $lapsRead  = $records | Where-Object {
      $_.AppliesToProperty -in $lapsAttributes -and $_.ActiveDirectoryRights.ToString() -match 'ReadProperty|ExtendedRight'
    }
    # The child-object type a CreateChild ACE may create is in ObjectType (AppliesToProperty),
    # NOT the inheritance-scope class InheritedObjectType (AppliesToClass). A "Create Computer
    # objects" delegation therefore shows up as AppliesToProperty='computer'; a blanket
    # CreateChild (empty ObjectType) also permits creating computers.
    $computerCreate = $records | Where-Object {
      $_.ActiveDirectoryRights.ToString() -match 'CreateChild' -and
      (($_.AppliesToProperty -match 'computer') -or (-not $_.ObjectTypeGuid))
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

    # ----------------------------
    # Risk Assessment - structured by SEVERITY so the operator can read top-down:
    # CRITICAL findings first (act now), HIGH next, MEDIUM/LOW after. Each
    # finding now carries: severity, what is wrong, why it matters (security
    # impact), how to fix it, and a sample of trustees / scopes to look at.
    # The old report listed nine numbered items with no severity grouping and
    # no "what to do" guidance per item, which made it hard to prioritise.
    # ----------------------------
    $findings = New-Object System.Collections.Generic.List[object]

    function _Add-Finding {
        param(
            [Parameter(Mandatory)][string]$Severity,
            [Parameter(Mandatory)][string]$Title,
            [Parameter(Mandatory)][int]$Count,
            [Parameter(Mandatory)][string]$Why,
            [Parameter(Mandatory)][string]$Fix,
            [string[]]$Samples = @()
        )
        $findings.Add([pscustomobject]@{
            Severity = $Severity
            Title    = $Title
            Count    = $Count
            Why      = $Why
            Fix      = $Fix
            Samples  = $Samples
        }) | Out-Null
    }

    if ($cntOver -gt 0) {
        $sev = if ($cntOver -gt 50) { 'CRITICAL' } elseif ($cntOver -gt 10) { 'HIGH' } else { 'MEDIUM' }
        $samples = @($overDelegations | Select-Object -ExpandProperty Trustee | Sort-Object -Unique | Select-Object -First 10)
        _Add-Finding -Severity $sev -Title 'Over-delegation: GenericAll / WriteDacl / DeleteTree' -Count $cntOver `
            -Why 'These rights let the trustee fully control or take ownership of the affected OU, which is equivalent to administrative access on every object below it. A single account or group with GenericAll on a Tier0 OU is a domain-takeover path.' `
            -Fix 'Replace these delegations with task-specific rights (e.g. ResetPassword, ReadPwdLastSet) scoped to the smallest necessary container. Document the business justification for any remaining GenericAll delegation.' `
            -Samples $samples
    }
    if ($cntMemberCtrl -gt 0) {
        $sev = if ($cntMemberCtrl -gt 40) { 'CRITICAL' } elseif ($cntMemberCtrl -gt 5) { 'HIGH' } else { 'MEDIUM' }
        $samples = @($membershipControl | Select-Object -ExpandProperty Trustee | Sort-Object -Unique | Select-Object -First 10)
        _Add-Finding -Severity $sev -Title 'Group membership modification rights (WriteProperty on member)' -Count $cntMemberCtrl `
            -Why 'Allows the trustee to add/remove accounts from arbitrary groups - a direct privilege-escalation vector if it leads to Tier0 groups (Domain/Enterprise Admins) via nested membership.' `
            -Fix 'Restrict member-write to controlled, audited group-admin roles. Never grant member-write on Tier0 groups except via JIT/PIM.' `
            -Samples $samples
    }
    if ($cntLaps -gt 0) {
        $samples = @($lapsRead | Select-Object -ExpandProperty Trustee | Sort-Object -Unique | Select-Object -First 10)
        _Add-Finding -Severity 'HIGH' -Title 'LAPS password read delegations' -Count $cntLaps `
            -Why 'Trustees with read access to ms-Mcs-AdmPwd / msLAPS-Password can recover the local-administrator password of every computer covered by the delegation. This is full local-admin on those endpoints.' `
            -Fix 'Limit LAPS read to a small, monitored helpdesk/Tier1 group. Audit each existing reader and remove anything outside that group. Monitor all reads.' `
            -Samples $samples
    }
    if ($cntComputerCreate -gt 0) {
        $samples = @($computerCreate | Select-Object -ExpandProperty Trustee | Sort-Object -Unique | Select-Object -First 10)
        _Add-Finding -Severity 'HIGH' -Title 'Computer object creation rights (CreateChild for computer class)' -Count $cntComputerCreate `
            -Why 'Trustees who can create computer objects can join arbitrary machines to the domain and chain that into Resource-Based Constrained Delegation (RBCD) attacks for privilege escalation.' `
            -Fix 'Constrain computer creation to a dedicated join service account with a low MachineAccountQuota (or 0). Never grant CreateChild=computer to broad groups.' `
            -Samples $samples
    }
    if ($cntAcctOps -gt 0) {
        _Add-Finding -Severity 'HIGH' -Title 'BUILTIN\Account Operators delegations present' -Count $cntAcctOps `
            -Why 'Account Operators can manage users/groups/computers in most of the domain - Microsoft explicitly recommends this group be empty. Membership and ACEs through it indirectly create privileged paths.' `
            -Fix 'Remove BUILTIN\Account Operators delegations from OUs unless explicitly required and reviewed. Replace with narrow, task-specific delegations.' `
            -Samples @()
    }
    if ($cntSvc -gt 0) {
        $sev = if ($cntSvc -gt 30) { 'HIGH' } else { 'MEDIUM' }
        $samples = @($serviceAcctDelegations | Select-Object -ExpandProperty Trustee | Sort-Object -Unique | Select-Object -First 10)
        _Add-Finding -Severity $sev -Title 'Service account elevated delegations' -Count $cntSvc `
            -Why 'Service accounts (svc-*, DJ-*, DomainJoin*) holding write/create rights are an attractive target - if compromised they can be used for SPN-based attacks (Kerberoasting), RBCD, and lateral movement.' `
            -Fix 'Apply least privilege per service account, rotate passwords, prefer Group Managed Service Accounts (gMSA), and tier them so they cannot reach Tier0 objects.' `
            -Samples $samples
    }
    if ($cntExchange -gt 0) {
        _Add-Finding -Severity 'MEDIUM' -Title 'Exchange security group delegations' -Count $cntExchange `
            -Why 'Exchange Trusted Subsystem / Organization Management / Exchange Windows Permissions traditionally hold rights well beyond mail scope. They have historically been a path to domain compromise (CVE-2019-0683 et al).' `
            -Fix 'Review these ACLs against Microsoft Exchange Split Permissions and remove anything not required by the current Exchange version. Replace any GenericAll with the documented minimum.' `
            -Samples @()
    }
    if ($cntUnknownSids -gt 0) {
        _Add-Finding -Severity 'MEDIUM' -Title 'Unknown / unresolved SIDs in ACLs' -Count $cntUnknownSids `
            -Why 'A SID that no longer resolves to a principal is usually orphaned (deleted account, deleted trust). Each one is dead weight in the ACL and complicates audits, but a foreign-domain SID could also indicate an unexpected trust relationship.' `
            -Fix 'For each SID, verify whether it belongs to a deleted local principal or a foreign domain, then remove the ACE. Do NOT bulk-delete without verification.' `
            -Samples @($unknownSids | Select-Object -First 10)
    }
    if ($cntPrintOps -gt 0) {
        _Add-Finding -Severity 'MEDIUM' -Title 'BUILTIN\Print Operators delegations present' -Count $cntPrintOps `
            -Why 'Print Operators can load device drivers and historically have been abused (e.g. PrintNightmare, SpoolSample). Microsoft recommends keeping the group empty.' `
            -Fix 'Remove Print Operators delegations from OUs unless required. Empty the group where possible; replace with explicit, scoped delegations.' `
            -Samples @()
    }
    if ($cntPreWin2k -gt 0) {
        _Add-Finding -Severity 'LOW' -Title 'Legacy Pre-Windows 2000 Compatible Access ACEs' -Count $cntPreWin2k `
            -Why 'Pre-Windows 2000 Compatible Access expands anonymous/legacy read scope. Modern environments should not need it.' `
            -Fix 'Decommission Pre-Windows 2000 Compatible Access ACEs if no legacy systems require them. Validate downstream impact in a maintenance window first.' `
            -Samples @()
    }

    # Sort findings by severity (CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL)
    $sevRank = @{ 'CRITICAL'=0; 'HIGH'=1; 'MEDIUM'=2; 'LOW'=3; 'INFORMATIONAL'=4 }
    $findings = @($findings | Sort-Object @{Expression={$sevRank[$_.Severity]}}, @{Expression={-1 * $_.Count}}, Title)

    $criticalCount = @($findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    $highCount     = @($findings | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $medCount      = @($findings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    $lowCount      = @($findings | Where-Object { $_.Severity -eq 'LOW' }).Count

    $overallRisk = if ($criticalCount -gt 0) { 'CRITICAL' }
                   elseif ($highCount -gt 0) { 'HIGH' }
                   elseif ($medCount  -gt 0) { 'MEDIUM' }
                   elseif ($lowCount  -gt 0) { 'LOW' }
                   else { 'CLEAN' }

    $riskSb = New-Object System.Text.StringBuilder
    [void]$riskSb.AppendLine('=====================================================================')
    [void]$riskSb.AppendLine(' DELEGATED PERMISSIONS RISK ASSESSMENT')
    [void]$riskSb.AppendLine('=====================================================================')
    [void]$riskSb.AppendLine(" Generated         : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$riskSb.AppendLine(" Scopes analysed   : $(@($scopes).Count)")
    [void]$riskSb.AppendLine(" ACE records       : $($records.Count)")
    [void]$riskSb.AppendLine(" Overall risk      : $overallRisk")
    [void]$riskSb.AppendLine(" Findings (CRITICAL/HIGH/MEDIUM/LOW): $criticalCount / $highCount / $medCount / $lowCount")
    [void]$riskSb.AppendLine('---------------------------------------------------------------------')
    [void]$riskSb.AppendLine('')
    [void]$riskSb.AppendLine('How to read this file:')
    [void]$riskSb.AppendLine(' - Findings are sorted by severity. Work CRITICAL/HIGH first.')
    [void]$riskSb.AppendLine(' - Each finding has: WHY (the security impact) and FIX (the action).')
    [void]$riskSb.AppendLine(' - For the per-account/per-OU breakdown of any finding, open the')
    [void]$riskSb.AppendLine('   matching file in OUs/ (.csv) or All/ADAudit_HighRisk_*.csv.')
    [void]$riskSb.AppendLine('')

    if ($findings.Count -eq 0) {
        [void]$riskSb.AppendLine('No findings detected against the heuristic baseline. This does not')
        [void]$riskSb.AppendLine('replace a manual ACL review - it only means the patterns this')
        [void]$riskSb.AppendLine('script tests for were not present.')
        [void]$riskSb.AppendLine('')
    } else {
        $idx = 0
        foreach ($f in $findings) {
            $idx++
            [void]$riskSb.AppendLine(("[{0}/{1}] [{2}] {3}" -f $idx, $findings.Count, $f.Severity, $f.Title))
            [void]$riskSb.AppendLine("    Count : $($f.Count) ACE records")
            [void]$riskSb.AppendLine("    Why   : $($f.Why)")
            [void]$riskSb.AppendLine("    Fix   : $($f.Fix)")
            if ($f.Samples -and $f.Samples.Count -gt 0) {
                [void]$riskSb.AppendLine("    Sample: $((($f.Samples | Select-Object -First 10) -join ', '))")
            }
            [void]$riskSb.AppendLine('')
        }
    }

    $riskPath = Join-Path $base 'ADAudit_RiskAssessment.txt'
    Set-Content -LiteralPath $riskPath -Value $riskSb.ToString() -Encoding UTF8
    Write-Host "Wrote: $riskPath"

    # ----------------------------
    # Recommendations - keep the existing prioritized action list (it's the
    # generic playbook that maps to the findings above).
    # ----------------------------
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

    # ----------------------------
    # Single consolidated per-scope summary that REPLACES the 73+ per-OU .txt
    # files we used to drop in OUs/. This is the human-readable companion to
    # the per-OU .csv files - one document, sorted by scope, grouped by
    # trustee, with rights inline. Use the .csv files when you need to filter
    # or pivot in Excel; this file is for reading top-down.
    # ----------------------------
    $perScopeSb = New-Object System.Text.StringBuilder
    [void]$perScopeSb.AppendLine('=====================================================================')
    [void]$perScopeSb.AppendLine(' DELEGATED PERMISSIONS - PER-SCOPE SUMMARY (HUMAN READABLE)')
    [void]$perScopeSb.AppendLine('=====================================================================')
    [void]$perScopeSb.AppendLine(" Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$perScopeSb.AppendLine(" Scopes     : $(@($scopes).Count)")
    [void]$perScopeSb.AppendLine(" ACE records: $($records.Count)")
    [void]$perScopeSb.AppendLine('---------------------------------------------------------------------')
    [void]$perScopeSb.AppendLine(' For machine-readable output use OUs\ADAudit_*.csv (one per scope) or')
    [void]$perScopeSb.AppendLine(' All\ADAudit_AllScopes_*.csv (everything in one CSV).')
    [void]$perScopeSb.AppendLine('---------------------------------------------------------------------')
    [void]$perScopeSb.AppendLine('')

    $byScopeForTxt = $records | Group-Object ScopeDN | Sort-Object Name
    foreach ($g in $byScopeForTxt) {
        $first = $g.Group | Select-Object -First 1
        [void]$perScopeSb.AppendLine('=====================================================================')
        [void]$perScopeSb.AppendLine(" Scope      : $($g.Name)")
        [void]$perScopeSb.AppendLine(" Type       : $($first.ScopeType)")
        if ($first.CanonicalScope) {
            [void]$perScopeSb.AppendLine(" Canonical  : $($first.CanonicalScope)")
        }
        [void]$perScopeSb.AppendLine(" ACE count  : $($g.Count)")
        [void]$perScopeSb.AppendLine('---------------------------------------------------------------------')
        foreach ($trGrp in ($g.Group | Group-Object Trustee | Sort-Object Name)) {
            $tFirst = $trGrp.Group | Select-Object -First 1
            [void]$perScopeSb.AppendLine("  Trustee  : $($trGrp.Name)  [$($tFirst.TrusteeType)]")
            foreach ($r in $trGrp.Group) {
                $line = "    {0,-20} ({1}) class={2} prop={3} inh={4}" -f `
                    $r.ActiveDirectoryRights, $r.AccessControlType,
                    ($(if($r.AppliesToClass){$r.AppliesToClass}else{'-'})),
                    ($(if($r.AppliesToProperty){$r.AppliesToProperty}else{'-'})),
                    $r.InheritanceType
                [void]$perScopeSb.AppendLine($line)
            }
            [void]$perScopeSb.AppendLine('')
        }
        [void]$perScopeSb.AppendLine('')
    }

    $perScopePath = Join-Path $base 'ADAudit_PerScopeSummary.txt'
    Set-Content -LiteralPath $perScopePath -Value $perScopeSb.ToString() -Encoding UTF8
    Write-Host "Wrote: $perScopePath"

    # CSVs
    $masterCsv = Join-Path -Path $allDir -ChildPath "ADAudit_AllScopes_$ts.csv"
    $records | Sort-Object ScopeType,ScopeDN,Trustee | Export-Csv -NoTypeInformation -Path $masterCsv -Encoding UTF8

    $byScope = $records | Group-Object ScopeDN
    foreach ($g in $byScope) {
      $safeName = ($g.Name -replace '[=,]','_') -replace '[^\w\.-]','_'
      $csvPath = Join-Path -Path $ouDir -ChildPath "ADAudit_$safeName.csv"
      $g.Group | Export-Csv -NoTypeInformation -Path $csvPath -Encoding UTF8
    }

    # ----------------------------
    # HTML index - now leads with the structured Findings (severity, why, fix,
    # sample trustees) and demotes the raw scope list to a collapsed section
    # so the operator sees risk first, scopes second.
    # ----------------------------
    $sevToBadge = @{
        'CRITICAL'      = 'badge-critical'
        'HIGH'          = 'badge-high'
        'MEDIUM'        = 'badge-medium'
        'LOW'           = 'badge-low'
        'INFORMATIONAL' = 'badge-info'
    }

    $index = New-Object System.Collections.Generic.List[string]
    $index.Add((Get-ADAuditReportHeader -Title 'AD Delegated Permissions Report'))
    $index.Add("<div class='hero'><h1>AD Delegated Permissions Report</h1>")
    $index.Add("<div class='meta'>Generated: $(Get-Date -Format 'u') &mdash; Overall risk: <strong>$overallRisk</strong></div></div>")

    $index.Add("<div class='stats'>")
    $index.Add("<div class='stat'><div class='val'>$($scopes.Count)</div><div class='lbl'>Scopes Analyzed</div></div>")
    $index.Add("<div class='stat'><div class='val'>$($records.Count)</div><div class='lbl'>Total ACEs</div></div>")
    $index.Add("<div class='stat'><div class='val' style='color:var(--critical)'>$criticalCount</div><div class='lbl'>Critical</div></div>")
    $index.Add("<div class='stat'><div class='val' style='color:var(--high)'>$highCount</div><div class='lbl'>High</div></div>")
    $index.Add("<div class='stat'><div class='val' style='color:var(--medium)'>$medCount</div><div class='lbl'>Medium</div></div>")
    $index.Add("<div class='stat'><div class='val' style='color:var(--low)'>$lowCount</div><div class='lbl'>Low</div></div>")
    $index.Add("</div>")

    $index.Add('<h2>How to read this report</h2>')
    $index.Add('<p>Findings are sorted by severity. Each finding tells you <strong>what is wrong</strong>, <strong>why it matters</strong> (the actual security impact), and the <strong>recommended fix</strong>. Use the per-scope CSV files at the bottom to drill into specific OUs.</p>')

    $index.Add('<h2>Findings</h2>')
    if ($findings.Count -eq 0) {
        $index.Add('<p>No findings detected against the heuristic baseline.</p>')
    } else {
        foreach ($f in $findings) {
            $badge = $sevToBadge[$f.Severity]; if (-not $badge) { $badge = 'badge-info' }
            $titleEnc  = [System.Web.HttpUtility]::HtmlEncode($f.Title)
            $whyEnc    = [System.Web.HttpUtility]::HtmlEncode($f.Why)
            $fixEnc    = [System.Web.HttpUtility]::HtmlEncode($f.Fix)
            $sampleTxt = if ($f.Samples -and $f.Samples.Count -gt 0) {
                ($f.Samples | Select-Object -First 10 | ForEach-Object { "<li><code>$([System.Web.HttpUtility]::HtmlEncode([string]$_))</code></li>" }) -join ''
            } else { '' }
            $sampleBlock = if ($sampleTxt) {
                "<p><strong>Sample trustees / SIDs:</strong></p><ul>$sampleTxt</ul>"
            } else { '' }
            $index.Add(@"
<details>
<summary><span class="badge $badge">$($f.Severity)</span> &nbsp; $titleEnc &nbsp;&mdash;&nbsp; <strong>$($f.Count) ACE records</strong></summary>
<div class="detail-body">
<p><strong>Why this matters:</strong> $whyEnc</p>
<p><strong>How to fix:</strong> $fixEnc</p>
$sampleBlock
</div>
</details>
"@)
        }
    }

    try { [void][System.Web.HttpUtility] } catch { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue }

    $index.Add('<h2>Reference Files</h2><ul class="link-list">')
    $index.Add("<li><a href='ADAudit_RiskAssessment.txt'>Risk Assessment (severity-grouped, with WHY/FIX per finding)</a></li>")
    $index.Add("<li><a href='ADAudit_Recommendations.txt'>Recommendations (prioritised playbook)</a></li>")
    $index.Add("<li><a href='ADAudit_PerScopeSummary.txt'>Per-Scope Summary (one human-readable file, all scopes)</a></li>")
    $index.Add("<li><a href='All/ADAudit_AllScopes_$ts.csv'>Master CSV - all ACEs across all scopes</a></li>")
    $index.Add("<li><a href='All/ADAudit_HighRisk_$ts.csv'>High-Risk CSV - flagged ACEs only</a></li>")
    $index.Add('</ul>')

    $index.Add('<h2>Per-Scope CSV (drill-down)</h2>')
    # Only scopes that produced ACE records get a CSV on disk; linking every
    # scope would leave mostly-dead links with the default switches.
    $scopesWithCsv = @($byScope | ForEach-Object Name)
    $index.Add('<details><summary>Show all ' + (@($scopesWithCsv).Count) + ' scope CSVs</summary><div class="detail-body"><ul class="link-list">')
    foreach ($dn in $scopesWithCsv) {
        $safe = ($dn -replace '[=,]','_') -replace '[^\w\.-]','_'
        $dnEnc = [System.Web.HttpUtility]::HtmlEncode([string]$dn)
        $index.Add("<li><a href='OUs/ADAudit_$safe.csv'><code>$dnEnc</code></a></li>")
    }
    $index.Add('</ul></div></details>')
    $index.Add((Get-ADAuditReportFooter))
    $indexPath = Join-Path $base 'index.html'
    $index -join "`r`n" | Out-File -Encoding UTF8 -FilePath $indexPath
    Write-Host "Index: $indexPath"

    Write-Host "Reports folder: $base"
    Write-Host "Master CSV:     $masterCsv"

    # End transcript
    try { Stop-Transcript | Out-Null } catch {}
}

function Invoke-DelegatedPermissionsCheck {
    if (-not $DelegatedOutputRoot) { $DelegatedOutputRoot = (Join-Path (Get-RawDataDir -BaseRoot $outputdir) 'DelegatedPermissions') }
    Invoke-DelegatedPermissionsReport -OutputRoot $DelegatedOutputRoot -IncludeSystemTrustees:$DelegIncludeSystemTrustees -IncludeDeny:$DelegIncludeDeny -IncludeInherited:$DelegIncludeInherited -Server $DelegServer
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select delegatedpermissions @args
}
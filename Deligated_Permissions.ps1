<#
.SYNOPSIS
  Generate delegated-permissions reports for Active Directory.

.DESCRIPTION
  - Scans Domain NC, all OUs, AdminSDHolder, and key containers (Users, Computers, System, Managed Service Accounts).
  - Collects explicit Allow ACEs by default. Optional inclusion of Deny and inherited ACEs.
  - Resolves ObjectType and InheritedObjectType GUIDs to schema names and extended rights.
  - Produces per-scope TXT, per-scope CSV, a master CSV, a high-risk CSV, risk assessment, recommendations, and an HTML index.

.PARAMETER OutputRoot
  Base folder for reports. Default: .\<COMPUTERNAME>\Delegated Permissions Report

.PARAMETER IncludeSystemTrustees
  Include built-in noisy trustees (SELF, Authenticated Users, Everyone, SYSTEM, etc.). Default: excluded.

.PARAMETER IncludeDeny
  Include Deny ACEs. Default: excluded.

.PARAMETER IncludeInherited
  Include inherited ACEs. Default: excluded.

.PARAMETER Server
  Optional DC to target for consistent reads.

.EXAMPLE
  .\Delegated_Permissions.ps1

.EXAMPLE
  .\Delegated_Permissions.ps1 -Server dc01.contoso.com -IncludeInherited
#>

[CmdletBinding()]
param(
  [string]$OutputRoot = (Join-Path -Path (Get-Location) -ChildPath "$( $env:COMPUTERNAME )\Delegated Permissions Report"),
  [switch]$IncludeSystemTrustees,
  [switch]$IncludeDeny,
  [switch]$IncludeInherited,
  [string]$Server
)

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
$index = @()
$index += "<h1>AD Delegated Permissions Report</h1>"
$index += "<p>Generated: $(Get-Date -Format 'u')</p>"
$index += "<h2>Scopes</h2><ul>"
foreach ($dn in $scopes) {
  $safe = ($dn -replace '[=,]','_') -replace '[^\w\.-]','_'
  $index += "<li><code>$dn</code> — <a href='OUs/ADAudit_$safe.csv'>CSV</a> | <a href='OUs/ADAudit_$safe.txt'>TXT</a></li>"
}
$index += "</ul>"
$index += "<h2>Summary</h2><ul>"
$index += "<li><a href='All/ADAudit_AllScopes_$ts.csv'>Master CSV</a></li>"
$index += "<li><a href='All/ADAudit_HighRisk_$ts.csv'>High-Risk CSV</a></li>"
$index += "<li><a href='ADAudit_RiskAssessment.txt'>Risk Assessment</a></li>"
$index += "<li><a href='ADAudit_Recommendations.txt'>Recommendations</a></li>"
$index += "</ul>"
$indexPath = Join-Path $base 'index.html'
$index -join "`r`n" | Out-File -Encoding UTF8 -FilePath $indexPath
Write-Host "Index: $indexPath"

Write-Host "Reports folder: $base"
Write-Host "Master CSV:     $masterCsv"

# End transcript
try { Stop-Transcript | Out-Null } catch {}

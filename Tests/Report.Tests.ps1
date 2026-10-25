<# Offline integration tests. Run: pwsh -NoProfile -File Tests/Report.Tests.ps1 #>
$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot -Parent
. (Join-Path $repository 'Library/ADAudit.Common.ps1')
. (Join-Path $repository 'Library/ADAudit.Report.ps1')
$versionnum = 'test-v9.2'; $starttime = 'test-start'; $endtime = 'test-end'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ADAudit-Report-Tests-' + [guid]::NewGuid().ToString('N'))
$assertionCount = 0
function Assert-Report([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Assertion failed: $Message" }
    $script:assertionCount++
}
function New-ReportFixture([string]$Name, [string]$Status = 'Completed', [switch]$WithoutManifest) {
    $root = Join-Path $testRoot $Name
    $source = Join-Path $root 'Raw Data/Source'
    New-Item -ItemType Directory -Path $source -Force | Out-Null
    if (-not $WithoutManifest) {
        [pscustomobject]@{RunId=$Name; ToolVersion='test-v9.2'; ScoringVersion='v2.1'; ComputerName='AUDIT-HOST'; Domain='example.test'; Forest='example.test'; SelectedChecks=@('fixture'); ExcludedChecks=@('outside-scope')} | ConvertTo-Json | Set-Content (Join-Path $source 'audit_run.json')
        [pscustomobject]@{CheckName='Fixture'; Switch='fixture'; Selected=$true; Status=$Status; Reason=$(if($Status -eq 'Partial'){'One target unavailable'}else{''}); NotAssessedCount=$(if($Status -eq 'Partial'){1}else{0}); FailureCount=0} | Export-Csv (Join-Path $source 'audit_check_status.csv') -NoTypeInformation
    }
    return [pscustomobject]@{Root=$root; Source=$source}
}
function Read-ReportFixture($Fixture) {
    $script:outputdir = $Fixture.Root
    $script:HtmlReportsDir = $null; $script:EvidenceFilesDir = $null; $script:LegacyArtifactsDir = $null
    Invoke-ManagementReport -InputRoot $Fixture.Root | Out-Null
    [pscustomobject]@{
        Summary = Get-Content (Join-Path $Fixture.Root 'Raw Data/report_summary.json') -Raw | ConvertFrom-Json
        Findings = @(Import-Csv (Join-Path $Fixture.Root 'Raw Data/report_findings.csv'))
        RiskHtml = Get-Content (Join-Path $Fixture.Root 'HTML Reports/Risk-Report.html') -Raw
        AuditHtml = Get-Content (Join-Path $Fixture.Root 'HTML Reports/ADAudit-Results.html') -Raw
    }
}
function Write-PasswordFixture($Fixture, [object[]]$Rows) {
    $Rows | Select-Object Category,SamAccountName,DistinguishedName,AccountStatus,ObjectClass,GroupId,EvidenceSource,PasswordEvidence,EvidenceDetail | Export-Csv (Join-Path $Fixture.Source 'password_quality_findings.csv') -NoTypeInformation
}
try {
    $fixture = New-ReportFixture 'critical'
    Write-PasswordFixture $fixture @([pscustomobject]@{Category='PreAuthNotRequired';SamAccountName='active';AccountStatus='Enabled';PasswordEvidence='NotApplicable';EvidenceDetail='Configured preauthentication exception'})
    $report = Read-ReportFixture $fixture
    Assert-Report ($report.Summary.Score -eq 12) 'One Critical retains its rule score of 12.'
    Assert-Report ($report.Summary.OverallLevel -eq 'Critical') 'A Critical finding cannot produce a Low headline.'
    Assert-Report ($report.Summary.IndexBand -eq 'Band 1' -and $report.Summary.HighestFindingSeverity -eq 'Critical') 'Numeric index bands are distinct from finding severity.'
    Assert-Report ($report.RiskHtml -match 'have not been empirically calibrated' -and $report.RiskHtml -notmatch 'Address during routine maintenance') 'Low points cannot imply low urgency or calibrated risk.'
    Assert-Report ($report.Summary.ScoringVersion -eq 'v2.1') 'The corrected scoring methodology is versioned.'
    Assert-Report ($report.RiskHtml -match 'not directly comparable with earlier report versions') 'Methodology change is disclosed.'
    Assert-Report ($report.AuditHtml -match 'Verify after the change') 'Expert verification guidance is rendered.'

    $fixture = New-ReportFixture 'password-states'
    Write-PasswordFixture $fixture @(
        [pscustomobject]@{Category='EmptyPassword';SamAccountName='disabled-mailbox';AccountStatus='Disabled';PasswordEvidence='EmptyNtHash'},
        [pscustomobject]@{Category='EmptyPassword';SamAccountName='smart-card';AccountStatus='Enabled';PasswordEvidence='NoNtHash'},
        [pscustomobject]@{Category='EmptyPassword';SamAccountName='unknown-state';AccountStatus='Unknown';PasswordEvidence='EmptyNtHash'},
        [pscustomobject]@{Category='PasswordNotRequired';SamAccountName='flag-only';AccountStatus='Enabled';PasswordEvidence='NotApplicable'}
    )
    $report = Read-ReportFixture $fixture
    $disabled = @($report.Findings | Where-Object Title -like '*confirmed empty passwords (disabled)')
    Assert-Report ($disabled.Count -eq 1 -and $disabled[0].Severity -eq 'Low' -and [int]$disabled[0].Score -eq 0) 'Disabled empty-password evidence stays visible as unscored hygiene.'
    Assert-Report (@($report.Findings | Where-Object Severity -eq 'Critical').Count -eq 0) 'Missing hashes, unknown status and a password-not-required flag cannot become enabled empty-password Critical findings.'
    Assert-Report (@($report.Findings | Where-Object { $_.Title -like '*password not required flag*' -and $_.Evidence -match 'does not prove an empty password' }).Count -eq 1) 'The flag is explicitly separated from empty-password evidence.'
    Assert-Report ($report.Summary.Coverage -eq 'Partial assessment') 'Unknown account state reduces confidence.'
    Assert-Report ($report.AuditHtml -match 'disabled-mailbox' -and $report.AuditHtml -match 'smart-card') 'State-specific evidence is embedded in the expert report.'

    $fixture = New-ReportFixture 'highrisk-only'
    $highRiskDir = Join-Path $fixture.Source 'HighRisk'
    New-Item -ItemType Directory -Path $highRiskDir -Force | Out-Null
    @(
        [pscustomobject]@{PasswordGroup='PWD-REUSE-001';SamAccountName='disabled-mailbox-1';AccountStatus='Disabled';Severity='LOW'},
        [pscustomobject]@{PasswordGroup='PWD-REUSE-001';SamAccountName='disabled-mailbox-2';AccountStatus='Disabled';Severity='LOW'},
        [pscustomobject]@{PasswordGroup='PWD-REUSE-002';SamAccountName='unresolved';AccountStatus='Unknown';Severity='INFORMATION'}
    ) | Export-Csv (Join-Path $highRiskDir 'DUPLICATE_PASSWORDS.csv') -NoTypeInformation
    $report = Read-ReportFixture $fixture
    Assert-Report ($report.Summary.Score -eq 0 -and $report.Summary.OverallLevel -eq 'Not assessed') 'HighRisk-only disabled and unknown duplicates do not become active Critical exposures.'
    Assert-Report (@($report.Findings | Where-Object { $_.RuleId -eq 'PQ-DuplicatePasswordGroups-Disabled' -and $_.Severity -eq 'Low' }).Count -eq 1) 'HighRisk-only disabled duplicates remain visible as hygiene.'
    Assert-Report (@($report.Findings | Where-Object { $_.RuleId -eq 'PQ-DuplicatePasswordGroups-Unknown' -and $_.Severity -eq 'Information' }).Count -eq 1) 'HighRisk-only unknown duplicates remain unassessed.'

    $fixture = New-ReportFixture 'collectors'
    [pscustomobject]@{Template='UserTemplate';PublishedBy='CA1';Rule='ESC1';Status='PotentialExposure';Severity='High';Trustees='S-1-5-21-test';Detail='Requires expert validation'} | Export-Csv (Join-Path $fixture.Source 'adcs_templates.csv') -NoTypeInformation
    [pscustomobject]@{CA='CA1';Endpoint='http://ca.example.test/certsrv/';Status='Review';HttpStatus=401;Authentication='Negotiate';Detail='Authentication protection unverified'} | Export-Csv (Join-Path $fixture.Source 'adcs_endpoints.csv') -NoTypeInformation
    [pscustomobject]@{ObjectType='user';ObjectName='admin';DistinguishedName='CN=Admin,DC=example,DC=test';IdentityReference='test\helpdesk';TrusteeSid='S-1-5-21-test';AccessControlType='Allow';ActiveDirectoryRights='GenericAll';ObjectTypeGuid='';InheritanceType='None';IsInherited=$false;Capability='Object control';Status='PotentialExposure';Severity='High'} | Export-Csv (Join-Path $fixture.Source 'dangerous_acls.csv') -NoTypeInformation
    [pscustomobject]@{Name='server-live';Assessment='Stale activity candidate';Reason='Timestamps exceed threshold; workload requires confirmation'} | Export-Csv (Join-Path $fixture.Source 'computers_inactive_90days.csv') -NoTypeInformation
    [pscustomobject]@{Name='laptop';Generation='Windows';Assessment='Backup destination unverified';Detail='May use Entra backup'} | Export-Csv (Join-Path $fixture.Source 'laps_status.csv') -NoTypeInformation
    [pscustomobject]@{Target='DC1';Setting='LmCompatibilityLevel';Status='Finding';Severity='Medium';Reason='Observed weak effective setting'} | Export-Csv (Join-Path $fixture.Source 'ntlm_dc_settings.csv') -NoTypeInformation
    [pscustomobject]@{Trustee='test\unexpected-sync';TrusteeSid='S-1-5-21-test-2001';ScopeDN='DC=example,DC=test';GetChanges=$true;GetChangesAll=$true;Status='PotentialExposure';Severity='Critical';Detail='Both domain replication rights'} | Export-Csv (Join-Path $fixture.Source 'replication_delegations.csv') -NoTypeInformation
    [pscustomobject]@{Source='AuditHost';Target='DC1';Port=636;Proto='TCP';PortName='LDAPS';Open=$false;Severity='Low'} | Export-Csv (Join-Path $fixture.Source 'dc_port_connectivity.csv') -NoTypeInformation
    'Probe evidence' | Set-Content (Join-Path $fixture.Source 'dc_port_connectivity.txt')
    $report = Read-ReportFixture $fixture
    Assert-Report (@($report.Findings | Where-Object { $_.Title -like 'AD CS template*' -and $_.Severity -eq 'High' }).Count -eq 1) 'AD CS configuration exposure reaches the main findings.'
    Assert-Report (@($report.Findings | Where-Object { $_.Title -like 'Directory ACL*' -and $_.Severity -eq 'High' }).Count -eq 1) 'ACL permission exposure reaches the main findings.'
    Assert-Report (@($report.Findings | Where-Object { $_.Title -like 'AD CS web*' -and $_.Severity -eq 'Information' }).Count -eq 1) 'HTTP challenge alone remains a review observation.'
    Assert-Report (@($report.Findings | Where-Object Title -like 'NTLM domain controller configuration*').Count -eq 1) 'Observed NTLM configuration is reported.'
    Assert-Report (@($report.Findings | Where-Object { $_.RuleId -eq 'AD-REPLICATION-RIGHTS' -and $_.Severity -eq 'Critical' }).Count -eq 1) 'Domain-root replication-rights combinations reach the main risk report.'
    Assert-Report (@($report.Findings | Where-Object { $_.Title -like 'Computer accounts with stale*' -and $_.Severity -eq 'Low' }).Count -eq 1) 'Timestamp candidates remain review findings.'
    Assert-Report (@($report.Findings | Where-Object { $_.Title -like 'LAPS coverage*' -and $_.Severity -eq 'Information' }).Count -eq 1) 'Unknown LAPS backup destination is not rated an enabled credential exposure.'
    Assert-Report ($report.RiskHtml -notmatch 'LDAP traffic forced to plaintext|All LDAP binds and searches') 'A failed 636 probe does not imply plaintext LDAP.'
    Assert-Report ($report.AuditHtml -match 'StartTLS|SASL') 'LDAP protection alternatives are explained.'
    Assert-Report (@($report.Findings | Where-Object { $_.Title -like 'DC port closed:*' -and ($_.Severity -ne 'Information' -or [int]$_.Score -ne 0) }).Count -eq 0) 'An optional LDAPS endpoint does not add risk points.'

    $fixture = New-ReportFixture 'port-source-integrity'
    $portPath = Join-Path $fixture.Source 'dc_port_connectivity.csv'
    @(1..12 | ForEach-Object { [pscustomobject]@{Source='AuditHost';Target="DC$_";Port=5985;Proto='TCP';PortName='WinRM HTTP';Open=$false;Required=$false;Severity='Information'} }) | Export-Csv -LiteralPath $portPath -NoTypeInformation
    'Synthetic port evidence' | Set-Content (Join-Path $fixture.Source 'dc_port_connectivity.txt')
    $sourceHash = (Get-FileHash -LiteralPath $portPath).Hash
    $firstReport = Read-ReportFixture $fixture
    $secondReport = Read-ReportFixture $fixture
    Assert-Report ($firstReport.Summary.Score -eq 0 -and $secondReport.Summary.Score -eq 0) 'Multiple informational port failures cannot become scored findings.'
    Assert-Report ((Get-FileHash -LiteralPath $portPath).Hash -eq $sourceHash) 'Rendering and rerendering preserve typed source evidence byte-for-byte.'
    Assert-Report ($firstReport.Findings.Count -eq $secondReport.Findings.Count -and $secondReport.Summary.ReportEvidenceIssues -eq 0) 'Repeat generation retains the same findings and valid schemas.'
    Assert-Report (Test-Path -LiteralPath (Join-Path $fixture.Root 'Raw Data/ReportDownloads/dc_port_connectivity.csv')) 'Derived text tables are exported separately from source evidence.'

    $fixture = New-ReportFixture 'port-invalid-schema'
    'Line,Result','1,Overwritten legacy evidence' | Set-Content (Join-Path $fixture.Source 'dc_port_connectivity.csv')
    $report = Read-ReportFixture $fixture
    Assert-Report ($report.Summary.ReportEvidenceIssues -gt 0 -and $report.Summary.Coverage -eq 'Partial assessment') 'A malformed port CSV is a reporting gap, not a clean probe result.'

    $fixture = New-ReportFixture 'privileged-rollup'
    $highRiskDir = Join-Path $fixture.Source 'HighRisk'
    New-Item -ItemType Directory -Path $highRiskDir -Force | Out-Null
    [pscustomobject]@{RiskId='PRIV_DA';IsFinding=$true} | Export-Csv (Join-Path $highRiskDir 'Summary.csv') -NoTypeInformation
    [pscustomobject]@{Group='Domain Admins';SamAccountName='fixture-admin'} | Export-Csv (Join-Path $highRiskDir 'PRIVILEGED_GROUPS.csv') -NoTypeInformation
    $report = Read-ReportFixture $fixture
    $rollup = @($report.Findings | Where-Object Title -eq 'Large privileged group membership')
    Assert-Report ($rollup.Count -eq 1 -and $rollup[0].Severity -eq 'Information' -and [int]$rollup[0].Score -eq 0) 'Privileged membership inventory does not add duplicate points.'

    $fixture = New-ReportFixture 'count-and-age-review'
    @('Findings', '[CRITICAL] Domain Admins | Observed: 12 | Baseline: <= 5', '[CRITICAL] Schema Admins | Observed: 2 | Baseline: 0', '[CRITICAL] Domain Admins group overlap | Observed: 8 | Baseline: 0', '[CRITICAL] krbtgt password age | Observed: 2020-01-01 (2400 days) | Baseline: 180 days') | Set-Content (Join-Path $fixture.Source 'ad_high_risk_baseline.txt')
    $report = Read-ReportFixture $fixture
    Assert-Report (@($report.Findings | Where-Object Severity -eq 'Critical').Count -eq 0) 'Membership counts and rotation age alone cannot create Critical findings, including legacy baseline inputs.'
    Assert-Report (@($report.Findings | Where-Object { $_.Title -like '*krbtgt*' -and $_.Severity -eq 'Medium' }).Count -eq 1) 'KRBTGT age is a rotation review rather than evidence of credential compromise.'

    $fixture = New-ReportFixture 'partial' -Status 'Partial'
    [pscustomobject]@{CheckName='SMB';Target='DC2';Reason='Access denied'} | Export-Csv (Join-Path $fixture.Source 'not_assessed.csv') -NoTypeInformation
    $report = Read-ReportFixture $fixture
    Assert-Report ($report.Summary.OverallLevel -eq 'Not assessed') 'No evidence from a partial run is not a Low-risk result.'
    Assert-Report ($report.RiskHtml -match 'Access denied' -and $report.AuditHtml -match 'Partial assessment') 'Both reports expose missing coverage and the reason.'

    $fixture = New-ReportFixture 'no-manifest' -WithoutManifest
    $report = Read-ReportFixture $fixture
    Assert-Report ($report.Summary.Coverage -eq 'Coverage not established' -and $report.Summary.OverallLevel -eq 'Not assessed') 'Missing execution manifest cannot become an all-clear.'

    $fixture = New-ReportFixture 'invalid-schema'
    'Unexpected,Columns', 'one,two' | Set-Content (Join-Path $fixture.Source 'password_quality_findings.csv')
    $report = Read-ReportFixture $fixture
    Assert-Report ($report.Summary.ReportEvidenceIssues -gt 0 -and $report.Summary.OverallLevel -eq 'Not assessed') 'Invalid typed evidence becomes a visible reporting gap.'

    $fixture = New-ReportFixture 'valid-empty'
    '"Category","SamAccountName","AccountStatus","PasswordEvidence"' | Set-Content (Join-Path $fixture.Source 'password_quality_findings.csv')
    $report = Read-ReportFixture $fixture
    Assert-Report ($report.Summary.ReportEvidenceIssues -eq 0 -and $report.Summary.OverallLevel -eq 'No scored findings') 'A valid header-only result and completed scope can report no scored findings.'
    Assert-Report ((Get-Content (Join-Path $fixture.Root 'Raw Data/report_findings.csv') -TotalCount 1) -match 'ScoringVersion.*RuleId.*Severity') 'The standalone finding register retains its schema when empty.'
    Assert-Report ($report.RiskHtml -match 'unselected|Unselected') 'Scope limitations remain visible on a clean selected assessment.'
    $fixture = New-ReportFixture 'isolated-copy'
    $manifestPath = Join-Path $fixture.Source 'audit_run.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest | Add-Member -NotePropertyName AssessmentMode -NotePropertyValue 'IsolatedClone'
    $manifest | Add-Member -NotePropertyName SnapshotDate -NotePropertyValue '2026-01-25'
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath
    $cloneHighRisk = Join-Path $fixture.Source 'HighRisk'
    New-Item -ItemType Directory -Path $cloneHighRisk -Force | Out-Null
    [pscustomobject]@{AgeDays=2400;IsFinding=$false;Assessment='Not assessed on isolated clone'} | Export-Csv (Join-Path $cloneHighRisk 'KRBTGT.csv') -NoTypeInformation
    $report = Read-ReportFixture $fixture
    Assert-Report ($report.RiskHtml -match 'ISOLATED CLONE' -and $report.AuditHtml -match 'ISOLATED CLONE') 'Both customer reports identify the isolated copy.'
    Assert-Report ($report.RiskHtml -match '2026-01-25' -and $report.RiskHtml -match 'does not establish current production') 'Snapshot date and production limitations are visible.'
    Assert-Report ($report.Summary.Run.AssessmentMode -eq 'IsolatedClone') 'Machine-readable output retains the assessment context.'
    Assert-Report (@($report.Findings | Where-Object { $_.Title -like '*krbtgt*' -and [int]$_.Score -gt 0 }).Count -eq 0) 'An old isolated copy cannot establish production KRBTGT rotation age.'
    $companionPath = Join-Path $fixture.Root 'HTML Reports/GPOReport.html'
    '<html><head><style>td{background:white;color:black}</style></head><body><table><tr><td>Synthetic GPO</td></tr></table></body></html>' | Set-Content -LiteralPath $companionPath
    Update-CompanionHtmlReports -Root $fixture.Root
    $companionHtml = Get-Content -LiteralPath $companionPath -Raw
    Assert-Report ($companionHtml -match 'ISOLATED CLONE' -and $companionHtml -match '2026-01-25') 'Native GPO companion reports inherit snapshot context from the manifest.'
    Assert-Report ($companionHtml -match 'wrapperThemeToggle' -and $companionHtml -match 'html\[data-theme="dark"\] .embedded-report') 'Legacy embedded report colors have dark-theme overrides.'
    Write-Host "Report tests passed: $assertionCount assertions. No AD calls were made."
} finally {
    $resolvedTestRoot = [System.IO.Path]::GetFullPath($testRoot)
    $allowedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\','/') + [System.IO.Path]::DirectorySeparatorChar
    if ($resolvedTestRoot.StartsWith($allowedTempRoot, [System.StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolvedTestRoot -Leaf) -like 'ADAudit-Report-Tests-*') {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

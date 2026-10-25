# Offline scoring regression tests; all directory and replication calls are mocked.
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'Checks/Invoke-AccountsCheck.ps1')
. (Join-Path $repoRoot 'Checks/Invoke-HighRiskCheck.ps1')
function Write-Both { param($Message) }
function Write-ADAuditProgress { param($Activity,$Status,$PercentComplete,[switch]$Completed) }
function Register-ADAuditNotAssessed { param($Name,$Reason,$Target) }
function Get-RawSourceDataDir { Join-Path $TestDrive 'Source' }
function Get-EvidencePath { param($Name) Join-Path $TestDrive $Name }
function Get-HtmlReportsDir { param($BaseRoot) Join-Path $TestDrive 'HTML' }
function Get-ADAuditReportHeader { param($Title) '<html><body>' }
function Get-ADAuditReportFooter { '</body></html>' }
function Import-ADAuditModule { param($Name) $false }
function Get-ADDomain { param($Current,$Identity,$Server,$ErrorAction) }
function Get-ADForest { param($ErrorAction) }
function Get-ADGroup { param($Identity,$Server,$ErrorAction) }
function Get-ADGroupMember { param($Identity,[switch]$Recursive,$Server,$ErrorAction) }
function Get-ADUser { param($Filter,$LDAPFilter,$Properties,$ErrorAction) }
function Search-ADAccount { param([switch]$PasswordNeverExpires,[switch]$UsersOnly,$ErrorAction) }
function Get-ADObject { param($Property) [pscustomobject]@{'ms-DS-MachineAccountQuota'=0} }

Describe 'Domain Admin review severity follows the strength of evidence' {
    It 'retains disabled membership as Low reactivation hygiene' {
        $result=Get-DomainAdminReviewAssessment -EnabledHumanUsers 100 -Members @([pscustomobject]@{Kind='Service';Enabled=$false;Stale=$true})
        $result.Severity | Should Be 'Low'
        $result.Reason | Should Match 'not an active credential exposure'
    }
    It 'keeps old logon signals below Critical and excludes clone age escalation' {
        $members=@([pscustomobject]@{Kind='NormalUser';Enabled=$true;Stale=$true})
        (Get-DomainAdminReviewAssessment -EnabledHumanUsers 100 -Members $members).Severity | Should Be 'Medium'
        (Get-DomainAdminReviewAssessment -EnabledHumanUsers 100 -Members $members -IsolatedClone).Severity | Should Be 'Information'
    }
    It 'uses High review for enabled service or managed principals and nested groups' {
        foreach ($kind in @('Service','Computer','gMSA','NestedGroup')) {
            (Get-DomainAdminReviewAssessment -EnabledHumanUsers 100 -Members @([pscustomobject]@{Kind=$kind;Enabled=$true;Stale=$false})).Severity | Should Be 'High'
        }
    }
    It 'does not presume an unreadable service account is enabled' {
        $result=Get-DomainAdminReviewAssessment -EnabledHumanUsers 100 -Members @([pscustomobject]@{Kind='Service';Enabled=$null;Stale=$false})
        $result.Severity | Should Be 'Information'
        $result.Reason | Should Match 'not assumed active'
    }
    It 'keeps a large enabled membership High when disabled members are also present' {
        $members=@(1..11 | ForEach-Object { [pscustomobject]@{Kind='NormalUser';Enabled=$true;Stale=$false} })
        $members += [pscustomobject]@{Kind='NormalUser';Enabled=$false;Stale=$true}
        (Get-DomainAdminReviewAssessment -EnabledHumanUsers 100 -Members $members).Severity | Should Be 'High'
    }
}

Describe 'HighRisk baseline count and age classifications' {
    BeforeEach {
        $script:outputdir=$TestDrive
        $script:ADAuditIsolatedClone=$false
        New-Item -ItemType Directory -Path (Get-RawSourceDataDir),(Get-HtmlReportsDir) -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path (Get-RawSourceDataDir) 'HighRisk') -Force | Out-Null
        [pscustomobject]@{SamAccountName='priv1';Enabled=$true;ExtraGroups='Review group'} | Export-Csv (Join-Path (Get-RawSourceDataDir) 'HighRisk/accounts_domain_admins_group_overlap.csv') -NoTypeInformation
        Mock Get-ADDomain { [pscustomobject]@{DomainSID=[pscustomobject]@{Value='S-1-5-21-1'};DNSRoot='example.test';DistinguishedName='DC=example,DC=test'} }
        Mock Get-ADForest { [pscustomobject]@{RootDomain='example.test';Name='example.test'} }
        Mock Get-ADGroup { $Identity }
        Mock Get-ADGroupMember {
            $count=if ($Identity -like '*-512') {6} elseif ($Identity -like '*-519') {3} elseif ($Identity -like '*-518') {1} else {0}
            for($i=1;$i -le $count;$i++){[pscustomobject]@{SamAccountName="priv$i";Name="Privileged fixture $i";objectClass='user'}}
        }
        Mock Get-ADUser {
            if ([string]$Filter -match 'krbtgt') { [pscustomobject]@{PasswordLastSet=(Get-Date).AddDays(-900)} }
        }
        Mock Search-ADAccount { [pscustomobject]@{SamAccountName='priv1';Name='Privileged fixture';Enabled=$true} }
        Mock Register-ADAuditNotAssessed {}
    }
    It 'reports membership count, overlap and password-age reviews without Critical escalation' {
        Get-HighRiskADBaselineReport
        $summary=@(Import-Csv (Join-Path (Get-RawSourceDataDir) 'HighRisk/Summary.csv'))
        foreach ($id in @('PRIV_DA','PRIV_EA','PRIV_SA','PRIV_DA_OVERLAP')) {
            ($summary | Where-Object RiskId -eq $id).Severity | Should Be 'HIGH'
        }
        ($summary | Where-Object RiskId -eq 'KRB_KRBTGT').Severity | Should Be 'MEDIUM'
        (Import-Csv (Join-Path (Get-RawSourceDataDir) 'HighRisk/PASSWORD_NEVER_EXPIRES.csv')).Severity | Should Be 'HIGH'
        @($summary | Where-Object { $_.IsFinding -eq 'True' -and $_.Severity -eq 'CRITICAL' }).Count | Should Be 0
    }
    It 'marks copied krbtgt age unassessed regardless of the apparent age' {
        $script:ADAuditIsolatedClone=$true
        Get-HighRiskADBaselineReport
        $row=Import-Csv (Join-Path (Get-RawSourceDataDir) 'HighRisk/KRBTGT.csv')
        $row.Severity | Should Be 'INFORMATION'
        $row.IsFinding | Should Be 'False'
        $row.Assessment | Should Be 'Not assessed on isolated clone'
        Assert-MockCalled Register-ADAuditNotAssessed -Times 1 -Exactly -ParameterFilter { $Name -eq 'HighRisk krbtgt rotation age' }
        $script:ADAuditIsolatedClone=$false
    }
}

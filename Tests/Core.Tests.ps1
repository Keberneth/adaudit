# Offline regression tests. No domain connection, replication, or network probe.
$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repoRoot 'Library/ADAudit.Common.ps1')
. (Join-Path $repoRoot 'Checks/Invoke-GroupPolicyCheck.ps1')
. (Join-Path $repoRoot 'Checks/Invoke-HealthCheck.ps1')

Describe 'Audit execution coverage' {
    BeforeEach {
        Mock Write-Both { }
        Mock Write-Progress { }
        Mock Get-FsmoRolesForServer { @() }
        $script:CheckFailures.Clear()
        $script:NotAssessed.Clear()
        Initialize-ADAuditCheckStatus -Checks @(
            [pscustomobject]@{Name='Selected';Switch='chosen'},
            [pscustomobject]@{Name='Omitted';Switch='omitted'}
        ) -SelectedSwitches @('chosen')
    }
    It 'separates omitted checks from completed checks' {
        Invoke-AuditCheck -Name 'Selected' -Switch 'chosen' -Description 'fixture' -Body { }
        ($script:ADAuditCheckStatus | Where-Object Switch -eq chosen).Status | Should Be 'Completed'
        ($script:ADAuditCheckStatus | Where-Object Switch -eq omitted).Status | Should Be 'NotSelected'
    }
    It 'marks a caught target failure partial and carries the switch into coverage' {
        Invoke-AuditCheck -Name 'Selected' -Switch 'chosen' -Description 'fixture' -Body {
            Register-ADAuditNotAssessed -Name 'Target' -Reason 'Access denied' -Target 'fixture.invalid'
        }
        ($script:ADAuditCheckStatus | Where-Object Switch -eq chosen).Status | Should Be 'Partial'
        $script:NotAssessed[0].Switch | Should Be 'chosen'
    }
    It 'marks a terminated check failed without terminating subsequent checks' {
        Invoke-AuditCheck -Name 'Selected' -Switch 'chosen' -Description 'fixture' -Body { throw 'Synthetic collection error' }
        ($script:ADAuditCheckStatus | Where-Object Switch -eq chosen).Status | Should Be 'Failed'
        $script:CheckFailures.Count | Should Be 1
    }
    It 'records a nonterminating collection error rather than completing silently' {
        Invoke-AuditCheck -Name 'Selected' -Switch 'chosen' -Description 'fixture' -Body { Write-Error 'Synthetic query failure' }
        ($script:ADAuditCheckStatus | Where-Object Switch -eq chosen).Status | Should Be 'Failed'
    }
    It 'records a missing dependency while still running independent subchecks' {
        $script:fixtureBodyRan = $false
        Invoke-AuditCheck -Name 'Selected' -Switch 'chosen' -Description 'fixture' -Modules '__ADAuditMissingFixtureModule__' -Body { $script:fixtureBodyRan = $true }
        ($script:ADAuditCheckStatus | Where-Object Switch -eq chosen).Status | Should Be 'Partial'
        $script:fixtureBodyRan | Should Be $true
        $script:NotAssessed[0].Reason | Should Match 'not loaded'
    }
    It 'prints selected and skipped counts and closes progress when a check fails' {
        Invoke-AuditCheck -Name 'Selected' -Switch 'chosen' -Description 'fixture' -CheckIndex 1 -SelectedCount 2 -AvailableCount 5 -Body { throw 'fixture failure' }
        Assert-MockCalled Write-Progress -ParameterFilter { $Id -eq 0 -and $Status -match 'Check 1 of 2.*3 skipped' } -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-Progress -ParameterFilter { $Id -eq 1 -and $Completed } -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-Progress -ParameterFilter { $Id -eq 0 -and $Completed } -Times 1 -Exactly -Scope It
        $script:ADAuditProgressContext | Should BeNullOrEmpty
    }
    It 'uses indeterminate progress when an operation does not expose a total' {
        $script:ADAuditProgressLastActivity = ''
        Write-ADAuditProgress -Activity 'Waiting for directory response' -Status 'Query in progress'
        Assert-MockCalled Write-Progress -ParameterFilter { $Id -eq 1 -and $PercentComplete -eq -1 } -Times 1 -Exactly -Scope It
    }
    It 'keeps the current target visible in the parent progress bar without inventing overall progress' {
        Invoke-AuditCheck -Name 'Selected' -Switch 'chosen' -Description 'fixture' -CheckIndex 1 -SelectedCount 2 -AvailableCount 5 -Body {
            Write-ADAuditProgress -Activity 'Services' -Status 'DC 2 of 2: dc2.fixture.invalid; waiting for response' -PercentComplete 50
        }
        Assert-MockCalled Write-Progress -ParameterFilter { $Id -eq 0 -and $Status -match 'Services.*DC 2 of 2: dc2.fixture.invalid' -and $Status -match '50% of phase' -and $PercentComplete -eq 0 -and $Activity -match '3 skipped' } -Times 1 -Exactly -Scope It
    }
    It 'forces target-start updates through throttling before a blocking operation' {
        $script:ADAuditProgressLastActivity = 'Services'
        $script:ADAuditProgressLastUi = [datetime]::UtcNow.AddMinutes(1)
        $script:ADAuditProgressLastLog = [datetime]::UtcNow.AddMinutes(1)
        Write-ADAuditProgress -Activity 'Services' -Status 'Starting next target' -PercentComplete 50 -Force
        Assert-MockCalled Write-Progress -ParameterFilter { $Id -eq 1 -and $Status -match 'Starting next target' } -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-Both -Times 1 -Exactly -Scope It
    }
}

Describe 'Readable run folders' {
    It 'uses local date and time and creates a separate folder on a timestamp collision' {
        $when = [datetimeoffset]'2026-10-25T11:28:24+01:00'
        $first = New-ADAuditRunDirectory -ParentPath $TestDrive -Timestamp $when
        Set-Content -LiteralPath (Join-Path $first 'keep.txt') -Value 'existing evidence'
        $second = New-ADAuditRunDirectory -ParentPath $TestDrive -Timestamp $when
        (Split-Path $first -Leaf) | Should Be '2026-10-25_11-28-24'
        (Split-Path $second -Leaf) | Should Be '2026-10-25_11-28-24_02'
        (Get-Content -LiteralPath (Join-Path $first 'keep.txt')) | Should Be 'existing evidence'
    }
}

Describe 'Shared report context and theme' {
    It 'provides an offline manual theme control and follows the operating system preference' {
        $header = Get-ADAuditReportHeader
        $header | Should Match 'sharedAuditThemeToggle'
        $header | Should Match 'prefers-color-scheme: dark'
        $header | Should Match 'localStorage'
    }
    It 'makes isolated snapshot limitations explicit and encodes supplied text' {
        $notice = Get-ADAuditCloneNotice -IsolatedClone $true -SnapshotDate '<unknown>'
        $notice | Should Match 'ISOLATED CLONE'
        $notice | Should Match '&lt;unknown&gt;'
        $notice | Should Match 'does not establish current production'
        (Get-ADAuditCloneNotice -IsolatedClone $false) | Should BeNullOrEmpty
    }
}

Describe 'GPO evidence is configuration inventory, not applied protection' {
    It 'retains disabled policy and numeric zero without inferring hardening' {
        [xml]$xml = '<GPO xmlns:q="urn:fixture"><Computer><ExtensionData><Extension><SecurityOptions><q:KeyName>RestrictNTLMInDomain</q:KeyName><SettingNumber>0</SettingNumber></SecurityOptions></Extension></ExtensionData></Computer></GPO>'
        $rows = @(ConvertTo-ADAuditGpoSettingRows -Xml $xml -GpoName 'Disabled policy' -GpoId 'fixture' -GpoStatus 'AllSettingsDisabled')
        $rows.Count | Should Be 1
        $rows[0].Value | Should Be '0'
        $rows[0].GpoStatus | Should Be 'AllSettingsDisabled'
        $rows[0].Assessment | Should Match 'not verified'
    }
    It 'handles namespace-independent security option names' {
        [xml]$xml = '<GPO xmlns="urn:fixture"><Computer><ExtensionData><Extension><SecurityOptions><KeyName>LmCompatibilityLevel</KeyName><SettingNumber>5</SettingNumber></SecurityOptions></Extension></ExtensionData></Computer></GPO>'
        $rows = @(ConvertTo-ADAuditGpoSettingRows -Xml $xml -GpoName 'Policy' -GpoId 'fixture' -GpoStatus 'AllSettingsEnabled')
        $rows[0].Value | Should Be '5'
    }
}

Describe 'Health report completeness' {
    BeforeEach {
        $script:outputdir = $TestDrive
        $script:HtmlReportsDir = $TestDrive
    }
    It 'does not show Healthy or 100 health when clock samples were unavailable' {
        $tests = @([pscustomobject]@{Title='Time synchronization';Subtitle='Clock samples';Status='Partial';Detail='No samples';EvidencePath='';NotAssessedCount=2})
        $report = Join-Path $TestDrive 'health.html'
        Write-ADHealthReport -OutputPath $report -Findings @() -Tests $tests -Domain 'fixture.invalid' -RunBy 'offline fixture'
        $html = Get-Content -LiteralPath $report -Raw
        $html | Should Match 'Assessment incomplete'
        $html | Should Match '>N/A</div>'
        $html | Should Not Match '>Healthy<'
    }
    It 'keeps a confirmed Critical issue visible during partial collection' {
        $tests = @([pscustomobject]@{Title='Replication health';Subtitle='fixture';Status='Fail';Detail='Finding with gaps';EvidencePath='';NotAssessedCount=1})
        $findings = @([pscustomobject]@{Category='Replication';Severity='Critical';Title='Fixture finding';Evidence='fixture';Score=25;Source=''})
        $report = Join-Path $TestDrive 'critical.html'
        Write-ADHealthReport -OutputPath $report -Findings $findings -Tests $tests -Domain 'fixture.invalid' -RunBy 'offline fixture'
        $html = Get-Content -LiteralPath $report -Raw
        $html | Should Match 'Critical'
        $html | Should Match 'Assessment incomplete'
    }
}

# Exercise the real collector with offline fixtures. All directory, remote, UNC,
# native diagnostic and socket operations are intercepted before invocation.
$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repoRoot 'Library/ADAudit.Common.ps1')
. (Join-Path $repoRoot 'Checks/Invoke-HealthCheck.ps1')

# Local command seams also make this suite runnable without RSAT or the DC tools.
function Get-ADDomainController { [CmdletBinding()]param($Filter,$Identity,$Server) throw 'Offline fixture was not mocked' }
function Get-ADDomain { [CmdletBinding()]param($Server) throw 'Offline fixture was not mocked' }
function Get-ADForest { [CmdletBinding()]param() throw 'Offline fixture was not mocked' }
function Get-ADReplicationPartnerMetadata { [CmdletBinding()]param($Target,$Scope) throw 'Offline fixture was not mocked' }
function Get-ADReplicationSite { [CmdletBinding()]param($Filter) throw 'Offline fixture was not mocked' }
function Get-ADOptionalFeature { [CmdletBinding()]param($Filter) throw 'Offline fixture was not mocked' }
function Get-ADGroup { [CmdletBinding()]param($Filter,$Properties) throw 'Offline fixture was not mocked' }
function Resolve-DnsName { [CmdletBinding()]param($Name,$Type) throw 'Offline fixture was not mocked' }

function repadmin { throw 'Native replication diagnostics disabled in this offline fixture' }
function w32tm { $global:LASTEXITCODE = 0; 'ntp.fixture.invalid' }
function dcdiag {
    $global:LASTEXITCODE = 0
    $requested = [string](@($args | Where-Object { $_ -like '/test:*' })[0])
    $requested = $requested -replace '^/test:', ''
    '......................... dc1 passed test Connectivity'
    if ($script:HealthDcdiagMode -eq 'RequestedPass') {
        "......................... dc1 passed test $requested"
    } elseif ($script:HealthDcdiagMode -eq 'RequestedFail') {
        "......................... dc1 failed test $requested"
    } else {
        "Skipping requested test $requested"
    }
}

function Read-HealthFixture {
    Invoke-HealthCheck
    [pscustomobject]@{
        Tests = @(Import-Csv -LiteralPath (Join-Path $TestDrive 'health_tests.csv'))
        Findings = @(Import-Csv -LiteralPath (Join-Path $TestDrive 'health_findings.csv'))
    }
}

Describe 'AD health collector evidence and incomplete coverage' {
    BeforeEach {
        $script:outputdir = $TestDrive
        $script:ADAuditIsolatedClone = $false
        $script:HealthDcdiagMode = 'RequestedPass'
        $script:HealthDnsState = 'Running'
        $script:HealthDfsrState = 'Running'
        $script:HealthSysvolMode = 'Reachable'
        $script:NotAssessed.Clear()

        Mock Write-Both { }
        Mock Write-ADAuditProgress { }
        Mock Import-ADAuditModule { }
        Mock Get-RawSourceDataDir { $TestDrive }
        Mock Get-HtmlReportsDir { $TestDrive }
        Mock Write-ADHealthReport { }
        Mock Get-ADDomainController {
            if ($Identity) { throw 'Holder lookup denied in fixture' }
            [pscustomobject]@{Name='dc1'; HostName='dc1.fixture.invalid'; IsReadOnly=$false; IsGlobalCatalog=$true; Site='FixtureSite'}
        }
        Mock Get-ADDomain {
            [pscustomobject]@{DNSRoot='fixture.invalid'; PDCEmulator='dc1.fixture.invalid'; RIDMaster='dc1.fixture.invalid'; InfrastructureMaster='dc1.fixture.invalid'}
        }
        Mock Get-ADForest {
            [pscustomobject]@{Name='fixture.invalid'; RootDomain='fixture.invalid'; Domains=@('fixture.invalid'); SchemaMaster='dc1.fixture.invalid'; DomainNamingMaster='dc1.fixture.invalid'}
        }
        Mock Resolve-DnsName { throw 'DNS lookup denied in fixture' }
        Mock Get-ADReplicationPartnerMetadata { throw 'Replication metadata denied in fixture' }
        Mock Invoke-Command { throw 'Remoting disabled in fixture' }
        Mock Get-ADAuditNtdsStorage { throw 'Storage collection disabled in fixture' }
        Mock Get-ADAuditHostUtcTime { throw 'Clock collection disabled in fixture' }
        Mock Get-WinEvent { @() }
        Mock Get-ADReplicationSite { @() }
        Mock Get-ADOptionalFeature { [pscustomobject]@{EnabledScopes=@('CN=Partitions,DC=fixture,DC=invalid')} }
        Mock Get-ADGroup { @() }
        Mock Get-ADAuditCimInstance {
            if ($Filter -eq "Name='DNS'") {
                if ($script:HealthDnsState -eq 'Absent') { return $null }
                return [pscustomobject]@{State=$script:HealthDnsState; StartMode='Auto'}
            }
            if ($Filter -eq "Name='DFSR'") { return [pscustomobject]@{State=$script:HealthDfsrState; StartMode='Auto'} }
            [pscustomobject]@{State='Running'; StartMode='Auto'}
        }
        Mock Test-Path {
            if ($script:HealthSysvolMode -eq 'Denied') { throw 'Access to SYSVOL denied in fixture' }
            $script:HealthSysvolMode -eq 'Reachable'
        } -ParameterFilter { $LiteralPath -like '\\*' }
        # Even a local computer named dc1 cannot cause this fixture to open sockets.
        Mock New-Object {
            $socket = [pscustomobject]@{}
            $socket | Add-Member -MemberType ScriptMethod -Name BeginConnect -Value { throw 'Offline socket: connection unavailable' }
            $socket | Add-Member -MemberType ScriptMethod -Name Close -Value { }
            $socket
        } -ParameterFilter { $TypeName -eq 'System.Net.Sockets.TcpClient' }
    }

    It 'records failed FSMO object and metadata reads as incomplete without inventing an outage' {
        $result = Read-HealthFixture
        $test = $result.Tests | Where-Object Title -eq 'FSMO role holders'
        $test.Status | Should Be 'Partial'
        ([int]$test.NotAssessedCount -ge 2) | Should Be $true
        @($script:NotAssessed | Where-Object { $_.Target -eq 'dc1.fixture.invalid' -and $_.Reason -like '*DC object lookup failed*' }).Count | Should Be 1
        @($script:NotAssessed | Where-Object { $_.Reason -like '*Replication metadata lookup failed*' }).Count | Should Be 1
        @($result.Findings | Where-Object Category -eq 'FSMO').Count | Should Be 0
    }

    It 'does not infer an FSMO outage from audit-host connectivity when directory metadata is readable' {
        Mock Get-ADDomainController {
            [pscustomobject]@{Name='dc1'; HostName='dc1.fixture.invalid'; IsReadOnly=$false; IsGlobalCatalog=$true; Site='FixtureSite'; IPv4Address='192.0.2.1'}
        }
        Mock Get-ADReplicationPartnerMetadata { [pscustomobject]@{LastReplicationSuccess=(Get-Date)} }
        $result = Read-HealthFixture
        ($result.Tests | Where-Object Title -eq 'FSMO role holders').Status | Should Be 'Partial'
        @($result.Findings | Where-Object Category -eq 'FSMO').Count | Should Be 0
        Assert-MockCalled New-Object -ParameterFilter { $TypeName -eq 'System.Net.Sockets.TcpClient' } -Times 2 -Scope It
    }

    It 'reports an installed stopped DNS service as a High service failure' {
        $script:HealthDnsState = 'Stopped'
        $result = Read-HealthFixture
        $finding = @($result.Findings | Where-Object { $_.Category -eq 'DC Services' -and $_.Evidence -like '*service DNS *' })
        $finding.Count | Should Be 1
        $finding[0].Severity | Should Be 'High'
        ($result.Tests | Where-Object Title -eq 'Core AD services').Status | Should Be 'Fail'
    }

    It 'accepts a successfully verified absent DNS role without a service failure' {
        $script:HealthDnsState = 'Absent'
        $result = Read-HealthFixture
        @($result.Findings | Where-Object { $_.Category -eq 'DC Services' -and $_.Evidence -like '*service DNS *' }).Count | Should Be 0
        ($result.Tests | Where-Object Title -eq 'Core AD services').Status | Should Be 'Pass'
    }

    It 'does not accept a prerequisite Connectivity pass as the requested dcdiag result' {
        $script:HealthDcdiagMode = 'PrerequisiteOnly'
        $result = Read-HealthFixture
        $test = $result.Tests | Where-Object Title -eq 'DC diagnostics (dcdiag)'
        $test.Status | Should Be 'Partial'
        [int]$test.NotAssessedCount | Should Be 10
        @($result.Findings | Where-Object Category -eq 'DC Diagnostics').Count | Should Be 0
    }

    It 'accepts explicit successful results for each requested dcdiag test' {
        $result = Read-HealthFixture
        $test = $result.Tests | Where-Object Title -eq 'DC diagnostics (dcdiag)'
        $test.Status | Should Be 'Pass'
        [int]$test.NotAssessedCount | Should Be 0
    }

    It 'retains explicit failed dcdiag results as findings' {
        $script:HealthDcdiagMode = 'RequestedFail'
        $result = Read-HealthFixture
        @($result.Findings | Where-Object { $_.Category -eq 'DC Diagnostics' -and $_.Severity -eq 'Medium' }).Count | Should Be 1
        ($result.Tests | Where-Object Title -eq 'DC diagnostics (dcdiag)').Status | Should Be 'Warn'
    }

    It 'keeps an unreachable SYSVOL share unknown without scoring a replication fault' {
        $script:HealthSysvolMode = 'Unreachable'
        $result = Read-HealthFixture
        ($result.Tests | Where-Object Title -eq 'SYSVOL / DFSR availability').Status | Should Be 'Partial'
        @($result.Findings | Where-Object Category -eq 'SYSVOL/DFSR').Count | Should Be 0
    }

    It 'keeps a denied SYSVOL read unknown without scoring a replication fault' {
        $script:HealthSysvolMode = 'Denied'
        $result = Read-HealthFixture
        $test = $result.Tests | Where-Object Title -eq 'SYSVOL / DFSR availability'
        $test.Status | Should Be 'Partial'
        [int]$test.NotAssessedCount | Should Be 1
        @($result.Findings | Where-Object Category -eq 'SYSVOL/DFSR').Count | Should Be 0
    }

    It 'retains an observed stopped DFSR service as a finding despite a SYSVOL collection gap' {
        $script:HealthSysvolMode = 'Denied'
        $script:HealthDfsrState = 'Stopped'
        $result = Read-HealthFixture
        @($result.Findings | Where-Object { $_.Category -eq 'SYSVOL/DFSR' -and $_.Severity -eq 'Medium' }).Count | Should Be 1
        [int]($result.Tests | Where-Object Title -eq 'SYSVOL / DFSR availability').NotAssessedCount | Should Be 1
    }

    It 'collects local clone health without contacting peer DCs or running production replication commands' {
        $script:ADAuditIsolatedClone = $true
        Mock Test-ADAuditLocalComputer { $ComputerName -eq 'dc1.fixture.invalid' }
        Mock Get-ADDomainController {
            [pscustomobject]@{Name='dc1'; HostName='dc1.fixture.invalid'; IsReadOnly=$false; IsGlobalCatalog=$true; Site='FixtureSite'}
            [pscustomobject]@{Name='dc2'; HostName='dc2.fixture.invalid'; IsReadOnly=$false; IsGlobalCatalog=$true; Site='FixtureSite'}
        }
        Mock repadmin { throw 'Replication must not execute in clone mode' }
        Mock Get-ADAuditNtdsStorage { [pscustomobject]@{DatabasePath='C:\NTDS\ntds.dit'; LogPath='C:\NTDS'; DatabaseBytes=1GB; LogFreeBytes=10GB} }
        Mock Get-ADAuditHostUtcTime { [DateTime]::UtcNow }
        Mock Get-ADAuditCimInstance {
            if ($ClassName -eq 'Win32_Share') { return [pscustomobject]@{Path=$TestDrive} }
            [pscustomobject]@{State='Running'; StartMode='Auto'}
        }
        $result = Read-HealthFixture
        ($result.Tests | Where-Object Title -eq 'Core AD services').Status | Should Be 'Pass'
        ($result.Tests | Where-Object Title -eq 'NTDS database').Status | Should Be 'Pass'
        ($result.Tests | Where-Object Title -eq 'Replication health').Status | Should Be 'Partial'
        ($result.Tests | Where-Object Title -eq 'FSMO role holders').Status | Should Be 'Partial'
        @($script:NotAssessed | Where-Object Target -eq 'dc2.fixture.invalid').Count | Should Be 1
        Assert-MockCalled repadmin -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-Command -Times 0 -Exactly -Scope It
        Assert-MockCalled Get-ADReplicationPartnerMetadata -Times 0 -Exactly -Scope It
        Assert-MockCalled Get-ADAuditCimInstance -ParameterFilter { $ComputerName -eq 'dc2.fixture.invalid' } -Times 0 -Exactly -Scope It
        Assert-MockCalled Get-WinEvent -ParameterFilter { $ComputerName } -Times 0 -Exactly -Scope It
        $script:ADAuditIsolatedClone = $false
    }
}

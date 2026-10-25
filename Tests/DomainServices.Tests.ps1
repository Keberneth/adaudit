# Offline regression tests for the DomainAudit service-query batch. Directory,
# ADSI and CIM command seams prevent live AD or network access.
$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repoRoot 'Library/ADAudit.Common.ps1')
. (Join-Path $repoRoot 'Checks/Invoke-DomainAuditCheck.ps1')
function Get-ADDomainController { [CmdletBinding()]param($Filter) throw 'Offline fixture requires a mock' }
function Get-CimInstance { [CmdletBinding()]param($ClassName,$Filter,$Property,$Namespace,$CimSession,$ComputerName,$OperationTimeoutSec) throw 'Offline fixture requires a mock' }
function New-CimSession { [CmdletBinding()]param($ComputerName,$SessionOption,$OperationTimeoutSec) throw 'No remote session is allowed in this fixture' }

function New-OfflineServiceSearcher {
    $searcher = [pscustomobject]@{}
    $searcher | Add-Member -MemberType ScriptMethod -Name FindOne -Value { if ($script:UseDfsr) { [pscustomobject]@{Present=$true} } }
    $searcher | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
    $searcher
}

Describe 'Batched domain-controller service collection' {
    BeforeEach {
        $script:ADAuditIsolatedClone = $false
        $script:UseDfsr = $true
        $script:NotAssessed.Clear()
        $script:ServiceCallOrder = [System.Collections.Generic.List[string]]::new()
        Mock Write-Both { }
        Mock Write-ADAuditProgress { $script:ServiceCallOrder.Add("progress:$Status") }
        Mock Get-ADDomainController { [pscustomobject]@{Name='dc1'}; [pscustomobject]@{Name='dc2'} }
        Mock New-Object { New-OfflineServiceSearcher } -ParameterFilter { $TypeName -eq 'System.DirectoryServices.DirectorySearcher' }
        Mock Get-ADAuditCimInstance {
            $script:ServiceCallOrder.Add("query:$ComputerName")
            foreach ($name in @('DNS','Netlogon','KDC','W32Time','DFSR','NtFrs')) { [pscustomobject]@{Name=$name; State='Running'} }
        }
    }

    It 'queries all five requested services once per DC using Name and State' {
        Get-CriticalServicesStatus
        Assert-MockCalled Get-ADAuditCimInstance -Times 2 -Exactly -Scope It
        Assert-MockCalled Get-ADAuditCimInstance -ParameterFilter {
            $ClassName -eq 'Win32_Service' -and $Filter -eq "Name='dns' OR Name='netlogon' OR Name='kdc' OR Name='w32time' OR Name='dfsr'" -and
            $Property -contains 'Name' -and $Property -contains 'State' -and $UseWsmanFallback
        } -Times 2 -Exactly -Scope It
        $script:NotAssessed.Count | Should Be 0
    }

    It 'shows the target and ordinal before each query and completed target count afterwards' {
        Get-CriticalServicesStatus
        $script:ServiceCallOrder.IndexOf('progress:DC 1/2: querying dc1 (5 services); 0 DCs completed') | Should BeGreaterThan -1
        $script:ServiceCallOrder.IndexOf('progress:DC 1/2: querying dc1 (5 services); 0 DCs completed') | Should BeLessThan $script:ServiceCallOrder.IndexOf('query:dc1')
        $script:ServiceCallOrder.IndexOf('query:dc1') | Should BeLessThan $script:ServiceCallOrder.IndexOf('progress:DC 1/2: dc1 queried')
        $script:ServiceCallOrder.IndexOf('progress:DC 2/2: querying dc2 (5 services); 1 DCs completed') | Should BeGreaterThan -1
        $script:ServiceCallOrder.IndexOf('progress:DC 2/2: querying dc2 (5 services); 1 DCs completed') | Should BeLessThan $script:ServiceCallOrder.IndexOf('query:dc2')
        Assert-MockCalled Write-ADAuditProgress -ParameterFilter { $Status -eq 'DC 1/2: querying dc1 (5 services); 0 DCs completed' -and $PercentComplete -eq 0 -and $Force } -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-ADAuditProgress -ParameterFilter { $Status -eq 'DC 2/2: querying dc2 (5 services); 1 DCs completed' -and $PercentComplete -eq 50 -and $Force } -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-ADAuditProgress -ParameterFilter { $Status -eq 'DC 1/2: dc1 queried' -and $PercentComplete -eq 50 } -Times 1 -Exactly -Scope It
        Assert-MockCalled Write-ADAuditProgress -ParameterFilter { $Completed } -Times 1 -Exactly -Scope It
    }

    It 'records one failed target covering all requested services and continues with the next DC' {
        Mock Get-ADAuditCimInstance {
            if ($ComputerName -eq 'dc1') { throw 'RPC unavailable in fixture' }
            foreach ($name in @('dns','netlogon','kdc','w32time','dfsr')) { [pscustomobject]@{Name=$name; State='Running'} }
        }
        Get-CriticalServicesStatus
        $script:NotAssessed.Count | Should Be 1
        $script:NotAssessed[0].Target | Should Be 'dc1'
        $script:NotAssessed[0].Reason | Should Match 'dns, netlogon, kdc, w32time, dfsr'
        Assert-MockCalled Get-ADAuditCimInstance -Times 2 -Exactly -Scope It
        Assert-MockCalled Write-ADAuditProgress -ParameterFilter { $Status -eq 'DC 1/2: dc1 not assessed' } -Times 1 -Exactly -Scope It
    }

    It 'keeps missing and empty service states unknown while retaining stopped service warnings' {
        Mock Get-ADDomainController { [pscustomobject]@{Name='dc1'} }
        Mock Get-ADAuditCimInstance {
            [pscustomobject]@{Name='netlogon'; State='Stopped'}
            [pscustomobject]@{Name='kdc'; State=''}
            [pscustomobject]@{Name='w32time'; State='Running'}
            [pscustomobject]@{Name='dfsr'; State='Running'}
        }
        Get-CriticalServicesStatus
        $script:NotAssessed.Count | Should Be 2
        @($script:NotAssessed | Where-Object Target -eq 'dc1/dns').Count | Should Be 1
        @($script:NotAssessed | Where-Object Target -eq 'dc1/kdc').Count | Should Be 1
        Assert-MockCalled Write-Both -ParameterFilter { ($args -join ' ') -like '*Service netlogon is not running on dc1*' } -Times 1 -Exactly -Scope It
    }

    It 'preserves the FRS selection when DFSR configuration is absent' {
        $script:UseDfsr = $false
        Get-CriticalServicesStatus
        Assert-MockCalled Get-ADAuditCimInstance -ParameterFilter { $Filter -like "*Name='ntfrs'" -and $Filter -notlike "*Name='dfsr'*" } -Times 2 -Exactly -Scope It
    }

    It 'records failed target discovery and closes progress without querying any service' {
        Mock Get-ADDomainController { throw 'Directory unavailable in fixture' }
        Get-CriticalServicesStatus
        $script:NotAssessed.Count | Should Be 1
        Assert-MockCalled Get-ADAuditCimInstance -Times 0 -Exactly -Scope It
        Assert-MockCalled Write-ADAuditProgress -ParameterFilter { $Completed } -Times 1 -Exactly -Scope It
    }
}

Describe 'Batched service collector respects the real clone guard' {
    BeforeEach {
        $script:ADAuditIsWindows = $true
        $script:ADAuditIsolatedClone = $true
        $script:UseDfsr = $true
        $script:NotAssessed.Clear()
        Mock Write-Both { }
        Mock Write-ADAuditProgress { }
        Mock Get-ADAuditLocalComputerNames { @('dc1') }
        Mock Get-ADDomainController { [pscustomobject]@{Name='dc1'}; [pscustomobject]@{Name='dc2'} }
        Mock New-Object { New-OfflineServiceSearcher } -ParameterFilter { $TypeName -eq 'System.DirectoryServices.DirectorySearcher' }
        Mock New-CimSession { throw 'No remote session is allowed in this fixture' }
        Mock Get-CimInstance {
            foreach ($name in @('dns','netlogon','kdc','w32time','dfsr')) { [pscustomobject]@{Name=$name; State='Running'} }
        }
    }
    It 'collects the local services once and excludes the peer before opening a connection' {
        Get-CriticalServicesStatus
        Assert-MockCalled Get-CimInstance -Times 1 -Exactly -Scope It
        Assert-MockCalled New-CimSession -Times 0 -Exactly -Scope It
        $script:NotAssessed.Count | Should Be 1
        $script:NotAssessed[0].Target | Should Be 'dc2'
        $script:NotAssessed[0].Reason | Should Match 'Isolated-clone'
        $script:ADAuditIsolatedClone = $false
    }
}

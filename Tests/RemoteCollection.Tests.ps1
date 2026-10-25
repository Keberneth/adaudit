# Offline transport and clone-scope regressions. Command stubs prevent native
# CIM sessions or directory/network calls even on a machine with RSAT installed.
$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repoRoot 'Library/ADAudit.Common.ps1')
. (Join-Path $repoRoot 'Checks/Invoke-HealthCheck.ps1')
. (Join-Path $repoRoot 'Checks/Invoke-DomainAuditCheck.ps1')
. (Join-Path $repoRoot 'Checks/Invoke-PortConnectivityCheck.ps1')
function Get-CimInstance { [CmdletBinding()]param($ClassName,$Query,$Filter,$Property,$Namespace,$CimSession,$ComputerName,$OperationTimeoutSec) throw 'Offline fixture requires a mock' }
function Invoke-CimMethod { [CmdletBinding()]param($ClassName,$MethodName,$Arguments,$Namespace,$CimSession,$OperationTimeoutSec) throw 'Offline fixture requires a mock' }
function New-CimSession { [CmdletBinding()]param($ComputerName,$SessionOption,$OperationTimeoutSec) throw 'Offline fixture requires a mock' }
function New-CimSessionOption { param($Protocol) throw 'Offline fixture requires a mock' }
function Remove-CimSession { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$CimSession) throw 'Offline fixture requires a mock' }
function Get-ADDomainController { [CmdletBinding()]param($Filter) throw 'Offline fixture requires a mock' }

Describe 'Local aliases and CIM transport selection' {
    BeforeEach {
        $script:ADAuditIsWindows = $true
        $script:ADAuditIsolatedClone = $false
        Mock Get-ADAuditLocalComputerNames { @('.', 'localhost', '127.0.0.1', '::1', 'dc1', 'dc1.fixture.invalid') }
        Mock New-CimSessionOption { [pscustomobject]@{Protocol=$Protocol} }
        Mock New-CimSession { [pscustomobject]@{Target=$ComputerName; Protocol=$SessionOption.Protocol} }
        Mock Remove-CimSession { }
        Mock Get-CimInstance { [pscustomobject]@{State='Running'} }
        Mock Invoke-CimMethod { [pscustomobject]@{ReturnValue=0; uValue=2; sValue='C:\NTDS\ntds.dit'} }
        Mock Invoke-Command { throw 'PowerShell remoting is forbidden in this fixture' }
    }
    It 'recognizes the configured local FQDN case-insensitively with a DNS trailing dot' {
        Test-ADAuditLocalComputer 'DC1.FIXTURE.INVALID.' | Should Be $true
        Test-ADAuditLocalComputer 'dc1' | Should Be $true
        Test-ADAuditLocalComputer '127.0.0.1' | Should Be $true
    }
    It 'does not mistake the same short name in another domain for this computer' {
        Test-ADAuditLocalComputer 'dc1.other.invalid' | Should Be $false
    }
    It 'uses local CIM for the local FQDN without creating a remote session' {
        (Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName 'dc1.fixture.invalid').State | Should Be 'Running'
        Assert-MockCalled New-CimSession -Times 0 -Exactly -Scope It
        Assert-MockCalled Get-CimInstance -ParameterFilter { -not $CimSession -and -not $ComputerName } -Times 1 -Exactly -Scope It
    }
    It 'uses DCOM before any optional WSMan fallback for a remote read' {
        Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName 'dc2.fixture.invalid' -UseWsmanFallback | Out-Null
        Assert-MockCalled New-CimSessionOption -ParameterFilter { $Protocol -eq 'Dcom' } -Times 1 -Exactly -Scope It
        Assert-MockCalled New-CimSessionOption -ParameterFilter { $Protocol -eq 'Wsman' } -Times 0 -Exactly -Scope It
        Assert-MockCalled Remove-CimSession -Times 1 -Exactly -Scope It
    }
    It 'uses the allowed WSMan fallback only after a DCOM connection failure' {
        Mock New-CimSession { throw 'DCOM unavailable in fixture' }
        Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName 'dc2.fixture.invalid' -UseWsmanFallback | Out-Null
        Assert-MockCalled New-CimSession -ParameterFilter { $SessionOption.Protocol -eq 'Dcom' -and $OperationTimeoutSec -eq 15 } -Times 1 -Exactly -Scope It
        Assert-MockCalled Get-CimInstance -ParameterFilter { $ComputerName -eq 'dc2.fixture.invalid' -and -not $CimSession } -Times 1 -Exactly -Scope It
    }
    It 'refuses an excluded remote CIM target before creating any session in clone mode' {
        $script:ADAuditIsolatedClone = $true
        $rejected = $false
        try { Get-ADAuditCimInstance -ClassName Win32_Service -ComputerName 'dc2.fixture.invalid' -UseWsmanFallback | Out-Null } catch { $rejected = $true }
        $rejected | Should Be $true
        Assert-MockCalled New-CimSession -Times 0 -Exactly -Scope It
        Assert-MockCalled Get-CimInstance -Times 0 -Exactly -Scope It
    }
    It 'reads the local FQDN registry without WinRM or a remote CIM session' {
        $result = Get-ADAuditRemoteRegistryDword -ComputerName 'dc1.fixture.invalid' -SubKey 'SYSTEM\Fixture' -ValueName 'Value'
        $result.Success | Should Be $true
        $result.Value | Should Be 2
        Assert-MockCalled New-CimSession -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-CimMethod -ParameterFilter { -not $CimSession -and $MethodName -eq 'GetDWORDValue' } -Times 1 -Exactly -Scope It
    }
    It 'returns excluded remote registry collection as unknown without attempting a connection' {
        $script:ADAuditIsolatedClone = $true
        $result = Get-ADAuditRemoteRegistryDword -ComputerName 'dc2.fixture.invalid' -SubKey 'SYSTEM\Fixture' -ValueName 'Value'
        $result.Success | Should Be $false
        $result.Error | Should Match 'Isolated-clone'
        Assert-MockCalled New-CimSession -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-CimMethod -Times 0 -Exactly -Scope It
    }
    It 'does not treat registry access denied as an absent setting' {
        Mock Invoke-CimMethod { [pscustomobject]@{ReturnValue=5} }
        (Get-ADAuditRemoteRegistryDword -ComputerName 'dc1.fixture.invalid' -SubKey 'SYSTEM\Fixture' -ValueName 'Value').Success | Should Be $false
    }
    It 'retains absent registry values as successfully queried but unset' {
        Mock Invoke-CimMethod { [pscustomobject]@{ReturnValue=2} }
        $result = Get-ADAuditRemoteRegistryDword -ComputerName 'dc1.fixture.invalid' -SubKey 'SYSTEM\Fixture' -ValueName 'Value'
        $result.Success | Should Be $true
        ($null -eq $result.Value) | Should Be $true
    }
    It 'gets effective SMB state through the DCOM provider without a remote PowerShell command' {
        Mock Invoke-CimMethod { [pscustomobject]@{ReturnValue=0; Output=[pscustomobject]@{EnableSMB1Protocol=$false; RequireSecuritySignature=$true}} }
        $config = Get-ADAuditSmbServerConfiguration -ComputerName 'dc2.fixture.invalid'
        $config.EnableSMB1Protocol | Should Be $false
        $config.RequireSecuritySignature | Should Be $true
        Assert-MockCalled Invoke-CimMethod -ParameterFilter { $Namespace -eq 'root/Microsoft/Windows/SMB' -and $MethodName -eq 'GetConfiguration' -and $CimSession.Protocol -eq 'Dcom' } -Times 1 -Exactly -Scope It
        Assert-MockCalled Invoke-Command -Times 0 -Exactly -Scope It
    }
    It 'uses the local UTC clock for the local FQDN without any remote operation' {
        $clock = Get-ADAuditHostUtcTime -ComputerName 'dc1.fixture.invalid'
        $clock.Kind | Should Be 'Utc'
        ([Math]::Abs(($clock - [DateTime]::UtcNow).TotalSeconds) -lt 5) | Should Be $true
        Assert-MockCalled Get-CimInstance -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-Command -Times 0 -Exactly -Scope It
    }
    It 'converts the remote UTC provider fields without applying the auditor timezone' {
        Mock Get-CimInstance { [pscustomobject]@{Year=2026; Month=10; Day=25; Hour=9; Minute=12; Second=34} }
        $clock = Get-ADAuditHostUtcTime -ComputerName 'dc2.fixture.invalid'
        $clock.ToString('yyyy-MM-ddTHH:mm:ssZ') | Should Be '2026-10-25T09:12:34Z'
        $clock.Kind | Should Be 'Utc'
        Assert-MockCalled Invoke-Command -Times 0 -Exactly -Scope It
    }
    It 'collects remote NTDS file and volume metadata using exact CIM filters' {
        Mock Get-ADAuditRemoteRegistryValue {
            if ($ValueName -eq 'DSA Database file') { return @{Success=$true; Value='C:\NTDS\ntds.dit'} }
            @{Success=$true; Value='C:\NTDS'}
        }
        Mock Get-CimInstance {
            if ($ClassName -eq 'CIM_DataFile') { return [pscustomobject]@{FileSize=123456} }
            if ($ClassName -eq 'Win32_LogicalDisk') { return [pscustomobject]@{FreeSpace=5GB} }
            throw 'Unexpected CIM class'
        }
        $storage = Get-ADAuditNtdsStorage -ComputerName 'dc2.fixture.invalid'
        $storage.DatabaseBytes | Should Be 123456
        $storage.LogFreeBytes | Should Be 5GB
        Assert-MockCalled Get-CimInstance -ParameterFilter { $ClassName -eq 'CIM_DataFile' -and $Filter -eq "Name='C:\\NTDS\\ntds.dit'" } -Times 1 -Exactly -Scope It
        Assert-MockCalled Invoke-Command -Times 0 -Exactly -Scope It
    }
    It 'reads local NTDS file and disk metadata without remote sessions' {
        Mock Get-ADAuditRemoteRegistryValue {
            if ($ValueName -eq 'DSA Database file') { return @{Success=$true; Value='C:\NTDS\ntds.dit'} }
            @{Success=$true; Value='C:\NTDS'}
        }
        Mock Get-Item { [pscustomobject]@{Length=123456} } -ParameterFilter { $LiteralPath -eq 'C:\NTDS\ntds.dit' }
        Mock Get-PSDrive { [pscustomobject]@{Free=10GB} } -ParameterFilter { $Name -eq 'C' }
        $storage = Get-ADAuditNtdsStorage -ComputerName 'dc1.fixture.invalid'
        $storage.DatabaseBytes | Should Be 123456
        $storage.LogFreeBytes | Should Be 10GB
        Assert-MockCalled New-CimSession -Times 0 -Exactly -Scope It
        Assert-MockCalled Get-CimInstance -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-Command -Times 0 -Exactly -Scope It
    }
}

Describe 'Port collection from the local DC and isolated-clone scope' {
    BeforeEach {
        $script:ADAuditIsolatedClone = $false
        $script:NotAssessed.Clear()
        Mock Get-ADAuditLocalComputerNames { @('dc1','dc1.fixture.invalid') }
        Mock Get-ADDomainController {
            [pscustomobject]@{Name='dc1'; HostName='dc1.fixture.invalid'; IPv4Address='192.0.2.1'; IsGlobalCatalog=$true}
            [pscustomobject]@{Name='dc2'; HostName='dc2.fixture.invalid'; IPv4Address='192.0.2.2'; IsGlobalCatalog=$true}
        }
        Mock Write-Both { }
        Mock Write-ADAuditProgress { }
        Mock Write-Nessus-Finding { }
        Mock Get-EvidencePath { Join-Path $TestDrive $FileName }
        Mock Test-ADAuditPortTargetResolution { $true }
        Mock Test-ADAuditPortEndpoint { [pscustomobject]@{Open=($Port -notin @(5985,5986)); Error=$null} }
        Mock Invoke-Command { throw 'No remote PowerShell is permitted in this fixture' }
    }
    It 'reuses probes originating on the local DC without requiring WinRM to itself' {
        Invoke-PortConnectivityCheck
        $rows = @(Import-Csv (Join-Path $TestDrive 'dc_port_connectivity.csv'))
        $rows.Count | Should Be 26
        @($rows | Where-Object { $_.Target -eq 'dc2.fixture.invalid' -and $_.ProbeFrom -like 'local DC*' }).Count | Should Be 13
        @($script:NotAssessed | Where-Object Target -eq 'dc1.fixture.invalid').Count | Should Be 0
        @($script:NotAssessed | Where-Object Target -eq 'dc2.fixture.invalid').Count | Should Be 1
        Assert-MockCalled Invoke-Command -Times 0 -Exactly -Scope It
    }
    It 'probes only local listeners and records the excluded peer in clone mode' {
        $script:ADAuditIsolatedClone = $true
        Invoke-PortConnectivityCheck
        $rows = @(Import-Csv (Join-Path $TestDrive 'dc_port_connectivity.csv'))
        $rows.Count | Should Be 13
        @($rows | Where-Object Target -ne 'dc1.fixture.invalid').Count | Should Be 0
        @($script:NotAssessed | Where-Object Target -eq 'dc2.fixture.invalid').Count | Should Be 1
        Assert-MockCalled Test-ADAuditPortEndpoint -ParameterFilter { $Target -eq 'dc2.fixture.invalid' } -Times 0 -Exactly -Scope It
        Assert-MockCalled Test-ADAuditPortTargetResolution -ParameterFilter { $Target -eq 'dc2.fixture.invalid' } -Times 0 -Exactly -Scope It
        Assert-MockCalled Invoke-Command -Times 0 -Exactly -Scope It
        $script:ADAuditIsolatedClone = $false
    }
}

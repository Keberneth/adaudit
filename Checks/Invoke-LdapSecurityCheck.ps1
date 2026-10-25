<# Read-only LDAP configuration, endpoint TLS and anonymous directory-read checks. #>
function Get-ADAuditLdapSigningAssessment {
    param($Value, [bool]$ModernServer, [bool]$VersionKnown)
    if ($Value -eq 2) { return [pscustomobject]@{Status='Pass'; Detail='LDAPServerIntegrity explicitly requires signing.'} }
    if ($null -eq $Value -or $Value -notin @(0,1,2) -or $ModernServer -or -not $VersionKnown) {
        return [pscustomobject]@{Status='NotAssessed'; Detail='Effective signing cannot be inferred from this value alone. Windows Server 2025 enforcement policy and OS/deployment defaults can take precedence; verify effective policy and unsigned-bind rejection.'}
    }
    [pscustomobject]@{Status='Finding'; Detail="LDAPServerIntegrity=$Value on a pre-2025 server; signing is not required by this setting."}
}

function Get-ADAuditAnonymousReadOutcome {
    param([int]$EntryCount, [Nullable[int]]$ErrorCode, [switch]$TransportFailure)
    if ($TransportFailure) { return 'NotAssessed' }
    if ($null -ne $ErrorCode) {
        # Authentication/authorization refusals demonstrate only rejection of this query.
        if ($ErrorCode -in @(8,13,48,49,50)) { return 'Rejected' }
        return 'NotAssessed'
    }
    if ($EntryCount -gt 0) { return 'Finding' }
    return 'NoDataReturned'
}

function Test-ADAuditLdapsEndpoint {
    param([string]$ComputerName)
    $tcp = $null; $tls = $null
    try {
        $tcp = [Net.Sockets.TcpClient]::new()
        $connect = $tcp.ConnectAsync($ComputerName,636)
        if (-not $connect.Wait(5000)) { throw 'TCP connection timeout on 636.' }
        $connect.GetAwaiter().GetResult()
        $tcp.ReceiveTimeout = 5000; $tcp.SendTimeout = 5000
        $tls = [Net.Security.SslStream]::new($tcp.GetStream(), $false)
        $tls.ReadTimeout = 5000; $tls.WriteTimeout = 5000
        # Default validation verifies the served certificate's chain, name and validity.
        $tls.AuthenticateAsClient($ComputerName)
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($tls.RemoteCertificate)
        try {
            [pscustomobject]@{Status='Pass'; Detail="LDAPS handshake validated using this host's trust store; subject=$($cert.Subject); expires=$($cert.NotAfter.ToUniversalTime().ToString('o')); thumbprint=$($cert.Thumbprint). Revocation, StartTLS and GC TLS were not assessed."}
        } finally { $cert.Dispose() }
    } catch {
        [pscustomobject]@{Status='NotAssessed'; Detail="LDAPS endpoint validation failed: $($_.Exception.Message). This does not prove a missing certificate or plaintext LDAP; inspect certificate trust/name/validity and connectivity. StartTLS/SASL protection on 389 was not assessed."}
    } finally {
        if ($tls) { $tls.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }
}

function Get-LDAPSecurity {
    $rows = [System.Collections.Generic.List[object]]::new()
    $evidence = Get-EvidencePath 'LDAPSecurity.txt'
    Remove-Item -LiteralPath $evidence -ErrorAction SilentlyContinue
    try {
        $domainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName
        $dcList = @(Get-ADDomainController -Filter * -ErrorAction Stop)
        if ($dcList.Count -eq 0) { throw 'No domain controllers enumerated.' }
    } catch {
        Register-ADAuditNotAssessed -Name 'LDAP security inventory' -Switch 'ldapsecurity' -Reason $_.Exception.Message
        return
    }
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    foreach ($controller in $dcList) {
        $dc = [string]$controller.HostName
        Write-ADAuditProgress -Activity 'LDAP security' -Status "Assessing $dc"
        if ($script:ADAuditIsolatedClone -and -not (Test-ADAuditLocalComputer -ComputerName $dc)) {
            $rows.Add([pscustomobject]@{Target=$dc; Control='CloneScope'; Status='NotAssessed'; Severity='Info'; Detail='Remote DC endpoint testing is outside isolated-clone scope; directory records describe the copied environment.'})
            continue
        }
        $versionKnown = [string]$controller.OperatingSystem -match 'Windows Server (2008|2012|2016|2019|2022|2025)'
        $modern = [string]$controller.OperatingSystem -match 'Windows Server 2025'
        $ntdsKey = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        $sig = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey $ntdsKey -ValueName 'LDAPServerIntegrity'
        $signing = if ($sig.Success) { Get-ADAuditLdapSigningAssessment -Value $sig.Value -ModernServer $modern -VersionKnown $versionKnown } else { [pscustomobject]@{Status='NotAssessed'; Detail="Registry read failed: $($sig.Error)"} }
        $rows.Add([pscustomobject]@{Target=$dc; Control='LDAPSigning'; Status=$signing.Status; Severity=$(if ($signing.Status -eq 'Finding') {'High'} else {'Info'}); Detail=$signing.Detail})
        $cb = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey $ntdsKey -ValueName 'LdapEnforceChannelBinding'
        $cbStatus = 'NotAssessed'; $cbDetail = "Channel-binding effective state unknown: $($cb.Error)"
        if ($cb.Success -and $null -ne $cb.Value) {
            switch ([int]$cb.Value) {
                2 { $cbStatus='Pass'; $cbDetail='Channel binding is explicitly set to Always.' }
                1 { $cbStatus='Finding'; $cbDetail='Channel binding is WhenSupported: compatible clients are checked, but clients without CBT can still connect. Review compatibility before moving to Always.' }
                0 { $cbStatus='Finding'; $cbDetail='Channel binding is explicitly set to Never.' }
                default { $cbDetail="Unrecognized channel-binding value $($cb.Value); effective behavior requires verification." }
            }
        } elseif ($cb.Success) { $cbDetail='Channel-binding value is absent; effective OS/deployment default was not confirmed.' }
        $rows.Add([pscustomobject]@{Target=$dc; Control='LDAPChannelBinding'; Status=$cbStatus; Severity=$(if ($cbStatus -eq 'Finding') {'Medium'} else {'Info'}); Detail=$cbDetail})
        $ldaps = Test-ADAuditLdapsEndpoint -ComputerName $dc
        $rows.Add([pscustomobject]@{Target=$dc; Control='LDAPSEndpoint'; Status=$ldaps.Status; Severity='Info'; Detail=$ldaps.Detail})
        $connection = $null
        $anonymousStatus = 'NotAssessed'; $anonymousDetail = ''
        try {
            $connection = [System.DirectoryServices.Protocols.LdapConnection]::new("${dc}:389")
            $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
            $connection.SessionOptions.ProtocolVersion = 3
            $connection.Timeout = [TimeSpan]::FromSeconds(5)
            $connection.Bind()
            # A bind/RootDSE result is normal and not evidence of directory disclosure.
            # This bounded read asks only for the DN of one entry under the domain NC.
            $request = [System.DirectoryServices.Protocols.SearchRequest]::new($domainDN,'(objectClass=*)',[System.DirectoryServices.Protocols.SearchScope]::Base,@('distinguishedName'))
            $request.SizeLimit = 1
            $request.TimeLimit = [TimeSpan]::FromSeconds(5)
            $response = [System.DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($request)
            $anonymousStatus = Get-ADAuditAnonymousReadOutcome -EntryCount $response.Entries.Count
            $anonymousDetail = "Explicit anonymous base-scope read of $domainDN returned $($response.Entries.Count) entry(s). This tests the domain object only, not every subtree or attribute."
        } catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
            $code = if ($_.Exception.Response) { [int]$_.Exception.Response.ResultCode } else { -1 }
            $anonymousStatus = Get-ADAuditAnonymousReadOutcome -ErrorCode $code
            $anonymousDetail = "Anonymous domain-object query result $code`: $($_.Exception.Message)"
        } catch [System.DirectoryServices.Protocols.LdapException] {
            $anonymousStatus = Get-ADAuditAnonymousReadOutcome -ErrorCode $_.Exception.ErrorCode
            $anonymousDetail = "Anonymous LDAP test error $($_.Exception.ErrorCode): $($_.Exception.Message)"
        } catch {
            $anonymousStatus = 'NotAssessed'; $anonymousDetail = $_.Exception.Message
        } finally { if ($connection) { $connection.Dispose() } }
        $rows.Add([pscustomobject]@{Target=$dc; Control='AnonymousDomainRead'; Status=$anonymousStatus; Severity=$(if ($anonymousStatus -eq 'Finding') {'Medium'} else {'Info'}); Detail=$anonymousDetail})
    }
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Get-EvidencePath 'ldap_security.csv')
    foreach ($row in $rows) {
        Write-Both "    [$($row.Status)] $($row.Target) / $($row.Control): $($row.Detail)"
        if ($row.Status -eq 'NotAssessed') { Register-ADAuditNotAssessed -Name $row.Control -Switch 'ldapsecurity' -Target $row.Target -Reason $row.Detail }
        if ($row.Status -eq 'Finding') {
            $line = "$($row.Target) / $($row.Control): $($row.Detail)"
            Add-Content -LiteralPath $evidence -Value $line
            Write-Nessus-Finding 'LDAP security configuration' 'KB1101' $line $row.Severity
        }
    }
}
function Invoke-LdapSecurityCheck { Get-LDAPSecurity }
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select ldapsecurity @args
}

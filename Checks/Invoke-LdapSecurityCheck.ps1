<# Read-only LDAP configuration, endpoint TLS and anonymous directory-read checks. #>
function Get-ADAuditLdapSigningAssessment {
    param($Value, [bool]$ModernServer, [bool]$VersionKnown)
    if ($Value -eq 2) { return [pscustomobject]@{Status='Pass'; Detail='Configured: LDAPServerIntegrity explicitly requires signing. Rejection of unsigned authenticated binds was not tested.'} }
    if ($null -eq $Value -or $Value -notin @(0,1,2) -or $ModernServer -or -not $VersionKnown) {
        return [pscustomobject]@{Status='NotAssessed'; Detail='Effective signing cannot be inferred from this value alone. Windows Server 2025 enforcement policy and OS/deployment defaults can take precedence; verify effective policy and unsigned-bind rejection.'}
    }
    [pscustomobject]@{Status='Finding'; Detail="LDAPServerIntegrity=$Value on a pre-2025 server; signing is not required by this setting."}
}

function Get-ADAuditAnonymousReadOutcome {
    param([int]$EntryCount, [Nullable[int]]$ErrorCode, [switch]$TransportFailure, [string]$Diagnostic = '')
    if ($TransportFailure) { return 'NotAssessed' }
    if ($null -ne $ErrorCode) {
        # Authentication/authorization refusals demonstrate only rejection of this query.
        if ($ErrorCode -in @(8,13,48,49,50)) { return 'Rejected' }
        # AD can return operationsError with ERROR_NOT_AUTHENTICATED. Only this
        # precise server diagnostic means the anonymous query required a bind;
        # other operationsError results remain unknown (including missing diagnostics).
        if ($ErrorCode -eq 1 -and $Diagnostic -match '(?im)^\s*000004DC\s*:') { return 'Rejected' }
        return 'NotAssessed'
    }
    if ($EntryCount -gt 0) { return 'Finding' }
    return 'NoDataReturned'
}

function Wait-ADAuditLdapTask {
    param($Task, [datetime]$DeadlineUtc)
    $remaining = [int][Math]::Floor(($DeadlineUtc - [datetime]::UtcNow).TotalMilliseconds)
    if ($remaining -le 0 -or -not $Task.Wait($remaining)) { throw [TimeoutException]::new('LDAP endpoint probe deadline expired.') }
    $Task.GetAwaiter().GetResult()
}

function Read-ADAuditLdapBytes {
    param($Stream, [int]$Count, [datetime]$DeadlineUtc)
    if ($Count -lt 0 -or $Count -gt 16384) { throw 'LDAP response exceeds the bounded probe size.' }
    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = Wait-ADAuditLdapTask -Task ($Stream.ReadAsync($buffer, $offset, $Count - $offset)) -DeadlineUtc $DeadlineUtc
        if ($read -le 0) { throw 'LDAP endpoint closed before returning a complete response.' }
        $offset += $read
    }
    return ,$buffer
}

function Read-ADAuditLdapFrame {
    param($Stream, [datetime]$DeadlineUtc)
    $header = Read-ADAuditLdapBytes -Stream $Stream -Count 2 -DeadlineUtc $DeadlineUtc
    if ($header[0] -ne 0x30) { throw 'Expected an LDAP message sequence.' }
    $length = [int]$header[1]
    if ($length -ge 128) {
        $width = $length -band 0x7f
        if ($width -lt 1 -or $width -gt 2) { throw 'Unsupported or oversized LDAP message length.' }
        $extra = Read-ADAuditLdapBytes -Stream $Stream -Count $width -DeadlineUtc $DeadlineUtc
        $header = [byte[]]($header + $extra)
        $length = 0
        foreach ($value in $extra) { $length = ($length * 256) + $value }
    }
    $payload = Read-ADAuditLdapBytes -Stream $Stream -Count $length -DeadlineUtc $DeadlineUtc
    return ,[byte[]]($header + $payload)
}

function Read-ADAuditLdapBerElement {
    param([byte[]]$Bytes, [ref]$Offset, [int]$Limit, [byte]$Tag)
    $pos = [int]$Offset.Value
    if ($pos + 2 -gt $Limit -or $Limit -gt $Bytes.Length -or $Bytes[$pos] -ne $Tag) { throw 'Unexpected LDAP response structure.' }
    $length = [int]$Bytes[$pos + 1]; $pos += 2
    if ($length -ge 128) {
        $width = $length -band 0x7f
        if ($width -lt 1 -or $width -gt 2 -or $pos + $width -gt $Limit) { throw 'Invalid LDAP response length.' }
        $length = 0
        for ($i = 0; $i -lt $width; $i++) { $length = ($length * 256) + $Bytes[$pos]; $pos++ }
    }
    if ($pos + $length -gt $Limit) { throw 'Truncated LDAP response.' }
    $Offset.Value = $pos + $length
    [pscustomobject]@{ Offset = $pos; Length = $length; End = $pos + $length }
}

function Get-ADAuditStartTlsResponse {
    param([byte[]]$Bytes)
    $position = 0
    $message = Read-ADAuditLdapBerElement $Bytes ([ref]$position) $Bytes.Length 0x30
    if ($position -ne $Bytes.Length) { throw 'Unexpected trailing LDAP message data.' }
    $position = $message.Offset
    $id = Read-ADAuditLdapBerElement $Bytes ([ref]$position) $message.End 0x02
    if ($id.Length -ne 1 -or $Bytes[$id.Offset] -ne 1) { throw 'Unexpected LDAP response message ID.' }
    $response = Read-ADAuditLdapBerElement $Bytes ([ref]$position) $message.End 0x78
    $position = $response.Offset
    $code = Read-ADAuditLdapBerElement $Bytes ([ref]$position) $response.End 0x0a
    if ($code.Length -ne 1) { throw 'Unexpected LDAP result code encoding.' }
    $matchedDn = Read-ADAuditLdapBerElement $Bytes ([ref]$position) $response.End 0x04
    $diagnostic = Read-ADAuditLdapBerElement $Bytes ([ref]$position) $response.End 0x04
    if ($Bytes[$code.Offset] -eq 0 -and $position -lt $response.End) {
        # A successful StartTLS response may carry responseName, but it must
        # identify StartTLS and must not contain a responseValue (RFC 4511).
        $name = Read-ADAuditLdapBerElement $Bytes ([ref]$position) $response.End 0x8a
        if ([Text.Encoding]::ASCII.GetString($Bytes, $name.Offset, $name.Length) -ne '1.3.6.1.4.1.1466.20037' -or $position -ne $response.End) { throw 'Unexpected StartTLS response name or value.' }
    }
    [pscustomobject]@{ Code = [int]$Bytes[$code.Offset]; Diagnostic = [Text.Encoding]::UTF8.GetString($Bytes, $diagnostic.Offset, $diagnostic.Length) }
}

function Get-ADAuditStartTlsRequest {
    # RFC 4511 section 4.14: message ID 1, StartTLS ExtendedRequest, no requestValue.
    # No bind, credentials, or directory modification is sent by this TLS probe.
    return ,[byte[]](@(0x30,0x1d,0x02,0x01,0x01,0x77,0x18,0x80,0x16) + [Text.Encoding]::ASCII.GetBytes('1.3.6.1.4.1.1466.20037'))
}

function New-ADAuditLdapTcpClient { param([Net.IPAddress]$Address) [Net.Sockets.TcpClient]::new($Address.AddressFamily) }
function New-ADAuditLdapTlsStream { param($Stream) [Net.Security.SslStream]::new($Stream, $false) }

function Test-ADAuditLdapTlsAddress {
    param([string]$ComputerName, [string]$Address, [ValidateSet('LDAPS','StartTLS')][string]$Mode, [datetime]$DeadlineUtc)
    $tcp = $null; $tls = $null; $cert = $null
    try {
        $ip = [Net.IPAddress]::Parse($Address)
        $port = if ($Mode -eq 'LDAPS') { 636 } else { 389 }
        $tcp = New-ADAuditLdapTcpClient -Address $ip
        Wait-ADAuditLdapTask -Task ($tcp.ConnectAsync($ip, $port)) -DeadlineUtc $DeadlineUtc | Out-Null
        $stream = $tcp.GetStream()
        if ($Mode -eq 'StartTLS') {
            $request = Get-ADAuditStartTlsRequest
            Wait-ADAuditLdapTask -Task ($stream.WriteAsync($request, 0, $request.Length)) -DeadlineUtc $DeadlineUtc | Out-Null
            $response = Get-ADAuditStartTlsResponse -Bytes (Read-ADAuditLdapFrame -Stream $stream -DeadlineUtc $DeadlineUtc)
            if ($response.Code -ne 0) { throw "StartTLS was not accepted (LDAP result $($response.Code)): $($response.Diagnostic)" }
        }
        # Default validation checks chain trust, validity and the DC FQDN even
        # though the socket connects to an address. No permissive callback exists.
        $tls = New-ADAuditLdapTlsStream -Stream $stream
        Wait-ADAuditLdapTask -Task ($tls.AuthenticateAsClientAsync($ComputerName)) -DeadlineUtc $DeadlineUtc | Out-Null
        if (-not $tls.IsEncrypted -or -not $tls.IsSigned) { throw 'The negotiated TLS stream did not provide encryption and integrity.' }
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($tls.RemoteCertificate)
        [pscustomobject]@{Status='Pass'; Detail="Observed $Mode TLS at ${Address}:$port; certificate chain/name/validity validated against $ComputerName using this host's trust store; protocol=$($tls.SslProtocol); expires=$($cert.NotAfter.ToUniversalTime().ToString('o')); thumbprint=$($cert.Thumbprint)."}
    } finally {
        if ($cert) { $cert.Dispose() }
        if ($tls) { $tls.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }
}

function Test-ADAuditLdapTlsEndpoint {
    param([string]$ComputerName, [string[]]$Addresses, [ValidateSet('LDAPS','StartTLS')][string]$Mode, [ValidateRange(1,60000)][int]$TimeoutMs = 10000)
    $targets = @($Addresses | Where-Object { $_ } | Select-Object -Unique)
    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    $failures = [System.Collections.Generic.List[string]]::new()
    $outcome = 'Unavailable'
    for ($i = 0; $i -lt $targets.Count; $i++) {
        $remaining = [int][Math]::Floor(($deadline - [datetime]::UtcNow).TotalMilliseconds)
        if ($remaining -le 0) { $outcome='Timeout'; $failures.Add('Shared endpoint deadline expired.'); break }
        # Reserve time for every alternate address instead of allowing the first
        # unreachable address to consume the entire endpoint budget.
        $slice = [Math]::Max(1, [Math]::Floor($remaining / ($targets.Count - $i)))
        try {
            $result = Test-ADAuditLdapTlsAddress -ComputerName $ComputerName -Address $targets[$i] -Mode $Mode -DeadlineUtc ([datetime]::UtcNow.AddMilliseconds($slice))
            return [pscustomobject]@{Status='Pass'; Outcome='Assessed'; Detail="$($result.Detail) At least one resolved address validated; this is endpoint availability, not proof that unprotected binds are rejected. Certificate revocation and other resolved addresses were not fully assessed. No credentials were sent."}
        } catch {
            $outcome = Get-ADAuditCoverageOutcome (Get-ADAuditOperationOutcome -ErrorRecord $_)
            $failures.Add("$($targets[$i]): $($_.Exception.Message)")
        }
    }
    [pscustomobject]@{Status='NotAssessed'; Outcome=$outcome; Detail="$Mode endpoint protection was not established within the shared $TimeoutMs ms budget: $($failures -join '; '). This does not prove plaintext LDAP or a missing certificate. No credentials were sent."}
}

function Test-ADAuditLdapsEndpoint {
    param([string]$ComputerName, [string]$Address = '', [string[]]$Addresses)
    if (-not $Addresses) { $Addresses = if ($Address) { @($Address) } else { @((Resolve-ADAuditTargetAddresses $ComputerName).Addresses) } }
    Test-ADAuditLdapTlsEndpoint -ComputerName $ComputerName -Addresses $Addresses -Mode LDAPS
}

function Invoke-ADAuditAnonymousLdapAddress {
    # Self-contained body for the disposable process worker. An explicit anonymous
    # bind sends no account credentials; referrals are disabled to bound scope.
    param([string]$Address, [string]$DomainDN, [int]$TimeoutMs)
    $connection = $null
    $deadline = [datetime]::UtcNow.AddMilliseconds($TimeoutMs)
    try {
        $identifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($Address, 389, $false, $false)
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($identifier)
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
        $connection.Timeout = [TimeSpan]::FromMilliseconds([Math]::Max(1, $TimeoutMs))
        $connection.Bind()
        $remaining = [int][Math]::Floor(($deadline - [datetime]::UtcNow).TotalMilliseconds)
        if ($remaining -le 0) { throw [TimeoutException]::new('Anonymous LDAP deadline expired after bind.') }
        $connection.Timeout = [TimeSpan]::FromMilliseconds($remaining)
        $request = [System.DirectoryServices.Protocols.SearchRequest]::new($DomainDN, '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, @('distinguishedName'))
        $request.SizeLimit = 1
        $request.TimeLimit = [TimeSpan]::FromMilliseconds($remaining)
        $response = [System.DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($request)
        [pscustomobject]@{ EntryCount = $response.Entries.Count; ErrorCode = $null; Diagnostic = ''; Detail = "Anonymous base-scope read of the domain object returned $($response.Entries.Count) entry(s)." }
    } catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.ResultCode } else { -1 }
        $diagnostic = if ($_.Exception.Response) { [string]$_.Exception.Response.ErrorMessage } else { '' }
        [pscustomobject]@{ EntryCount = 0; ErrorCode = $code; Diagnostic = $diagnostic; Detail = "LDAP query result $code`: $($_.Exception.Message); server diagnostic: $diagnostic" }
    } catch [System.DirectoryServices.Protocols.LdapException] {
        $diagnostic = [string]$_.Exception.ServerErrorMessage
        [pscustomobject]@{ EntryCount = 0; ErrorCode = [int]$_.Exception.ErrorCode; Diagnostic = $diagnostic; Detail = "LDAP error $($_.Exception.ErrorCode): $($_.Exception.Message); server diagnostic: $diagnostic" }
    } finally { if ($connection) { $connection.Dispose() } }
}

function Test-ADAuditAnonymousLdapRead {
    param([string]$ComputerName, [string[]]$Addresses, [string]$DomainDN, [ValidateRange(1,60)][int]$TimeoutSec = 10)
    $targets = @($Addresses | Where-Object { $_ } | Select-Object -Unique)
    $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSec)
    $failures = [System.Collections.Generic.List[string]]::new()
    $definition = (Get-Command Invoke-ADAuditAnonymousLdapAddress -CommandType Function).Definition
    $lastOutcome = 'Unavailable'
    for ($i = 0; $i -lt $targets.Count; $i++) {
        $remaining = ($deadline - [datetime]::UtcNow).TotalSeconds
        if ($remaining -lt 1) { $lastOutcome='Timeout'; break }
        $slice = [Math]::Max(1, [int][Math]::Floor($remaining / ($targets.Count - $i)))
        $result = Invoke-ADAuditBoundedOperation -Target $ComputerName -Operation 'anonymous LDAP domain-object read' -Isolation Process -TimeoutSec $slice -Quiet -ScriptBlock {
            param($Body, $Address, $DomainDN, $TimeoutMs)
            Add-Type -AssemblyName System.DirectoryServices.Protocols
            & ([scriptblock]::Create($Body)) -Address $Address -DomainDN $DomainDN -TimeoutMs $TimeoutMs
        } -ArgumentList @($definition, $targets[$i], $DomainDN, ($slice * 1000))
        if ($result.Outcome -ne 'Success') {
            $lastOutcome = Get-ADAuditCoverageOutcome $result.Outcome
            $failures.Add("$($targets[$i]): $($result.Error)")
            continue
        }
        $read = $result.Result
        $status = Get-ADAuditAnonymousReadOutcome -EntryCount $read.EntryCount -ErrorCode $read.ErrorCode -Diagnostic $read.Diagnostic
        if ($status -ne 'NotAssessed') {
            return [pscustomobject]@{ Status=$status; Outcome='Assessed'; Detail="$($targets[$i]): $($read.Detail) Only the domain object's distinguishedName was queried; other subtrees, attributes and address paths were not assessed. A rejected anonymous query does not prove signing or channel-binding enforcement." }
        }
        $failures.Add("$($targets[$i]): $($read.Detail)")
    }
    [pscustomobject]@{Status='NotAssessed'; Outcome=$lastOutcome; Detail="Anonymous domain-object read was inconclusive within the shared $TimeoutSec s operation budget: $($failures -join '; '). No account credentials were sent."}
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
    function Add-LdapEvidenceRow {
        param($Control, $Status, $Severity, $Detail, $EvidenceType, $Outcome = '')
        if (-not $Outcome) { $Outcome = switch ($Status) { 'Excluded' {'Excluded'} 'NotAssessed' {'Unavailable'} 'NotTested' {'NotTested'} default {'Assessed'} } }
        $rows.Add([pscustomobject]@{Target=$dc; Control=$Control; Status=$Status; Severity=$Severity; Detail=$Detail; EvidenceType=$EvidenceType; Outcome=$Outcome})
    }
    foreach ($controller in $dcList) {
        $dc = [string]$controller.HostName
        Write-ADAuditProgress -Activity 'LDAP security' -Status "Assessing $dc"
        if ($script:ADAuditIsolatedClone -and -not (Test-ADAuditLocalComputer -ComputerName $dc)) {
            Add-LdapEvidenceRow 'CloneScope' 'Excluded' 'Info' 'Remote DC configuration and endpoint testing are intentionally excluded by IsolateHost; directory records describe the copied environment.' 'Scope' 'Excluded'
            continue
        }
        $versionKnown = [string]$controller.OperatingSystem -match 'Windows Server (2008|2012|2016|2019|2022|2025)'
        $modern = [string]$controller.OperatingSystem -match 'Windows Server 2025'
        $ntdsKey = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        $sig = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey $ntdsKey -ValueName 'LDAPServerIntegrity'
        $signing = if ($sig.Success) { Get-ADAuditLdapSigningAssessment -Value $sig.Value -ModernServer $modern -VersionKnown $versionKnown } else { [pscustomobject]@{Status='NotAssessed'; Detail="Registry read failed: $($sig.Error)"} }
        Add-LdapEvidenceRow 'LDAPSigning' $signing.Status $(if ($signing.Status -eq 'Finding') {'High'} else {'Info'}) $signing.Detail 'Configuration'
        $cb = Get-ADAuditRemoteRegistryDword -ComputerName $dc -SubKey $ntdsKey -ValueName 'LdapEnforceChannelBinding'
        $cbStatus = 'NotAssessed'; $cbDetail = "Channel-binding effective state unknown: $($cb.Error)"
        if ($cb.Success -and $null -ne $cb.Value) {
            switch ([int]$cb.Value) {
                2 { $cbStatus='Pass'; $cbDetail='Configured: channel binding is explicitly set to Always. Rejection of absent or invalid channel-binding tokens was not tested.' }
                1 { $cbStatus='Finding'; $cbDetail='Configured: channel binding is WhenSupported; the setting permits clients without CBT. Review compatibility before moving to Always. Enforcement was not actively tested.' }
                0 { $cbStatus='Finding'; $cbDetail='Configured: channel binding is explicitly set to Never. Enforcement was not actively tested.' }
                default { $cbDetail="Unrecognized channel-binding value $($cb.Value); effective behavior requires verification." }
            }
        } elseif ($cb.Success) { $cbDetail='Channel-binding value is absent; effective OS/deployment default was not confirmed.' }
        Add-LdapEvidenceRow 'LDAPChannelBinding' $cbStatus $(if ($cbStatus -eq 'Finding') {'Medium'} else {'Info'}) $cbDetail 'Configuration'
        Add-LdapEvidenceRow 'LDAPEnforcement' 'NotTested' 'Info' 'Authenticated unsigned-bind rejection, SASL signing/sealing and CBT enforcement were not actively tested. A TLS handshake or an accepted protected bind does not establish rejection of unprotected binds. LDAP on 389 can use StartTLS or SASL protection.' 'Scope'
        Add-LdapEvidenceRow 'GCTLS' 'NotTested' 'Info' 'Global Catalog TLS on 3269 and certificate revocation are outside this probe scope.' 'Scope'
        # One bounded resolution per DC; a name that does not resolve is recorded without
        # paying the LDAPS and anonymous-bind timeouts, and probes use the resolved address.
        $dcResolution = Resolve-ADAuditTargetAddresses -ComputerName $dc
        if ($dcResolution.Status -ne 'Resolved' -or @($dcResolution.Addresses).Count -eq 0) {
            foreach ($control in @('LDAPSEndpoint','LDAPStartTLS','AnonymousDomainRead')) {
                Add-LdapEvidenceRow $control 'NotAssessed' 'Info' "Endpoint not probed: $($dcResolution.Detail) This does not establish plaintext LDAP or the absence of protection." 'ObservedEndpoint' 'Unreachable'
            }
            continue
        }
        $ldaps = Test-ADAuditLdapsEndpoint -ComputerName $dc -Addresses @($dcResolution.Addresses)
        Add-LdapEvidenceRow 'LDAPSEndpoint' $ldaps.Status 'Info' $ldaps.Detail 'ObservedEndpoint' $ldaps.Outcome
        $startTls = Test-ADAuditLdapTlsEndpoint -ComputerName $dc -Addresses @($dcResolution.Addresses) -Mode StartTLS
        Add-LdapEvidenceRow 'LDAPStartTLS' $startTls.Status 'Info' $startTls.Detail 'ObservedEndpoint' $startTls.Outcome
        $anonymous = Test-ADAuditAnonymousLdapRead -ComputerName $dc -Addresses @($dcResolution.Addresses) -DomainDN $domainDN
        Add-LdapEvidenceRow 'AnonymousDomainRead' $anonymous.Status $(if ($anonymous.Status -eq 'Finding') {'Medium'} else {'Info'}) $anonymous.Detail 'ObservedRead' $anonymous.Outcome
    }
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Get-EvidencePath 'ldap_security.csv')
    foreach ($row in $rows) {
        Write-Both "    [$($row.Status)] $($row.Target) / $($row.Control): $($row.Detail)"
        if ($row.Status -in @('NotAssessed','Excluded')) { Register-ADAuditNotAssessed -Name $row.Control -Switch 'ldapsecurity' -Target $row.Target -Reason $row.Detail -Outcome $row.Outcome }
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

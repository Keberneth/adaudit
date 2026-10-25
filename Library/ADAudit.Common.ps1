<#
    .SYNOPSIS
        ADAudit shared library: run state and helpers used by every check.

    .DESCRIPTION
        Dot-sourced by AdAudit-PS7.ps1 before the check files, so everything here runs in the
        runner's script scope. Holds the output-folder helpers, console logging, the per-check
        failure wrapper (Invoke-AuditCheck / Invoke-AuditStep), "could not assess" tracking
        (Register-ADAuditNotAssessed), the Nessus export, the shared report CSS / navigation,
        module import, CIM / registry helpers, the DSInternals replication cache, the
        bounded remote-collection layer (transport cache, session reuse, cancellable
        workers with deadlines, bounded parallel targets, native command isolation)
        and the optional-dependency installer (-installdeps).

        State lives in $script: variables of the runner (CheckFailures, NotAssessed, output
        directories ...). Check files must call these helpers instead of reaching for the
        variables, and must be dot-sourced (never run with '&'): a child script scope would
        resolve $script: to the wrong place.

    .NOTES
        Functions moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was split.
#>
function Import-ADAuditModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$Required,

        [switch]$PreferWindowsPowerShell
    )

    $loaded = Get-Module -Name $Name | Select-Object -First 1
    if ($loaded) { return $loaded }

    $available = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending
    if (-not $available) {
        if ($Required) { throw "Module '$Name' is not available on this host." }
        return $null
    }

    $attempts = New-Object System.Collections.Generic.List[hashtable]
    if ($script:ADAuditIsPowerShell7Plus -and $PreferWindowsPowerShell) {
        $attempts.Add(@{ UseWindowsPowerShell = $true })
    }

    $attempts.Add(@{})

    if ($script:ADAuditIsPowerShell7Plus) {
        $attempts.Add(@{ SkipEditionCheck = $true })
    }

    if ($script:ADAuditIsPowerShell7Plus -and -not $PreferWindowsPowerShell) {
        $attempts.Add(@{ UseWindowsPowerShell = $true })
    }

    $lastError = $null
    foreach ($attempt in $attempts) {
        try {
            Import-Module -Name $Name @attempt -ErrorAction Stop | Out-Null
            return (Get-Module -Name $Name | Sort-Object Version -Descending | Select-Object -First 1)
        }
        catch {
            $lastError = $_
        }
    }

    if ($Required) {
        if ($lastError) {
            throw "Failed to import module '$Name'. $($lastError.Exception.Message)"
        }
        throw "Failed to import module '$Name'."
    }

    return $null
}

function Get-ADAuditLocalComputerNames {
    # These are local configuration reads, not DNS lookups. Do not treat every
    # FQDN sharing our short name as local: another domain can reuse that name.
    if ($script:ADAuditLocalComputerNameSnapshot) { return @($script:ADAuditLocalComputerNameSnapshot) }
    $names = @('.', 'localhost', '127.0.0.1', '::1', $env:COMPUTERNAME, [Environment]::MachineName)
    try {
        $ip = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $names += $ip.HostName
        if ($ip.HostName -and $ip.DomainName) { $names += "$($ip.HostName).$($ip.DomainName)" }
    } catch { }
    @($names | Where-Object { $_ } | ForEach-Object { $_.Trim().TrimEnd('.').ToLowerInvariant() } | Select-Object -Unique)
}

function Test-ADAuditLocalComputer {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$ComputerName)
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $true }
    (Get-ADAuditLocalComputerNames) -contains $ComputerName.Trim().TrimEnd('.').ToLowerInvariant()
}

function Assert-ADAuditRemoteTargetAllowed {
    param([string]$ComputerName)
    if ($script:ADAuditIsolatedClone -and -not (Test-ADAuditLocalComputer $ComputerName)) {
        throw "Isolated-host mode: remote target '$ComputerName' was intentionally not contacted. Snapshot data cannot establish current production state."
    }
}

# ---------------------------------------------------------------------------
# Bounded remote collection (v9.3)
#
# Every remote operation against one target runs as a cancellable worker with
# an end-to-end deadline that covers name resolution, connection setup, the
# operation itself and any transport fallback. The coordinator (the runner's
# main runspace) owns the waiting loop, so progress keeps updating while a
# remote call blocks, and it alone writes coverage records and evidence files.
#
# Shared state lives in thread-safe collections that are handed to worker
# runspaces by reference:
#   ADAuditTransportCache  - run-scoped, expiring reachability results keyed by
#                            target|protocol|identity. Only genuine connection
#                            failures (Unreachable, Timeout) block a retry.
#   ADAuditCimSessionPool  - reusable CIM sessions keyed by target|protocol.
#
# Isolation modes:
#   Runspace - in-process worker runspace from a small pool (CIM, remoting,
#              event logs). Stop() cancels the cmdlet; a worker that does not
#              stop within the grace period is recorded as orphaned.
#   Process  - out-of-process runspace (pwsh child) for calls that cannot be
#              cancelled in a runspace (UNC access, directory metadata). The
#              child process is killed on deadline expiry.
#   Native tools (dcdiag, repadmin, w32tm) run as separate processes through
#   Invoke-ADAuditNativeCommand and are killed on deadline expiry.
#
# Offline tests set ADAuditWorkerMode = 'InProcess' so command seams and
# Pester mocks apply; deadlines are then not enforced (documented test seam).
# ---------------------------------------------------------------------------
$script:ADAuditTargetTimeoutSec = 60
$script:ADAuditConnectionCacheSec = 300
$script:ADAuditCimOperationTimeoutSec = 15
$script:ADAuditMaxConcurrency = 2
$script:ADAuditHeartbeatSeconds = 5
$script:ADAuditHeartbeatLogSeconds = 30
$script:ADAuditWorkerStopGraceSec = 5
$script:ADAuditWorkerMode = 'Runspace'
$script:ADAuditInWorker = $false
$script:ADAuditLocalComputerNameSnapshot = $null
$script:ADAuditTargetDnsSuffix = ''
$script:ADAuditPreflightTimeoutMs = 3000
# TCP port each transport needs before any session or RPC call can succeed. A closed port is
# recorded as Unreachable after a short probe instead of waiting for the protocol timeout.
# PS remoting is absent: the port check chooses HTTP or HTTPS per DC from its own probes.
$script:ADAuditTransportPorts = @{ Dcom = 135; Rpc = 135; EventLog = 135; Wsman = 5985; Smb = 445; Adws = 9389; Ldap = 389 }
$script:ADAuditResolutionTimeoutMs = 5000
# Run-scoped name resolution results (Resolved with addresses, Unresolvable, or NoAnswer when the
# resolver did not answer in time). Every collector resolves a target once; probes use the address.
$script:ADAuditResolutionCache = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:ADAuditTransportIdentity = "$env:USERDOMAIN\$env:USERNAME"
$script:ADAuditTransportCache = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:ADAuditCimSessionPool = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:ADAuditWorkerRunspaces = [System.Collections.Generic.List[object]]::new()
$script:ADAuditProcessRunspaces = [System.Collections.Generic.List[object]]::new()
$script:ADAuditActiveWorkers = [System.Collections.Generic.List[object]]::new()
$script:ADAuditOrphanedWorkers = [System.Collections.Generic.List[object]]::new()
$script:ADAuditWorkerSessionState = $null
$script:ADAuditWorkerCounter = 0
$script:ADAuditWorkerStats = @{ RunspacesCreated = 0; ProcessesCreated = 0; Timeouts = 0; Orphaned = 0; ProcessesKilled = 0 }
# Functions copied into worker runspaces. Checks may append their own worker-safe
# collectors. Coordinator-only functions (progress, coverage, console, Nessus)
# are deliberately replaced by guards inside workers.
$script:ADAuditWorkerFunctionNames = @(
    'Get-ADAuditTargetKey','Get-ADAuditShortMessage','Test-ADAuditTcpPort','Test-ADAuditTransportPreflight','Test-ADAuditTargetResolvable','Get-ADAuditDnsAddresses','Resolve-ADAuditTargetAddresses','Get-ADAuditProbeAddress','Get-ADAuditLocalComputerNames','Test-ADAuditLocalComputer',
    'Assert-ADAuditRemoteTargetAllowed','Get-ADAuditOperationOutcome','Get-ADAuditTransportKey','Test-ADAuditTransportBlocked',
    'Set-ADAuditTransportResult','Get-ADAuditCimSessionLease','Add-ADAuditCimSession','Complete-ADAuditCimSessionLease',
    'Remove-ADAuditCimSession','Invoke-ADAuditCimRequest','Get-ADAuditCimInstance','Invoke-ADAuditCimMethod',
    'Get-ADAuditRemoteRegistryValue','Get-ADAuditRemoteRegistryDword','New-ADAuditOperationResult','ConvertTo-ADAuditWorkerOutput',
    'Invoke-ADAuditInlineOperation','Invoke-ADAuditBoundedOperation','Receive-ADAuditOperationResult','Convert-ADAuditFileTime'
)
$script:ADAuditWorkerGuardedFunctions = @('Write-Both','Write-ADAuditProgress','Register-ADAuditNotAssessed','Write-Nessus-Finding','Register-AuditFailure')

function Get-ADAuditTargetKey {
    # Cache identity of a target. A bare short name is qualified with the audited domain's
    # DNS suffix (set by Get-Variables) so 'DC2' and 'dc2.example.test' share one entry.
    param([AllowNull()][AllowEmptyString()][string]$ComputerName)
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return '' }
    $key = $ComputerName.Trim().TrimEnd('.').ToLowerInvariant()
    if ($key -notmatch '[.:]' -and $key -notin @('localhost') -and $script:ADAuditTargetDnsSuffix) {
        $key = "$key.$($script:ADAuditTargetDnsSuffix.Trim().TrimEnd('.').ToLowerInvariant())"
    }
    $key
}

function Get-ADAuditShortMessage {
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$MaxLength = 140)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $flat = ($Text -replace '\s+', ' ').Trim()
    if ($flat.Length -le $MaxLength) { return $flat }
    $flat.Substring(0, $MaxLength - 1).TrimEnd() + '…'
}

function Test-ADAuditTcpPort {
    # Bounded TCP connect used as a transport preflight. Resolves through the run cache and
    # connects to the address, so a slow resolver is paid once per target. Never throws.
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][int]$Port, [int]$TimeoutMs = $script:ADAuditPreflightTimeoutMs)
    $resolution = Resolve-ADAuditTargetAddresses -ComputerName $ComputerName
    if ($resolution.Status -eq 'Unresolvable') { return [pscustomobject]@{ Open = $false; Error = $resolution.Detail } }
    $target = if ($resolution.Status -eq 'Resolved') { [string]@($resolution.Addresses)[0] } else { $ComputerName }
    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($target, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return [pscustomobject]@{ Open = $false; Error = "no answer within $TimeoutMs ms" } }
        $client.EndConnect($async)
        [pscustomobject]@{ Open = $true; Error = $null }
    } catch {
        [pscustomobject]@{ Open = $false; Error = $_.Exception.Message }
    } finally {
        if ($client) { try { $client.Close() } catch { } }
    }
}

function Test-ADAuditTransportPreflight {
    # Returns $null when the transport may be attempted. When the transport's TCP port does not
    # answer within the preflight window the failure is recorded for the cache lifetime and the
    # entry is returned, so no protocol timeout is paid for a host that is down.
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][string]$Protocol)
    if (-not $script:ADAuditTransportPorts.ContainsKey($Protocol)) { return $null }
    if (Test-ADAuditLocalComputer $ComputerName) { return $null }
    $port = [int]$script:ADAuditTransportPorts[$Protocol]
    $probe = Test-ADAuditTcpPort -ComputerName $ComputerName -Port $port
    if ($probe.Open) { return $null }
    Set-ADAuditTransportResult -ComputerName $ComputerName -Protocol $Protocol -Outcome 'Unreachable' -Message "TCP $port required by $Protocol did not accept a connection ($($probe.Error)); the $Protocol attempt was not made"
}

function Get-ADAuditDnsAddresses {
    # Single bounded resolver call (OS resolver: hosts file, cache, DNS). Never throws.
    param([Parameter(Mandatory)][string]$ComputerName, [int]$TimeoutMs = $script:ADAuditResolutionTimeoutMs)
    try {
        $task = [System.Net.Dns]::GetHostAddressesAsync($ComputerName)
        if (-not $task.Wait($TimeoutMs)) { return [pscustomobject]@{ Status = 'NoAnswer'; Addresses = @(); Detail = "Name resolution for '$ComputerName' did not answer within $([int]($TimeoutMs / 1000)) s from this host." } }
        $addresses = @($task.Result | Sort-Object { if ($_.AddressFamily -eq 'InterNetwork') { 0 } else { 1 } } | ForEach-Object { $_.IPAddressToString })
        if ($addresses.Count -eq 0) { return [pscustomobject]@{ Status = 'Unresolvable'; Addresses = @(); Detail = "Name '$ComputerName' did not resolve from this host (no addresses returned)." } }
        [pscustomobject]@{ Status = 'Resolved'; Addresses = $addresses; Detail = "Resolved to $($addresses -join ', ')." }
    } catch {
        $message = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        [pscustomobject]@{ Status = 'Unresolvable'; Addresses = @(); Detail = "Name '$ComputerName' did not resolve from this host ($message)." }
    }
}

function Resolve-ADAuditTargetAddresses {
    # Cached resolution for the run. Resolved entries live for the run, an unresolvable name for
    # the connection-cache lifetime and a resolver that did not answer for at most 60 s, so a
    # slow resolver costs one bounded wait per target instead of one per probe.
    param([Parameter(Mandatory)][string]$ComputerName)
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($ComputerName.Trim(), [ref]$ip)) { return [pscustomobject]@{ Status = 'Resolved'; Addresses = @($ip.ToString()); Detail = 'Address literal.' } }
    $key = Get-ADAuditTargetKey $ComputerName
    $entry = $null
    if ($script:ADAuditResolutionCache.TryGetValue($key, [ref]$entry) -and $entry.ExpiresUtc -gt [datetime]::UtcNow) { return $entry }
    $result = Get-ADAuditDnsAddresses -ComputerName $ComputerName
    $ttl = switch ($result.Status) { 'Resolved' { 3600 } 'NoAnswer' { [Math]::Min(60, [Math]::Max(1, [int]$script:ADAuditConnectionCacheSec)) } default { [Math]::Max(1, [int]$script:ADAuditConnectionCacheSec) } }
    $entry = [pscustomobject]@{ Target = $key; Status = $result.Status; Addresses = @($result.Addresses); Detail = $result.Detail; RecordedUtc = [datetime]::UtcNow; ExpiresUtc = [datetime]::UtcNow.AddSeconds($ttl) }
    $script:ADAuditResolutionCache[$key] = $entry
    $entry
}

function Test-ADAuditTargetResolvable {
    # Returns $true (resolved), $false (does not resolve) or $null (resolver did not answer).
    param([Parameter(Mandatory)][string]$ComputerName, [int]$TimeoutMs = 0)
    switch ((Resolve-ADAuditTargetAddresses -ComputerName $ComputerName).Status) {
        'Resolved' { return $true }
        'Unresolvable' { return $false }
        default { return $null }
    }
}

function Get-ADAuditProbeAddress {
    # Address to open sockets against: the first resolved address, else the name itself.
    param([Parameter(Mandatory)][string]$ComputerName)
    $resolution = Resolve-ADAuditTargetAddresses -ComputerName $ComputerName
    if ($resolution.Status -eq 'Resolved' -and @($resolution.Addresses).Count -gt 0) { return [string]@($resolution.Addresses)[0] }
    $ComputerName
}

function Get-ADAuditOperationOutcome {
    # Separates collection outcomes: Success means the collection succeeded, not
    # that a control passed. Only Unreachable and Timeout are cached as
    # connection failures; AccessDenied and Unsupported never mark a host down.
    [CmdletBinding()]
    param([AllowNull()]$ErrorRecord, [string]$Message, [string]$ErrorType)
    $exception = $null
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $exception = $ErrorRecord.Exception }
    elseif ($ErrorRecord -is [System.Exception]) { $exception = $ErrorRecord }
    if ($exception) {
        if (-not $Message) { $Message = [string]$exception.Message }
        if (-not $ErrorType) { $ErrorType = $exception.GetType().FullName }
        $inner = $exception.InnerException
        $depth = 0
        while ($inner -and $depth -lt 5) {
            $Message += ' | ' + $inner.Message
            $ErrorType += '/' + $inner.GetType().Name
            if ($inner -is [System.TimeoutException]) { return 'Timeout' }
            $inner = $inner.InnerException
            $depth++
        }
        if ($exception -is [System.TimeoutException]) { return 'Timeout' }
        if ($exception -is [System.OperationCanceledException] -or $exception -is [System.Management.Automation.PipelineStoppedException]) { return 'Timeout' }
        if ($exception -is [System.UnauthorizedAccessException] -or $exception -is [System.Security.SecurityException]) { return 'AccessDenied' }
    }
    if ($Message -match '(?i)intentionally not contacted|isolated-host mode|outside isolated-host scope') { return 'Excluded' }
    if ($Message -match '(?i)\b(timed out|time-?out|deadline)\b') { return 'Timeout' }
    if ($Message -match '(?i)access (is )?denied|0x80070005|0x80041003|unauthori[sz]ed|E_ACCESSDENIED|logon failure|user name or password is incorrect|not authorized|0x8007052E|0x80070522|credentials (are|were) rejected|authentication (failed|scheme)|TrustedHosts') { return 'AccessDenied' }
    if ($Message -match '(?i)invalid namespace|invalid class|invalid method|not supported|0x80041010|0x80041002|0x8004100E|0x80041011|provider (load failure|not found)|is not recognized as|unsupported') { return 'Unsupported' }
    if ($Message -match '(?i)RPC server is unavailable|0x800706BA|server name cannot be resolved|No such host|name resolution|did not resolve|could not contact|server is not operational|cannot connect|connection (refused|reset|failed|was forcibly)|network path was not found|0x80070035|unreachable|WinRM cannot complete the operation|WS-Management service|0x800706BF|0x80070079|host is down|endpoint mapper|semaphore timeout|no logon servers|ServerDown|LDAP server is unavailable|Unable to contact the server|0x8007274C|actively refused|0x80072EFD|unable to resolve') { return 'Unreachable' }
    if ($ErrorType -match '(?i)SocketException|EndpointNotFound|DirectoryServerDown|ActiveDirectoryServerDown|PSRemotingTransportException|HostNotFound|RpcException') { return 'Unreachable' }
    'Failed'
}

function Get-ADAuditTransportKey {
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][string]$Protocol)
    "$(Get-ADAuditTargetKey $ComputerName)|$($Protocol.ToLowerInvariant())|$($script:ADAuditTransportIdentity.ToLowerInvariant())"
}

function Test-ADAuditTransportBlocked {
    # Returns the unexpired connection-failure entry for target+protocol, else $null.
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][string]$Protocol)
    $key = Get-ADAuditTransportKey -ComputerName $ComputerName -Protocol $Protocol
    $entry = $null
    if (-not $script:ADAuditTransportCache.TryGetValue($key, [ref]$entry)) { return $null }
    if ($entry.ExpiresUtc -le [datetime]::UtcNow) {
        $removed = $null
        [void]$script:ADAuditTransportCache.TryRemove($key, [ref]$removed)
        return $null
    }
    if ($entry.Outcome -in @('Unreachable','Timeout')) { return $entry }
    $null
}

function Set-ADAuditTransportResult {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$Protocol,
        [Parameter(Mandatory)][ValidateSet('Reachable','Unreachable','Timeout')][string]$Outcome,
        [string]$Message = ''
    )
    $now = [datetime]::UtcNow
    $ttl = if ($Outcome -eq 'Reachable') { 3600 } else { [Math]::Max(1, [int]$script:ADAuditConnectionCacheSec) }
    $entry = [pscustomobject]@{
        Target = Get-ADAuditTargetKey $ComputerName; Protocol = $Protocol; Identity = $script:ADAuditTransportIdentity
        Outcome = $Outcome; Message = [string]$Message; RecordedUtc = $now; ExpiresUtc = $now.AddSeconds($ttl)
    }
    $script:ADAuditTransportCache[(Get-ADAuditTransportKey -ComputerName $ComputerName -Protocol $Protocol)] = $entry
    $entry
}

function Get-ADAuditTransportSummary {
    # Diagnostic rows for run metadata: transport outcomes only, never query content.
    @($script:ADAuditTransportCache.Values | Sort-Object Target, Protocol | ForEach-Object {
        [pscustomobject]@{ Target=$_.Target; Protocol=$_.Protocol; Outcome=$_.Outcome; Message=$_.Message; RecordedUtc=$_.RecordedUtc.ToString('o'); ExpiresUtc=$_.ExpiresUtc.ToString('o') }
    })
}

function Get-ADAuditCimSessionLease {
    # Hands out a pooled session for exclusive use; $null when none is free.
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][string]$Protocol)
    $key = "$(Get-ADAuditTargetKey $ComputerName)|$($Protocol.ToLowerInvariant())"
    $entry = $null
    if (-not $script:ADAuditCimSessionPool.TryGetValue($key, [ref]$entry)) { return $null }
    if ([System.Threading.Monitor]::TryEnter($entry)) {
        try {
            if (-not $entry.InUse) { $entry.InUse = $true; return $entry }
        } finally { [System.Threading.Monitor]::Exit($entry) }
    }
    $null
}

function Add-ADAuditCimSession {
    # Registers a new session as in-use; returns the lease. A concurrent worker that
    # already registered a session for the same key keeps its entry and this session
    # becomes a transient lease that is disposed on completion.
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][string]$Protocol, [Parameter(Mandatory)]$Session)
    $key = "$(Get-ADAuditTargetKey $ComputerName)|$($Protocol.ToLowerInvariant())"
    $entry = [pscustomobject]@{ Key=$key; Target=$ComputerName; Protocol=$Protocol; Session=$Session; InUse=$true; Pooled=$true; CreatedUtc=[datetime]::UtcNow }
    if (-not $script:ADAuditCimSessionPool.TryAdd($key, $entry)) { $entry.Pooled = $false }
    $entry
}

function Complete-ADAuditCimSessionLease {
    param([Parameter(Mandatory)]$Lease)
    if ($Lease.Pooled) { $Lease.InUse = $false } else { Remove-ADAuditCimSession -Lease $Lease }
}

function Remove-ADAuditCimSession {
    # Evicts a lease from the pool and disposes its session.
    param([Parameter(Mandatory)]$Lease)
    if ($Lease.Pooled) {
        $removed = $null
        [void]$script:ADAuditCimSessionPool.TryRemove($Lease.Key, [ref]$removed)
    }
    $session = $Lease.Session
    if ($null -eq $session) { return }
    try {
        if ($session.PSObject.Methods['Dispose']) { $session.Dispose() }
        else { $session | Remove-CimSession -ErrorAction SilentlyContinue }
    } catch { }
}

function Clear-ADAuditTransportState {
    # Resets reachability results and disposes pooled sessions. Called at the start
    # and end of a run so target/protocol results never leak into another run.
    foreach ($lease in @($script:ADAuditCimSessionPool.Values)) {
        try { Remove-ADAuditCimSession -Lease $lease } catch { }
    }
    $script:ADAuditCimSessionPool.Clear()
    $script:ADAuditTransportCache.Clear()
    $script:ADAuditResolutionCache.Clear()
}

function New-ADAuditOperationResult {
    param(
        [string]$Target, [string]$Operation, [Parameter(Mandatory)][string]$Outcome, [string]$Transport = '',
        [datetime]$StartedUtc = [datetime]::UtcNow, [datetime]$FinishedUtc = [datetime]::UtcNow,
        [AllowNull()]$Result = $null, [string]$Error = '', [string]$ErrorType = '', [AllowNull()]$ErrorRecord = $null,
        [string]$Isolation = 'Inline', [int]$TimeoutSec = 0
    )
    [pscustomobject]@{
        PSTypeName = 'ADAudit.OperationResult'
        Target = $Target; Operation = $Operation; Outcome = $Outcome; Transport = $Transport
        StartedUtc = $StartedUtc; FinishedUtc = $FinishedUtc; ElapsedSeconds = [Math]::Round(($FinishedUtc - $StartedUtc).TotalSeconds, 3)
        Result = $Result; Error = $Error; ErrorType = $ErrorType; ErrorRecord = $ErrorRecord; Isolation = $Isolation; TimeoutSec = $TimeoutSec
    }
}

function ConvertTo-ADAuditWorkerOutput {
    param([AllowNull()]$Output)
    if ($null -eq $Output) { return $null }
    $items = @($Output)
    if ($items.Count -eq 0) { return $null }
    if ($items.Count -eq 1) { return $items[0] }
    return ,$items
}

function Invoke-ADAuditInlineOperation {
    # Synchronous execution with the same typed result as a worker. Used inside
    # workers (already isolated) and in the InProcess offline test mode.
    param([Parameter(Mandatory)][scriptblock]$ScriptBlock, [object[]]$ArgumentList = @(), [string]$Target = '', [string]$Operation = '', [int]$TimeoutSec = 0, [string]$Isolation = 'Inline')
    $started = [datetime]::UtcNow
    # Non-terminating collection errors must fail the operation, never return empty data.
    $ErrorActionPreference = 'Stop'
    try {
        $output = @(& $ScriptBlock @ArgumentList)
        New-ADAuditOperationResult -Target $Target -Operation $Operation -Outcome 'Success' -StartedUtc $started -Result (ConvertTo-ADAuditWorkerOutput $output) -Isolation $Isolation -TimeoutSec $TimeoutSec
    } catch {
        $outcome = Get-ADAuditOperationOutcome -ErrorRecord $_
        New-ADAuditOperationResult -Target $Target -Operation $Operation -Outcome $outcome -StartedUtc $started -Error $_.Exception.Message -ErrorType $_.Exception.GetType().FullName -ErrorRecord $_ -Isolation $Isolation -TimeoutSec $TimeoutSec
    }
}

function Get-ADAuditWorkerSessionState {
    if ($script:ADAuditWorkerSessionState) { return $script:ADAuditWorkerSessionState }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    foreach ($name in @($script:ADAuditWorkerFunctionNames | Select-Object -Unique)) {
        $command = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) { $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, $command.Definition)) }
    }
    foreach ($name in $script:ADAuditWorkerGuardedFunctions) {
        $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($name, "throw 'ADAudit worker: $name is coordinator-only. Return data from the worker instead.'"))
    }
    $variables = @{
        ADAuditInWorker = $true; ADAuditWorkerMode = 'Runspace'; ADAuditIsWindows = $script:ADAuditIsWindows
        ADAuditIsolatedClone = [bool]$script:ADAuditIsolatedClone; ADAuditTransportCache = $script:ADAuditTransportCache
        ADAuditCimSessionPool = $script:ADAuditCimSessionPool; ADAuditConnectionCacheSec = $script:ADAuditConnectionCacheSec
        ADAuditTargetTimeoutSec = $script:ADAuditTargetTimeoutSec; ADAuditCimOperationTimeoutSec = $script:ADAuditCimOperationTimeoutSec
        ADAuditTransportIdentity = $script:ADAuditTransportIdentity; ADAuditLocalComputerNameSnapshot = @(Get-ADAuditLocalComputerNames)
        ADAuditTargetDnsSuffix = [string]$script:ADAuditTargetDnsSuffix; ADAuditPreflightTimeoutMs = $script:ADAuditPreflightTimeoutMs; ADAuditTransportPorts = $script:ADAuditTransportPorts
        ADAuditResolutionCache = $script:ADAuditResolutionCache; ADAuditResolutionTimeoutMs = $script:ADAuditResolutionTimeoutMs
        ErrorActionPreference = 'Stop'; ProgressPreference = 'SilentlyContinue'
    }
    foreach ($entry in $variables.GetEnumerator()) {
        $iss.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($entry.Key, $entry.Value, 'ADAudit worker state'))
    }
    $script:ADAuditWorkerSessionState = $iss
    $iss
}

function Get-ADAuditWorkerRunspace {
    param([ValidateSet('Runspace','Process')][string]$Isolation = 'Runspace')
    # Assign inside the branches: an if-expression would enumerate the list into the pipeline.
    if ($Isolation -eq 'Process') { $pool = $script:ADAuditProcessRunspaces } else { $pool = $script:ADAuditWorkerRunspaces }
    while ($pool.Count -gt 0) {
        $candidate = $pool[0]
        $pool.RemoveAt(0)
        if ($candidate.Runspace.RunspaceStateInfo.State -eq 'Opened' -and $candidate.Runspace.RunspaceAvailability -eq 'Available') { return $candidate }
        try { $candidate.Runspace.Dispose() } catch { }
    }
    $script:ADAuditWorkerCounter++
    if ($Isolation -eq 'Process') {
        $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateOutOfProcessRunspace($null)
        $runspace.Name = "ADAudit-ProcessWorker-$($script:ADAuditWorkerCounter)"
        $runspace.Open()
        $processId = $null
        $probe = [powershell]::Create()
        try {
            $probe.Runspace = $runspace
            $processId = [int](@($probe.AddScript('$PID').Invoke())[0])
        } finally { $probe.Dispose() }
        $script:ADAuditWorkerStats.ProcessesCreated++
        return [pscustomobject]@{ Runspace = $runspace; Isolation = 'Process'; ProcessId = $processId }
    }
    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace((Get-ADAuditWorkerSessionState))
    $runspace.Name = "ADAudit-Worker-$($script:ADAuditWorkerCounter)"
    $runspace.ThreadOptions = 'ReuseThread'
    $runspace.Open()
    $script:ADAuditWorkerStats.RunspacesCreated++
    [pscustomobject]@{ Runspace = $runspace; Isolation = 'Runspace'; ProcessId = $null }
}

function Push-ADAuditWorkerRunspace {
    param([Parameter(Mandatory)]$Slot)
    if ($Slot.Runspace.RunspaceStateInfo.State -ne 'Opened') { try { $Slot.Runspace.Dispose() } catch { }; return }
    if ($Slot.Isolation -eq 'Process') { $script:ADAuditProcessRunspaces.Add($Slot) } else { $script:ADAuditWorkerRunspaces.Add($Slot) }
}

function Start-ADAuditWorker {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock, [object[]]$ArgumentList = @(), [string]$Target = '', [string]$Operation = '',
        [int]$TimeoutSec = $script:ADAuditTargetTimeoutSec, [ValidateSet('Runspace','Process')][string]$Isolation = 'Runspace'
    )
    $slot = Get-ADAuditWorkerRunspace -Isolation $Isolation
    $powershell = [powershell]::Create()
    $powershell.Runspace = $slot.Runspace
    # One script, no AddStatement: a second pipeline statement never completed under PS 7.6
    # in testing. ErrorActionPreference is forced inside the script so non-terminating
    # collection errors become failures instead of empty successful results.
    $script = "`$ErrorActionPreference = 'Stop'`n& { $($ScriptBlock.ToString()) } @args"
    [void]$powershell.AddScript($script)
    foreach ($argument in @($ArgumentList)) { [void]$powershell.AddArgument($argument) }
    $started = [datetime]::UtcNow
    $handle = [pscustomobject]@{
        Target = $Target; Operation = $Operation; Isolation = $Isolation; Slot = $slot; PowerShell = $powershell
        Async = $null; StartedUtc = $started; DeadlineUtc = $started.AddSeconds([Math]::Max(1, $TimeoutSec)); TimeoutSec = $TimeoutSec; State = 'Running'
    }
    $handle.Async = $powershell.BeginInvoke()
    $script:ADAuditActiveWorkers.Add($handle)
    $handle
}

function Resolve-ADAuditWorkerException {
    # EndInvoke surfaces a worker failure wrapped in RuntimeException/MethodInvocationException,
    # and a cmdlet error stopped by ErrorActionPreference arrives as ActionPreferenceStopException.
    # Unwrap to the original exception (CimException, SocketException, ItemNotFound ...) and keep
    # the original error record (with its FullyQualifiedErrorId) when one is available.
    param([Parameter(Mandatory)][System.Exception]$Exception, [string]$Target = '')
    $record = $null
    for ($depth = 0; $depth -lt 8; $depth++) {
        if ($Exception -is [System.Management.Automation.ActionPreferenceStopException] -and $Exception.ErrorRecord -and $Exception.ErrorRecord.Exception) {
            $record = $Exception.ErrorRecord
            $Exception = $record.Exception
            continue
        }
        $wrapper = $Exception -is [System.Management.Automation.MethodInvocationException] -or $Exception.GetType() -eq [System.Management.Automation.RuntimeException]
        if ($wrapper -and $Exception.InnerException) {
            $Exception = $Exception.InnerException
            $record = $null
            continue
        }
        break
    }
    if (-not $record) { $record = [System.Management.Automation.ErrorRecord]::new($Exception, 'ADAuditWorkerFailure', [System.Management.Automation.ErrorCategory]::NotSpecified, $Target) }
    [pscustomobject]@{ Exception = $Exception; Record = $record }
}

function Complete-ADAuditWorker {
    # Collects a finished worker and returns its runspace to the pool.
    param([Parameter(Mandatory)]$Handle)
    $result = $null
    try {
        $output = $Handle.PowerShell.EndInvoke($Handle.Async)
        if ($Handle.PowerShell.Streams.Error.Count -gt 0) {
            $record = $Handle.PowerShell.Streams.Error[0]
            $result = New-ADAuditOperationResult -Target $Handle.Target -Operation $Handle.Operation -Outcome (Get-ADAuditOperationOutcome -ErrorRecord $record) -StartedUtc $Handle.StartedUtc -Error $record.Exception.Message -ErrorType $record.Exception.GetType().FullName -ErrorRecord $record -Isolation $Handle.Isolation -TimeoutSec $Handle.TimeoutSec
        } else {
            $result = New-ADAuditOperationResult -Target $Handle.Target -Operation $Handle.Operation -Outcome 'Success' -StartedUtc $Handle.StartedUtc -Result (ConvertTo-ADAuditWorkerOutput @($output)) -Isolation $Handle.Isolation -TimeoutSec $Handle.TimeoutSec
        }
    } catch {
        $resolved = Resolve-ADAuditWorkerException -Exception $_.Exception -Target $Handle.Target
        $exception = $resolved.Exception
        $result = New-ADAuditOperationResult -Target $Handle.Target -Operation $Handle.Operation -Outcome (Get-ADAuditOperationOutcome -ErrorRecord $resolved.Record) -StartedUtc $Handle.StartedUtc -Error $exception.Message -ErrorType $exception.GetType().FullName -ErrorRecord $resolved.Record -Isolation $Handle.Isolation -TimeoutSec $Handle.TimeoutSec
    } finally {
        $Handle.State = 'Completed'
        try { $Handle.PowerShell.Dispose() } catch { }
        [void]$script:ADAuditActiveWorkers.Remove($Handle)
        Push-ADAuditWorkerRunspace -Slot $Handle.Slot
    }
    $result
}

function Stop-ADAuditWorker {
    # Cancels a running worker. Returns a Timeout result; the runspace is never
    # reused. A worker that ignores Stop within the grace period is tracked as an
    # orphan and reported in run metadata; a process worker is killed.
    param([Parameter(Mandatory)]$Handle, [string]$Reason = 'Deadline expired', [int]$GraceSec = $script:ADAuditWorkerStopGraceSec)
    $Handle.State = 'Stopping'
    $script:ADAuditWorkerStats.Timeouts++
    try { [void]$Handle.PowerShell.BeginStop($null, $null) } catch { }
    $graceEnd = [datetime]::UtcNow.AddSeconds([Math]::Max(0, $GraceSec))
    while ([datetime]::UtcNow -lt $graceEnd -and $Handle.PowerShell.InvocationStateInfo.State -in @('Running','Stopping')) { Start-Sleep -Milliseconds 50 }
    $stopped = $Handle.PowerShell.InvocationStateInfo.State -notin @('Running','Stopping')
    if ($Handle.Isolation -eq 'Process' -and $Handle.Slot.ProcessId) {
        try { Stop-Process -Id $Handle.Slot.ProcessId -Force -ErrorAction Stop; $script:ADAuditWorkerStats.ProcessesKilled++ } catch { }
        $stopped = $true
    }
    if ($stopped) {
        try { $Handle.PowerShell.Dispose() } catch { }
        try { $Handle.Slot.Runspace.Dispose() } catch { }
        $Handle.State = 'Stopped'
    } else {
        $script:ADAuditWorkerStats.Orphaned++
        $Handle.State = 'Orphaned'
        $script:ADAuditOrphanedWorkers.Add([pscustomobject]@{ Target=$Handle.Target; Operation=$Handle.Operation; Reason=$Reason; Handle=$Handle; RecordedUtc=[datetime]::UtcNow })
        try { $Handle.Slot.Runspace.CloseAsync() } catch { }
    }
    [void]$script:ADAuditActiveWorkers.Remove($Handle)
    $elapsed = [Math]::Round(([datetime]::UtcNow - $Handle.StartedUtc).TotalSeconds, 1)
    $message = "Deadline of $($Handle.TimeoutSec) s expired for $($Handle.Operation) on '$($Handle.Target)' after $elapsed s ($Reason). The worker was $(if ($Handle.State -eq 'Stopped') { 'stopped' } else { 'abandoned and recorded as orphaned' }); completed results for other targets are retained."
    New-ADAuditOperationResult -Target $Handle.Target -Operation $Handle.Operation -Outcome 'Timeout' -StartedUtc $Handle.StartedUtc -Error $message -ErrorType 'System.TimeoutException' -Isolation $Handle.Isolation -TimeoutSec $Handle.TimeoutSec
}

function Write-ADAuditWaitHeartbeat {
    param([string]$Activity, [object[]]$Handles, [string]$Summary = '', [double]$PercentComplete = -1)
    $now = [datetime]::UtcNow
    $waits = @($Handles | ForEach-Object { "$($_.Target) $([int]($now - $_.StartedUtc).TotalSeconds)/$($_.TimeoutSec) s" })
    $status = if ($Summary) { "$Summary; waiting for response: $($waits -join ', ')" } else { "Waiting for response: $($waits -join ', ')" }
    if (-not $Activity) { $Activity = if ($script:ADAuditProgressLastActivity) { $script:ADAuditProgressLastActivity } else { 'Remote collection' } }
    Write-ADAuditProgress -Activity $Activity -Status $status -PercentComplete $PercentComplete -Heartbeat
}

function Invoke-ADAuditBoundedOperation {
    <#
    .SYNOPSIS
        Runs one cancellable collection operation against one target with an end-to-end
        deadline, emitting waiting heartbeats while the call blocks.
    .OUTPUTS
        ADAudit.OperationResult with Outcome Success | Timeout | Unreachable | AccessDenied |
        Unsupported | Excluded | Failed. Use Receive-ADAuditOperationResult to unwrap or throw.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [string]$Target = '',
        [string]$Operation = 'remote collection',
        [int]$TimeoutSec = 0,
        [string]$Activity = '',
        [double]$PercentComplete = -1,
        [ValidateSet('Runspace','Process')][string]$Isolation = 'Runspace',
        [string]$Transport = '',
        [switch]$Quiet
    )
    if ($TimeoutSec -le 0) { $TimeoutSec = $script:ADAuditTargetTimeoutSec }
    if ($Transport -and $Target) {
        $blocked = Test-ADAuditTransportBlocked -ComputerName $Target -Protocol $Transport
        if ($blocked) {
            $age = [int]([datetime]::UtcNow - $blocked.RecordedUtc).TotalSeconds
            $message = "$Operation on '$Target' was not attempted: a $Transport connection failure ($($blocked.Outcome)) was recorded $age s ago ($(Get-ADAuditShortMessage $blocked.Message)). Another attempt is allowed after $($blocked.ExpiresUtc.ToLocalTime().ToString('HH:mm:ss'))."
            return New-ADAuditOperationResult -Target $Target -Operation $Operation -Outcome $blocked.Outcome -Transport $Transport -Error $message -ErrorType 'ADAudit.CachedTransportFailure' -Isolation 'Skipped' -TimeoutSec $TimeoutSec
        }
        $preflight = Test-ADAuditTransportPreflight -ComputerName $Target -Protocol $Transport
        if ($preflight) {
            return New-ADAuditOperationResult -Target $Target -Operation $Operation -Outcome 'Unreachable' -Transport $Transport -Error "$Operation on '$Target' was not attempted: $($preflight.Message)." -ErrorType 'ADAudit.TransportPreflightFailure' -Isolation 'Skipped' -TimeoutSec $TimeoutSec
        }
    }
    if ($script:ADAuditInWorker -or $script:ADAuditWorkerMode -eq 'InProcess') {
        $result = Invoke-ADAuditInlineOperation -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -Target $Target -Operation $Operation -TimeoutSec $TimeoutSec
    } else {
        $handle = Start-ADAuditWorker -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -Target $Target -Operation $Operation -TimeoutSec $TimeoutSec -Isolation $Isolation
        $result = $null
        try {
            $nextBeat = [datetime]::UtcNow.AddSeconds($script:ADAuditHeartbeatSeconds)
            while (-not $handle.Async.IsCompleted) {
                [void]$handle.Async.AsyncWaitHandle.WaitOne(250)
                if ($handle.Async.IsCompleted) { break }
                $now = [datetime]::UtcNow
                if ($now -ge $handle.DeadlineUtc) {
                    $result = Stop-ADAuditWorker -Handle $handle
                    break
                }
                if (-not $Quiet -and $now -ge $nextBeat) {
                    Write-ADAuditWaitHeartbeat -Activity $Activity -Handles @($handle) -PercentComplete $PercentComplete
                    $nextBeat = $now.AddSeconds($script:ADAuditHeartbeatSeconds)
                }
            }
            if (-not $result) { $result = Complete-ADAuditWorker -Handle $handle }
        } catch {
            if ($handle.State -eq 'Running') { [void](Stop-ADAuditWorker -Handle $handle -Reason 'Coordinator interrupted') }
            throw
        }
    }
    if ($Transport -and $Target) {
        if ($result.Outcome -eq 'Success') { [void](Set-ADAuditTransportResult -ComputerName $Target -Protocol $Transport -Outcome 'Reachable') }
        elseif ($result.Outcome -in @('Unreachable','Timeout')) { [void](Set-ADAuditTransportResult -ComputerName $Target -Protocol $Transport -Outcome $result.Outcome -Message $result.Error) }
        $result.Transport = $Transport
    }
    $result
}

function Receive-ADAuditOperationResult {
    # Unwraps a successful result or throws the preserved error so callers keep their
    # existing catch/Register-ADAuditNotAssessed handling.
    param([Parameter(Mandatory)]$Result)
    switch ($Result.Outcome) {
        'Success' { return $Result.Result }
        'Timeout' { throw [System.TimeoutException]::new($Result.Error) }
        default {
            if ($Result.ErrorRecord -is [System.Management.Automation.ErrorRecord]) { throw $Result.ErrorRecord }
            throw $Result.Error
        }
    }
}

function Get-ADAuditCoverageOutcome {
    # Maps an operation outcome onto the coverage-record outcome set.
    param([string]$OperationOutcome)
    if ($OperationOutcome -in @('Timeout','Unreachable','AccessDenied','Unsupported','Excluded')) { return $OperationOutcome }
    'Unavailable'
}

function Invoke-ADAuditEventLogQuery {
    # Bounded event-log read. Returns an array of live records (empty when no event
    # matched) and throws on transport or access failure, so an unreadable log never
    # becomes an empty successful result. Local logs are read inline.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][hashtable]$FilterHashtable,
        [int]$MaxEvents = 0,
        [string]$Activity = '',
        [double]$PercentComplete = -1
    )
    Assert-ADAuditRemoteTargetAllowed -ComputerName $ComputerName
    $parameters = @{ FilterHashtable = $FilterHashtable; ErrorAction = 'Stop' }
    if ($MaxEvents -gt 0) { $parameters.MaxEvents = $MaxEvents }
    $local = Test-ADAuditLocalComputer $ComputerName
    if (-not $local) { $parameters.ComputerName = $ComputerName }
    $query = {
        param($Parameters)
        try { ,@(Get-WinEvent @Parameters) }
        catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { ,@() } else { throw } }
    }
    # Workers return the record set as one array object; emit the records here so a
    # caller's @(...) receives the rows (zero, one or many), never a nested array.
    if ($local) { $records = & $query $parameters; return @($records) }
    $logNames = @($FilterHashtable['LogName']) -join ', '
    $result = Invoke-ADAuditBoundedOperation -Target $ComputerName -Operation "event log $logNames" -Transport 'EventLog' -Activity $Activity -PercentComplete $PercentComplete -ScriptBlock $query -ArgumentList @(,$parameters)
    $records = Receive-ADAuditOperationResult -Result $result
    @($records)
}

function Invoke-ADAuditParallelTargets {
    <#
    .SYNOPSIS
        Runs one worker per target with bounded concurrency and per-target deadlines.
        Workers receive ($Target, $Context) and return data; this coordinator merges the
        typed results in input order and owns all progress output. Callers register
        coverage and write evidence from the returned results. MaxConcurrency 1 is the
        serial troubleshooting mode and produces identical results. In isolated-host
        mode nonlocal targets are recorded as Excluded before any worker starts.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Targets = @(),
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [hashtable]$Context = @{},
        [string]$Operation = 'collection',
        [string]$Activity = 'Remote collection',
        [string]$UnitName = 'DC',
        [string]$WorkDescription = '',
        [scriptblock]$TargetLabel = { param($t) [string]$t },
        [scriptblock]$TargetHost = $null,
        [int]$MaxConcurrency = $script:ADAuditMaxConcurrency,
        [int]$TimeoutSec = 0,
        [double]$PercentBase = 0,
        [double]$PercentSpan = 100,
        [ValidateSet('Runspace','Process')][string]$Isolation = 'Runspace'
    )
    $total = $Targets.Count
    if ($total -eq 0) { return @() }
    if ($TimeoutSec -le 0) { $TimeoutSec = $script:ADAuditTargetTimeoutSec }
    if ($MaxConcurrency -lt 1) { $MaxConcurrency = 1 }
    $results = New-Object object[] $total
    $labels = New-Object string[] $total
    $pending = [System.Collections.Generic.List[int]]::new()
    $excluded = 0
    for ($i = 0; $i -lt $total; $i++) {
        $labels[$i] = [string](& $TargetLabel $Targets[$i])
        $hostName = if ($TargetHost) { [string](& $TargetHost $Targets[$i]) } else { $labels[$i] }
        if ($script:ADAuditIsolatedClone -and $hostName -and -not (Test-ADAuditLocalComputer $hostName)) {
            $results[$i] = New-ADAuditOperationResult -Target $labels[$i] -Operation $Operation -Outcome 'Excluded' -Error "Isolated-host mode: remote target '$hostName' was intentionally not contacted. Snapshot data cannot establish current production state." -ErrorType 'ADAudit.IsolatedHostExclusion' -Isolation 'Skipped' -TimeoutSec $TimeoutSec
            $excluded++
        } else { $pending.Add($i) }
    }
    $completed = $excluded
    $work = if ($WorkDescription) { " ($WorkDescription)" } else { '' }
    $excludedNote = if ($excluded) { "; $excluded excluded" } else { '' }
    $percentOf = { param($done) [int]($PercentBase + $PercentSpan * $done / [Math]::Max(1, $total)) }
    $outcomeLabel = {
        param($r)
        switch ($r.Outcome) { 'Success' { 'queried' } 'Timeout' { 'not assessed (deadline expired)' } default { 'not assessed' } }
    }
    if ($script:ADAuditInWorker -or $script:ADAuditWorkerMode -eq 'InProcess') {
        foreach ($i in $pending) {
            Write-ADAuditProgress -Activity $Activity -Status "$UnitName $($i + 1)/${total}: querying $($labels[$i])$work; $completed ${UnitName}s completed$excludedNote" -PercentComplete (& $percentOf $completed) -Force
            $results[$i] = Invoke-ADAuditInlineOperation -ScriptBlock $ScriptBlock -ArgumentList @($Targets[$i], $Context) -Target $labels[$i] -Operation $Operation -TimeoutSec $TimeoutSec
            $completed++
            Write-ADAuditProgress -Activity $Activity -Status "$UnitName $completed/${total}: $($labels[$i]) $(& $outcomeLabel $results[$i])" -PercentComplete (& $percentOf $completed)
        }
        return ,$results
    }
    $running = @{}
    $next = 0
    $nextBeat = [datetime]::UtcNow.AddSeconds($script:ADAuditHeartbeatSeconds)
    try {
        while ($true) {
            while ($running.Count -lt $MaxConcurrency -and $next -lt $pending.Count) {
                $i = $pending[$next]
                Write-ADAuditProgress -Activity $Activity -Status "$UnitName $($i + 1)/${total}: querying $($labels[$i])$work; $completed ${UnitName}s completed$excludedNote" -PercentComplete (& $percentOf $completed) -Force
                $running[$i] = Start-ADAuditWorker -ScriptBlock $ScriptBlock -ArgumentList @($Targets[$i], $Context) -Target $labels[$i] -Operation $Operation -TimeoutSec $TimeoutSec -Isolation $Isolation
                $next++
            }
            if ($running.Count -eq 0) { break }
            $handles = @($running.Values)
            $waitHandles = [System.Threading.WaitHandle[]]@($handles | ForEach-Object { $_.Async.AsyncWaitHandle })
            [void][System.Threading.WaitHandle]::WaitAny($waitHandles, 250)
            $now = [datetime]::UtcNow
            foreach ($index in @($running.Keys)) {
                $handle = $running[$index]
                $result = $null
                if ($handle.Async.IsCompleted) { $result = Complete-ADAuditWorker -Handle $handle }
                elseif ($now -ge $handle.DeadlineUtc) { $result = Stop-ADAuditWorker -Handle $handle }
                if ($result) {
                    $results[$index] = $result
                    $running.Remove($index)
                    $completed++
                    Write-ADAuditProgress -Activity $Activity -Status "$UnitName $completed/${total}: $($handle.Target) $(& $outcomeLabel $result)" -PercentComplete (& $percentOf $completed)
                }
            }
            if ($running.Count -gt 0 -and $now -ge $nextBeat) {
                Write-ADAuditWaitHeartbeat -Activity $Activity -Handles @($running.Values) -Summary "$completed/$total ${UnitName}s completed" -PercentComplete (& $percentOf $completed)
                $nextBeat = $now.AddSeconds($script:ADAuditHeartbeatSeconds)
            }
        }
    } catch {
        foreach ($handle in @($running.Values)) { if ($handle.State -eq 'Running') { [void](Stop-ADAuditWorker -Handle $handle -Reason 'Coordinator interrupted') } }
        throw
    }
    ,$results
}
function Invoke-ADAuditNativeCommand {
    <#
    .SYNOPSIS
        Runs a native diagnostic tool (dcdiag, repadmin, w32tm) as a separate process with
        an enforceable deadline. Output is captured; the process is killed on expiry.
        A PowerShell function with the tool's name is used as an offline command seam.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSec = 0,
        [string]$Target = '',
        [string]$Operation = '',
        [string]$Activity = '',
        [double]$PercentComplete = -1,
        [string]$Transport = ''
    )
    if (-not $Operation) { $Operation = "$FilePath $($ArgumentList -join ' ')".Trim() }
    if ($TimeoutSec -le 0) { $TimeoutSec = $script:ADAuditTargetTimeoutSec }
    $started = [datetime]::UtcNow
    $finish = {
        param($Outcome, $ExitCode, $Output, $Error, $Record = $true)
        $r = New-ADAuditOperationResult -Target $Target -Operation $Operation -Outcome $Outcome -Transport $Transport -StartedUtc $started -Result $Output -Error $Error -Isolation $(if ($Record) { 'Process' } else { 'Skipped' }) -TimeoutSec $TimeoutSec
        $r | Add-Member -NotePropertyName ExitCode -NotePropertyValue $ExitCode
        $r | Add-Member -NotePropertyName Output -NotePropertyValue ([string]$Output)
        # A cached skip or a preflight failure is already recorded; recording it again would
        # nest the skip text into the cache message and extend the expiry on every hit.
        if ($Record -and $Transport -and $Target) {
            if ($Outcome -eq 'Success') { [void](Set-ADAuditTransportResult -ComputerName $Target -Protocol $Transport -Outcome 'Reachable') }
            elseif ($Outcome -in @('Unreachable','Timeout')) { [void](Set-ADAuditTransportResult -ComputerName $Target -Protocol $Transport -Outcome $Outcome -Message $Error) }
        }
        $r
    }
    if ($Transport -and $Target) {
        $blocked = Test-ADAuditTransportBlocked -ComputerName $Target -Protocol $Transport
        if ($blocked) {
            $age = [int]([datetime]::UtcNow - $blocked.RecordedUtc).TotalSeconds
            return (& $finish $blocked.Outcome $null '' "$Operation on '$Target' was not attempted: a $Transport connection failure ($($blocked.Outcome)) was recorded $age s ago ($(Get-ADAuditShortMessage $blocked.Message)). Another attempt is allowed after $($blocked.ExpiresUtc.ToLocalTime().ToString('HH:mm:ss'))." $false)
        }
        $preflight = Test-ADAuditTransportPreflight -ComputerName $Target -Protocol $Transport
        if ($preflight) {
            return (& $finish 'Unreachable' $null '' "$Operation on '$Target' was not attempted: $($preflight.Message)." $false)
        }
    }
    $seam = Get-Command -Name $FilePath -CommandType Function -ErrorAction SilentlyContinue
    if ($seam) {
        try {
            $global:LASTEXITCODE = 0
            $text = (& $seam @ArgumentList 2>&1 | Out-String)
            return (& $finish 'Success' $global:LASTEXITCODE $text '')
        } catch {
            return (& $finish (Get-ADAuditOperationOutcome -ErrorRecord $_) $null '' $_.Exception.Message)
        }
    }
    $executable = if ([System.IO.Path]::GetExtension($FilePath)) { $FilePath } else { "$FilePath.exe" }
    $application = Get-Command -Name $executable -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $application) { return (& $finish 'Unsupported' $null '' "$executable was not found on this host.") }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new($application.Source)
    $startInfo.Arguments = (@($ArgumentList | ForEach-Object { if ($_ -match '\s|"') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    try { $startInfo.StandardOutputEncoding = [Console]::OutputEncoding; $startInfo.StandardErrorEncoding = [Console]::OutputEncoding } catch { }
    $process = $null
    try {
        $process = [System.Diagnostics.Process]::Start($startInfo)
    } catch {
        return (& $finish 'Failed' $null '' "Could not start ${executable}: $($_.Exception.Message)")
    }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $deadline = $started.AddSeconds($TimeoutSec)
    $nextBeat = [datetime]::UtcNow.AddSeconds($script:ADAuditHeartbeatSeconds)
    $timedOut = $false
    try {
        while (-not $process.WaitForExit(250)) {
            $now = [datetime]::UtcNow
            if ($now -ge $deadline) {
                $timedOut = $true
                try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
                [void]$process.WaitForExit(5000)
                break
            }
            if ($now -ge $nextBeat) {
                $elapsed = [int]($now - $started).TotalSeconds
                $heartbeatActivity = if ($Activity) { $Activity } elseif ($script:ADAuditProgressLastActivity) { $script:ADAuditProgressLastActivity } else { 'Native diagnostics' }
                Write-ADAuditProgress -Activity $heartbeatActivity -Status "$Operation$(if ($Target) { " on $Target" }); waiting for the process to finish ($elapsed/$TimeoutSec s)" -PercentComplete $PercentComplete -Heartbeat
                $nextBeat = $now.AddSeconds($script:ADAuditHeartbeatSeconds)
            }
        }
        if (-not $timedOut) { $process.WaitForExit() }
    } catch {
        try { if (-not $process.HasExited) { $process.Kill($true) } } catch { }
        throw
    }
    $outText = ''; $errText = ''
    try { if ($stdout.Wait(3000)) { $outText = [string]$stdout.Result } } catch { }
    try { if ($stderr.Wait(3000)) { $errText = [string]$stderr.Result } } catch { }
    $combined = $outText
    if ($errText) { $combined = if ($combined) { $combined.TrimEnd() + "`n" + $errText } else { $errText } }
    $exitCode = $null
    try { if ($process.HasExited) { $exitCode = $process.ExitCode } } catch { }
    try { $process.Dispose() } catch { }
    if ($timedOut) {
        $script:ADAuditWorkerStats.Timeouts++
        $script:ADAuditWorkerStats.ProcessesKilled++
        return (& $finish 'Timeout' $exitCode $combined "Deadline of $TimeoutSec s expired for $Operation$(if ($Target) { " on '$Target'" }); the process was terminated. Partial output is retained as evidence only.")
    }
    & $finish 'Success' $exitCode $combined ''
}

function Stop-ADAuditWorkers {
    # End-of-run cleanup: stops anything still active, retries orphans, disposes pooled
    # runspaces and child processes. Returns counts for run metadata.
    param([switch]$KeepPools)
    foreach ($handle in @($script:ADAuditActiveWorkers)) {
        try { [void](Stop-ADAuditWorker -Handle $handle -Reason 'Run ended' -GraceSec 2) } catch { }
    }
    foreach ($orphan in @($script:ADAuditOrphanedWorkers)) {
        try {
            $handle = $orphan.Handle
            if ($handle.PowerShell.InvocationStateInfo.State -notin @('Running','Stopping')) {
                try { $handle.PowerShell.Dispose() } catch { }
                try { $handle.Slot.Runspace.Dispose() } catch { }
                [void]$script:ADAuditOrphanedWorkers.Remove($orphan)
            } elseif ($handle.Slot.ProcessId) {
                try { Stop-Process -Id $handle.Slot.ProcessId -Force -ErrorAction SilentlyContinue } catch { }
            }
        } catch { }
    }
    if (-not $KeepPools) {
        foreach ($slot in @($script:ADAuditWorkerRunspaces) + @($script:ADAuditProcessRunspaces)) {
            try { $slot.Runspace.Dispose() } catch { }
            if ($slot.ProcessId) { try { Stop-Process -Id $slot.ProcessId -Force -ErrorAction SilentlyContinue } catch { } }
        }
        $script:ADAuditWorkerRunspaces.Clear()
        $script:ADAuditProcessRunspaces.Clear()
        $script:ADAuditWorkerSessionState = $null
    }
    [pscustomobject]@{
        RunspacesCreated = $script:ADAuditWorkerStats.RunspacesCreated; ProcessesCreated = $script:ADAuditWorkerStats.ProcessesCreated
        Timeouts = $script:ADAuditWorkerStats.Timeouts; ProcessesKilled = $script:ADAuditWorkerStats.ProcessesKilled
        Orphaned = $script:ADAuditWorkerStats.Orphaned; OrphansRemaining = $script:ADAuditOrphanedWorkers.Count
        OrphanDetails = @($script:ADAuditOrphanedWorkers | ForEach-Object { "$($_.Operation) on $($_.Target): $($_.Reason)" })
    }
}

function Reset-ADAuditWorkerState {
    # Full reset between runs or offline test cases.
    [void](Stop-ADAuditWorkers)
    Clear-ADAuditTransportState
    $script:ADAuditActiveWorkers.Clear()
    $script:ADAuditOrphanedWorkers.Clear()
    $script:ADAuditWorkerStats = @{ RunspacesCreated = 0; ProcessesCreated = 0; Timeouts = 0; Orphaned = 0; ProcessesKilled = 0 }
}

function Get-ADAuditActiveWorkerCount {
    @($script:ADAuditActiveWorkers).Count + @($script:ADAuditOrphanedWorkers).Count
}

function Invoke-ADAuditCimRequest {
    # Transport policy for one remote CIM request, executed inside the bounded worker:
    # resolution check, DCOM first, optional WSMan fallback, per-protocol reachability
    # cache, pooled session reuse with one fresh-session retry. Never contacts a
    # protocol whose connection failure was recorded within the cache lifetime.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Instance','Method')][string]$Kind,
        [Parameter(Mandatory)][hashtable]$Parameters,
        [Parameter(Mandatory)][string]$ComputerName,
        [bool]$UseWsmanFallback = $false,
        [int]$OperationTimeoutSec = $script:ADAuditCimOperationTimeoutSec,
        [string]$Label = 'CIM request'
    )
    $protocols = @('Dcom')
    if ($UseWsmanFallback) { $protocols += 'Wsman' }
    $skipped = [System.Collections.Generic.List[string]]::new()
    $lastError = $null
    $attempted = $false
    $resolvable = $null
    foreach ($protocol in $protocols) {
        $blocked = Test-ADAuditTransportBlocked -ComputerName $ComputerName -Protocol $protocol
        if ($blocked) {
            $age = [int]([datetime]::UtcNow - $blocked.RecordedUtc).TotalSeconds
            $skipped.Add("$protocol not retried ($($blocked.Outcome) recorded $age s ago: $(Get-ADAuditShortMessage $blocked.Message); next attempt allowed after $($blocked.ExpiresUtc.ToLocalTime().ToString('HH:mm:ss')))")
            continue
        }
        if ($null -eq $resolvable) {
            $resolvable = Test-ADAuditTargetResolvable -ComputerName $ComputerName
            if ($resolvable -eq $false) {
                $message = "Name '$ComputerName' did not resolve from this host; no transport was attempted."
                foreach ($p in $protocols) { [void](Set-ADAuditTransportResult -ComputerName $ComputerName -Protocol $p -Outcome 'Unreachable' -Message $message) }
                throw [System.Net.Sockets.SocketException]::new(11001)
            }
        }
        $pooledLease = Get-ADAuditCimSessionLease -ComputerName $ComputerName -Protocol $protocol
        if ($pooledLease) { Complete-ADAuditCimSessionLease -Lease $pooledLease }
        else {
            # No pooled session: a short TCP preflight replaces the protocol timeout for a host that is down.
            $preflight = Test-ADAuditTransportPreflight -ComputerName $ComputerName -Protocol $protocol
            if ($preflight) {
                $lastError = [System.Management.Automation.ErrorRecord]::new([System.Net.Sockets.SocketException]::new(10060), 'ADAuditTransportPreflight', [System.Management.Automation.ErrorCategory]::ConnectionError, $ComputerName)
                $lastError.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($preflight.Message)
                $skipped.Add("$protocol not attempted: $($preflight.Message)")
                $attempted = $true
                continue
            }
        }
        $attempted = $true
        $attempt = 0
        $moveToNextProtocol = $false
        while (-not $moveToNextProtocol -and $attempt -lt 2) {
            $attempt++
            $lease = Get-ADAuditCimSessionLease -ComputerName $ComputerName -Protocol $protocol
            $pooled = $null -ne $lease
            $session = $null
            try {
                if ($pooled) { $session = $lease.Session }
                else {
                    $option = New-CimSessionOption -Protocol $protocol
                    $session = New-CimSession -ComputerName $ComputerName -SessionOption $option -OperationTimeoutSec $OperationTimeoutSec -ErrorAction Stop
                    $lease = Add-ADAuditCimSession -ComputerName $ComputerName -Protocol $protocol -Session $session
                }
                $output = if ($Kind -eq 'Instance') { Get-CimInstance @Parameters -CimSession $session } else { Invoke-CimMethod @Parameters -CimSession $session }
                [void](Set-ADAuditTransportResult -ComputerName $ComputerName -Protocol $protocol -Outcome 'Reachable')
                Complete-ADAuditCimSessionLease -Lease $lease
                return $output
            } catch {
                $lastError = $_
                $outcome = Get-ADAuditOperationOutcome -ErrorRecord $_
                if ($lease) { Remove-ADAuditCimSession -Lease $lease }
                elseif ($session) { try { $session | Remove-CimSession -ErrorAction SilentlyContinue } catch { } }
                if ($pooled -and $outcome -notin @('AccessDenied','Unsupported')) { continue }
                if ($outcome -in @('Unreachable','Timeout')) { [void](Set-ADAuditTransportResult -ComputerName $ComputerName -Protocol $protocol -Outcome $outcome -Message $_.Exception.Message) }
                $moveToNextProtocol = $true
            }
        }
    }
    if (-not $attempted) {
        throw "No transport was attempted for '$ComputerName' ($Label): $($skipped -join '; '). A recent connection failure prevented another attempt within the $($script:ADAuditConnectionCacheSec) s cache lifetime."
    }
    if ($lastError -and $lastError.FullyQualifiedErrorId -like 'ADAuditTransportPreflight*') {
        throw "$Label against '$ComputerName' was not attempted: $($skipped -join '; ')."
    }
    if ($lastError) { throw $lastError }
    throw "CIM request '$Label' against '$ComputerName' produced no result."
}

function Get-ADAuditCimInstance {
    [CmdletBinding(DefaultParameterSetName = 'ByClass')]
    param(
        [Parameter(ParameterSetName = 'ByClass', Mandatory = $true)]
        [string]$ClassName,

        [Parameter(ParameterSetName = 'ByQuery', Mandatory = $true)]
        [string]$Query,

        [string]$Namespace = 'root/cimv2',

        [string]$Filter,

        [string[]]$Property,

        [string]$ComputerName = $env:COMPUTERNAME,

        [switch]$UseWsmanFallback,

        [ValidateRange(1,300)][int]$OperationTimeoutSec = $script:ADAuditCimOperationTimeoutSec,

        [int]$TimeoutSec = 0,

        [switch]$Inline
    )

    if (-not $script:ADAuditIsWindows) {
        throw "Get-ADAuditCimInstance requires Windows."
    }

    Assert-ADAuditRemoteTargetAllowed -ComputerName $ComputerName
    $remoteTarget = -not (Test-ADAuditLocalComputer $ComputerName)
    $baseParams = @{ Namespace = $Namespace; ErrorAction = 'Stop'; OperationTimeoutSec = $OperationTimeoutSec }

    if ($PSCmdlet.ParameterSetName -eq 'ByClass') {
        $baseParams.ClassName = $ClassName
        if ($Filter)   { $baseParams.Filter = $Filter }
        if ($Property) { $baseParams.Property = $Property }
    }
    else {
        $baseParams.Query = $Query
    }

    if (-not $remoteTarget) {
        return Get-CimInstance @baseParams
    }

    $label = if ($ClassName) { "CIM $ClassName" } else { 'CIM query' }
    $request = @{ Kind = 'Instance'; Parameters = $baseParams; ComputerName = $ComputerName; UseWsmanFallback = [bool]$UseWsmanFallback; OperationTimeoutSec = $OperationTimeoutSec; Label = $label }
    if ($Inline -or $script:ADAuditInWorker) { return Invoke-ADAuditCimRequest @request }
    $result = Invoke-ADAuditBoundedOperation -Target $ComputerName -Operation $label -TimeoutSec $TimeoutSec -ScriptBlock { param($Request) Invoke-ADAuditCimRequest @Request } -ArgumentList @(,$request)
    Receive-ADAuditOperationResult -Result $result
}

function Invoke-ADAuditCimMethod {
    # Read-only collectors use this for StdRegProv and SMB configuration methods.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$ClassName,
        [Parameter(Mandatory)][string]$MethodName,
        [string]$Namespace = 'root/cimv2',
        [hashtable]$Arguments = @{},
        [switch]$UseWsmanFallback,
        [ValidateRange(1,300)][int]$OperationTimeoutSec = $script:ADAuditCimOperationTimeoutSec,
        [int]$TimeoutSec = 0,
        [switch]$Inline
    )
    Assert-ADAuditRemoteTargetAllowed -ComputerName $ComputerName
    $params = @{Namespace=$Namespace; ClassName=$ClassName; MethodName=$MethodName; Arguments=$Arguments; OperationTimeoutSec=$OperationTimeoutSec; ErrorAction='Stop'}
    if (Test-ADAuditLocalComputer $ComputerName) { return Invoke-CimMethod @params }
    $label = "CIM $ClassName.$MethodName"
    $request = @{ Kind = 'Method'; Parameters = $params; ComputerName = $ComputerName; UseWsmanFallback = [bool]$UseWsmanFallback; OperationTimeoutSec = $OperationTimeoutSec; Label = $label }
    if ($Inline -or $script:ADAuditInWorker) { return Invoke-ADAuditCimRequest @request }
    $result = Invoke-ADAuditBoundedOperation -Target $ComputerName -Operation $label -TimeoutSec $TimeoutSec -ScriptBlock { param($Request) Invoke-ADAuditCimRequest @Request } -ArgumentList @(,$request)
    Receive-ADAuditOperationResult -Result $result
}

function Convert-ADAuditFileTime {
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return $null }

    $raw = [string]$Value
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    try {
        return [datetime]::FromFileTimeUtc([int64]$raw).ToLocalTime()
    }
    catch {
        return $null
    }
}

function Get-ADAuditFunctionalLevelRank {
    param([string]$Mode)

    # Ranks cover every Domain/Forest mode the ActiveDirectory module emits,
    # going back to NT4 (rank 0) and forward to Server 2025 (rank 10). Earlier
    # versions of this table only covered 2016+, which made
    # Test-ADAuditFunctionalLevelAtLeast return $false whenever the minimum
    # mode was Windows2003/2008/2008R2/2012/2012R2 because $minimumRank ended
    # up $null - which broke the Protected Users / Authentication Policies
    # checks on every estate at or above DFL 2008R2.
    switch ($Mode) {
        'Windows2000Domain'        { return 0 }
        'Windows2000Forest'        { return 0 }
        'Windows2003InterimDomain' { return 1 }
        'Windows2003InterimForest' { return 1 }
        'Windows2003Domain'        { return 2 }
        'Windows2003Forest'        { return 2 }
        'Windows2008Domain'        { return 3 }
        'Windows2008Forest'        { return 3 }
        'Windows2008R2Domain'      { return 4 }
        'Windows2008R2Forest'      { return 4 }
        'Windows2012Domain'        { return 5 }
        'Windows2012Forest'        { return 5 }
        'Windows2012R2Domain'      { return 6 }
        'Windows2012R2Forest'      { return 6 }
        'Windows2016Domain'        { return 7 }
        'Windows2016Forest'        { return 7 }
        'WinThreshold'             { return 7 }
        'Windows2019Domain'        { return 8 }
        'Windows2019Forest'        { return 8 }
        'Windows2022Domain'        { return 9 }
        'Windows2022Forest'        { return 9 }
        'Windows2025Domain'        { return 10 }
        'Windows2025Forest'        { return 10 }
        default                    { return $null }
    }
}

function Get-ADAuditFunctionalLevelMode {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Rank,

        [ValidateSet('Domain','Forest')]
        [string]$Scope = 'Domain'
    )

    switch ($Rank) {
        0  { return "Windows2000$Scope" }
        2  { return "Windows2003$Scope" }
        3  { return "Windows2008$Scope" }
        4  { return "Windows2008R2$Scope" }
        5  { return "Windows2012$Scope" }
        6  { return "Windows2012R2$Scope" }
        7  { return "Windows2016$Scope" }
        8  { return "Windows2019$Scope" }
        9  { return "Windows2022$Scope" }
        10 { return "Windows2025$Scope" }
        default { return $null }
    }
}

function Test-ADAuditFunctionalLevelAtLeast {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [string]$MinimumMode
    )

    $modeRank = Get-ADAuditFunctionalLevelRank -Mode $Mode
    $minimumRank = Get-ADAuditFunctionalLevelRank -Mode $MinimumMode

    if ($null -eq $modeRank -or $null -eq $minimumRank) {
        return $false
    }

    return ($modeRank -ge $minimumRank)
}

function Get-ADAuditDcFunctionalLevelCapRank {
    param(
        [Parameter(Mandatory = $true)]
        $DomainController
    )

    $operatingSystem = [string]$DomainController.OperatingSystem
    $version = [string]$DomainController.OperatingSystemVersion

    if ($operatingSystem -match '2025') { return 10 }
    if ($operatingSystem -match '2022') { return 9 }
    if ($operatingSystem -match '2019') { return 8 }
    if ($operatingSystem -match '2016') { return 7 }
    if ($operatingSystem -match '2012 ?R2') { return 6 }
    if ($operatingSystem -match '2012') { return 5 }
    if ($operatingSystem -match '2008 ?R2') { return 4 }
    if ($operatingSystem -match '2008') { return 3 }
    if ($operatingSystem -match '2003') { return 2 }
    if ($operatingSystem -match '2000') { return 0 }

    try {
        $parsedVersion = [version]$version
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 26000) { return 10 }
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 20348) { return 9 }
        if ($parsedVersion.Major -eq 10 -and $parsedVersion.Build -ge 17763) { return 8 }
        if ($parsedVersion.Major -eq 10) { return 7 }
        if ($parsedVersion.Major -eq 6 -and $parsedVersion.Minor -eq 3) { return 6 }
        if ($parsedVersion.Major -eq 6 -and $parsedVersion.Minor -eq 2) { return 5 }
        if ($parsedVersion.Major -eq 6 -and $parsedVersion.Minor -eq 1) { return 4 }
        if ($parsedVersion.Major -eq 6 -and $parsedVersion.Minor -eq 0) { return 3 }
        if ($parsedVersion.Major -eq 5 -and $parsedVersion.Minor -eq 2) { return 2 }
    }
    catch { }

    return $null
}

$script:ADAuditReplAccountCache = @{}

function Get-ADAuditReplAccountsCached {
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)][string]$NamingContext
    )
    # Full-domain secrets replication (Get-ADReplAccount -All, a DCSync) is the single
    # most expensive and most SOC-alarming operation in this tool. Both the password
    # quality check and the high-risk baseline need it; cache the result per
    # Server+NamingContext so a single -all run replicates once, not twice.
    $key = "$Server|$NamingContext"
    if ($script:ADAuditReplAccountCache.ContainsKey($key)) {
        return $script:ADAuditReplAccountCache[$key]
    }
    $accounts = Get-ADReplAccount -All -Server $Server -NamingContext $NamingContext -ErrorAction Stop
    $script:ADAuditReplAccountCache[$key] = $accounts
    return $accounts
}

Function Get-Variables() {
    #Retrieve group names and OS version
    $script:OSVersion = (Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
    $script:Administrators = (Get-ADGroup -Identity S-1-5-32-544).SamAccountName
    $script:Users = (Get-ADGroup -Identity S-1-5-32-545).SamAccountName
    $currentDomain = Get-ADDomain -Current LoggedOnUser
    $domainSidValue = $currentDomain.domainsid.value
    # Cache identity: short DC names and their FQDNs must share one reachability entry.
    $script:ADAuditTargetDnsSuffix = [string]$currentDomain.DNSRoot
    $script:DomainAdminsSID = $domainSidValue + "-512"
    $script:DomainUsersSID = $domainSidValue + "-513"
    $script:DomainControllersSID = $domainSidValue + "-516"
    # Schema Admins (518) and Enterprise Admins (519) exist only in the FOREST
    # ROOT domain; in a child domain the current domain's SID-518/519 resolve
    # to nothing and the lookups below would leave the names null.
    $rootDomainSidValue = $null
    try {
        $forestRootDomain = (Get-ADForest -ErrorAction Stop).RootDomain
        $rootDomainSidValue = (Get-ADDomain -Server $forestRootDomain -ErrorAction Stop).domainsid.value
    } catch { Register-ADAuditNotAssessed -Name 'Forest-root privileged group discovery' -Reason $_.Exception.Message }
    $script:SchemaAdminsSID = if ($rootDomainSidValue) { $rootDomainSidValue + '-518' } else { $null }
    $script:EnterpriseAdminsSID = if ($rootDomainSidValue) { $rootDomainSidValue + '-519' } else { $null }
    $script:EveryOneSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
    $script:EntrepriseDomainControllersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-9"
    $script:AuthenticatedUsersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-11"
    $script:SystemSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
    $script:LocalServiceSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-19"
    $script:DomainAdmins = (Get-ADGroup -Identity $DomainAdminsSID).SamAccountName
    $script:DomainUsers = (Get-ADGroup -Identity $DomainUsersSID).SamAccountName
    $script:DomainControllers = (Get-ADGroup -Identity $DomainControllersSID).SamAccountName
    # Fall back to the well-known English names rather than leaving these null:
    # downstream -match/-eq checks against a null name would match everything.
    $script:SchemaAdmins = try { (Get-ADGroup -Identity $SchemaAdminsSID -Server $forestRootDomain -ErrorAction Stop).SamAccountName } catch { 'Schema Admins (unresolved)' }
    $script:EnterpriseAdmins = try { (Get-ADGroup -Identity $EnterpriseAdminsSID -Server $forestRootDomain -ErrorAction Stop).SamAccountName } catch { 'Enterprise Admins (unresolved)' }
    $script:EveryOne = $EveryOneSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:EntrepriseDomainControllers = $EntrepriseDomainControllersSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:AuthenticatedUsers = $AuthenticatedUsersSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:System = $SystemSID.Translate([System.Security.Principal.NTAccount]).Value
    $script:LocalService = $LocalServiceSID.Translate([System.Security.Principal.NTAccount]).Value
    Write-Both "    [+] Administrators               : $Administrators"
    Write-Both "    [+] Users                        : $Users"
    Write-Both "    [+] Domain Admins                : $DomainAdmins"
    Write-Both "    [+] Domain Users                 : $DomainUsers"
    Write-Both "    [+] Domain Controllers           : $DomainControllers"
    Write-Both "    [+] Schema Admins                : $SchemaAdmins"
    Write-Both "    [+] Enterprise Admins            : $EnterpriseAdmins"
    Write-Both "    [+] Every One                    : $EveryOne"
    Write-Both "    [+] Entreprise Domain Controllers: $EntrepriseDomainControllers"
    Write-Both "    [+] Authenticated Users          : $AuthenticatedUsers"
    Write-Both "    [+] System                       : $System"
    Write-Both "    [+] Local Service                : $LocalService"
}

Function Write-Both() {
    #Writes to console only. Findings are rendered into the HTML audit and management reports.
    Write-Host "$args"
}

Function Get-HtmlReportsDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    if ([string]::IsNullOrWhiteSpace($BaseRoot)) {
        $BaseRoot = Join-Path (Get-Location) $env:COMPUTERNAME
    }

    $path = if ($script:HtmlReportsDir) { $script:HtmlReportsDir } else { Join-Path $BaseRoot 'HTML Reports' }
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}

Function Get-RawDataDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    if ([string]::IsNullOrWhiteSpace($BaseRoot)) {
        $BaseRoot = Join-Path (Get-Location) $env:COMPUTERNAME
    }

    $path = if ($script:EvidenceFilesDir) { $script:EvidenceFilesDir } else { Join-Path $BaseRoot 'Raw Data' }
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}

Function Get-RawSourceDataDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    $path = if ($script:LegacyArtifactsDir) { $script:LegacyArtifactsDir } else { Join-Path (Get-RawDataDir -BaseRoot $BaseRoot) 'Source' }
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}

Function Get-PreparedDataDir {
    # Derived report tables must never share names with collected evidence.
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    $path = Join-Path (Get-RawDataDir -BaseRoot $BaseRoot) 'ReportDownloads'
    if (-not (Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
    return $path
}

Function Get-HtmlDownloadsDir {
    param(
        [string]$BaseRoot = $(if ($script:outputdir) { $script:outputdir } elseif ($outputdir) { $outputdir } else { Join-Path (Get-Location) $env:COMPUTERNAME })
    )

    return (Get-PreparedDataDir -BaseRoot $BaseRoot)
}

Function Get-ADAuditReportCss {
    <#
    .SYNOPSIS
        Returns the shared CSS style block used by all companion HTML reports.
        Matches the design language of ADAudit-Results.html (light default + dark mode).
    #>
    return @'
<style>
:root {
  --bg:#f5f7fb; --panel:#ffffff; --text:#1b2430; --muted:#5f6b7a;
  --line:#d9e0ea; --shadow:0 10px 24px rgba(15,23,42,.08); --radius:14px;
  --accent:#3b82f6; --accent-soft:#dbeafe;
  --critical:#c62828; --critical-soft:#fdecec;
  --high:#ef6c00;    --high-soft:#fff2e5;
  --medium:#0277bd;  --medium-soft:#e8f4fd;
  --low:#2e7d32;     --low-soft:#edf8ee;
  --info:#6c757d;    --info-soft:#f2f4f6;
}
@media(prefers-color-scheme:dark){
  :root {
    --bg:#0f172a; --panel:#1e293b; --text:#e2e8f0; --muted:#94a3b8;
    --line:#334155; --shadow:0 10px 24px rgba(0,0,0,.4);
    --accent:#60a5fa; --accent-soft:rgba(96,165,250,.15);
    --critical:#f87171; --critical-soft:rgba(248,113,113,.15);
    --high:#fb923c;    --high-soft:rgba(251,146,60,.15);
    --medium:#60a5fa;  --medium-soft:rgba(96,165,250,.15);
    --low:#4ade80;     --low-soft:rgba(74,222,128,.15);
    --info:#94a3b8;    --info-soft:rgba(148,163,184,.15);
  }
}
*,*::before,*::after{box-sizing:border-box}
body{margin:0;padding:32px 24px;font-family:'Segoe UI',system-ui,-apple-system,Arial,sans-serif;
  background:var(--bg);color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}
.container{max-width:1280px;margin:0 auto}
.hero{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);
  padding:32px 36px;margin-bottom:28px}
.hero h1{margin:0 0 4px;font-size:1.65rem;font-weight:700}
.hero .meta{color:var(--muted);font-size:.88rem}
.mono{font-family:Consolas,Menlo,Monaco,monospace;font-size:.92em}
h2{font-size:1.25rem;font-weight:600;margin:28px 0 14px;padding-bottom:8px;border-bottom:2px solid var(--line)}
h3{font-size:1.05rem;font-weight:600;margin:20px 0 10px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:Consolas,Menlo,Monaco,monospace;font-size:.9em;background:var(--accent-soft);
  padding:2px 7px;border-radius:5px}
pre{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:16px 20px;overflow-x:auto;font-size:.88rem;font-family:Consolas,Menlo,Monaco,monospace}

/* Tables */
table{width:100%;border-collapse:separate;border-spacing:0;margin:12px 0 20px;
  background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
thead th{background:var(--accent-soft);color:var(--text);font-weight:600;font-size:.85rem;
  text-transform:uppercase;letter-spacing:.04em;padding:12px 14px;text-align:left;
  position:sticky;top:0;z-index:1;border-bottom:2px solid var(--line)}
tbody td{padding:10px 14px;border-bottom:1px solid var(--line);font-size:.92rem;vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--accent-soft)}

/* Severity badges */
.badge{display:inline-block;padding:3px 12px;border-radius:999px;font-size:.82rem;font-weight:600;letter-spacing:.02em}
.badge-critical{background:var(--critical-soft);color:var(--critical)}
.badge-high{background:var(--high-soft);color:var(--high)}
.badge-medium{background:var(--medium-soft);color:var(--medium)}
.badge-low{background:var(--low-soft);color:var(--low)}
.badge-info{background:var(--info-soft);color:var(--info)}

/* Stat cards */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin:16px 0 24px}
.stat{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);
  padding:18px 20px;text-align:center}
.stat .val{font-size:1.8rem;font-weight:700;line-height:1.1}
.stat .lbl{font-size:.82rem;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.04em}

/* Details/Accordion */
details{background:var(--panel);border-radius:var(--radius);box-shadow:var(--shadow);
  margin:10px 0;border-left:5px solid var(--accent)}
details[open]{border-left-color:var(--accent)}
summary{cursor:pointer;padding:14px 20px;font-weight:600;font-size:.95rem;list-style:none;
  display:flex;align-items:center;gap:10px}
summary::-webkit-details-marker{display:none}
summary::before{content:'\25B8';font-size:1rem;transition:transform .15s ease;display:inline-block}
details[open]>summary::before{transform:rotate(90deg)}
details>div,details>.detail-body{padding:0 20px 16px}
details table{box-shadow:none;margin:0}

/* List styling */
ul.link-list{list-style:none;padding:0}
ul.link-list li{padding:8px 14px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px}
ul.link-list li:last-child{border-bottom:none}
ul.link-list li::before{content:'\1F4C4';font-size:1rem}

/* Footer */
.footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--line);
  color:var(--muted);font-size:.82rem;text-align:center}

/* Responsive */
@media(max-width:768px){
  body{padding:16px 12px}
  .hero{padding:20px}
  .stats{grid-template-columns:repeat(auto-fit,minmax(120px,1fr))}
  table{display:block;overflow-x:auto}
}
</style>
'@
}

function Test-ADAuditIsolatedAssessmentMode {
    # Saved run metadata may carry the current 'IsolatedHost' value or the earlier
    # 'IsolatedClone' value; both identify an isolated-copy assessment.
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $Value.Trim() -in @('IsolatedHost','IsolatedClone')
}

function Test-ADAuditIsolatedAssessmentMode {
    # Saved run metadata may carry the current 'IsolatedHost' value or the earlier
    # 'IsolatedClone' value; both identify an isolated-copy assessment.
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $Value.Trim() -in @('IsolatedHost','IsolatedClone')
}

function Get-ADAuditCloneNotice {
    param([bool]$IsolatedClone = $script:ADAuditIsolatedClone, [string]$SnapshotDate = $script:ADAuditSnapshotDate)
    if (-not $IsolatedClone) { return '' }
    $date = if ($SnapshotDate) { [System.Net.WebUtility]::HtmlEncode($SnapshotDate) } else { 'not supplied' }
    return "<aside class='clone-notice' style='border:2px solid #b45309;border-radius:10px;padding:16px;margin:16px 0;background:var(--panel);color:var(--text)'><strong>ISOLATED HOST ASSESSMENT (copied directory) — snapshot date: $date</strong><p>This assessment describes an isolated copy of a domain controller and that host's local state. It does not establish current production security or operational health. Password ages, activity timestamps, certificates and replication evidence may reflect the age of the copy. Verify time-based findings in the current environment before remediation. Unreachable production systems are outside this assessment.</p></aside>"
}

function Get-ADAuditThemeMarkup {
    return @'
<style>
html[data-theme="dark"]{--bg:#0f172a;--panel:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--line:#334155;--shadow:0 10px 24px rgba(0,0,0,.4);--accent:#60a5fa;--accent-soft:rgba(96,165,250,.15);--critical:#f87171;--critical-soft:rgba(248,113,113,.15);--high:#fb923c;--high-soft:rgba(251,146,60,.15);--medium:#60a5fa;--medium-soft:rgba(96,165,250,.15);--low:#4ade80;--low-soft:rgba(74,222,128,.15);--info:#94a3b8;--info-soft:rgba(148,163,184,.15);color-scheme:dark}
html[data-theme="light"]{--bg:#f5f7fb;--panel:#fff;--text:#1b2430;--muted:#5f6b7a;--line:#d9e0ea;--shadow:0 10px 24px rgba(15,23,42,.08);--accent:#3b82f6;--accent-soft:#dbeafe;--critical:#c62828;--critical-soft:#fdecec;--high:#ef6c00;--high-soft:#fff2e5;--medium:#0277bd;--medium-soft:#e8f4fd;--low:#2e7d32;--low-soft:#edf8ee;--info:#6c757d;--info-soft:#f2f4f6;color-scheme:light}
.audit-theme-toggle{display:block;margin:0 0 16px auto;padding:9px 15px;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:999px;cursor:pointer;font:inherit}
@media print{.audit-theme-toggle{display:none}}
</style>
<button id="sharedAuditThemeToggle" class="audit-theme-toggle" type="button" aria-pressed="false">Dark mode</button>
<script>
(function(){
  var key='adaudit-theme', root=document.documentElement;
  function stored(){try{return localStorage.getItem(key)}catch(e){return null}}
  var media=window.matchMedia?window.matchMedia('(prefers-color-scheme: dark)'):null;
  function apply(theme){root.setAttribute('data-theme',theme);var b=document.getElementById('sharedAuditThemeToggle');if(b){b.textContent=theme==='dark'?'Light mode':'Dark mode';b.setAttribute('aria-pressed',theme==='dark'?'true':'false')}}
  var saved=stored();apply(saved==='light'||saved==='dark'?saved:media&&media.matches?'dark':'light');
  var button=document.getElementById('sharedAuditThemeToggle');if(button){button.addEventListener('click',function(){var next=root.getAttribute('data-theme')==='dark'?'light':'dark';apply(next);try{localStorage.setItem(key,next)}catch(e){}})}
  if(media&&media.addEventListener){media.addEventListener('change',function(e){var s=stored();if(s!=='light'&&s!=='dark')apply(e.matches?'dark':'light')})}
})();
</script>
'@
}

Function Get-ADAuditReportHeader {
    <#
    .SYNOPSIS
        Returns the HTML header/doctype block for companion reports.
    #>
    param([string]$Title = 'AD Audit Report', [switch]$NoThemeControl)
    $css = Get-ADAuditReportCss
    return @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>$Title</title>
$css
</head>
<body>
<div class="container">
$(if (-not $NoThemeControl) { Get-ADAuditThemeMarkup })
$(Get-ADAuditCloneNotice)
"@
}

Function Get-ADAuditReportFooter {
    <#
    .SYNOPSIS
        Returns the HTML footer block for companion reports.
    #>
    return @"
<div class="footer">Generated by AD Audit &mdash; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
</div>
</body>
</html>
"@
}

Function Get-ADAuditPrimaryNav {
    <#
    .SYNOPSIS
        Returns the shared CSS + <nav> block linking the primary HTML reports.
        The Operations tab is intentionally not included - it is not part of the audit.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('audit','risk','health','overlap','lateral','none')]
        [string]$Active = 'none'
    )
    $links = @(
        [pscustomobject]@{ Key='audit';   Href='ADAudit-Results.html';            Label='Audit Results' }
        [pscustomobject]@{ Key='risk';    Href='Risk-Report.html';                Label='Risk Report' }
        [pscustomobject]@{ Key='health';  Href='AD_Health.html';                  Label='AD Health' }
        [pscustomobject]@{ Key='overlap'; Href='overlapping_group_memberships.html'; Label='Overlapping Groups' }
        [pscustomobject]@{ Key='lateral'; Href='Lateral-Movement.html';            Label='Lateral Movement' }
    )
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(@'
<style>
.primary-nav{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 20px;padding:10px 14px;background:var(--panel,#fff);border:1px solid var(--line,#d9e0ea);border-radius:12px;box-shadow:var(--shadow,0 10px 24px rgba(15,23,42,.08))}
.primary-nav-link{padding:6px 12px;border-radius:999px;font-size:.85rem;font-weight:600;text-decoration:none;color:var(--text,#1b2430);border:1px solid transparent}
.primary-nav-link:hover{background:var(--accent-soft,#dbeafe);text-decoration:none}
.primary-nav-link.active{background:var(--accent,#3b82f6);color:#fff;border-color:var(--accent,#3b82f6)}
</style>
'@)
    [void]$sb.Append("<nav class='primary-nav'>")
    foreach ($link in $links) {
        $cls = if ($link.Key -eq $Active) { 'primary-nav-link active' } else { 'primary-nav-link' }
        [void]$sb.Append("<a class='$cls' href='$($link.Href)'>$($link.Label)</a>")
    }
    [void]$sb.AppendLine("</nav>")
    return $sb.ToString()
}

Function Get-EvidencePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )
    $dir = Get-RawSourceDataDir
    return (Join-Path $dir $FileName)
}

# ---------------------------------------------------------------------------
# Audit check resilience: per-check try/catch wrapper + FSMO context lookup
# Lets a single failing check (DNS, Delegated Permissions, etc.) be logged
# without stopping the entire script. A separate connection_failures.txt /
# .csv summarises every failure, the error, the suspected target server, and
# - if reachable - the FSMO roles that server holds, so the operator knows
# exactly which checks were skipped and why.
# ---------------------------------------------------------------------------
$script:CheckFailures = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# "Could not assess" tracking. Distinct from CheckFailures (thrown errors):
# this records checks/targets we deliberately could NOT evaluate (e.g. a DC
# was unreachable over remote PowerShell/CIM, or the host running the script
# is not a DC so a host-local setting could not be read from a DC). These are
# NEVER turned into Nessus/risk findings - an un-assessable check must lower
# confidence, not raise the risk score.
# ---------------------------------------------------------------------------
$script:NotAssessed = New-Object System.Collections.Generic.List[object]
$script:ADAuditCheckStatus = New-Object System.Collections.Generic.List[object]
$script:ADAuditCurrentCheckSwitch = $null
$script:ADAuditIsolatedClone = $false
$script:ADAuditSnapshotDate = $null
$script:ADAuditProgressContext = $null
$script:ADAuditProgressLastActivity = ''
$script:ADAuditProgressLastUi = [datetime]::MinValue
$script:ADAuditProgressLastLog = [datetime]::MinValue

function New-ADAuditRunDirectory {
    param([Parameter(Mandatory)][string]$ParentPath, [datetimeoffset]$Timestamp = [datetimeoffset]::Now)
    New-Item -ItemType Directory -Path $ParentPath -Force -ErrorAction Stop | Out-Null
    $name = $Timestamp.ToString('yyyy-MM-dd_HH-mm-ss', [cultureinfo]::InvariantCulture)
    $suffix = 1
    while ($true) {
        $leaf = if ($suffix -eq 1) { $name } else { '{0}_{1:00}' -f $name,$suffix }
        $candidate = Join-Path $ParentPath $leaf
        try { return (New-Item -ItemType Directory -Path $candidate -ErrorAction Stop).FullName }
        catch { if (-not (Test-Path -LiteralPath $candidate)) { throw }; $suffix++ }
    }
}

function Write-ADAuditProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Activity,
        [string]$Status = 'Working',
        [ValidateRange(-1,100)][double]$PercentComplete = -1,
        [switch]$Completed,
        [switch]$Force,
        [switch]$Heartbeat
    )
    $now = [datetime]::UtcNow
    $context = $script:ADAuditProgressContext
    $prefix = if ($context) { "Check $($context.Index) of $($context.Total)" } else { 'Audit' }
    $elapsed = if ($context) { ' | elapsed {0:hh\:mm\:ss}' -f ($now - $context.Started) } else { '' }
    $percentLabel = if ($PercentComplete -ge 0) { '{0:0}% of phase' -f $PercentComplete } else { 'total not available' }
    $changed = $Activity -ne $script:ADAuditProgressLastActivity
    # Heartbeats repeat the current operation while a remote call blocks: the bars are
    # refreshed every time, the console only every ADAuditHeartbeatLogSeconds, and the
    # percentage stays whatever the caller measured - elapsed time never advances it.
    $uiDue = $Force -or $Completed -or $changed -or $Heartbeat -or ($now - $script:ADAuditProgressLastUi).TotalMilliseconds -ge 250
    $logDue = if ($Heartbeat) { $changed -or ($now - $script:ADAuditProgressLastLog).TotalSeconds -ge $script:ADAuditHeartbeatLogSeconds } else { $Force -or $Completed -or $changed -or ($now - $script:ADAuditProgressLastLog).TotalSeconds -ge 10 }
    if ($uiDue) {
        $parameters = @{ Id=1; Activity="$prefix - $Activity"; Status="$Status | $percentLabel$elapsed"; PercentComplete=[int]$PercentComplete }
        if ($context) {
            $parameters.ParentId = 0
            # Some hosts only display the parent record during a blocking call.
            # Keep its status useful even when the child phase bar is hidden.
            $overallActivity = if ($context.Available) { "AD audit - $($context.Total) of $($context.Available) checks selected; $($context.Available - $context.Total) skipped" } else { "AD audit - $($context.Total) checks selected" }
            Write-Progress -Id 0 -Activity $overallActivity -Status "$prefix`: $Activity - $Status | $percentLabel$elapsed" -PercentComplete ([int](100 * ($context.Index - 1) / $context.Total))
        }
        if ($Completed) { $parameters.Completed = $true }
        Write-Progress @parameters
        $script:ADAuditProgressLastUi = $now
    }
    if ($logDue) {
        $state = if ($Completed) { 'phase finished' } else { $percentLabel }
        Write-Both "    [$prefix] $Activity - $Status ($state$elapsed)"
        $script:ADAuditProgressLastLog = $now
    }
    $script:ADAuditProgressLastActivity = if ($Completed) { '' } else { $Activity }
}
function Initialize-ADAuditCheckStatus {
    param([object[]]$Checks, [string[]]$SelectedSwitches)
    $script:ADAuditCheckStatus.Clear()
    foreach ($check in $Checks) {
        $selected = $check.Switch -in $SelectedSwitches
        $script:ADAuditCheckStatus.Add([pscustomobject]@{
            CheckName = $check.Name; Switch = $check.Switch; Selected = $selected
            Status = $(if ($selected) { 'NotRun' } else { 'NotSelected' })
            StartedUtc = ''; FinishedUtc = ''; DurationSeconds = 0
            FailureCount = 0; NotAssessedCount = 0; Reason = ''
        })
    }
}

function Write-ADAuditRunMetadata {
    param([hashtable]$Metadata)
    $rawDir = Get-RawSourceDataDir
    $script:ADAuditCheckStatus | Export-Csv -LiteralPath (Join-Path $rawDir 'audit_check_status.csv') -NoTypeInformation -Encoding UTF8
    $Metadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $rawDir 'audit_run.json') -Encoding UTF8
}

$script:ADAuditIsDC = $null

Function Get-FsmoRolesForServer {
    [CmdletBinding()]
    param([string]$ServerHostnameOrFqdn)

    if ([string]::IsNullOrWhiteSpace($ServerHostnameOrFqdn)) { return @() }
    $needle = $ServerHostnameOrFqdn.Trim().TrimEnd('.').ToLowerInvariant()
    $shortNeedle = ($needle -split '\.')[0]

    $roles = @()
    try {
        $forest = Get-ADForest -ErrorAction Stop
        if ($forest) {
            foreach ($pair in @(
                @{ N='SchemaMaster';        V=$forest.SchemaMaster },
                @{ N='DomainNamingMaster';  V=$forest.DomainNamingMaster }
            )) {
                if ($pair.V) {
                    $v = $pair.V.ToString().ToLowerInvariant().TrimEnd('.')
                    $vShort = ($v -split '\.')[0]
                    if ($v -eq $needle -or $vShort -eq $shortNeedle) { $roles += $pair.N }
                }
            }
        }
    } catch { }
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        if ($domain) {
            foreach ($pair in @(
                @{ N='PDCEmulator';          V=$domain.PDCEmulator },
                @{ N='RIDMaster';            V=$domain.RIDMaster },
                @{ N='InfrastructureMaster'; V=$domain.InfrastructureMaster }
            )) {
                if ($pair.V) {
                    $v = $pair.V.ToString().ToLowerInvariant().TrimEnd('.')
                    $vShort = ($v -split '\.')[0]
                    if ($v -eq $needle -or $vShort -eq $shortNeedle) { $roles += $pair.N }
                }
            }
        }
    } catch { }
    return ,$roles
}

Function Resolve-ServerHintFromError {
    [CmdletBinding()]
    param([string]$ErrorMessage)

    if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { return @() }
    $hints = New-Object System.Collections.Generic.List[string]

    foreach ($pat in @(
        "(?i)server\s+'([^']+)'",
        '(?i)server\s+"([^"]+)"',
        '(?i)on\s+server\s+([A-Za-z0-9_\-\.]+)',
        '(?i)from\s+server\s+([A-Za-z0-9_\-\.]+)',
        '(?i)computer\s+''([^'']+)''',
        '(?i)host\s+([A-Za-z0-9_\-\.]+)',
        '(?i)\\\\([A-Za-z0-9_\-\.]+)\\',
        '(?i)to\s+([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-\.]+)'
    )) {
        foreach ($m in [regex]::Matches($ErrorMessage, $pat)) {
            if ($m.Groups.Count -gt 1) {
                $val = $m.Groups[1].Value.Trim()
                if ($val -and $val -notmatch '^\s*$') { $hints.Add($val) | Out-Null }
            }
        }
    }
    return ,(@($hints | Sort-Object -Unique))
}

Function Test-IsConnectionError {
    [CmdletBinding()]
    param([string]$ErrorMessage, [string]$ErrorType)
    if (-not $ErrorMessage) { return $false }
    if ($ErrorMessage -match '(?i)\b(rpc|the rpc server is unavailable|cannot find|could not contact|server is not operational|cannot connect|connection (refused|timed out|reset|failed)|network path was not found|firewall|unreachable|0x80004005|access (is )?denied|no logon servers|target principal name is incorrect)\b') { return $true }
    if ($ErrorType -match '(?i)CimException|RpcException|RemoteException|DirectoryServerDownException|ActiveDirectoryServerDownException|EndpointNotFound') { return $true }
    return $false
}

Function Register-AuditFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord,
        [Parameter(Mandatory)][string]$Name,
        [string]$Description,
        [string]$Switch,
        [string]$Prefix = '    [!] STEP FAILED'
    )

    if (-not $Switch) { $Switch = $script:ADAuditCurrentCheckSwitch }
    $errMsg  = $ErrorRecord.Exception.Message
    $errType = $ErrorRecord.Exception.GetType().FullName
    $isConn  = Test-IsConnectionError -ErrorMessage $errMsg -ErrorType $errType

    $serverHints = Resolve-ServerHintFromError -ErrorMessage $errMsg
    $fsmoEntries = New-Object System.Collections.Generic.List[string]
    foreach ($hint in $serverHints) {
        $rolesForHost = Get-FsmoRolesForServer -ServerHostnameOrFqdn $hint
        if ($rolesForHost.Count -gt 0) {
            $fsmoEntries.Add("$hint = [$($rolesForHost -join ', ')]") | Out-Null
        }
    }

    $script:CheckFailures.Add([pscustomobject]@{
        Time                = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        CheckName           = $Name
        Switch              = $Switch
        Description         = if ($Description) { $Description } else { $Name }
        ErrorType           = $errType
        ErrorMessage        = $errMsg
        IsConnectionIssue   = $isConn
        ServerHints         = ($serverHints -join ', ')
        FsmoOnFailedServers = ($fsmoEntries -join '; ')
        ScriptStackTrace    = ([string]$ErrorRecord.ScriptStackTrace)
    }) | Out-Null

    Write-Both ("{0} ({1}): {2}" -f $Prefix, $Name, $errMsg)
    if ($isConn) {
        Write-Both "    [!] Reason: connection / RPC / firewall / authentication issue with an AD or DNS server."
    }
    if ($serverHints.Count -gt 0) {
        Write-Both ("    [!] Suspected server(s) from error: {0}" -f ($serverHints -join ', '))
    }
    if ($fsmoEntries.Count -gt 0) {
        foreach ($entry in $fsmoEntries) {
            Write-Both "    [!] FSMO holder: $entry"
        }
    } elseif ($isConn -and $serverHints.Count -gt 0) {
        Write-Both "    [!] FSMO lookup: server(s) above do not appear to currently hold FSMO roles (or AD lookup also failed)."
    }
}

Function Invoke-AuditCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Body,
        [string]$Switch,
        [string[]]$Modules = @(),
        [int]$CheckIndex = 0,
        [int]$SelectedCount = 0,
        [int]$AvailableCount = 0
    )

    $previousProgressContext = $script:ADAuditProgressContext
    $script:ADAuditProgressLastActivity = ''
    if ($SelectedCount -gt 0) {
        $script:ADAuditProgressContext = @{ Index=$CheckIndex; Total=$SelectedCount; Available=$AvailableCount; Started=[datetime]::UtcNow }
        Write-Both "[*] Check $CheckIndex of $SelectedCount - $Description ($SelectedCount of $AvailableCount selected; $($AvailableCount - $SelectedCount) skipped)"
        Write-Progress -Id 0 -Activity "AD audit - $SelectedCount of $AvailableCount checks selected" -Status "Check $CheckIndex of $SelectedCount - $Description; $($AvailableCount - $SelectedCount) skipped" -PercentComplete ([int](100 * ($CheckIndex - 1) / $SelectedCount))
    } else { Write-Both "[*] $Description" }
    Write-ADAuditProgress -Activity $Description -Status 'Starting collection'
    $previousSwitch = $script:ADAuditCurrentCheckSwitch
    $script:ADAuditCurrentCheckSwitch = $Switch
    $status = $script:ADAuditCheckStatus | Where-Object { $_.Switch -eq $Switch } | Select-Object -First 1
    $started = [datetime]::UtcNow
    $failuresBefore = $script:CheckFailures.Count
    $unknownBefore = $script:NotAssessed.Count
    $terminated = $false
    if ($status) { $status.StartedUtc = $started.ToString('o') }
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        foreach ($moduleName in $Modules) {
            if (-not (Get-Module -Name $moduleName)) {
                Register-ADAuditNotAssessed -Name $Name -Switch $Switch -Target $moduleName -Reason "Required module '$moduleName' was not loaded. Dependent subchecks may be unavailable."
            }
        }
        & $Body
    } catch {
        $terminated = $true
        Register-AuditFailure -ErrorRecord $_ -Name $Name -Description $Description -Switch $Switch -Prefix '    [!] CHECK FAILED'
        Write-Both "    [*] Continuing with remaining checks..."
    } finally {
        $ErrorActionPreference = $previousErrorAction
        if ($status) {
            $status.FinishedUtc = [datetime]::UtcNow.ToString('o')
            $status.DurationSeconds = [math]::Round(([datetime]::UtcNow - $started).TotalSeconds, 2)
            $status.FailureCount = $script:CheckFailures.Count - $failuresBefore
            $status.NotAssessedCount = $script:NotAssessed.Count - $unknownBefore
            $status.Status = if ($terminated) { 'Failed' } elseif ($status.FailureCount -gt 0 -or $status.NotAssessedCount -gt 0) { 'Partial' } else { 'Completed' }
            $status.Reason = if ($terminated) { 'Check terminated; inspect collection failures.' } elseif ($status.Status -eq 'Partial') { 'Some subchecks or targets could not be assessed; findings cover collected evidence only.' } else { 'Execution completed without recorded collection gaps; this does not mean all controls passed.' }
        }
        Write-Progress -Id 1 -Activity $Description -Completed
        # Also clear legacy/default records left by older check implementations.
        Write-Progress -Id 0 -Activity 'AD audit' -Completed
        $resultLabel = if ($status) { $status.Status } elseif ($terminated) { 'Failed' } else { 'Finished' }
        Write-Both ("[+] {0}: {1} in {2:hh\:mm\:ss}" -f $Name,$resultLabel,([datetime]::UtcNow - $started))
        if ($SelectedCount -gt 0 -and $CheckIndex -lt $SelectedCount) {
            Write-Progress -Id 0 -Activity "AD audit - $SelectedCount of $AvailableCount checks selected" -Status "$CheckIndex of $SelectedCount finished; $($AvailableCount - $SelectedCount) skipped" -PercentComplete ([int](100 * $CheckIndex / $SelectedCount))
        }
        $script:ADAuditProgressContext = $previousProgressContext
        $script:ADAuditCurrentCheckSwitch = $previousSwitch
    }
}

Function Invoke-AuditStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body,
        [string]$Switch
    )

    Write-ADAuditProgress -Activity $Name -Status 'Collecting; this operation does not expose a total'
    try {
        & $Body
    } catch {
        Register-AuditFailure -ErrorRecord $_ -Name $Name -Switch $Switch -Prefix '    [!] STEP FAILED'
    } finally {
        Write-Progress -Id 1 -Activity $Name -Completed
        $script:ADAuditProgressLastActivity = ''
    }
}

Function Write-CheckFailuresReport {
    [CmdletBinding()]
    param([string]$BaseRoot)

    if (-not $script:CheckFailures -or $script:CheckFailures.Count -eq 0) { return }

    $rawDir = Get-RawSourceDataDir
    if (-not (Test-Path -LiteralPath $rawDir)) {
        New-Item -ItemType Directory -Path $rawDir -Force | Out-Null
    }
    $txtPath = Join-Path $rawDir 'connection_failures.txt'
    $csvPath = Join-Path $rawDir 'connection_failures.csv'

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(' AUDIT CHECK FAILURES (script continued past these)')
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(" Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine(" Total failures: $($script:CheckFailures.Count)")
    [void]$sb.AppendLine('---------------------------------------------------------------------')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('What this file means:')
    [void]$sb.AppendLine(' - One or more audit checks could not complete (typically because an AD')
    [void]$sb.AppendLine('   or DNS server was unreachable, RPC was blocked, the user lacked')
    [void]$sb.AppendLine('   permissions, or a required PowerShell module was missing).')
    [void]$sb.AppendLine(' - The script kept running and finished every other check. Anything that')
    [void]$sb.AppendLine('   appears below was SKIPPED, so the corresponding section of the HTML')
    [void]$sb.AppendLine('   report may be incomplete.')
    [void]$sb.AppendLine(' - For each failure we record the suspected target server (parsed from')
    [void]$sb.AppendLine('   the error message) and which FSMO role(s) that server holds, so you')
    [void]$sb.AppendLine('   can decide whether to retry from a different DC.')
    [void]$sb.AppendLine('')

    $i = 0
    foreach ($f in $script:CheckFailures) {
        $i++
        [void]$sb.AppendLine("[$i] $($f.CheckName)  ($($f.Time))")
        [void]$sb.AppendLine("    Description : $($f.Description)")
        if ($f.Switch) { [void]$sb.AppendLine("    Switch      : -$($f.Switch)") }
        [void]$sb.AppendLine("    Connection  : $(if($f.IsConnectionIssue){'YES (RPC / network / auth)'}else{'no - other error'})")
        [void]$sb.AppendLine("    Error type  : $($f.ErrorType)")
        [void]$sb.AppendLine("    Error       : $($f.ErrorMessage)")
        if ($f.ServerHints)         { [void]$sb.AppendLine("    Server hint : $($f.ServerHints)") }
        if ($f.FsmoOnFailedServers) { [void]$sb.AppendLine("    FSMO held   : $($f.FsmoOnFailedServers)") }
        [void]$sb.AppendLine("    Effect      : results for this check are MISSING from the report.")
        [void]$sb.AppendLine('')
    }

    Set-Content -LiteralPath $txtPath -Value $sb.ToString() -Encoding UTF8
    $script:CheckFailures | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    Write-Both ""
    Write-Both "[!] $($script:CheckFailures.Count) check(s) failed during this run - see connection_failures.txt"

    try {
        Write-Nessus-Finding "AuditCheckFailures" "KB1300" ([System.IO.File]::ReadAllText($txtPath))
    } catch {}
}

Function Test-ADAuditIsDomainController {
    # Returns $true if the host running the script is itself a Domain Controller.
    # Cached for the run. Used so host-local checks (registry/SMB config) know
    # whether reading the LOCAL machine is meaningful or whether they must target
    # a DC remotely (or report "could not assess").
    if ($null -ne $script:ADAuditIsDC) { return $script:ADAuditIsDC }
    try {
        # Win32_OperatingSystem.ProductType: 1=Workstation, 2=Domain Controller, 3=Member/Standalone Server
        $pt = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType
        $script:ADAuditIsDC = ($pt -eq 2)
    }
    catch {
        try {
            # DomainRole: 4=Backup DC, 5=Primary DC
            $role = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
            $script:ADAuditIsDC = ($role -in 4, 5)
        }
        catch { $script:ADAuditIsDC = $false }
    }
    return $script:ADAuditIsDC
}

Function Register-ADAuditNotAssessed {
    # Records a check (or a per-target portion of a check) that could NOT be
    # assessed, with the reason. Deliberately does NOT emit a Nessus/risk finding
    # so an un-assessable check never inflates the risk score.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Reason,
        [string]$Switch,
        [string]$Target,
        [switch]$RequiresRemotePS,
        [ValidateSet('','Timeout','Unreachable','AccessDenied','Unsupported','Excluded','Unavailable')][string]$Outcome = ''
    )
    if (-not $Switch) { $Switch = $script:ADAuditCurrentCheckSwitch }
    # Outcome separates deadline expiry, unreachable transport, denied access, unsupported
    # operations and intentional exclusion from generic unavailability. Derived from the
    # reason text when the caller does not state it.
    if (-not $Outcome) {
        $derived = Get-ADAuditOperationOutcome -Message $Reason
        $Outcome = if ($derived -in @('Timeout','Unreachable','AccessDenied','Unsupported','Excluded')) { $derived } else { 'Unavailable' }
    }
    $script:NotAssessed.Add([pscustomobject]@{
        Time             = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        CheckName        = $Name
        Switch           = $Switch
        Target           = $Target
        Reason           = $Reason
        Outcome          = $Outcome
        RequiresRemotePS = [bool]$RequiresRemotePS
    }) | Out-Null
    $tgt = if ($Target) { " [$Target]" } else { "" }
    Write-Both "    [~] NOT ASSESSED ($Name$tgt): $Reason"
}

Function Get-ADAuditRemoteRegistryValue {
    # Reads one HKLM value locally or with StdRegProv over DCOM first. Returns:
    #   Success=$true,  Value=<int>  -> reached the host, value is set
    #   Success=$true,  Value=$null  -> reached the host, value is NOT set
    #   Success=$false, Error=<msg>  -> could not reach/query the host (=> NotAssessed)
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$ValueName,
        [ValidateSet('Dword','String')][string]$ValueType = 'Dword',
        [switch]$UseWsmanFallback
    )
    $HKLM = [uint32]2147483650
    $result = @{ Success = $false; Value = $null; Error = $null }
    $regArgs = @{ hDefKey = $HKLM; sSubKeyName = $SubKey; sValueName = $ValueName }
    try {
        $method = if ($ValueType -eq 'Dword') { 'GetDWORDValue' } else { 'GetStringValue' }
        $r = Invoke-ADAuditCimMethod -ComputerName $ComputerName -Namespace 'root/default' -ClassName StdRegProv -MethodName $method -Arguments $regArgs -UseWsmanFallback:$UseWsmanFallback -ErrorAction Stop
        # Provider errors do not throw. Only missing key/value (1/2) is absence;
        # access denied, unsupported provider and other failures remain unknown.
        if ($r.ReturnValue -eq 0) {
            $result.Success = $true
            $result.Value = if ($ValueType -eq 'Dword') { $r.uValue } else { $r.sValue }
        } elseif ($r.ReturnValue -in 1, 2) {
            $result.Success = $true
        } else {
            $result.Error = "StdRegProv $method failed (ReturnValue=$($r.ReturnValue))"
        }
    } catch {
        $result.Error = $_.Exception.Message
    }
    return $result
}

Function Get-ADAuditRemoteRegistryDword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$ValueName
    )
    Get-ADAuditRemoteRegistryValue -ComputerName $ComputerName -SubKey $SubKey -ValueName $ValueName -ValueType Dword -UseWsmanFallback
}

Function Write-NotAssessedReport {
    # Writes the "could not assess" artifacts (not_assessed.txt/.csv) at end of run.
    # Surfaced as informational only - never scored.
    [CmdletBinding()]
    param([string]$BaseRoot)

    if (-not $script:NotAssessed -or $script:NotAssessed.Count -eq 0) { return }

    $rawDir = Get-RawSourceDataDir
    if (-not (Test-Path -LiteralPath $rawDir)) {
        New-Item -ItemType Directory -Path $rawDir -Force | Out-Null
    }
    $txtPath = Join-Path $rawDir 'not_assessed.txt'
    $csvPath = Join-Path $rawDir 'not_assessed.csv'

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(' CHECKS / TARGETS THAT COULD NOT BE ASSESSED')
    [void]$sb.AppendLine('=====================================================================')
    [void]$sb.AppendLine(" Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine(" Total: $($script:NotAssessed.Count)")
    [void]$sb.AppendLine('---------------------------------------------------------------------')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('What this file means:')
    [void]$sb.AppendLine(' - These checks (or specific DC targets) could NOT be evaluated, usually')
    [void]$sb.AppendLine('   because this host is not a DC and remote PowerShell/CIM to a DC was')
    [void]$sb.AppendLine('   unavailable, a DC was unreachable, or a required data source was absent.')
    [void]$sb.AppendLine(' - These are NOT findings and do NOT raise the risk score. They indicate')
    [void]$sb.AppendLine('   REDUCED COVERAGE: the corresponding posture is unknown, not "good".')
    [void]$sb.AppendLine(' - To assess them, re-run from a Domain Controller, or enable remote')
    [void]$sb.AppendLine('   PowerShell (WinRM) / DCOM to the DCs from this management host.')
    [void]$sb.AppendLine('')

    $i = 0
    foreach ($n in $script:NotAssessed) {
        $i++
        [void]$sb.AppendLine("[$i] $($n.CheckName)  ($($n.Time))")
        if ($n.Switch) { [void]$sb.AppendLine("    Switch          : -$($n.Switch)") }
        if ($n.Target) { [void]$sb.AppendLine("    Target          : $($n.Target)") }
        [void]$sb.AppendLine("    Outcome         : $($n.Outcome)")
        [void]$sb.AppendLine("    Requires remote : $(if($n.RequiresRemotePS){'YES (remote PowerShell/CIM to a DC)'}else{'no'})")
        [void]$sb.AppendLine("    Reason          : $($n.Reason)")
        [void]$sb.AppendLine('')
    }

    Set-Content -LiteralPath $txtPath -Value $sb.ToString() -Encoding UTF8
    $script:NotAssessed | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    Write-Both ""
    Write-Both "[~] $($script:NotAssessed.Count) item(s) could not be assessed (reduced coverage, not risk) - see not_assessed.txt"
}

Function Write-Nessus-Header() {
    #Creates nessus XML file header
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<?xml version=`"1.0`" ?><AdAudit>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<Report name=`"$env:ComputerName`" xmlns:cm=`"http://www.nessus.org/cm`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportHost name=`"$env:ComputerName`"><HostProperties></HostProperties>"
}

# Maps ADAudit KB identifiers to a Nessus severity tier so the exported
# .nessus file can be triaged by risk instead of every item landing on "Low".
# Anything not listed defaults to Medium; callers may override per finding by
# passing -Severity (Critical/High/Medium/Low/Info).
$script:NessusSeverityByKB = @{
    'KB510' = 'Critical'; 'KB1200' = 'Critical'; 'KB253' = 'Critical'; 'KB611' = 'Critical'
    'KB720' = 'Critical'; 'KB1095' = 'Critical'; 'KB1096' = 'Critical'; 'KB1205' = 'Critical'
    'KB329' = 'Critical'; 'KB1206' = 'Critical'
    'KB842' = 'High'; 'KB551' = 'High'; 'KB426' = 'High'; 'KB427' = 'High'; 'KB428' = 'High'
    'KB262' = 'High'; 'KB263' = 'High'; 'KB81' = 'High'; 'KB290' = 'High'; 'KB479' = 'High'
    'KB995' = 'High'; 'KB1101' = 'High'; 'KB1203' = 'High'; 'KB1204' = 'High'; 'KB258' = 'High'
    'KB250' = 'Medium'; 'KB251' = 'Medium'; 'KB254' = 'Medium'; 'KB259' = 'Medium'
    'KB500' = 'Medium'; 'KB546' = 'Medium'; 'KB547' = 'Medium'; 'KB549' = 'Medium'
    'KB550' = 'Medium'; 'KB552' = 'Medium'; 'KB1202' = 'Medium'; 'KB1310' = 'Medium'
    'KB309' = 'Medium'; 'KB1201' = 'Medium'
    'KB501' = 'Low'; 'KB1300' = 'Low'
}

function Get-NessusSeverityTuple([string]$Severity) {
    switch ($Severity) {
        'Critical' { return @{ Num = 4; Risk = 'Critical' } }
        'High'     { return @{ Num = 3; Risk = 'High' } }
        'Medium'   { return @{ Num = 2; Risk = 'Medium' } }
        'Low'      { return @{ Num = 1; Risk = 'Low' } }
        'Info'     { return @{ Num = 0; Risk = 'None' } }
        default    { return @{ Num = 2; Risk = 'Medium' } }
    }
}

Function Write-Nessus-Finding( [string]$pluginname, [string]$pluginid, [string]$pluginexample, [string]$Severity = '') {
    # Resolve severity: explicit override, else KB map, else Medium.
    if ([string]::IsNullOrWhiteSpace($Severity)) {
        $kb = ($pluginid -replace '[^A-Za-z0-9]', '')
        if ($script:NessusSeverityByKB.ContainsKey($kb)) { $Severity = $script:NessusSeverityByKB[$kb] }
        else { $Severity = 'Medium' }
    }
    $sev = Get-NessusSeverityTuple $Severity

    # Escape every value at write time so evidence text containing < > & " '
    # can never produce malformed XML (the previous post-hoc sanitizer could
    # not distinguish markup from content and left the file unparseable).
    $nameEsc = [System.Security.SecurityElement]::Escape([string]$pluginname)
    $idEsc = [System.Security.SecurityElement]::Escape([string]$pluginid)
    $exEsc = [System.Security.SecurityElement]::Escape([string]$pluginexample)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("<ReportItem port=`"0`" svc_name=`"`" protocol=`"`" severity=`"$($sev.Num)`" pluginID=`"ADAudit_$idEsc`" pluginName=`"$nameEsc`" pluginFamily=`"Windows`">")
    [void]$sb.AppendLine("<description>Active Directory audit finding: $nameEsc</description>")
    [void]$sb.AppendLine("<plugin_type>remote</plugin_type><risk_factor>$($sev.Risk)</risk_factor>")
    [void]$sb.AppendLine("<solution>Review the '$nameEsc' finding in the ADAudit report and remediate per its recommended action.</solution>")
    [void]$sb.AppendLine("<synopsis>ADAudit detected a potential issue: $nameEsc</synopsis>")
    [void]$sb.AppendLine("<plugin_output>$exEsc</plugin_output></ReportItem>")
    Add-Content -Path "$outputdir\adaudit.nessus" -Value $sb.ToString().TrimEnd()
}

Function Write-Nessus-Footer() {
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "</ReportHost></Report></AdAudit>"
}

Function Install-Dependencies {
    #Install optional dependency modules for the audit
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch { }

    Write-Both "    [+] Preparing optional dependency installation"

    try {
        if (Get-Command Install-PSResource -ErrorAction SilentlyContinue) {
            $repo = Get-PSResourceRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($repo -and -not $repo.Trusted) {
                Set-PSResourceRepository -Name PSGallery -Trusted -ErrorAction Stop
            }

            if (-not (Get-Module -ListAvailable -Name DSInternals)) {
                Install-PSResource -Name DSInternals -Scope CurrentUser -TrustRepository -ErrorAction Stop
            }
        }
        elseif (Get-Command Install-Module -ErrorAction SilentlyContinue) {
            $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($repo -and $repo.InstallationPolicy -eq 'Untrusted') {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            }

            if (-not (Get-Module -ListAvailable -Name DSInternals)) {
                Install-Module -Name DSInternals -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
        }
        else {
            Write-Both "    [!] No supported PowerShell package manager was found. Install DSInternals manually."
            return
        }

        if (Import-ADAuditModule -Name DSInternals) {
            Write-Both "    [+] DSInternals module is available."
        }
        else {
            Write-Both "    [!] DSInternals installation completed, but the module could not be imported in the current session."
        }

        if (Get-Module -ListAvailable -Name LAPS) {
            Write-Both "    [+] Windows LAPS module is available on this host."
        }
        elseif (Get-Module -ListAvailable -Name 'AdmPwd.PS') {
            Write-Both "    [+] Legacy Microsoft LAPS module (AdmPwd.PS) is available on this host."
        }
        else {
            Write-Both "    [*] No LAPS module was found. Windows LAPS ships with supported Windows builds; legacy Microsoft LAPS uses AdmPwd.PS."
        }
    }
    catch {
        Write-Both "    [!] Failed to install optional dependencies. $($_.Exception.Message)"
    }
}


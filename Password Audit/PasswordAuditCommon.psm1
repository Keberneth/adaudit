<#
.SYNOPSIS
Shared helpers for the Password Audit scripts (Invoke-PwnedPasswordCheck.ps1 and Invoke-SamePasswordCheck.ps1).

.DESCRIPTION
Centralizes the functions that were previously copy-pasted across both scripts:

- Resolve-DefaultServer
- Ensure-DirectoryPath
- Resolve-ParentDirectory
- Convert-BytesToHex
- Get-AccountTypeLabel
- Get-AccountStatusFromReplObject   (derives status from the DSInternals object; no per-account AD query)
- Test-NtlmHashPwned                (single hash; rich { Pwned; PwnedCount } object; retry/429/backoff)
- Invoke-HibpNtlmRangeLookup        (prefix-batched lookups; k-anonymity preserved)
- Get-ReplicatedAccountHashes       (Get-ADReplAccount + NTLM hash extraction in one place)

k-anonymity is preserved everywhere: only the first 5 characters of the NTLM hash are ever
transmitted, via the HIBP range endpoint in NTLM mode (?mode=ntlm).
#>

Set-StrictMode -Version Latest

function Write-PasswordAuditStage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Message)
    # Host output is visible in a console/transcript without contaminating the
    # success stream, which can contain credential-equivalent replication data.
    Write-Host ('[{0}] {1}' -f [datetime]::Now.ToString('HH:mm:ss'), $Message)
}

function Resolve-DefaultServer {
    [CmdletBinding()]
    param()

    $dcObj = Get-ADDomainController -Discover -ErrorAction Stop

    foreach ($propertyName in @('DNSHostName', 'HostName', 'Name')) {
        # ADDirectoryServer has no DNSHostName property; probing it directly
        # would throw under the module's StrictMode.
        $property = $dcObj.PSObject.Properties[$propertyName]
        if ($null -eq $property) {
            continue
        }
        $candidate = $property.Value
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            return [string]$candidate
        }
    }

    throw 'Could not determine a domain controller hostname.'
}

function Ensure-DirectoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Resolve-ParentDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent)) {
        return (Get-Location).Path
    }

    return $parent
}

function Convert-BytesToHex {
    [CmdletBinding()]
    param(
        [byte[]]$Bytes
    )

    if ($null -eq $Bytes -or $Bytes.Count -eq 0) {
        return $null
    }

    return (-join ($Bytes | ForEach-Object { $_.ToString('x2') })).ToUpperInvariant()
}

function Get-AccountTypeLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName
    )

    if ($AccountName -match '\$$') {
        return 'Computer'
    }

    return 'User'
}

function Get-AccountStatusFromReplObject {
    <#
    .SYNOPSIS
    Derives Active/Disabled/Unknown from the DSInternals replication object already in hand.

    .DESCRIPTION
    Avoids a per-account Get-ADUser / Get-ADComputer round-trip. Get-ADReplAccount returns a
    DSAccount object which exposes an Enabled property (nullable bool) and UserAccountControl.
    This reads Enabled first; if that is not populated it derives the state from the
    UserAccountControl ACCOUNTDISABLE bit (0x2). Returns 'Unknown' when neither is available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ReplAccount
    )

    # Preferred: the object's own Enabled flag.
    $enabled = $null
    if ($ReplAccount.PSObject.Properties['Enabled']) {
        $enabled = $ReplAccount.Enabled
    }

    if ($enabled -is [bool] -or ($null -ne $enabled -and $enabled -is [System.Nullable[bool]])) {
        if ($enabled) { return 'Active' }
        return 'Disabled'
    }

    # Fallback: derive from UserAccountControl (ACCOUNTDISABLE = 0x2).
    if ($ReplAccount.PSObject.Properties['UserAccountControl']) {
        $uac = $ReplAccount.UserAccountControl
        if ($null -ne $uac) {
            try {
                $uacInt = [int]$uac
                if (($uacInt -band 0x2) -ne 0) {
                    return 'Disabled'
                }
                return 'Active'
            }
            catch {
                # fall through to Unknown
            }
        }
    }

    return 'Unknown'
}

function Test-NtlmHashPwned {
    <#
    .SYNOPSIS
    Checks a single NTLM hash against HIBP (NTLM range mode) and returns a rich result object.

    .DESCRIPTION
    Always returns [pscustomobject]@{ Pwned; PwnedCount }.
    - Pwned      : 'Yes' | 'No' | 'LookupFailed'
    - PwnedCount : breach count when 'Yes', 0 when 'No', $null when 'LookupFailed'

    Retries transient web failures up to MaxRetries times with exponential backoff.
    Honors Retry-After on HTTP 429 responses. After exhausting retries, returns an EXPLICIT
    'LookupFailed' marker (never 'No') so callers can distinguish a failed lookup from a clean one.

    k-anonymity: only the 5-char prefix is transmitted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$NtlmHash,

        [Parameter(Mandatory = $false)]
        [string]$UserAgent = 'PasswordAuditCommon.psm1',

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 4
    )

    $NtlmHash = $NtlmHash.ToUpperInvariant()

    if ($NtlmHash -notmatch '^[A-F0-9]{32}$') {
        throw 'Invalid NTLM hash format; expected 32 hexadecimal characters. The supplied value is not logged.'
    }

    $suffix = $NtlmHash.Substring(5)
    $range = Invoke-HibpNtlmRangeLookup -Prefix $NtlmHash.Substring(0, 5) -UserAgent $UserAgent -MaxRetries $MaxRetries

    if ($range.Failed) {
        return [pscustomobject]@{
            Pwned      = 'LookupFailed'
            PwnedCount = $null
        }
    }

    if ($range.Suffixes.ContainsKey($suffix)) {
        return [pscustomobject]@{
            Pwned      = 'Yes'
            PwnedCount = $range.Suffixes[$suffix]
        }
    }

    return [pscustomobject]@{
        Pwned      = 'No'
        PwnedCount = 0
    }
}

function Invoke-HibpNtlmRangeLookup {
    <#
    .SYNOPSIS
    Fetches ALL suffixes for a single 5-char NTLM prefix from the HIBP range API, once.

    .DESCRIPTION
    The HIBP range API returns every suffix that shares a given 5-char prefix in a single
    response. This helper fetches that response once and returns the parsed suffix->count map,
    so callers can match many full hashes locally without refetching identical prefixes.

    Returns [pscustomobject]@{
        Prefix   = <5-char prefix>
        Failed   = <bool>              # $true if lookup could not be completed
        Suffixes = <hashtable>         # suffix (27-char, upper) -> [int64] count (real rows only)
    }

    Retries transient failures up to MaxRetries with exponential backoff; honors Retry-After
    on HTTP 429. Padded rows (count 0, from Add-Padding) are excluded from the map.
    k-anonymity: only the prefix is transmitted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $false)]
        [string]$UserAgent = 'PasswordAuditCommon.psm1',

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 4
    )

    $Prefix = $Prefix.ToUpperInvariant()
    if ($Prefix -notmatch '^[A-F0-9]{5}$') {
        throw 'Invalid range prefix; expected exactly five hexadecimal characters. The supplied value is not logged.'
    }
    $uri = 'https://api.pwnedpasswords.com/range/{0}?mode=ntlm' -f $Prefix

    $response = $null
    $attempt = 0

    while ($true) {
        $attempt++
        try {
            $response = Invoke-WebRequest -Uri $uri -Method Get -Headers @{
                'User-Agent'  = $UserAgent
                'Add-Padding' = 'true'
            } -TimeoutSec 30 -ErrorAction Stop
            break
        }
        catch {
            $ex = $_.Exception

            # Try to extract an HTTP status code / Retry-After from the exception's response.
            $statusCode = $null
            $retryAfterSeconds = $null
            $webResponse = $null
            if ($ex.PSObject.Properties['Response']) {
                $webResponse = $ex.Response
            }
            if ($null -ne $webResponse) {
                try {
                    if ($webResponse.PSObject.Properties['StatusCode']) {
                        $statusCode = [int]$webResponse.StatusCode
                    }
                }
                catch { }

                try {
                    $raw = $null
                    # System.Net.Http.HttpResponseMessage (PS 6+/7+)
                    if ($webResponse.PSObject.Properties['Headers'] -and
                        $webResponse.Headers.PSObject.Properties['RetryAfter'] -and
                        $null -ne $webResponse.Headers.RetryAfter) {
                        $ra = $webResponse.Headers.RetryAfter
                        if ($ra.PSObject.Properties['Delta'] -and $null -ne $ra.Delta) {
                            $raw = $ra.Delta.TotalSeconds
                        }
                    }
                    # System.Net.HttpWebResponse (Windows PowerShell 5.1)
                    if ($null -eq $raw -and $webResponse.PSObject.Properties['Headers']) {
                        try { $raw = $webResponse.Headers['Retry-After'] } catch { }
                    }
                    if ($null -ne $raw) {
                        $parsed = 0
                        if ([int]::TryParse([string]$raw, [ref]$parsed) -and $parsed -gt 0) {
                            $retryAfterSeconds = $parsed
                        }
                    }
                }
                catch { }
            }

            if ($attempt -gt $MaxRetries) {
                $failureKind = if ($statusCode) { "HTTP $statusCode" } else { 'network/TLS request error' }
                Write-Warning ("HIBP range lookup failed after {0} attempt(s): {1}. Affected accounts remain LookupFailed. Check HTTPS/proxy/TLS access; no response body or password prefix is logged." -f $attempt, $failureKind)
                return [pscustomobject]@{
                    Prefix   = $Prefix
                    Failed   = $true
                    Suffixes = @{}
                }
            }

            # Exponential backoff (1,2,4,8...), capped. 429 Retry-After overrides when present.
            $delay = [math]::Min([math]::Pow(2, ($attempt - 1)), 30)
            if ($statusCode -eq 429 -and $null -ne $retryAfterSeconds) {
                $delay = $retryAfterSeconds
            }
            elseif ($statusCode -eq 429) {
                # 429 without a usable Retry-After: back off a little harder.
                $delay = [math]::Min($delay * 2, 60)
            }

            Write-Warning ("HIBP range request failed (attempt {0}/{1}{2}); retrying in {3}s. Password prefixes and response bodies are not logged." -f `
                $attempt, ($MaxRetries + 1), $(if ($statusCode) { ", HTTP $statusCode" } else { ', network/TLS request error' }), $delay)
            Start-Sleep -Seconds ([int]$delay)
        }
    }

    $suffixes = @{}
    $validRows = 0
    $invalidResponse = $false
    if ($null -eq $response -or -not $response.PSObject.Properties['Content'] -or [string]::IsNullOrWhiteSpace([string]$response.Content)) {
        $invalidResponse = $true
    } else {
        foreach ($line in ([string]$response.Content -split "(`r`n|`n|`r)")) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }
            # A successful HTTP response may still be a proxy error page or a
            # truncated/malformed range. Never turn an unvalidated body into No.
            $entry = $line.Trim()
            if ($entry -notmatch '^(?<Suffix>[A-Fa-f0-9]{27}):(?<Count>[0-9]+)$') {
                $invalidResponse = $true
                break
            }
            $returnedSuffix = $Matches['Suffix'].ToUpperInvariant()
            $countValue = [int64]0
            if (-not [int64]::TryParse($Matches['Count'], [ref]$countValue)) {
                $invalidResponse = $true
                break
            }
            $validRows++
            # Count-zero entries are padding, not matches.
            if ($countValue -gt 0) { $suffixes[$returnedSuffix] = $countValue }
        }
    }
    if ($invalidResponse -or $validRows -eq 0) {
        Write-Warning 'HIBP returned an empty or malformed range response. Affected lookups remain unknown; response content is not logged.'
        return [pscustomobject]@{ Prefix=$Prefix; Failed=$true; Suffixes=@{} }
    }

    return [pscustomobject]@{
        Prefix   = $Prefix
        Failed   = $false
        Suffixes = $suffixes
    }
}

function Get-PwnedResultsForHashes {
    <#
    .SYNOPSIS
    Checks a set of unique NTLM hashes against HIBP, batching one range fetch per 5-char prefix.

    .DESCRIPTION
    Groups the supplied unique hashes by their 5-char prefix, fetches each prefix's range
    EXACTLY ONCE, then matches every hash that shares that prefix against the cached suffix set
    locally. Returns a hashtable keyed by the full (upper-case) hash whose values are the rich
    result object [pscustomobject]@{ Pwned; PwnedCount } (Pwned = 'Yes'|'No'|'LookupFailed').

    k-anonymity: only the 5-char prefix is ever transmitted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Hashes,

        [Parameter(Mandatory = $false)]
        [string]$UserAgent = 'PasswordAuditCommon.psm1',

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 4
    )

    $result = @{}

    $normalized = @(
        $Hashes |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.ToUpperInvariant() } |
            Select-Object -Unique
    )

    if ($normalized.Count -eq 0) {
        return $result
    }
    foreach ($hash in $normalized) {
        if ($hash -notmatch '^[A-F0-9]{32}$') { throw 'Invalid NTLM hash format; expected 32 hexadecimal characters. The supplied value is not logged.' }
    }

    $byPrefix = @($normalized | Group-Object -Property { $_.Substring(0, 5) })
    $timer = [diagnostics.stopwatch]::StartNew()
    $completed = 0
    $failedRanges = 0
    $lastMessageSeconds = 0
    Write-PasswordAuditStage ("HIBP lookup started: {0} unique hashes in {1} range requests. Each request can take 30 seconds before retrying." -f $normalized.Count, $byPrefix.Count)

    try { foreach ($prefixGroup in $byPrefix) {
        Write-Progress -Id 42 -Activity 'Password audit: HIBP range lookups' -Status ("{0}/{1} ranges completed; {2} failed; elapsed {3:n0}s" -f $completed,$byPrefix.Count,$failedRanges,$timer.Elapsed.TotalSeconds) -PercentComplete ([int](100*$completed/$byPrefix.Count))
        $prefix = [string]$prefixGroup.Name
        $range = Invoke-HibpNtlmRangeLookup -Prefix $prefix -UserAgent $UserAgent -MaxRetries $MaxRetries
        $completed++
        if ($range.Failed) { $failedRanges++ }
        if ($timer.Elapsed.TotalSeconds - $lastMessageSeconds -ge 30 -or $completed -eq $byPrefix.Count) {
            Write-PasswordAuditStage ("HIBP progress: {0}/{1} ranges completed; {2} failed; elapsed {3:n0}s." -f $completed,$byPrefix.Count,$failedRanges,$timer.Elapsed.TotalSeconds)
            $lastMessageSeconds = $timer.Elapsed.TotalSeconds
        }

        foreach ($hash in $prefixGroup.Group) {
            if ($range.Failed) {
                $result[$hash] = [pscustomobject]@{
                    Pwned      = 'LookupFailed'
                    PwnedCount = $null
                }
                continue
            }

            $suffix = $hash.Substring(5)
            if ($range.Suffixes.ContainsKey($suffix)) {
                $result[$hash] = [pscustomobject]@{
                    Pwned      = 'Yes'
                    PwnedCount = $range.Suffixes[$suffix]
                }
            }
            else {
                $result[$hash] = [pscustomobject]@{
                    Pwned      = 'No'
                    PwnedCount = 0
                }
            }
        }
    } } finally { Write-Progress -Id 42 -Activity 'Password audit: HIBP range lookups' -Completed; $timer.Stop() }

    return $result
}

function Get-ReplicatedAccountHashes {
    <#
    .SYNOPSIS
    Runs Get-ADReplAccount -All and returns the raw replication objects.

    .DESCRIPTION
    Centralizes the full-domain secrets replication call so both scripts invoke it identically.
    Returns the array of DSInternals replication objects; hash extraction (Convert-BytesToHex on
    $ra.NTHash) and account filtering remain in each caller, which have different scoping rules.
    Throws if no accounts are returned.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$NamingContext
    )

    $timer = [diagnostics.stopwatch]::StartNew()
    $lastMessageSeconds = 0
    $replAccounts = New-Object System.Collections.Generic.List[object]
    Write-PasswordAuditStage 'AD replication started. Waiting for DSInternals; the first result can take several minutes. The total account count is not known yet.'
    Write-Progress -Id 41 -Activity 'Password audit: AD replication' -Status 'Waiting for the first account; total count unknown' -PercentComplete -1
    try {
        Get-ADReplAccount -All -Server $Server -NamingContext $NamingContext -ErrorAction Stop | ForEach-Object {
            $replAccounts.Add($_)
            if ($replAccounts.Count -eq 1 -or $replAccounts.Count % 100 -eq 0) {
                Write-Progress -Id 41 -Activity 'Password audit: AD replication' -Status ("{0} accounts received; elapsed {1:n0}s; total count unknown" -f $replAccounts.Count,$timer.Elapsed.TotalSeconds) -PercentComplete -1
            }
            if ($timer.Elapsed.TotalSeconds - $lastMessageSeconds -ge 30) {
                Write-PasswordAuditStage ("AD replication progress: {0} accounts received; elapsed {1:n0}s." -f $replAccounts.Count,$timer.Elapsed.TotalSeconds)
                $lastMessageSeconds = $timer.Elapsed.TotalSeconds
            }
        }
    } finally { Write-Progress -Id 41 -Activity 'Password audit: AD replication' -Completed; $timer.Stop() }

    if ($replAccounts.Count -eq 0) {
        throw "No replication accounts were returned from $Server."
    }

    Write-PasswordAuditStage ("AD replication completed: {0} accounts received in {1:n1}s." -f $replAccounts.Count,$timer.Elapsed.TotalSeconds)
    return $replAccounts.ToArray()
}

function Export-PasswordAuditSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutCsv,
        [Parameter(Mandatory)][ValidateSet('Pwned','Duplicate')][string]$Mode,
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][int]$ReturnedCount,
        [Parameter(Mandatory)][int]$ProcessedCount,
        [int]$ExcludedCount, [int]$MissingNameCount, [int]$MissingHashCount,
        [int]$EnabledProcessedCount, [int]$DisabledProcessedCount, [int]$UnknownProcessedCount,
        [int]$LookupFailedCount, [int]$DuplicateGroupCount, [int]$HibpCheckedCount,
        [switch]$HibpRequested,
        [AllowEmptyCollection()][object[]]$Results = @()
    )
    # Only explicitly allowed display fields are serialized below. In particular,
    # this helper never serializes replication objects or full NT/LM hashes.
    $findingRows = @($Results | Where-Object {
        $_.SamAccountName -and ($(if ($Mode -eq 'Pwned') { $_.Pwned -eq 'Yes' } else { $_.DuplicatePasswordGroup -ne '' }))
    })
    $enabled = @($findingRows | Where-Object AccountStatus -in @('Active','Enabled')).Count
    $disabled = @($findingRows | Where-Object AccountStatus -eq 'Disabled').Count
    $unknown = @($findingRows | Where-Object AccountStatus -eq 'Unknown').Count
    $unavailableRows = @($Results | Where-Object { $_.SamAccountName -and $_.Pwned -eq 'NotAssessed' })
    $missingEnabled = @($unavailableRows | Where-Object AccountStatus -in @('Active','Enabled')).Count
    $missingDisabled = @($unavailableRows | Where-Object AccountStatus -eq 'Disabled').Count
    # Include missing records without display rows in the unknown-state bucket.
    $missingUnknown = [math]::Max(0, $MissingHashCount - $missingEnabled - $missingDisabled)
    $coverage = if ($ProcessedCount -eq 0) { 'Not assessed' } elseif ($MissingHashCount -or $MissingNameCount -or $LookupFailedCount -or $unknown -or $UnknownProcessedCount) { 'Partial' } else { 'Complete for selected scope' }
    $coverageReasons = New-Object System.Collections.Generic.List[string]
    if ($ProcessedCount -eq 0) { $coverageReasons.Add('No accounts had usable password material for the selected check.') }
    if ($MissingHashCount) { $coverageReasons.Add(("Accounts with unavailable NT password material: {0} ({1} enabled, {2} disabled, {3} unknown state)." -f $MissingHashCount,$missingEnabled,$missingDisabled,$missingUnknown)) }
    if ($MissingNameCount) { $coverageReasons.Add("$MissingNameCount accounts had no usable account name.") }
    if ($LookupFailedCount) { $coverageReasons.Add("$LookupFailedCount accounts could not complete their HIBP lookup.") }
    if ($UnknownProcessedCount -or $unknown) { $coverageReasons.Add('Some account enablement states could not be established.') }
    if ($coverageReasons.Count -eq 0) { $coverageReasons.Add('All available accounts in the selected scope completed the requested check.') }
    $hibpStatus = if (-not $HibpRequested) { 'Not requested' } elseif ($HibpCheckedCount -eq 0 -and $LookupFailedCount -gt 0) { 'Failed' } elseif ($LookupFailedCount -gt 0) { 'Partial' } elseif ($HibpCheckedCount -gt 0) { 'Completed' } else { 'No eligible accounts' }
    $summary = [pscustomobject][ordered]@{
        GeneratedUTC=[datetime]::UtcNow.ToString('o'); Audit=$Mode; SourceServer=$Server; Coverage=$coverage
        CoverageReasons=($coverageReasons -join ' ')
        ReturnedAccounts=$ReturnedCount; ExcludedByScope=$ExcludedCount; MissingAccountName=$MissingNameCount
        ProcessedAccounts=$ProcessedCount; MissingNTPasswordMaterial=$MissingHashCount
        MissingNTEnabledAccounts=$missingEnabled; MissingNTDisabledAccounts=$missingDisabled; MissingNTUnknownStateAccounts=$missingUnknown
        EnabledProcessedAccounts=$EnabledProcessedCount; DisabledProcessedAccounts=$DisabledProcessedCount; UnknownStateProcessedAccounts=$UnknownProcessedCount
        HIBPRequested=[bool]$HibpRequested; HIBPStatus=$hibpStatus; HIBPSuccessfulAccounts=$HibpCheckedCount; HIBPLookupFailedAccounts=$LookupFailedCount
        EnabledFindingAccounts=$enabled; DisabledFindingAccounts=$disabled; UnknownStateFindingAccounts=$unknown
        DuplicateGroups=$DuplicateGroupCount
    }
    $summaryPath = [IO.Path]::ChangeExtension($OutCsv, 'summary.csv')
    $htmlPath = [IO.Path]::ChangeExtension($OutCsv, 'html')
    $summary | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8
    $encode = { param($value) [System.Net.WebUtility]::HtmlEncode([string]$value) }
    $html = [System.Text.StringBuilder]::new()
    [void]$html.AppendLine(@'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Password audit</title><style>
:root{color-scheme:light;--page:#f4f6fa;--surface:#fff;--text:#172033;--muted:#536174;--border:#ccd3df;--card:#f8fafc;--header:#e9eef5;--note:#edf3fa;--accent:#6588ad;--link:#174a8b}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d1420;--surface:#151f2e;--text:#e5ecf6;--muted:#aebed2;--border:#43526a;--card:#1d2a3c;--header:#29384d;--note:#20344b;--accent:#91b9ed;--link:#a9d1ff}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d1420;--surface:#151f2e;--text:#e5ecf6;--muted:#aebed2;--border:#43526a;--card:#1d2a3c;--header:#29384d;--note:#20344b;--accent:#91b9ed;--link:#a9d1ff}
body{font:16px system-ui,sans-serif;color:var(--text);background:var(--page);margin:0}main{max-width:1200px;margin:2rem auto;padding:2rem;background:var(--surface);border:1px solid var(--border);border-radius:14px}h1{margin:0 0 .4rem}h2{font-size:1.2rem;margin-top:1.5rem}.meta{color:var(--muted);font-size:.9rem}.toolbar{display:flex;justify-content:flex-end;gap:.6rem;align-items:center;margin-bottom:1rem}.toolbar label{color:var(--muted);font-size:.9rem}select{font:inherit;color:var(--text);background:var(--card);border:1px solid var(--border);border-radius:6px;padding:.35rem}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.8rem;margin:1.4rem 0}.metric{border:1px solid var(--border);border-radius:10px;padding:1rem;background:var(--card)}.metric-label{font-size:.85rem;color:var(--muted)}.metric-value{font-size:1.8rem;font-weight:700;margin-top:.3rem}.metric-value.coverage{font-size:1.1rem;line-height:1.45}.table-wrap{overflow-x:auto;max-width:100%}table{border-collapse:collapse;width:100%;margin:.8rem 0}th,td{text-align:left;border:1px solid var(--border);padding:.6rem;vertical-align:top;overflow-wrap:anywhere}th{background:var(--header)}.account-table{min-width:760px}.scope-table th{width:34%;font-weight:600}a{color:var(--link)}.note{background:var(--note);border-left:4px solid var(--accent);padding:1rem;line-height:1.5}details{border:1px solid var(--border);border-radius:8px;padding:.8rem;margin:1rem 0}summary{cursor:pointer;font-weight:600}
@media(max-width:760px){main{margin:0;padding:1rem;border-radius:0}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media print{:root{color-scheme:light}body,main,.metric,.note,th,td{background:#fff!important;color:#000!important;border-color:#777!important}.toolbar{display:none}main{margin:0;border:0;max-width:none}.metrics{grid-template-columns:repeat(4,minmax(0,1fr))}.table-wrap{overflow:visible}.account-table{min-width:0;font-size:10px}a{color:#000!important}}
</style></head><body><main><div class="toolbar"><label for="theme">Appearance</label><select id="theme" aria-label="Report appearance"><option value="system">Use system setting</option><option value="light">Light</option><option value="dark">Dark</option></select></div>
<script>(function(){var select=document.getElementById('theme');function apply(value){if(value==='light'||value==='dark'){document.documentElement.setAttribute('data-theme',value)}else{document.documentElement.removeAttribute('data-theme');value='system'}select.value=value}try{apply(localStorage.getItem('adaudit-password-theme')||'system')}catch(e){apply('system')}select.addEventListener('change',function(){apply(select.value);try{localStorage.setItem('adaudit-password-theme',select.value)}catch(e){}})})();</script>
'@)
    $reportTitle = if ($Mode -eq 'Duplicate') { 'Shared password assessment' } else { 'Known breached password assessment' }
    [void]$html.AppendLine("<h1>$reportTitle</h1><p class='meta'>Source: $(& $encode $Server) · Generated: $(& $encode $summary.GeneratedUTC)</p>")
    [void]$html.AppendLine("<div class='metrics'><div class='metric'><div class='metric-label'>Assessment coverage</div><div class='metric-value coverage'>$(& $encode $coverage)</div></div><div class='metric'><div class='metric-label'>Enabled finding accounts</div><div class='metric-value'>$enabled</div></div><div class='metric'><div class='metric-label'>Disabled finding accounts</div><div class='metric-value'>$disabled</div></div><div class='metric'><div class='metric-label'>Unknown-state finding accounts</div><div class='metric-value'>$unknown</div></div></div>")
    [void]$html.AppendLine("<p class='note'><strong>Coverage explanation:</strong> $(& $encode $summary.CoverageReasons)<br><strong>HIBP lookup:</strong> $(& $encode $hibpStatus). $HibpCheckedCount accounts completed their lookup; $LookupFailedCount failed.</p>")
    [void]$html.AppendLine('<p class="note">Enabled accounts are prioritized for remediation. Disabled accounts remain visible for cleanup and reactivation review. Unknown account state, unavailable password material and failed lookups are not evidence of a clean account. A corpus match identifies a known password, not proof this customer account was breached. A negative match is not proof of password strength.</p>')
    $friendlyLabels = @{
        GeneratedUTC='Report generated (UTC)'; Audit='Assessment type'; SourceServer='Source domain controller'; Coverage='Assessment coverage'; CoverageReasons='Coverage explanation'
        ReturnedAccounts='Accounts returned by replication'; ExcludedByScope='Accounts excluded by scope'; MissingAccountName='Accounts without a usable name'
        ProcessedAccounts='Accounts with password material checked'; MissingNTPasswordMaterial='Accounts without NT password material'
        MissingNTEnabledAccounts='Enabled accounts without NT material'; MissingNTDisabledAccounts='Disabled accounts without NT material'; MissingNTUnknownStateAccounts='Unknown-state accounts without NT material'
        EnabledProcessedAccounts='Enabled accounts checked'; DisabledProcessedAccounts='Disabled accounts checked'; UnknownStateProcessedAccounts='Checked accounts with unknown enablement state'
        HIBPRequested='HIBP lookup requested'; HIBPStatus='HIBP run status'; HIBPSuccessfulAccounts='Accounts with a successful HIBP lookup'; HIBPLookupFailedAccounts='Accounts with a failed HIBP lookup'
        EnabledFindingAccounts='Enabled finding accounts'; DisabledFindingAccounts='Disabled finding accounts'; UnknownStateFindingAccounts='Finding accounts with unknown enablement state'
        DuplicateGroups='Shared password groups'
    }
    $lookupScope = if (-not $HibpRequested) { 'HIBP lookup was not requested. NotChecked is expected; run Invoke-SamePasswordCheck.ps1 -Pwned to include that optional lookup.' } elseif ($Mode -eq 'Duplicate') { 'HIBP lookup covers shared password groups only; unique-password accounts are outside that lookup.' } else { 'HIBP lookup covers accounts with available NT password material in the selected scope.' }
    [void]$html.AppendLine("<h2>Collection scope</h2><p>$ProcessedCount of $ReturnedCount returned accounts had password material checked; $ExcludedCount excluded by scope; $MissingHashCount without NT password material. $lookupScope</p><details><summary>Collection totals and lookup coverage</summary><div class='table-wrap'><table class='scope-table'><tbody>")
    foreach ($property in $summary.PSObject.Properties) {
        $label = if ($friendlyLabels.ContainsKey($property.Name)) { $friendlyLabels[$property.Name] } else { $property.Name }
        [void]$html.AppendLine("<tr><th scope='row'>$(& $encode $label)</th><td>$(& $encode $property.Value)</td></tr>")
    }
    [void]$html.AppendLine('</tbody></table></div></details><p class="meta">Results describe the directory data returned by the selected controller at collection time. An isolated or cloned controller may contain historical account and password state.</p><h2>Recommended actions</h2><p>Prioritize enabled privileged and service accounts. Coordinate password rotation with application owners and dependencies; use unique credentials and managed service accounts where supported. Review disabled accounts before reactivation. Investigate unavailable password material separately from failed network lookups. Shared password group identifiers apply only within this run.</p>')
    $columns = @('SamAccountName','AccountType','AccountStatus','DuplicatePasswordGroup','DuplicatePasswordGroupSize','Pwned','PwnedCount','Comment')
    $presentColumns = @($columns | Where-Object { $field=$_; @($Results | Where-Object { $_.PSObject.Properties[$field] }).Count -gt 0 })
    $otherRows = @($Results | Where-Object {
        -not ($_.SamAccountName -and ($(if ($Mode -eq 'Pwned') { $_.Pwned -eq 'Yes' } else { $_.DuplicatePasswordGroup -ne '' })))
    })
    $sections = @(
        [pscustomobject]@{Title='Confirmed account findings';Rows=$findingRows;Collapsed=$false},
        [pscustomobject]@{Title='Unavailable checks and additional evidence';Rows=$otherRows;Collapsed=$true}
    )
    foreach ($section in $sections) {
        if ($section.Rows.Count -eq 0) { continue }
        if ($section.Collapsed) { [void]$html.AppendLine("<details><summary>$($section.Title) (records: $($section.Rows.Count))</summary>") }
        else { [void]$html.AppendLine("<h2>$($section.Title)</h2>") }
        [void]$html.AppendLine('<div class="table-wrap"><table class="account-table"><thead><tr>')
        $columnLabels = @{SamAccountName='Account';AccountType='Account type';AccountStatus='Account state';DuplicatePasswordGroup='Shared password group';DuplicatePasswordGroupSize='Accounts in group';Pwned='HIBP result';PwnedCount='Corpus occurrences';Comment='Evidence and interpretation'}
        foreach ($column in $presentColumns) { [void]$html.AppendLine("<th>$(& $encode $columnLabels[$column])</th>") }
        [void]$html.AppendLine('</tr></thead><tbody>')
        foreach ($row in $section.Rows) {
            [void]$html.AppendLine('<tr>')
            foreach ($column in $presentColumns) {
                $value = if ($row.PSObject.Properties[$column]) { $row.$column } else { '' }
                [void]$html.AppendLine("<td>$(& $encode $value)</td>")
            }
            [void]$html.AppendLine('</tr>')
        }
        [void]$html.AppendLine('</tbody></table></div>')
        if ($section.Collapsed) { [void]$html.AppendLine('</details>') }
    }
    [void]$html.AppendLine("<p><a href='$(& $encode ([uri]::EscapeDataString([IO.Path]::GetFileName($OutCsv))))'>Download account evidence</a> · <a href='$(& $encode ([uri]::EscapeDataString([IO.Path]::GetFileName($summaryPath))))'>Download coverage summary</a></p></main></body></html>")
    Set-Content -LiteralPath $htmlPath -Value $html.ToString() -Encoding UTF8
    Write-Host "Coverage: $coverage. Enabled finding accounts: $enabled; disabled: $disabled; unknown state: $unknown."
    Write-Host ("Coverage explanation: {0} HIBP status: {1}." -f $summary.CoverageReasons,$hibpStatus)
    Write-Host "Customer report: $htmlPath"
}

Export-ModuleMember -Function `
    Write-PasswordAuditStage, `
    Resolve-DefaultServer, `
    Ensure-DirectoryPath, `
    Resolve-ParentDirectory, `
    Convert-BytesToHex, `
    Get-AccountTypeLabel, `
    Get-AccountStatusFromReplObject, `
    Test-NtlmHashPwned, `
    Invoke-HibpNtlmRangeLookup, `
    Get-PwnedResultsForHashes, `
    Get-ReplicatedAccountHashes, `
    Export-PasswordAuditSummary

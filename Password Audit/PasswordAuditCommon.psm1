<#
.SYNOPSIS
Shared helpers for the Password Audit scripts (pwned_password_prof.ps1 and same_passwd_prof.ps1).

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
        throw "Invalid NTLM hash format: $NtlmHash"
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
                Write-Warning ("Failed pwned lookup for hash prefix {0} after {1} attempt(s): {2}" -f $Prefix, $attempt, $ex.Message)
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

            Write-Warning ("HIBP lookup for prefix {0} failed (attempt {1}/{2}{3}); retrying in {4}s: {5}" -f `
                $Prefix, ($attempt), ($MaxRetries + 1), $(if ($statusCode) { ", HTTP $statusCode" } else { '' }), $delay, $ex.Message)
            Start-Sleep -Seconds ([int]$delay)
        }
    }

    $suffixes = @{}

    if (-not [string]::IsNullOrWhiteSpace($response.Content)) {
        foreach ($line in ($response.Content -split "(`r`n|`n|`r)")) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $parts = $line.Split(':', 2)
            if ($parts.Count -ne 2) {
                continue
            }

            $returnedSuffix = $parts[0].Trim().ToUpperInvariant()
            $countText = $parts[1].Trim()

            # Ignore padded fake rows when Add-Padding=true.
            if ($countText -eq '0') {
                continue
            }

            $countValue = [int64]0
            [void][int64]::TryParse($countText, [ref]$countValue)

            $suffixes[$returnedSuffix] = $countValue
        }
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

    $byPrefix = $normalized | Group-Object -Property { $_.Substring(0, 5) }

    foreach ($prefixGroup in $byPrefix) {
        $prefix = [string]$prefixGroup.Name
        $range = Invoke-HibpNtlmRangeLookup -Prefix $prefix -UserAgent $UserAgent -MaxRetries $MaxRetries

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
    }

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

    $replAccounts = @(Get-ADReplAccount -All -Server $Server -NamingContext $NamingContext -ErrorAction Stop)

    if ($replAccounts.Count -eq 0) {
        throw "No replication accounts were returned from $Server."
    }

    return $replAccounts
}

Export-ModuleMember -Function `
    Resolve-DefaultServer, `
    Ensure-DirectoryPath, `
    Resolve-ParentDirectory, `
    Convert-BytesToHex, `
    Get-AccountTypeLabel, `
    Get-AccountStatusFromReplObject, `
    Test-NtlmHashPwned, `
    Invoke-HibpNtlmRangeLookup, `
    Get-PwnedResultsForHashes, `
    Get-ReplicatedAccountHashes

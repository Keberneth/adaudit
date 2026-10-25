<# Offline tests of HIBP response validation. No network or AD calls. #>
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'Password Audit/PasswordAuditCommon.psm1'
$tokens=$null; $issues=$null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$issues)
if (@($issues).Count) { throw 'Password audit module did not parse.' }
foreach ($name in @('Write-PasswordAuditStage','Invoke-HibpNtlmRangeLookup','Test-NtlmHashPwned','Get-PwnedResultsForHashes','Get-ReplicatedAccountHashes')) {
    $definition = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    Invoke-Expression $definition.Extent.Text
}
$script:requestCount=0
$script:mockBody=''
$script:requestUri=''
$script:mockRequestFailure=$false
function Invoke-WebRequest {
    param($Uri,$Method,$Headers,$TimeoutSec,$ErrorAction)
    $script:requestCount++
    $script:requestUri=[string]$Uri
    if ($script:mockRequestFailure) { throw "Synthetic TLS failure at $Uri" }
    [pscustomobject]@{Content=$script:mockBody}
}
$assertions=0
function Assert-Lookup([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw "Assertion failed: $Message" }
    $script:assertions++
}
$testHash='AAAAABBBBBBBBBBBBBBBBBBBBBBBBBBB'
foreach ($body in @('', '   ', '<html>Proxy maintenance</html>', ('B'*27 + ':not-a-number'), ('B'*27 + ':9223372036854775808'), ('B'*26 + ':5'))) {
    $script:mockBody=$body
    $result=Test-NtlmHashPwned -NtlmHash $testHash -MaxRetries 0 -WarningAction SilentlyContinue
    Assert-Lookup ($result.Pwned -eq 'LookupFailed' -and $null -eq $result.PwnedCount) 'Empty, malformed or invalid-count HTTP success responses remain unknown.'
}
$script:mockBody=('B'*27 + ':7') + "`r`n" + ('C'*27 + ':0')
$result=Test-NtlmHashPwned -NtlmHash $testHash -MaxRetries 0
Assert-Lookup ($result.Pwned -eq 'Yes' -and $result.PwnedCount -eq 7) 'A validated suffix match retains the actual count.'
Assert-Lookup ($script:requestUri -eq 'https://api.pwnedpasswords.com/range/AAAAA?mode=ntlm') 'Only the five-character prefix is included in the request.'
$result=Test-NtlmHashPwned -NtlmHash ('AAAAA' + 'C'*27) -MaxRetries 0
Assert-Lookup ($result.Pwned -eq 'No' -and $result.PwnedCount -eq 0) 'Padding rows are not counted as matches.'
$script:mockBody=('B'*27 + ':7') + "`ntruncated-data"
$result=Get-PwnedResultsForHashes -Hashes @($testHash,('AAAAA'+'D'*27)) -MaxRetries 0 -WarningAction SilentlyContinue
Assert-Lookup ($result[$testHash].Pwned -eq 'LookupFailed' -and $result['AAAAA'+'D'*27].Pwned -eq 'LookupFailed') 'A malformed range makes every hash using that range unknown.'
$before=$script:requestCount; $safeError=$false
try { Invoke-HibpNtlmRangeLookup -Prefix $testHash | Out-Null } catch { $safeError=$_.Exception.Message -notmatch [regex]::Escape($testHash) }
Assert-Lookup ($safeError -and $script:requestCount -eq $before) 'An oversized range prefix is rejected without a request or echoed hash.'
$safeError=$false
try { Get-PwnedResultsForHashes -Hashes @('bad-value') | Out-Null } catch { $safeError=$_.Exception.Message -notmatch 'bad-value' }
Assert-Lookup ($safeError -and $script:requestCount -eq $before) 'Invalid batched hashes fail without a request or echoed input.'

$script:mockRequestFailure=$true
$lookupWarnings=@()
$result=Test-NtlmHashPwned -NtlmHash $testHash -MaxRetries 0 -WarningVariable lookupWarnings -WarningAction SilentlyContinue
Assert-Lookup ($result.Pwned -eq 'LookupFailed') 'A transport failure is unknown, not a negative corpus match.'
Assert-Lookup (($lookupWarnings -join ' ') -notmatch 'AAAAA|range/|Synthetic TLS') 'Network diagnostics exclude queried prefixes and the raw exception body.'
$script:mockRequestFailure=$false

$script:progressMessages=New-Object System.Collections.Generic.List[object]
$script:stageMessages=New-Object System.Collections.Generic.List[string]
function Write-Progress {
    param($Id,$Activity,$Status,$PercentComplete,[switch]$Completed)
    $script:progressMessages.Add([pscustomobject]@{Id=$Id;Activity=$Activity;Status=$Status;Percent=$PercentComplete;Completed=[bool]$Completed})
}
function Write-PasswordAuditStage { param([string]$Message) $script:stageMessages.Add($Message) }
$script:mockBody=('B'*27 + ':7')
$result=Get-PwnedResultsForHashes -Hashes @($testHash,('CCCCC'+'B'*27)) -MaxRetries 0
Assert-Lookup ($result.Count -eq 2 -and @($script:progressMessages | Where-Object Completed).Count -eq 1) 'Batched lookup keeps its results and completes its progress indicator.'
Assert-Lookup (($script:stageMessages -join ' ') -match '2/2 ranges completed') 'Console progress includes completed and total ranges.'
Assert-Lookup (($script:stageMessages -join ' ') -notmatch 'AAAAA|CCCCC') 'Batch progress contains no password prefixes.'

$script:progressMessages.Clear(); $script:stageMessages.Clear()
function Get-ADReplAccount {
    param([switch]$All,$Server,$NamingContext,$ErrorAction)
    [pscustomobject]@{SamAccountName='synthetic-one';NTHash=[byte[]](1..16)}
    [pscustomobject]@{SamAccountName='synthetic-two';NTHash=[byte[]](2..17)}
}
$replicated=@(Get-ReplicatedAccountHashes -Server 'dc.test' -NamingContext 'DC=test')
Assert-Lookup ($replicated.Count -eq 2 -and $replicated[0].NTHash.Count -eq 16) 'Replication progress does not contaminate or alter the data stream.'
Assert-Lookup (($script:stageMessages -join ' ') -match '2 accounts received' -and ($script:stageMessages -join ' ') -notmatch 'synthetic-one|synthetic-two') 'Replication console messages show counts without account identities.'
Assert-Lookup (@($script:progressMessages | Where-Object Completed).Count -eq 1) 'Replication completes its progress indicator.'
Write-Host "Password lookup tests passed: $assertions assertions. No network or AD calls were made."

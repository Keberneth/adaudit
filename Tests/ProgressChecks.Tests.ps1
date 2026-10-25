# Offline progress regression tests. No AD module, directory access or network calls.
# Run: pwsh -NoProfile -File Tests/ProgressChecks.Tests.ps1
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$script:assertions = 0
function Assert-ProgressCondition {
    param([bool]$Condition, [string]$Message)
    $script:assertions++
    if (-not $Condition) { throw "Assertion failed: $Message" }
}
function Import-ProgressTestFunction {
    param([string]$Path, [string]$Name)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw ($errors.Message -join '; ') }
    $definition = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true)
    if (-not $definition) { throw "Missing test function: $Name" }
    Set-Item -Path "function:global:$Name" -Value ([scriptblock]::Create($definition.Body.Extent.Text.TrimStart('{').TrimEnd('}')))
}

$script:progressCalls = [System.Collections.Generic.List[object]]::new()
$script:unknownCalls = [System.Collections.Generic.List[object]]::new()
function Write-ADAuditProgress {
    param([string]$Activity, [string]$Status, [double]$PercentComplete = -1, [switch]$Completed)
    $script:progressCalls.Add([pscustomobject]@{ Activity=$Activity; Status=$Status; Percent=$PercentComplete; Completed=[bool]$Completed })
}
function Register-ADAuditNotAssessed {
    param([string]$Name, [string]$Switch, [string]$Target, [string]$Reason)
    $script:unknownCalls.Add([pscustomobject]@{ Name=$Name; Target=$Target; Reason=$Reason })
}
function Write-Both { param([string]$Message) }
function Write-Nessus-Finding { }

$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ('adaudit-progress-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    . (Join-Path $repo 'Checks/Invoke-DangerousAclCheck.ps1')
    $outputdir = $fixture
    function Get-EvidencePath { param([string]$Name) Join-Path $fixture $Name }
    function Get-HtmlReportsDir { param([string]$BaseRoot) $fixture }
    function Get-ADDomain {
        [CmdletBinding()]param()
        [pscustomobject]@{ NetBIOSName='EXAMPLE'; DomainSID=[pscustomobject]@{ Value='S-1-5-21-1-2-3' } }
    }
    function Get-ADObject {
        [CmdletBinding()]param($Filter, $Properties, $ResultPageSize)
        if ([string]$Filter -match "objectClass -eq 'computer'") {
            [pscustomobject]@{ DistinguishedName='CN=readable,DC=example'; Name='readable' }
            [pscustomobject]@{ DistinguishedName='CN=unreadable,DC=example'; Name='unreadable' }
        } elseif ([string]$Filter -match "objectCategory -eq 'person'") {
            [pscustomobject]@{ DistinguishedName='CN=user,DC=example'; Name='user' }
        }
    }
    $script:aclReads = 0
    function Get-ADObjectAclSafe {
        param([string]$DistinguishedName)
        $script:aclReads++
        if ($DistinguishedName -like 'CN=unreadable,*') { throw 'Synthetic access denied' }
        [pscustomobject]@{ Access=@() }
    }
    Invoke-DangerousAclCheck -WarningAction SilentlyContinue
    Assert-ProgressCondition ($script:aclReads -eq 3) 'Each object ACL is read once, including the failed target.'
    Assert-ProgressCondition ($script:unknownCalls.Count -eq 1) 'Unreadable ACL remains not assessed.'
    $computerCompletion = @($script:progressCalls | Where-Object { $_.Activity -eq 'ACL: computers' -and $_.Status -eq '2/2 ACL reads finished; 1 unreadable' })
    Assert-ProgressCondition ($computerCompletion.Count -eq 1 -and $computerCompletion[0].Percent -eq 100) 'Failed ACL reads advance attempted-work progress without claiming successful assessment.'
    Assert-ProgressCondition ($script:progressCalls[$script:progressCalls.Count - 1].Completed) 'ACL progress is cleared after normal completion.'
    $coverage = @(Import-Csv (Join-Path $fixture 'dangerous_acl_coverage.csv'))
    Assert-ProgressCondition (@($coverage | Where-Object Status -eq 'Assessed').Count -eq 2) 'Coverage retains the two successfully assessed objects.'
    Assert-ProgressCondition (@($coverage | Where-Object Status -eq 'NotAssessed').Count -eq 1) 'Coverage retains the unreadable object.'

    function Get-ADObject { [CmdletBinding()]param($Filter,$Properties,$ResultPageSize) throw 'Synthetic enumeration failure' }
    $script:progressCalls.Clear()
    $caught = $false
    try { Invoke-DangerousAclCheck } catch { $caught = $true }
    Assert-ProgressCondition $caught 'Directory enumeration failure is preserved.'
    Assert-ProgressCondition ($script:progressCalls[$script:progressCalls.Count - 1].Completed) 'ACL progress is cleared after enumeration failure.'

    # Successful SID translations are reused only inside the supplied run cache.
    $script:translations = 0
    $identity = [pscustomobject]@{ Name='EXAMPLE\Readers' }
    $identity | Add-Member -MemberType ScriptMethod -Name ToString -Value { $this.Name } -Force
    $identity | Add-Member -MemberType ScriptMethod -Name Translate -Value {
        param($TargetType)
        $script:translations++
        [pscustomobject]@{ Value='S-1-5-21-1-2-3-513' }
    }
    $ace = [pscustomobject]@{ IdentityReference=$identity }
    $sidCache = @{}
    $first = Get-ADAuditAceSid -Ace $ace -Cache $sidCache
    $second = Get-ADAuditAceSid -Ace $ace -Cache $sidCache
    Assert-ProgressCondition ($first -eq $second -and $script:translations -eq 1) 'Repeated trustees use one successful SID translation per run.'
    [void](Get-ADAuditAceSid -Ace $ace -Cache @{})
    Assert-ProgressCondition ($script:translations -eq 2) 'A new run cache does not reuse earlier trustee translations.'
    $sid = Get-ADAuditAceSid -Ace ([pscustomobject]@{ IdentityReference='S-1-5-11' }) -Cache $sidCache
    Assert-ProgressCondition ($sid -eq 'S-1-5-11' -and $script:translations -eq 2) 'SID-valued trustees require no translation.'
    $script:retryTranslations = 0
    $retryIdentity = [pscustomobject]@{ Name='EXAMPLE\TemporaryLookupFailure' }
    $retryIdentity | Add-Member -MemberType ScriptMethod -Name ToString -Value { $this.Name } -Force
    $retryIdentity | Add-Member -MemberType ScriptMethod -Name Translate -Value {
        param($TargetType)
        $script:retryTranslations++
        if ($script:retryTranslations -eq 1) { throw 'Synthetic temporary translation failure' }
        [pscustomobject]@{ Value='S-1-5-21-1-2-3-515' }
    }
    $retryAce = [pscustomobject]@{ IdentityReference=$retryIdentity }
    $missingSid = Get-ADAuditAceSid -Ace $retryAce -Cache $sidCache
    $recoveredSid = Get-ADAuditAceSid -Ace $retryAce -Cache $sidCache
    Assert-ProgressCondition ($null -eq $missingSid -and $recoveredSid -eq 'S-1-5-21-1-2-3-515' -and $script:retryTranslations -eq 2) 'Failed SID lookups are not cached as a false negative.'

    # Every standard entry point owns cleanup even if its implementation throws.
    foreach ($name in @('Accounts','PasswordPolicy','OUPermissions','GroupPolicy','OldBoxes','DataExtract','HighRisk')) {
        Import-ProgressTestFunction -Path (Join-Path $repo "Checks/Invoke-${name}Check.ps1") -Name "Invoke-${name}Check"
    }
    function Invoke-AuditStep { param($Name,$Switch,$Body) throw 'Synthetic step failure' }
    function Get-OUPerms { throw 'Synthetic OU failure' }
    function Get-OldBoxes { throw 'Synthetic computer failure' }
    function Export-ADAuditDataExtract { throw 'Synthetic export failure' }
    function Get-HighRiskADBaselineReport { throw 'Synthetic baseline failure' }
    foreach ($name in @('Accounts','PasswordPolicy','OUPermissions','GroupPolicy','OldBoxes','DataExtract','HighRisk')) {
        $script:progressCalls.Clear()
        $caught = $false
        try { & "Invoke-${name}Check" } catch { $caught = $true }
        Assert-ProgressCondition ($caught -and $script:progressCalls[$script:progressCalls.Count - 1].Completed) "$name clears child progress and preserves failures."
    }

    $lateralPath = Join-Path $repo 'Checks/Invoke-LateralMovementCheck.ps1'
    Import-ProgressTestFunction -Path $lateralPath -Name 'Write-LmProgress'
    Import-ProgressTestFunction -Path $lateralPath -Name 'Invoke-LmMain'
    $script:LmHasSharedProgress = $true
    $script:LmNotAssessed = [System.Collections.Generic.List[object]]::new()
    function Write-LmLog { param([string]$Message) }
    function Get-LmRuleCatalog { @{} }
    function Get-LmWellKnownCatalog { @() }
    function Get-LmOutputDirs { param($OutputRoot) @{ Lm=$fixture } }
    function Register-LmNotAssessed { param($Reason,$Target) }
    function Get-LmDirectoryData { throw 'Synthetic lateral directory failure' }
    $script:progressCalls.Clear()
    [void](Invoke-LmMain -OutputRoot $fixture)
    Assert-ProgressCondition ($script:progressCalls[$script:progressCalls.Count - 1].Completed) 'Lateral progress clears after handled directory failure and early return.'
    function Get-LmDirectoryData { [pscustomobject]@{ GroupIds=@(1) } }
    function Invoke-LmGraphAnalysis { throw 'Synthetic graph failure' }
    $script:progressCalls.Clear()
    $caught = $false
    try { Invoke-LmMain -OutputRoot $fixture } catch { $caught = $true }
    Assert-ProgressCondition ($caught -and $script:progressCalls[$script:progressCalls.Count - 1].Completed) 'Lateral progress clears after unhandled analysis failure.'

    $script:LmHasSharedProgress = $false
    $script:LmProgressActivity = ''
    $script:LmProgressUi = [datetime]::MinValue
    $script:LmProgressLog = [datetime]::MinValue
    $script:nativeProgress = [System.Collections.Generic.List[object]]::new()
    function Write-Progress {
        param($Id,$Activity,$Status,$PercentComplete,[switch]$Completed)
        $script:nativeProgress.Add([pscustomobject]@{ Id=$Id; Completed=[bool]$Completed })
    }
    Write-LmProgress -Activity 'Synthetic standalone phase' -Status 'Waiting for collection' -PercentComplete -1
    Write-LmProgress -Activity 'Synthetic standalone phase' -Completed
    Assert-ProgressCondition ($script:nativeProgress.Count -eq 2 -and @($script:nativeProgress | Where-Object Id -ne 1).Count -eq 0) 'Standalone lateral progress uses its reserved ID 1.'
    Assert-ProgressCondition ($script:nativeProgress[1].Completed) 'Standalone completion bypasses throttling.'

    # An isolated clone keeps known edges but does not resolve names or domains
    # through production systems. Every AD command and SID constructor is mocked.
    foreach ($name in @('Get-LmDirectoryData','New-LmNode','Get-LmRdnValue','Get-LmParentDn','Get-LmDnDomainSuffix','Get-LmScopeName','Test-LmSecurityGroup','Add-LmListItem','ConvertFrom-LmFileTime')) {
        Import-ProgressTestFunction -Path $lateralPath -Name $name
    }
    $script:LmHasSharedProgress = $true
    $script:ADAuditIsolatedClone = $true
    $script:LmWellKnownSids = @{}
    $script:cloneQueries = [System.Collections.Generic.List[object]]::new()
    $script:cloneUnknown = [System.Collections.Generic.List[object]]::new()
    $script:foreignSidConstructors = 0
    function New-Object {
        [CmdletBinding()]param([Parameter(Position=0)]$TypeName,[Parameter(Position=1)]$ArgumentList)
        if ($TypeName -eq 'System.Security.Principal.SecurityIdentifier') {
            $script:foreignSidConstructors++
            throw 'Offline test blocks SID translation.'
        }
        Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
    }
    function Register-LmNotAssessed {
        param($Reason,$Target)
        $script:cloneUnknown.Add([pscustomobject]@{ Reason=$Reason; Target=$Target })
    }
    function Get-ADDomain {
        [CmdletBinding()]param($Server,$Identity)
        $script:cloneQueries.Add([pscustomobject]@{ Command='Domain'; Server=$Server; Identity=$Identity })
        if ($Identity) { throw 'Offline test blocks another domain.' }
        [pscustomobject]@{ DomainSID=[pscustomobject]@{Value='S-1-5-21-1-2-3'}; DistinguishedName='DC=child,DC=example'; DNSRoot='child.example'; NetBIOSName='CHILD' }
    }
    function Get-ADForest {
        [CmdletBinding()]param($Server)
        $script:cloneQueries.Add([pscustomobject]@{ Command='Forest'; Server=$Server; Identity='' })
        [pscustomobject]@{ RootDomain='root.example' }
    }
    function Get-ADObject {
        [CmdletBinding()]param($Server,$LDAPFilter,$SearchBase,$SearchScope,$Properties,$ResultPageSize,$Identity)
        $script:cloneQueries.Add([pscustomobject]@{ Command='Object'; Server=$Server; Identity=$Identity })
        if ($Identity) { throw 'Offline test blocks individual member lookup.' }
        if ($LDAPFilter -eq '(objectCategory=group)') {
            [pscustomobject]@{
                DistinguishedName='CN=Role,DC=child,DC=example'; name='Role'; sAMAccountName='Role'
                objectSid=[pscustomobject]@{Value='S-1-5-21-1-2-3-1100'}; groupType=-2147483646
                member=@('CN=S-1-5-21-8-9-10-512,CN=ForeignSecurityPrincipals,DC=child,DC=example','CN=ForeignGroup,DC=external,DC=example')
            }
        }
    }
    $graph = Get-LmDirectoryData -Server 'do-not-contact.invalid' -Catalog @() -TierTagPattern 'T{0}' -AdminGroupPattern 'admin' -AdminAccountPattern 'adm' -TemporaryGroupPattern 'temp'
    Assert-ProgressCondition (@($script:cloneQueries | Where-Object { $_.Server -ne $env:COMPUTERNAME }).Count -eq 0) 'Clone collection pins every AD request to this computer.'
    Assert-ProgressCondition (@($script:cloneQueries | Where-Object { $_.Identity }).Count -eq 0 -and $script:foreignSidConstructors -eq 0) 'Clone collection makes no other-domain or foreign SID resolution attempts.'
    Assert-ProgressCondition ($graph.Nodes.Count -eq 3 -and $graph.Edges.Count -eq 2) 'Skipped external members and their known membership edges remain in the graph.'
    Assert-ProgressCondition ($graph.Stats.Unresolved -eq 2 -and $graph.Coverage.Count -eq 1 -and $script:cloneUnknown.Count -eq 3) 'Unresolved members and forest-root classification are disclosed as coverage gaps.'
    Remove-Item function:New-Object

    Import-ProgressTestFunction -Path $lateralPath -Name 'Write-LmHtmlReport'
    Import-ProgressTestFunction -Path $lateralPath -Name 'Get-LmHtmlEncoded'
    Import-ProgressTestFunction -Path (Join-Path $repo 'Library/ADAudit.Common.ps1') -Name 'Get-ADAuditCloneNotice'
    function Get-LmHtmlJson { param($Data,$Summary,$HtmlUserLimit,$Dirs,$HtmlPath) '{}' }
    function Get-LmPrimaryNav { '' }
    $script:LmHtmlCss=''; $script:LmHtmlBody='<main>Fixture</main>'; $script:LmHtmlJs1=''; $script:LmHtmlJs2=''
    $script:ADAuditSnapshotDate = '2026-10-20'
    $htmlPath = Write-LmHtmlReport -Data $graph -Summary @{} -Dirs @{Html=$fixture} -HtmlUserLimit 10
    $html = Get-Content -LiteralPath $htmlPath -Raw
    Assert-ProgressCondition ($html -match 'ISOLATED CLONE' -and $html -match '2026-10-20') 'The separate lateral HTML renderer includes the shared clone notice.'
    $script:ADAuditIsolatedClone = $false
    $htmlPath = Write-LmHtmlReport -Data $graph -Summary @{} -Dirs @{Html=$fixture} -HtmlUserLimit 10
    Assert-ProgressCondition ((Get-Content -LiteralPath $htmlPath -Raw) -notmatch 'ISOLATED CLONE') 'A normal lateral HTML report does not receive a clone notice.'

    Write-Host "$script:assertions progress assertions passed. No live AD or network operations were executed."
} finally {
    $fullFixture = [System.IO.Path]::GetFullPath($fixture)
    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $fullFixture.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $fullFixture -Leaf) -notlike 'adaudit-progress-*') { throw 'Refusing to clean an unexpected fixture path.' }
    Remove-Item -LiteralPath $fullFixture -Recurse -Force -ErrorAction SilentlyContinue
}

# Offline synthetic graph regressions. No collectors, AD commands or network calls.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path -Parent $PSScriptRoot) 'Checks/Invoke-LateralMovementCheck.ps1'
$tokens=$null; $parseErrors=$null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors) { throw ($parseErrors.Message -join '; ') }
foreach ($name in @('Get-LmRuleCatalog','Get-LmWellKnownCatalog','Get-LmParentDn','Get-LmRdnValue','Get-LmDnDomainSuffix','New-LmNode','Add-LmListItem','Get-LmChainSinkRank','Invoke-LmGraphAnalysis','Add-LmFinding','Get-LmMaxSeverity','Get-LmGroupLabel','Test-LmKnownTier0Path','Invoke-LmFindings')) {
    $definition = $ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Write-LmLog { param($Message) }
function Write-LmProgress { param($Activity,$Status,$PercentComplete,[switch]$Completed) }
function Register-LmNotAssessed { param($Reason,$Target) throw "Unexpected coverage error in a synthetic graph: $Reason" }
$script:LmSeverityRank = @{Critical=5; High=4; Medium=3; Low=2; Information=1}
$script:LmSeverityScore = @{Critical=40; High=20; Medium=8; Low=3; Information=0}
$script:LmRules = Get-LmRuleCatalog
$script:assertions=0
function Assert-Lateral { param([bool]$Condition,[string]$Message) $script:assertions++; if (-not $Condition) { throw "Assertion failed: $Message" } }
function New-FixtureGraph {
    @{
        DomainSid='S-1-5-21-1-2-3'; Nodes=[System.Collections.Generic.List[object]]::new()
        GroupIds=[System.Collections.Generic.List[int]]::new(); PrincipalIds=[System.Collections.Generic.List[int]]::new()
        Edges=[System.Collections.Generic.List[object]]::new()
        Parents=[System.Collections.Generic.Dictionary[int,System.Collections.Generic.List[int]]]::new()
        Children=[System.Collections.Generic.Dictionary[int,System.Collections.Generic.List[int]]]::new()
        BySid=[System.Collections.Generic.Dictionary[string,int]]::new(); BySam=[System.Collections.Generic.Dictionary[string,int]]::new()
        Stats=@{EnabledUsers=0}; CycleCount=0
    }
}
function Add-FixtureNode {
    param($Data,[string]$Name,[string]$Type='group',[string]$KnownKey='', [switch]$AdminName, [switch]$NamedTier0, [switch]$Broad)
    $node=New-LmNode -Id $Data.Nodes.Count -Dn "CN=$Name,DC=example" -Type $Type
    $node.Name=$Name; $node.Sam=$Name; $node.Scope='Global'; $node.Security=$true
    $node.Enabled=$true; $node.AdminIsh=[bool]$AdminName; $node.AdminNamed=$true; $node.Broad=[bool]$Broad
    $node.BroadReason='synthetic broad membership'; $node.WhenCreated=Get-Date; $node.LastLogon=Get-Date; $node.PwdLastSet=Get-Date
    if ($NamedTier0) { $node.DeclTier=0; $node.DeclTierSource='name tag' }
    if ($KnownKey) {
        $entry=@(Get-LmWellKnownCatalog | Where-Object Key -eq $KnownKey)[0]
        $node.WellKnown=$entry.Name; $node.WkKey=$KnownKey; $node.WkTier=$entry.Tier
        $node.Sid=if($entry.Where -eq 'Builtin') {"S-1-5-32-$($entry.Rid)"} else {"$($Data.DomainSid)-$($entry.Rid)"}
        if ($entry.Tier -eq 0) { $node.DeclTier=0; $node.DeclTierSource='well-known' }
    } else { $node.Sid="$($Data.DomainSid)-$(1100+$node.Id)" }
    $Data.Nodes.Add($node); $Data.BySid[$node.Sid]=$node.Id; $Data.BySam[$node.Sam]=$node.Id
    if ($Type -eq 'group') { $Data.GroupIds.Add($node.Id) } else { $Data.PrincipalIds.Add($node.Id); $Data.Stats.EnabledUsers++ }
    return $node
}
function Add-FixtureEdge {
    param($Data,$Parent,$Child,[string]$Kind='member')
    $Data.Edges.Add([pscustomobject]@{P=$Parent.Id;C=$Child.Id;Kind=$Kind})
    Add-LmListItem -Dict $Data.Parents -Key $Child.Id -Value $Parent.Id
    Add-LmListItem -Dict $Data.Children -Key $Parent.Id -Value $Child.Id
    $Child.ParentsCount++
    $Parent.DirectTotal++
    if($Child.Type -eq 'group'){$Parent.DirectGroups++}elseif($Child.Type -eq 'user'){$Parent.DirectUsers++}
}
function Invoke-Fixture {
    param($Data)
    Invoke-LmGraphAnalysis -Data $Data
    Invoke-LmFindings -Data $Data
}
function New-NestedFixture {
    param([switch]$NameOnly,[switch]$Disabled,[switch]$Spn,[switch]$NoPreAuth)
    $data=New-FixtureGraph
    $target=if($NameOnly){Add-FixtureNode $data 'T0-Application' -NamedTier0}else{Add-FixtureNode $data 'Domain Admins' -KnownKey DA}
    $role=Add-FixtureNode $data 'ReviewedRole'
    $user=Add-FixtureNode $data 'adm-auditor' -Type user
    $user.Enabled=-not $Disabled; $user.HasSpn=[bool]$Spn; if($Spn){$user.Spns=1}; if($NoPreAuth){$user.Uac=0x400000}
    Add-FixtureEdge $data $target $role
    Add-FixtureEdge $data $role $user
    return $data
}

$graph=New-NestedFixture
Invoke-Fixture $graph
$user=$graph.Nodes[2]
Assert-Lateral ($user.ReachesT0 -and $user.T0Targets.Count -eq 1) 'Confirmed nested Domain Admin membership is retained.'
Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM01' -and $_.Severity -eq 'High' }).Count -eq 1) 'Ordinary privileged group nesting is a High review rather than automatically Critical.'
Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM02' -and $_.Severity -eq 'High' }).Count -eq 1) 'Ordinary nested user membership is a High review rather than automatically Critical.'
Assert-Lateral (@($graph.Findings | Where-Object Severity -eq 'Critical').Count -eq 0) 'Nesting without another exposure does not make this graph Critical.'

$graph=New-NestedFixture -NameOnly -Spn
Invoke-Fixture $graph
Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM02' -and $_.Severity -eq 'Medium' }).Count -eq 1) 'A Tier 0 name tag alone produces a Medium membership review.'
Assert-Lateral (@($graph.Findings | Where-Object Severity -eq 'Critical').Count -eq 0) 'An SPN plus a name-only Tier 0 path is not treated as verified critical privilege.'

$graph=New-NestedFixture -Disabled -Spn -NoPreAuth
Invoke-Fixture $graph
Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM15' -and $_.Severity -eq 'Low' }).Count -eq 1) 'Disabled Tier 0 SPN/preauth accounts remain Low hygiene findings.'
Assert-Lateral (@($graph.Findings | Where-Object { $_.Subject -eq 'adm-auditor' -and $_.Severity -in @('Critical','High') }).Count -eq 0) 'Disabled user flags do not create an active high-severity account finding.'
$graph=New-NestedFixture -NoPreAuth
Invoke-Fixture $graph
Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM15' -and $_.Severity -eq 'Critical' }).Count -eq 1) 'Enabled preauthentication exposure retains its Critical priority.'
$graph=New-NestedFixture -Spn
Invoke-Fixture $graph
Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM15' -and $_.Severity -eq 'Critical' }).Count -eq 1) 'An enabled SPN account with confirmed high-impact privileged membership retains Critical review priority.'

foreach ($nameOnly in @($true,$false)) {
    $graph=New-FixtureGraph
    $target=if($nameOnly){Add-FixtureNode $graph 'T0-Application' -NamedTier0}else{Add-FixtureNode $graph 'Domain Admins' -KnownKey DA}
    $user=Add-FixtureNode $graph 'primary-user' -Type user
    $user.PrimaryGroupId=[int]($target.Sid.Split('-')[-1])
    Add-FixtureEdge $graph $target $user -Kind primary
    Invoke-Fixture $graph
    $expected=if($nameOnly){'Medium'}else{'Critical'}
    Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM04' -and $_.Severity -eq $expected }).Count -eq 1) "Primary-group priority distinguishes name-only classification from SID-identified privilege ($expected)."
}

$graph=New-FixtureGraph
$named=Add-FixtureNode $graph 'T0-Application' -NamedTier0
$foreign=Add-FixtureNode $graph 'BroadForeignIdentity' -Type fsp -Broad
Add-FixtureEdge $graph $named $foreign
Invoke-Fixture $graph
Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM03' -and $_.Severity -eq 'High' }).Count -eq 1) 'Broad foreign membership into a name-only Tier 0 group does not assert Critical verified privilege.'

foreach ($cycle in @($false,$true)) {
    $graph=New-FixtureGraph
    $role=Add-FixtureNode $graph 'Aggregation'
    $user=Add-FixtureNode $graph 'ordinary-user' -Type user
    $user.AdminNamed=$false
    Add-FixtureEdge $graph $role $user
    for($i=1;$i -le 10;$i++) {
        $candidate=Add-FixtureNode $graph "App-$i-Admins" -AdminName
        Add-FixtureEdge $graph $candidate $role
        if($cycle -and $i -eq 1){Add-FixtureEdge $graph $role $candidate}
    }
    Invoke-Fixture $graph
    Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM22' -and $_.Subject -eq 'Aggregation' -and $_.Severity -eq 'Medium' }).Count -eq 1) 'Ten admin-name matches are a Medium group-membership review.'
    Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM23' -and $_.Severity -eq 'Medium' }).Count -eq 1) 'Account names and ten admin-name matches do not imply High or Critical host access.'
    Assert-Lateral (@($graph.Findings | Where-Object Severity -eq 'Critical').Count -eq 0) 'Name-based administration reach, including a loop, does not make the graph Critical.'
    Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -in @('LM22','LM23') -and $_.Detail -match 'administrators on every|holds administrative membership on .*system' }).Count -eq 0) 'Name-matched groups are not described as verified administrator rights on systems.'
    if($cycle){Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM05' -and $_.Severity -eq 'High' }).Count -eq 1) 'An administrative-name membership loop remains visible as High review.'}
}

$graph=New-FixtureGraph
$broad=Add-FixtureNode $graph 'AllEmployees' -Broad
$named=Add-FixtureNode $graph 'Application-Admins' -AdminName
Add-FixtureEdge $graph $named $broad
Invoke-Fixture $graph
Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM06' -and $_.Severity -eq 'High' }).Count -eq 1) 'Broad membership in an admin-named group is a High review with unverified permissions.'
Assert-Lateral (@($graph.Findings | Where-Object Severity -eq 'Critical').Count -eq 0) 'An administrative name alone cannot turn broad group membership Critical.'

$graph=New-FixtureGraph
$broad=Add-FixtureNode $graph 'Domain Users' -KnownKey DU -Broad
$target=Add-FixtureNode $graph 'Domain Admins' -KnownKey DA
Add-FixtureEdge $graph $target $broad
Invoke-Fixture $graph
Assert-Lateral (@($graph.Findings | Where-Object { $_.RuleId -eq 'LM06' -and $_.Severity -eq 'Critical' }).Count -eq 1) 'Broad membership reaching a SID-identified Domain Admins group remains Critical.'

Write-Host "$script:assertions lateral severity assertions passed. No live AD or network operations were executed."

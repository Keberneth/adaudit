<# Read-only DC SMB configuration and share-root permission evidence.
   Loaded by Invoke-DomainAuditCheck.ps1; never performs remediation or probes access
   with another identity. ACE candidates are not an effective-access calculation. #>

function Get-ADAuditDcBoolean {
    param([AllowNull()]$Object, [string]$Name)
    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name] -or $null -eq $Object.$Name) { return $null }
    $value = $Object.$Name
    if ($value -is [bool]) { return $value }
    if ([string]$value -match '^(?i:true|1)$') { return $true }
    if ([string]$value -match '^(?i:false|0)$') { return $false }
    return $null
}

function Get-ADAuditDcEffectiveEncryption {
    param([AllowNull()]$Server, [AllowNull()]$Share)
    $serverRequired = Get-ADAuditDcBoolean $Server 'EncryptData'
    $shareRequired = Get-ADAuditDcBoolean $Share 'EncryptData'
    $reject = Get-ADAuditDcBoolean $Server 'RejectUnencryptedAccess'
    if ($reject -eq $false) { return $false }
    if ($serverRequired -eq $true -or $shareRequired -eq $true) {
        if ($reject -eq $true) { return $true }
        return $null
    }
    if ($serverRequired -eq $false -and $shareRequired -eq $false) { return $false }
    return $null
}

function Invoke-ADAuditDcSecurityDescriptor {
    param([string]$ComputerName,[string]$ClassName,[string]$Key,[string]$Value)
    Assert-ADAuditRemoteTargetAllowed -ComputerName $ComputerName
    # A client-only keyed instance avoids a preliminary enumeration. The method
    # is sent through the same bounded DCOM-first transport as all other CIM reads.
    $instance = New-CimInstance -ClassName $ClassName -Namespace 'root/cimv2' -Property @{$Key=$Value} -Key $Key -ClientOnly
    $parameters = @{InputObject=$instance;MethodName='GetSecurityDescriptor';OperationTimeoutSec=$script:ADAuditCimOperationTimeoutSec;ErrorAction='Stop'}
    $response = if (Test-ADAuditLocalComputer $ComputerName) { Invoke-CimMethod @parameters } else {
        Invoke-ADAuditCimRequest -Kind Method -Parameters $parameters -ComputerName $ComputerName -UseWsmanFallback $true -Label "$ClassName.GetSecurityDescriptor"
    }
    if ($null -eq $response -or $null -eq $response.ReturnValue -or $response.ReturnValue -ne 0 -or $null -eq $response.Descriptor) {
        $code = if ($null -ne $response) { $response.ReturnValue } else { 'no response' }
        if ($code -in @(2,9)) { throw [System.UnauthorizedAccessException]::new("Security descriptor access denied (provider code $code).") }
        throw "Security descriptor unavailable (provider code $code)."
    }
    return $response.Descriptor
}

function ConvertTo-ADAuditDcAceRows {
    param([string]$Target,[string]$ShareName,[string]$Layer,[Parameter(Mandatory)]$Descriptor)
    if ($null -eq $Descriptor.PSObject.Properties['ControlFlags']) { throw 'Security descriptor control flags were not returned.' }
    if ($null -eq $Descriptor.PSObject.Properties['DACL']) { throw 'Security descriptor DACL property was not returned.' }
    # An absent/null DACL and an explicitly empty DACL have opposite meanings.
    if (([long]$Descriptor.ControlFlags -band 4) -eq 0 -or $null -eq $Descriptor.DACL) {
        return [pscustomobject]@{Target=$Target;ShareName=$ShareName;Layer=$Layer;TrusteeSid='S-1-1-0';Identity='Everyone (null DACL)';AccessControlType='Allow';AccessMask=268435456;Rights='GenericAll (null DACL)';AceFlags=0;IsInherited=$false;InheritanceFlags='None';PropagationFlags='None'}
    }
    foreach ($ace in @($Descriptor.DACL)) {
        if ($null -eq $ace.PSObject.Properties['AccessMask'] -or $null -eq $ace.AccessMask -or $null -eq $ace.PSObject.Properties['AceType'] -or $null -eq $ace.AceType) { throw 'An ACE did not expose its rights or access-control type.' }
        $sid = [string]$ace.Trustee.SIDString
        if (-not $sid -and $ace.Trustee.SID) { try { $sid = [Security.Principal.SecurityIdentifier]::new([byte[]]$ace.Trustee.SID,0).Value } catch { } }
        if (-not $sid) { throw 'An ACE trustee SID could not be read; principal scope is unknown.' }
        $identity = if ($ace.Trustee.Name) { if ($ace.Trustee.Domain) { "$($ace.Trustee.Domain)\$($ace.Trustee.Name)" } else { [string]$ace.Trustee.Name } } else { $sid }
        $mask = [long]$ace.AccessMask
        $rights = try { ([Security.AccessControl.FileSystemRights]$mask).ToString() } catch { '0x{0:X8}' -f $mask }
        $flags = [int]$ace.AceFlags
        [pscustomobject]@{
            Target=$Target;ShareName=$ShareName;Layer=$Layer;TrusteeSid=$sid;Identity=$identity
            AccessControlType=$(if ([int]$ace.AceType -in @(0,5)) {'Allow'} elseif ([int]$ace.AceType -in @(1,6)) {'Deny'} else {"Other ($($ace.AceType))"})
            AccessMask=$mask;Rights=$rights;AceFlags=$flags;IsInherited=($flags -band 16) -ne 0
            InheritanceFlags=(@($(if ($flags -band 1) {'ObjectInherit'}),$(if ($flags -band 2) {'ContainerInherit'})) | Where-Object {$_}) -join ','
            PropagationFlags=(@($(if ($flags -band 4) {'NoPropagateInherit'}),$(if ($flags -band 8) {'InheritOnly'})) | Where-Object {$_}) -join ','
        }
    }
}

function Test-ADAuditDcBroadTrustee {
    param([string]$Sid)
    return $Sid -in @('S-1-1-0','S-1-5-7','S-1-5-11','S-1-5-32-545','S-1-5-32-546') -or $Sid -match '^S-1-5-21-\d+-\d+-\d+-(513|515)$'
}

function Test-ADAuditDcWriteMask {
    param([long]$Mask)
    # Generic all/write, WRITE_DAC, WRITE_OWNER, DELETE, write/append data,
    # write attributes/EA and delete-child. Ordinary read/execute is not flagged.
    $writeMask = 0x10000000L -bor 0x40000000L -bor 0x40000L -bor 0x80000L -bor 0x10000L -bor 2L -bor 4L -bor 16L -bor 64L -bor 256L
    return ($Mask -band $writeMask) -ne 0
}

function Get-ADAuditDcShareCandidates {
    param([object[]]$Aces)
    foreach ($ace in @($Aces)) {
        if ($ace.AccessControlType -ne 'Allow' -or -not (Test-ADAuditDcBroadTrustee $ace.TrusteeSid) -or -not (Test-ADAuditDcWriteMask $ace.AccessMask)) { continue }
        $otherLayer = if ($ace.Layer -eq 'Share') { 'NTFS' } else { 'Share' }
        $other = @($Aces | Where-Object { $_.Layer -eq $otherLayer -and $_.AccessControlType -eq 'Allow' -and (Test-ADAuditDcBroadTrustee $_.TrusteeSid) -and (Test-ADAuditDcWriteMask $_.AccessMask) })
        $denies = @($Aces | Where-Object AccessControlType -eq 'Deny').Count
        [pscustomobject]@{Layer=$ace.Layer;TrusteeSid=$ace.TrusteeSid;Rights=$ace.Rights;OtherLayerWriteCandidates=$other.Count;DenyAceCount=$denies;InheritanceFlags=$ace.InheritanceFlags;PropagationFlags=$ace.PropagationFlags}
    }
}

function Get-ADAuditDcSmbSnapshot {
    param([string]$Target,[hashtable]$Context)
    $errors = [Collections.Generic.List[object]]::new()
    $server = $null; $client = $null; $os = $null; $shares = @(); $sharesComplete = $false; $registryFallback=@{}
    $sessions = [Collections.Generic.List[object]]::new()
    foreach ($kind in @('Server','Client')) {
        try {
            if ($kind -eq 'Server' -and $Context.CachedServers.ContainsKey($Target)) { $configuration = $Context.CachedServers[$Target] }
            else {
                $response = Invoke-ADAuditCimMethod -ComputerName $Target -Namespace 'root/Microsoft/Windows/SMB' -ClassName "MSFT_Smb${kind}Configuration" -MethodName GetConfiguration -UseWsmanFallback -ErrorAction Stop
                if ($null -eq $response.ReturnValue -or $response.ReturnValue -ne 0 -or $null -eq $response.Output) { throw 'SMB configuration provider returned no usable configuration.' }
                $configuration = $response.Output
            }
            if ($kind -eq 'Server') { $server=$configuration } else { $client=$configuration }
        } catch { $errors.Add([pscustomobject]@{Control="${kind}Configuration";Reason=$_.Exception.Message;Outcome=(Get-ADAuditOperationOutcome -ErrorRecord $_)}) }
    }
    foreach ($setting in @(@{Control='SMB1';Property='EnableSMB1Protocol';Registry='SMB1'},@{Control='ServerSigning';Property='RequireSecuritySignature';Registry='RequireSecuritySignature'},@{Control='NullSessionRestriction';Property='RestrictNullSessAccess';Registry='RestrictNullSessAccess'})) {
        if ($null -ne (Get-ADAuditDcBoolean $server $setting.Property)) { continue }
        try {
            $value=Get-ADAuditRemoteRegistryDword -ComputerName $Target -SubKey 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ValueName $setting.Registry
            if ($value.Success -and $null -ne $value.Value) {
                $boolean=Get-ADAuditDcBoolean $value 'Value'
                if ($null -ne $boolean) { $registryFallback[$setting.Control]=$boolean }
            }
        } catch { } # The property-level NotAssessed row below preserves this gap.
    }
    try { $os = Get-ADAuditCimInstance -ComputerName $Target -ClassName Win32_OperatingSystem -Property Caption,Version,BuildNumber -UseWsmanFallback -ErrorAction Stop } catch { $errors.Add([pscustomobject]@{Control='OperatingSystem';Reason=$_.Exception.Message;Outcome=(Get-ADAuditOperationOutcome -ErrorRecord $_)}) }
    try {
        $shares = @(Get-ADAuditCimInstance -ComputerName $Target -Namespace 'root/Microsoft/Windows/SMB' -ClassName MSFT_SmbShare -UseWsmanFallback -ErrorAction Stop)
        $sharesComplete = $true
    } catch {
        try {
            $shares = @(Get-ADAuditCimInstance -ComputerName $Target -ClassName Win32_Share -Property Name,Path,Type,Description -UseWsmanFallback -ErrorAction Stop)
            $sharesComplete = $true
        } catch { $errors.Add([pscustomobject]@{Control='ShareInventory';Reason=$_.Exception.Message;Outcome=(Get-ADAuditOperationOutcome -ErrorRecord $_)}) }
    }
    # Session dialects describe only the present sample, never allowed versions.
    foreach ($direction in @('Inbound','Outbound')) {
        $class = if ($direction -eq 'Inbound') {'MSFT_SmbSession'} else {'MSFT_SmbConnection'}
        try {
            $sample = @(Get-ADAuditCimInstance -ComputerName $Target -Namespace 'root/Microsoft/Windows/SMB' -ClassName $class -UseWsmanFallback -ErrorAction Stop)
            if ($sample.Count -eq 0) { $sessions.Add([pscustomobject]@{Target=$Target;Direction=$direction;Dialect='';Encrypted='';Signed='';ObservationCount=0;Status='Observed';Detail='No current sessions returned. This does not establish allowed dialects or protection of future sessions.'}) }
            else {
                $normalized = foreach ($session in $sample) { [pscustomobject]@{Dialect=[string]$session.Dialect;Encrypted=(Get-ADAuditDcBoolean $session 'Encrypted');Signed=(Get-ADAuditDcBoolean $session 'Signed')} }
                foreach ($group in @($normalized | Group-Object Dialect,Encrypted,Signed)) {
                    $sessions.Add([pscustomobject]@{Target=$Target;Direction=$direction;Dialect=$group.Group[0].Dialect;Encrypted=$group.Group[0].Encrypted;Signed=$group.Group[0].Signed;ObservationCount=$group.Count;Status='Observed';Detail='Current-session sample only. Blank fields were not exposed; account and client identities are not exported.'})
                }
            }
        } catch { $sessions.Add([pscustomobject]@{Target=$Target;Direction=$direction;Dialect='';Encrypted='';Signed='';ObservationCount=0;Status='NotAssessed';Detail=$_.Exception.Message}) }
    }
    [pscustomobject]@{Target=$Target;Server=$server;Client=$client;RegistryFallback=$registryFallback;OperatingSystem=$os;Shares=$shares;SharesComplete=$sharesComplete;Sessions=$sessions.ToArray();Errors=$errors.ToArray()}
}

function Get-ADAuditDcShareAclSnapshot {
    param($Target,$Context)
    $rows=[Collections.Generic.List[object]]::new(); $errors=[Collections.Generic.List[object]]::new()
    foreach ($layer in @('Share','NTFS')) {
        try {
            $class=if ($layer -eq 'Share') {'Win32_LogicalShareSecuritySetting'} else {'Win32_LogicalFileSecuritySetting'}
            $key=if ($layer -eq 'Share') {'Name'} else {'Path'}
            $value=if ($layer -eq 'Share') {$Target.ShareName} else {$Target.Path}
            $descriptor=Invoke-ADAuditDcSecurityDescriptor -ComputerName $Target.ComputerName -ClassName $class -Key $key -Value $value
            foreach ($row in @(ConvertTo-ADAuditDcAceRows -Target $Target.ComputerName -ShareName $Target.ShareName -Layer $layer -Descriptor $descriptor)) { $rows.Add($row) }
        } catch { $errors.Add([pscustomobject]@{Layer=$layer;Reason=$_.Exception.Message;Outcome=(Get-ADAuditOperationOutcome -ErrorRecord $_)}) }
    }
    [pscustomobject]@{Target=$Target.ComputerName;ShareName=$Target.ShareName;Path=$Target.Path;ShareType=$Target.ShareType;Aces=$rows.ToArray();Errors=$errors.ToArray()}
}

function Export-ADAuditDcSecurityCsv {
    param([object[]]$Rows,[string]$Name,[string[]]$Columns)
    $path=Get-EvidencePath $Name
    if (@($Rows).Count) { $Rows | Select-Object $Columns | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8 }
    else { ('"' + ($Columns -join '","') + '"') | Set-Content -LiteralPath $path -Encoding UTF8 }
}

function Set-ADAuditDcSmbObservation {
    param([string]$Target,[ValidateSet('SMB1','ServerSigning')][string]$Control,[bool]$Value,[string]$Source)
    if (-not (Get-Variable -Name ADAuditDcSmbObservations -Scope Script -ErrorAction SilentlyContinue)) { $script:ADAuditDcSmbObservations=@{} }
    $expected=$Control -eq 'ServerSigning'
    $observedUtc=[datetime]::UtcNow.ToString('o')
    $key="$(Get-ADAuditTargetKey $Target)|$Control"
    $script:ADAuditDcSmbObservations[$key]=[pscustomobject]@{
        Target=$Target;Control=$Control;Status=$(if($Value -eq $expected){'Pass'}else{'Finding'});Severity='High';Observed=[string]$Value
        Detail="Separate check observed $Control=$Value at $observedUtc during this invocation. Retained because the combined snapshot did not provide a definitive result for this control."
        Source=$Source;KB=$(if($Control -eq 'SMB1'){'KB290'}else{'KB1204'})
    }
}

function Merge-ADAuditDcSmbObservations {
    # Coordinator-only, invocation-scoped evidence reconciliation; no new queries.
    if (-not $script:ADAuditDcSmbObservations -or -not $script:ADAuditDcSmbObservations.Count) { return }
    $path=Get-EvidencePath 'dc_smb_security.csv'
    $rows=@(if(Test-Path -LiteralPath $path){Import-Csv -LiteralPath $path})
    foreach($observation in $script:ADAuditDcSmbObservations.Values) {
        $targetKey=Get-ADAuditTargetKey $observation.Target
        $sameTarget=@($rows | Where-Object {(Get-ADAuditTargetKey $_.Target) -eq $targetKey})
        if (@($sameTarget | Where-Object {$_.Status -eq 'Excluded'}).Count) { continue }
        $known=@($sameTarget | Where-Object {$_.Control -eq $observation.Control -and $_.Status -in @('Pass','Finding')})
        if($known.Count){continue} # A definitive matrix observation remains authoritative.
        $rows=@($rows | Where-Object {-not ((Get-ADAuditTargetKey $_.Target) -eq $targetKey -and $_.Control -eq $observation.Control)})
        $rows+= $observation
    }
    Export-ADAuditDcSecurityCsv -Rows $rows -Name 'dc_smb_security.csv' -Columns Target,Control,Status,Severity,Observed,Detail,Source,KB
}

function Get-DcShareSecurity {
    if (-not (Get-Variable -Name ADAuditSmbServerConfigCache -Scope Script -ErrorAction SilentlyContinue)) { $script:ADAuditSmbServerConfigCache=@{} }
    $dcs=@(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
    $matrix=[Collections.Generic.List[object]]::new(); $shareRows=[Collections.Generic.List[object]]::new()
    $aceRows=[Collections.Generic.List[object]]::new(); $sessionRows=[Collections.Generic.List[object]]::new(); $targets=[Collections.Generic.List[object]]::new()
    $script:ADAuditDcShareInventory=@{}
    function Add-SmbRow($dc,$control,$status,$severity,$observed,$detail,$source,$kb) {
        $matrix.Add([pscustomobject]@{Target=$dc;Control=$control;Status=$status;Severity=$severity;Observed=$observed;Detail=$detail;Source=$source;KB=$kb})
    }
    if (-not $dcs.Count) { Register-ADAuditNotAssessed -Name 'DC SMB and share security' -Switch 'domainaudit' -Reason 'No domain controllers enumerated.' }
    $cached=@{}
    foreach ($dc in $dcs) { $key=Get-ADAuditTargetKey $dc; if ($script:ADAuditSmbServerConfigCache -and $script:ADAuditSmbServerConfigCache.ContainsKey($key)) { $cached[$dc]=$script:ADAuditSmbServerConfigCache[$key] } }
    $results=Invoke-ADAuditParallelTargets -Targets $dcs -Operation 'SMB configuration and share inventory' -Activity 'DC SMB and share security' -Context @{CachedServers=$cached} -PercentBase 0 -PercentSpan 40 -ScriptBlock {param($Target,$Context) Get-ADAuditDcSmbSnapshot -Target $Target -Context $Context}
    foreach ($result in $results) {
        $dc=$result.Target
        if ($result.Outcome -ne 'Success') {
            $status=if ($result.Outcome -eq 'Excluded') {'Excluded'} else {'NotAssessed'}
            Add-SmbRow $dc 'Collection' $status 'Info' '' $result.Error 'Local/CIM' ''
            Register-ADAuditNotAssessed -Name 'DC SMB and share security' -Switch 'domainaudit' -Target $dc -Reason $result.Error -Outcome (Get-ADAuditCoverageOutcome $result.Outcome)
            $script:ADAuditDcShareInventory[(Get-ADAuditTargetKey $dc)]=[pscustomobject]@{Complete=$false;Shares=@();Reason=$result.Error}
            continue
        }
        $data=$result.Result
        $server=$data.Server; $client=$data.Client
        if ($server) { $script:ADAuditSmbServerConfigCache[(Get-ADAuditTargetKey $dc)]=$server }
        foreach ($spec in @(
            @{Control='SMB1';Object=$server;Property='EnableSMB1Protocol';Expected=$false;Severity='High';KB='KB290'},
            @{Control='ServerSigning';Object=$server;Property='RequireSecuritySignature';Expected=$true;Severity='High';KB='KB1204'},
            @{Control='ClientSigning';Object=$client;Property='RequireSecuritySignature';Expected=$true;Severity='High';KB='KB1501'},
            @{Control='InsecureGuestLogons';Object=$client;Property='EnableInsecureGuestLogons';Expected=$false;Severity='High';KB='KB1502'},
            @{Control='NullSessionRestriction';Object=$server;Property='RestrictNullSessAccess';Expected=$true;Severity='High';KB='KB1505'}
        )) {
            $value=Get-ADAuditDcBoolean $spec.Object $spec.Property
            $source='Effective SMB CIM provider'
            if ($null -eq $value -and $data.RegistryFallback -and $data.RegistryFallback.ContainsKey($spec.Control)) { $value=$data.RegistryFallback[$spec.Control];$source='Explicit LanmanServer REG_DWORD fallback (provider unavailable)' }
            $status=if ($null -eq $value) {'NotAssessed'} elseif ($value -eq $spec.Expected) {'Pass'} else {'Finding'}
            $detail=if ($status -eq 'NotAssessed') {'Effective provider property was unavailable or not a recognized Boolean; no default was inferred.'} else {"Observed effective $($spec.Property)=$value; expected $($spec.Expected). Confirm compatibility before policy changes."}
            Add-SmbRow $dc $spec.Control $status $spec.Severity ([string]$value) $detail $source $spec.KB
            if ($status -eq 'NotAssessed') { Register-ADAuditNotAssessed -Name "DC SMB $($spec.Control)" -Switch 'domainaudit' -Target $dc -Reason $detail }
            elseif ($status -eq 'Finding' -and $spec.Control -notin @('SMB1','ServerSigning')) { Write-Nessus-Finding "DC SMB $($spec.Control)" $spec.KB "$dc : $detail" $spec.Severity }
        }
        foreach ($kind in @('Server','Client')) {
            $object=if ($kind -eq 'Server') {$server} else {$client}
            $settings=foreach ($property in @('EnableSMB2Protocol','Smb2DialectMin','Smb2DialectMax')) { if ($object -and $null -ne $object.PSObject.Properties[$property] -and $null -ne $object.$property) { "$property=$($object.$property)" } }
            $os=$data.OperatingSystem
            Add-SmbRow $dc "${kind}DialectConfiguration" 'Observed' 'Info' ($settings -join '; ') "OS: $($os.Caption); version $($os.Version); build $($os.BuildNumber). Only properties exposed by this OS/provider are shown. Missing minimum/maximum fields do not establish allowed dialects; SMB2 enabled does not prove every dialect is allowed." 'SMB provider and Win32_OperatingSystem' ''
        }
        foreach ($property in @('NullSessionShares','NullSessionPipes')) {
            $available=$server -and $null -ne $server.PSObject.Properties[$property] -and $null -ne $server.$property
            $values=@(if ($available) { @($server.$property) | ForEach-Object { ([string]$_ -split '[,\r\n]+') } | ForEach-Object {$_.Trim()} | Where-Object {$_} | Sort-Object -Unique })
            $status=if (-not $available) {'NotAssessed'} elseif ($values.Count) {'Review'} else {'Pass'}
            Add-SmbRow $dc $property $status 'Info' ($values -join '; ') 'Configured exception inventory only. Validate role dependency and resource ACL; an entry does not prove anonymous access. Missing properties are not an empty allow-list.' 'Effective SMB CIM provider' 'KB1505'
            if (-not $available) { Register-ADAuditNotAssessed -Name "DC SMB $property" -Switch 'domainaudit' -Target $dc -Reason 'Exception-list property was unavailable; an empty list was not established.' }
        }
        foreach ($row in @($data.Sessions)) {
            $sessionRows.Add($row)
            if ($row.Status -eq 'NotAssessed') { Register-ADAuditNotAssessed -Name "DC SMB $($row.Direction) session sample" -Switch 'domainaudit' -Target $dc -Reason $row.Detail }
        }
        foreach ($error in @($data.Errors)) { Register-ADAuditNotAssessed -Name "DC SMB $($error.Control)" -Switch 'domainaudit' -Target $dc -Reason $error.Reason -Outcome (Get-ADAuditCoverageOutcome $error.Outcome) }
        $script:ADAuditDcShareInventory[(Get-ADAuditTargetKey $dc)]=[pscustomobject]@{Complete=$data.SharesComplete;Shares=@($data.Shares);Reason='Share inventory unavailable in DC SMB assessment.'}
        foreach ($share in @($data.Shares)) {
            $required=[string]$share.Name -in @('SYSVOL','NETLOGON')
            if (-not $required -and ((Get-ADAuditDcBoolean $share 'Special') -eq $true -or [string]$share.Name -in @('ADMIN$','IPC$') -or [string]$share.Name -match '^[A-Za-z]\$$' -or -not $share.Path)) { continue }
            $type=if ($required) {'Directory infrastructure'} else {'Custom DC share'}
            $shareRows.Add([pscustomobject]@{Target=$dc;ShareName=$share.Name;ShareType=$type;Path=$share.Path;Control='Inventory';Status='Observed';Severity='Info';Observed=$share.Description;Detail='Share presence alone is not a security finding. SYSVOL/NETLOGON authenticated read access is expected; custom shares require role and data-classification review.';KB=''})
            $encryption=Get-ADAuditDcEffectiveEncryption $server $share
            $status=if ($null -eq $encryption) {'NotAssessed'} elseif ($encryption) {'Pass'} else {'Review'}
            $shareRows.Add([pscustomobject]@{Target=$dc;ShareName=$share.Name;ShareType=$type;Path=$share.Path;Control='EncryptionRequired';Status=$status;Severity='Info';Observed=[string]$encryption;Detail='Effective requirement = (server EncryptData OR share EncryptData) AND RejectUnencryptedAccess. Encryption is an engagement/data-classification review, not an automatic DC vulnerability; this is configuration, not proof of every live session.';KB='KB1503'})
            if ($null -eq $encryption) { Register-ADAuditNotAssessed -Name 'DC share encryption' -Switch 'domainaudit' -Target "$dc/$($share.Name)" -Reason 'Effective encryption requirement could not be resolved from available server/share properties.' }
            if ($share.PSObject.Properties['ScopeName'] -and $share.ScopeName -and $share.ScopeName -ne '*') {
                $detail="Scoped SMB share '$($share.ScopeName)' requires scope-aware permission collection; the Win32 share-security provider is keyed only by share name. No potentially different share ACL was substituted."
                $shareRows.Add([pscustomobject]@{Target=$dc;ShareName=$share.Name;ShareType=$type;Path=$share.Path;Control='PermissionCollection';Status='NotAssessed';Severity='Info';Observed=$share.ScopeName;Detail=$detail;KB='KB1504'})
                Register-ADAuditNotAssessed -Name 'DC scoped share ACL' -Switch 'domainaudit' -Target "$dc/$($share.Name)" -Reason $detail
            }
            elseif ($share.Path) { $targets.Add([pscustomobject]@{ComputerName=$dc;ShareName=[string]$share.Name;Path=[string]$share.Path;ShareType=$type}) }
            else { Register-ADAuditNotAssessed -Name 'DC share ACL' -Switch 'domainaudit' -Target "$dc/$($share.Name)" -Reason 'Share path was not returned; NTFS permissions cannot be assessed.' }
        }
    }
    $aclResults=Invoke-ADAuditParallelTargets -Targets $targets.ToArray() -TargetLabel {param($t) "$($t.ComputerName)/$($t.ShareName)"} -TargetHost {param($t) $t.ComputerName} -Operation 'share and NTFS root ACLs' -Activity 'DC share permissions' -PercentBase 40 -PercentSpan 60 -ScriptBlock {param($Target,$Context) Get-ADAuditDcShareAclSnapshot $Target $Context}
    foreach ($result in $aclResults) {
        if ($result.Outcome -ne 'Success') {
            Register-ADAuditNotAssessed -Name 'DC share ACL' -Switch 'domainaudit' -Target $result.Target -Reason $result.Error -Outcome (Get-ADAuditCoverageOutcome $result.Outcome)
            $status=if ($result.Outcome -eq 'Excluded') {'Excluded'} else {'NotAssessed'}
            $shareRows.Add([pscustomobject]@{Target=($result.Target -split '/',2)[0];ShareName=($result.Target -split '/',2)[1];ShareType='';Path='';Control='PermissionCollection';Status=$status;Severity='Info';Observed='';Detail=$result.Error;KB='KB1504'})
            continue
        }
        $data=$result.Result
        foreach ($ace in @($data.Aces)) { $aceRows.Add($ace) }
        foreach ($error in @($data.Errors)) {
            Register-ADAuditNotAssessed -Name "DC share $($error.Layer) ACL" -Switch 'domainaudit' -Target "$($data.Target)/$($data.ShareName)" -Reason $error.Reason -Outcome (Get-ADAuditCoverageOutcome $error.Outcome)
            $shareRows.Add([pscustomobject]@{Target=$data.Target;ShareName=$data.ShareName;ShareType=$data.ShareType;Path=$data.Path;Control='PermissionCollection';Status='NotAssessed';Severity='Info';Observed=$error.Layer;Detail=$error.Reason;KB='KB1504'})
        }
        $candidates=@(Get-ADAuditDcShareCandidates -Aces @($data.Aces))
        $detail=if ($candidates.Count) { 'Broad write/control ACE candidates require effective-access review. Rights, inheritance, deny ACEs, nested groups and the concrete user token must be evaluated; this does not establish exploitable access.' } else { 'No broad write/control ACE candidate was found in the collected root ACLs. Broad read/execute is not flagged. This does not establish effective access or permissions below the share root.' }
        $status=if ($candidates.Count) {'Review'} elseif (@($data.Errors).Count) {'NotAssessed'} else {'Observed'}
        $shareRows.Add([pscustomobject]@{Target=$data.Target;ShareName=$data.ShareName;ShareType=$data.ShareType;Path=$data.Path;Control='BroadWriteControlCandidates';Status=$status;Severity='Info';Observed=($candidates | ConvertTo-Json -Depth 4 -Compress);Detail=$detail;KB='KB1504'})
    }
    Export-ADAuditDcSecurityCsv -Rows $matrix.ToArray() -Name 'dc_smb_security.csv' -Columns Target,Control,Status,Severity,Observed,Detail,Source,KB
    Merge-ADAuditDcSmbObservations
    Export-ADAuditDcSecurityCsv -Rows $shareRows.ToArray() -Name 'dc_share_security.csv' -Columns Target,ShareName,ShareType,Path,Control,Status,Severity,Observed,Detail,KB
    Export-ADAuditDcSecurityCsv -Rows $aceRows.ToArray() -Name 'dc_share_aces.csv' -Columns Target,ShareName,Layer,TrusteeSid,Identity,AccessControlType,AccessMask,Rights,AceFlags,IsInherited,InheritanceFlags,PropagationFlags
    Export-ADAuditDcSecurityCsv -Rows $sessionRows.ToArray() -Name 'dc_smb_sessions.csv' -Columns Target,Direction,Dialect,Encrypted,Signed,ObservationCount,Status,Detail
}

# Checks are loaded before worker creation. Only data-returning, read-only helpers
# enter the workers; progress, evidence files, coverage and Nessus stay coordinated.
$script:ADAuditWorkerFunctionNames += @('Get-ADAuditDcBoolean','Get-ADAuditDcEffectiveEncryption','Invoke-ADAuditDcSecurityDescriptor','ConvertTo-ADAuditDcAceRows','Get-ADAuditDcSmbSnapshot','Get-ADAuditDcShareAclSnapshot')

<# Read-only AD CS configuration review. No enrollment, relay, or credential use. #>
function Get-ADAuditTemplateAssessment {
    param($Template, [string[]]$PublishedBy = @(), [string[]]$EnrollTrustees = @(), [string[]]$WriteTrustees = @())
    $ekus = @($Template.pKIExtendedKeyUsage | Where-Object { $null -ne $_ -and [string]$_ } | ForEach-Object { [string]$_ })
    $approval = (([int]$Template.'msPKI-Enrollment-Flag' -band 2) -ne 0)
    $signatures = [int]$Template.'msPKI-RA-Signature'
    $suppliesSubject = (([int]$Template.'msPKI-Certificate-Name-Flag' -band 1) -ne 0)
    $anyPurpose = ($ekus.Count -eq 0 -or '2.5.29.37.0' -in $ekus)
    $authentication = $anyPurpose -or [bool]@($ekus | Where-Object { $_ -in @('1.3.6.1.5.5.7.3.2','1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.2.3.4') }).Count
    $candidateRules = @()
    if ($suppliesSubject -and $authentication -and $EnrollTrustees.Count -gt 0) { $candidateRules += 'ESC1' }
    if ($anyPurpose -and $EnrollTrustees.Count -gt 0) { $candidateRules += 'ESC2' }
    if ('1.3.6.1.4.1.311.20.2.1' -in $ekus -and $EnrollTrustees.Count -gt 0) { $candidateRules += 'ESC3' }
    if ($WriteTrustees.Count -gt 0) { $candidateRules += 'ESC4' }
    if (-not $candidateRules) { $candidateRules = @('TemplateReview') }
    foreach ($rule in $candidateRules) {
        $exposed = $PublishedBy.Count -gt 0 -and ($rule -eq 'ESC4' -or (-not $approval -and $signatures -eq 0)) -and $rule -ne 'TemplateReview'
        [pscustomobject]@{
            Template = $Template.Name
            PublishedBy = $PublishedBy -join '; '
            Rule = $rule
            Status = if ($exposed) { 'PotentialExposure' } elseif ($rule -eq 'TemplateReview') { 'NoBroadExposureDetected' } else { 'Review' }
            Severity = if ($exposed) { 'High' } else { 'Info' }
            Trustees = $(if ($rule -eq 'ESC4') { $WriteTrustees } else { $EnrollTrustees }) -join '; '
            Detail = "Published=$($PublishedBy.Count -gt 0); manager approval=$approval; authorized signatures=$signatures; EKUs=$($ekus -join ','). Static broad-group allow-ACE assessment only; deny/group access, CA enrollment permissions, enrollment-agent restrictions and certificate mapping need validation. No exploitation attempted."
        }
    }
}

function Get-ADAuditAdcsEndpointAssessment {
    param([Nullable[int]]$HttpStatus, [string]$Authentication, [string]$ErrorText)
    if ($ErrorText -or $null -eq $HttpStatus) { return [pscustomobject]@{Status='NotAssessed'; Detail="Endpoint could not be assessed: $ErrorText"} }
    if ($HttpStatus -eq 404) { return [pscustomobject]@{Status='Review'; Detail='This URL returned 404; other enrollment services and HTTPS configuration are not excluded.'} }
    [pscustomobject]@{Status='Review'; Detail="HTTP response $HttpStatus; advertised authentication=$Authentication. Verify NTLM, HTTPS requirement and EPA on CA Web Enrollment and Certificate Enrollment Web Service. This response does not prove ESC8 or its absence."}
}

function Get-ADCSVulns {
    $templateRows = [System.Collections.Generic.List[object]]::new()
    $endpointRows = [System.Collections.Generic.List[object]]::new()
    foreach ($name in @('vulnerable_templates.txt','web_enrollment.txt')) { Remove-Item -LiteralPath (Get-EvidencePath $name) -ErrorAction SilentlyContinue }
    try {
        $config = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        $cas = @(Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$config" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName,certificateTemplates -ErrorAction Stop)
        $templates = @(Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$config" -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties pKIExtendedKeyUsage,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,nTSecurityDescriptor -ErrorAction Stop)
    } catch {
        Register-ADAuditNotAssessed -Name 'AD CS inventory' -Switch 'adcs' -Reason "CA/template LDAP inventory failed: $($_.Exception.Message)"
        return
    }
    foreach ($template in $templates) {
        $published = @($cas | Where-Object { $template.Name -in @($_.certificateTemplates) } | Select-Object -ExpandProperty Name)
        try {
            $acl = $template.nTSecurityDescriptor
            if ($null -eq $acl) { throw 'Template security descriptor was not returned.' }
            $enroll = [System.Collections.Generic.List[string]]::new()
            $write = [System.Collections.Generic.List[string]]::new()
            foreach ($ace in $acl.Access) {
                if ([string]$ace.AccessControlType -ne 'Allow' -or [string]$ace.PropagationFlags -match 'InheritOnly') { continue }
                $sid = Get-ADAuditAceSid $ace
                if ($sid -notin @('S-1-1-0','S-1-5-11','S-1-5-32-545') -and $sid -notmatch '^S-1-5-21-(\d+-){3}(513|515)$') { continue }
                $rights = [int]$ace.ActiveDirectoryRights
                $objectGuid = [string]$ace.ObjectType
                $all = (-not $objectGuid -or $objectGuid -eq [guid]::Empty.ToString())
                if (($rights -band 983551) -eq 983551 -or (($rights -band 256) -ne 0 -and ($all -or $objectGuid -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55'))) { $enroll.Add($sid) }
                if (($rights -band 983551) -eq 983551 -or ($rights -band 262144) -ne 0 -or ($rights -band 524288) -ne 0 -or (($rights -band 32) -ne 0 -and $all)) { $write.Add($sid) }
            }
            foreach ($row in @(Get-ADAuditTemplateAssessment -Template $template -PublishedBy $published -EnrollTrustees @($enroll) -WriteTrustees @($write))) { $templateRows.Add($row) }
        } catch {
            Register-ADAuditNotAssessed -Name 'AD CS template' -Switch 'adcs' -Target $template.DistinguishedName -Reason "Template ACL evaluation failed: $($_.Exception.Message)"
            $templateRows.Add([pscustomobject]@{Template=$template.Name; PublishedBy=$published -join '; '; Rule='TemplateReview'; Status='NotAssessed'; Severity='Info'; Trustees=''; Detail=$_.Exception.Message})
        }
    }
    Export-ADAuditSecurityCsv -Rows $templateRows -Columns @('Template','PublishedBy','Rule','Status','Severity','Trustees','Detail') -Path (Get-EvidencePath 'adcs_templates.csv')
    $exposures = @($templateRows | Where-Object Status -eq 'PotentialExposure')
    if ($exposures.Count -gt 0) {
        $exposures | ForEach-Object { "Potential $($_.Rule) exposure: $($_.Template) | CAs: $($_.PublishedBy) | Trustees: $($_.Trustees) | $($_.Detail)" } | Set-Content -Encoding UTF8 -Path (Get-EvidencePath 'vulnerable_templates.txt')
        Write-Nessus-Finding 'Potential AD CS template exposure (static assessment)' 'KB1096' ([IO.File]::ReadAllText((Get-EvidencePath 'vulnerable_templates.txt'))) 'High'
    }
    Write-Both "    [*] AD CS: $($cas.Count) enterprise CA object(s), $($templates.Count) template(s), $($exposures.Count) potential broad-group template exposure(s). Custom trustee groups and CA-side configuration require review."
    if ($cas.Count -eq 0) {
        Write-Both '    [*] No enterprise CA objects discovered. Standalone CAs and external enrollment endpoints were not inventoried.'
        return
    }
    foreach ($ca in $cas) {
        $server = [string]$ca.dNSHostName
        if ([string]::IsNullOrWhiteSpace($server)) {
            Register-ADAuditNotAssessed -Name 'AD CS enrollment endpoint' -Switch 'adcs' -Target $ca.Name -Reason 'CA object has no DNS host name; web endpoints cannot be inferred.'
            continue
        }
        if ($script:ADAuditIsolatedClone -and -not (Test-ADAuditLocalComputer -ComputerName $server)) {
            Register-ADAuditNotAssessed -Name 'AD CS enrollment endpoint' -Switch 'adcs' -Target $server -Reason 'Remote enrollment endpoints are outside isolated-clone scope. Template configuration was read from the copied directory.'
            $endpointRows.Add([pscustomobject]@{CA=$ca.Name; Endpoint=$server; Status='NotAssessed'; HttpStatus=$null; Authentication=''; Detail='Not probed: remote endpoint outside isolated-clone scope.'})
            continue
        }
        # One bounded resolution and one TCP probe per endpoint replace two 10 s web timeouts
        # when the CA host is down; the HTTP request is only sent to a listening port.
        $caResolution = Resolve-ADAuditTargetAddresses -ComputerName $server
        foreach ($scheme in @('http','https')) {
            $url = "${scheme}://$server/certsrv/"
            $status = $null; $auth = ''; $failure = ''
            $endpointPort = if ($scheme -eq 'https') { 443 } else { 80 }
            if ($caResolution.Status -eq 'Unresolvable') { $failure = $caResolution.Detail }
            else {
                $probe = Test-ADAuditTcpPort -ComputerName $server -Port $endpointPort
                if (-not $probe.Open) { $failure = "TCP $endpointPort on $server did not accept a connection from this host ($($probe.Error)); no HTTP request was sent." }
            }
            if (-not $failure) {
                try {
                    # Never send audit credentials or follow redirects to undiscovered hosts.
                    $response = Invoke-WebRequest -Uri $url -Method Head -MaximumRedirection 0 -TimeoutSec 10 -SkipHttpErrorCheck -ErrorAction Stop
                    $status = [int]$response.StatusCode
                    $auth = [string]($response.Headers['WWW-Authenticate'] -join ', ')
                } catch { $failure = $_.Exception.Message }
            }
            $assessment = Get-ADAuditAdcsEndpointAssessment -HttpStatus $status -Authentication $auth -ErrorText $failure
            $endpointRows.Add([pscustomobject]@{CA=$ca.Name; Endpoint=$url; Status=$assessment.Status; HttpStatus=$status; Authentication=$auth; Detail=$assessment.Detail})
            if ($assessment.Status -eq 'NotAssessed') { Register-ADAuditNotAssessed -Name 'AD CS enrollment endpoint' -Switch 'adcs' -Target $url -Reason $assessment.Detail }
        }
        Register-ADAuditNotAssessed -Name 'AD CS ESC8 configuration' -Switch 'adcs' -Target $ca.Name -Reason 'Endpoint reachability is inventory only. IIS authentication/EPA/SSL settings, CES roles on other hosts, and CA-side issuance permissions were not collected; ESC8 is not concluded.'
    }
    $endpointRows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Get-EvidencePath 'adcs_endpoints.csv')
    $endpointRows | ForEach-Object { "$($_.Status): $($_.Endpoint) | $($_.Detail)" } | Set-Content -Encoding UTF8 -Path (Get-EvidencePath 'adcs_endpoint_review.txt')
}

function Invoke-AdcsCheck { Get-ADCSVulns }
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select adcs @args
}

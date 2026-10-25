# Offline regressions for previously incorrect security conclusions. No AD, registry,
# enrollment or network requests are executed; only pure assessment functions run.
$checkRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'Checks'
foreach ($name in @('DangerousAcl','Adcs','LdapSecurity','Trusts','DelegatedPermissions','AuthPolicies')) {
    . (Join-Path $checkRoot "Invoke-${name}Check.ps1")
}
function New-TestAce {
    param([int]$Rights=983551,[string]$Access='Allow',[string]$Guid='00000000-0000-0000-0000-000000000000',[string]$Propagation='None')
    [pscustomobject]@{ActiveDirectoryRights=$Rights; AccessControlType=$Access; ObjectType=$Guid; PropagationFlags=$Propagation}
}
function New-TestTemplate {
    param([int]$EnrollmentFlags=0,[int]$Signatures=0,$Ekus=@('1.3.6.1.5.5.7.3.2'))
    [pscustomobject]@{Name='TestTemplate'; pKIExtendedKeyUsage=$Ekus; 'msPKI-Enrollment-Flag'=$EnrollmentFlags; 'msPKI-RA-Signature'=$Signatures; 'msPKI-Certificate-Name-Flag'=1}
}
Describe 'Applicable allow-ACE classification' {
    It 'does not call a protective deny a grant' {
        @(Get-ADAuditDangerousAceCapability (New-TestAce -Access Deny)).Count | Should Be 0
    }
    It 'does not apply an inherit-only ACE to the current object' {
        @(Get-ADAuditDangerousAceCapability (New-TestAce -Propagation InheritOnly)).Count | Should Be 0
    }
    It 'retains descendant-scoped grants when reviewing container delegations' {
        @(Get-ADAuditDangerousAceCapability (New-TestAce -Propagation InheritOnly) -IncludeDescendants).Count | Should Be 1
    }
    It 'finds Reset Password by control-access GUID' {
        Get-ADAuditDangerousAceCapability (New-TestAce -Rights 256 -Guid '00299570-246d-11d0-a768-00aa006e0529') | Should Be 'ResetPasswordOrAllExtendedRights'
    }
    It 'does not confuse Change Password with Reset Password' {
        @(Get-ADAuditDangerousAceCapability (New-TestAce -Rights 256 -Guid 'ab721a53-1e2f-11d0-9819-00aa0040529b')).Count | Should Be 0
    }
    It 'does not flag ordinary ReadProperty access' {
        @(Get-ADAuditDangerousAceCapability (New-TestAce -Rights 16)).Count | Should Be 0
    }
    It 'finds member-property write permissions' {
        Get-ADAuditDangerousAceCapability (New-TestAce -Rights 32 -Guid 'bf9679c0-0de6-11d0-a285-00aa003049e2') | Should Be 'WriteGroupMembership'
    }
}
Describe 'AD CS static exposure conditions' {
    It 'reports a published requester-subject authentication template as potential only' {
        $row = Get-ADAuditTemplateAssessment -Template (New-TestTemplate) -PublishedBy @('CA1') -EnrollTrustees @('S-1-5-11')
        $row.Status | Should Be 'PotentialExposure'
        $row.Rule | Should Be 'ESC1'
    }
    It 'does not call an approval-gated enrollment template immediately exposed' {
        (Get-ADAuditTemplateAssessment -Template (New-TestTemplate -EnrollmentFlags 2) -PublishedBy @('CA1') -EnrollTrustees @('S-1-5-11')).Status | Should Be 'Review'
    }
    It 'does not overlook required authorized signatures' {
        (Get-ADAuditTemplateAssessment -Template (New-TestTemplate -Signatures 1) -PublishedBy @('CA1') -EnrollTrustees @('S-1-5-11')).Status | Should Be 'Review'
    }
    It 'does not call an unpublished template an active issuance exposure' {
        (Get-ADAuditTemplateAssessment -Template (New-TestTemplate) -EnrollTrustees @('S-1-5-11')).Status | Should Be 'Review'
    }
    It 'retains template-control exposure even when issuance approval is enabled' {
        $row = Get-ADAuditTemplateAssessment -Template (New-TestTemplate -EnrollmentFlags 2) -PublishedBy @('CA1') -WriteTrustees @('S-1-5-11')
        $row.Rule | Should Be 'ESC4'
        $row.Status | Should Be 'PotentialExposure'
    }
    It 'recognizes absent EKUs as any-purpose configuration' {
        $rows = @(Get-ADAuditTemplateAssessment -Template (New-TestTemplate -Ekus $null) -PublishedBy @('CA1') -EnrollTrustees @('S-1-5-11'))
        @($rows | Where-Object Rule -eq 'ESC2').Count | Should Be 1
    }
    It 'does not label a 401 challenge confirmed ESC8' {
        (Get-ADAuditAdcsEndpointAssessment -HttpStatus 401 -Authentication NTLM).Status | Should Be 'Review'
    }
    It 'never converts a connection failure into not vulnerable' {
        (Get-ADAuditAdcsEndpointAssessment -ErrorText 'Connection timed out').Status | Should Be 'NotAssessed'
    }
}
Describe 'LDAP outcome distinctions' {
    It 'keeps a missing setting unknown rather than assuming insecure defaults' {
        (Get-ADAuditLdapSigningAssessment -Value $null -ModernServer $false -VersionKnown $true).Status | Should Be 'NotAssessed'
    }
    It 'does not ignore modern signing enforcement precedence' {
        (Get-ADAuditLdapSigningAssessment -Value 1 -ModernServer $true -VersionKnown $true).Status | Should Be 'NotAssessed'
    }
    It 'recognizes an explicit legacy non-enforcing value' {
        (Get-ADAuditLdapSigningAssessment -Value 1 -ModernServer $false -VersionKnown $true).Status | Should Be 'Finding'
    }
    It 'recognizes explicit required signing' {
        (Get-ADAuditLdapSigningAssessment -Value 2 -ModernServer $true -VersionKnown $true).Status | Should Be 'Pass'
    }
    It 'treats LDAP server-down errors as unknown' {
        Get-ADAuditAnonymousReadOutcome -ErrorCode 81 | Should Be 'NotAssessed'
    }
    It 'distinguishes explicit access refusal from network errors' {
        Get-ADAuditAnonymousReadOutcome -ErrorCode 50 | Should Be 'Rejected'
    }
    It 'does not claim all anonymous access denied from an empty response' {
        Get-ADAuditAnonymousReadOutcome -EntryCount 0 | Should Be 'NoDataReturned'
    }
    It 'reports actual anonymous domain-data return' {
        Get-ADAuditAnonymousReadOutcome -EntryCount 1 | Should Be 'Finding'
    }
}
Describe 'Trust boundary and LAPS permission semantics' {
    It 'does not assume a forest trust without quarantine has no SID filtering' {
        $row = Get-ADAuditTrustAssessment ([pscustomobject]@{Name='other'; trustAttributes=8; trustDirection=3; trustType=2})
        $row.Boundary | Should Be 'CrossForest'
        $row.Status | Should Be 'Review'
    }
    It 'flags explicitly enabled cross-boundary TGT delegation for review' {
        (Get-ADAuditTrustAssessment ([pscustomobject]@{Name='other'; trustAttributes=2056; trustDirection=3; trustType=2})).Status | Should Be 'Finding'
    }
    It 'keeps expiration metadata separate from password material' {
        Get-ADAuditLapsPermissionKind 'msLAPS-PasswordExpirationTime' | Should Be 'ExpirationMetadata'
    }
    It 'keeps encrypted attribute access separate from plaintext access' {
        Get-ADAuditLapsPermissionKind 'msLAPS-EncryptedPassword' | Should Be 'EncryptedPasswordAttribute'
    }
}
Describe 'Authentication policy coverage' {
    It 'does not count an unassigned policy as protection' {
        (Get-ADAuditAuthenticationPolicyState -HasAssignment $false).Status | Should Be 'Missing'
    }
    It 'does not count audit mode as enforced' {
        $policy = [pscustomobject]@{Enforce=$false; UserAllowedToAuthenticateFrom='restriction'; UserAllowedToAuthenticateTo=$null}
        (Get-ADAuditAuthenticationPolicyState -Policy $policy -HasAssignment $true).Status | Should Be 'AuditOnly'
    }
    It 'does not equate a lifetime-only policy with host containment' {
        $policy = [pscustomobject]@{Enforce=$true; UserAllowedToAuthenticateFrom=$null; UserAllowedToAuthenticateTo=$null}
        (Get-ADAuditAuthenticationPolicyState -Policy $policy -HasAssignment $true).Status | Should Be 'AssignedUnrestricted'
    }
    It 'reports configuration evidence for an enforced assigned restriction' {
        $policy = [pscustomobject]@{Enforce=$true; UserAllowedToAuthenticateFrom='restriction'; UserAllowedToAuthenticateTo=$null}
        (Get-ADAuditAuthenticationPolicyState -Policy $policy -HasAssignment $true).Status | Should Be 'ConfiguredRestriction'
    }
}
Describe 'Read-only replication-right correlation' {
    function New-TestReplicationAce {
        param([string]$Guid,[string]$Trustee='CONTOSO\sync',[string]$Access='Allow',[string]$Propagation='None',[string]$Sid='S-1-5-21-1-2-3-2000')
        [pscustomobject]@{ScopeType='Domain'; ScopeDN='DC=contoso,DC=test'; AccessControlType=$Access; PropagationFlags=$Propagation; ActiveDirectoryRights='ExtendedRight'; ObjectTypeGuid=$Guid; Trustee=$Trustee; TrusteeSid=$Sid}
    }
    It 'correlates both replication rights on the same trustee' {
        $records = @((New-TestReplicationAce '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'),(New-TestReplicationAce '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))
        (Get-ADAuditReplicationDelegations $records).Status | Should Be 'PotentialExposure'
    }
    It 'does not combine unrelated trustees into a DCSync capability' {
        $records = @((New-TestReplicationAce '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'),(New-TestReplicationAce '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -Trustee 'CONTOSO\other' -Sid 'S-1-5-21-1-2-3-2001'))
        @(Get-ADAuditReplicationDelegations $records | Where-Object Status -eq 'PotentialExposure').Count | Should Be 0
    }
    It 'does not count denied or descendant-only replication rights' {
        $records = @((New-TestReplicationAce '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'),(New-TestReplicationAce '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -Access Deny),(New-TestReplicationAce '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -Propagation InheritOnly))
        (Get-ADAuditReplicationDelegations $records).Status | Should Be 'Review'
    }
    It 'retains expected administrator capability as inventory' {
        $record = New-TestReplicationAce '00000000-0000-0000-0000-000000000000' -Sid 'S-1-5-32-544'
        (Get-ADAuditReplicationDelegations @($record)).Status | Should Be 'Review'
    }
}
Describe 'Structured evidence for an empty result' {
    It 'writes the schema even when there are no findings' {
        $path = Join-Path $TestDrive 'empty.csv'
        Export-ADAuditSecurityCsv -Rows @() -Columns @('Status','Severity','Detail') -Path $path
        (Get-Content -LiteralPath $path -First 1) | Should Be '"Status","Severity","Detail"'
        @(Import-Csv -LiteralPath $path).Count | Should Be 0
    }
}

# Minimal command seams allow collector-path tests on hosts without RSAT.
# Unmocked calls throw: these tests cannot accidentally reach a directory.
if (-not (Get-Command Get-ADRootDSE -ErrorAction SilentlyContinue)) {
    function Get-ADRootDSE { [CmdletBinding()]param() throw 'Offline test requires mock' }
}
if (-not (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
    function Get-ADObject { [CmdletBinding()]param($SearchBase,$LDAPFilter,$Properties) throw 'Offline test requires mock' }
}
if (-not (Get-Command Get-EvidencePath -ErrorAction SilentlyContinue)) {
    function Get-EvidencePath { param($Name) throw 'Offline test requires mock' }
}
if (-not (Get-Command Write-Both -ErrorAction SilentlyContinue)) {
    function Write-Both { param($Message) throw 'Offline test requires mock' }
}
if (-not (Get-Command Register-ADAuditNotAssessed -ErrorAction SilentlyContinue)) {
    function Register-ADAuditNotAssessed { param($Name,$Switch,$Target,$Reason) throw 'Offline test requires mock' }
}
Describe 'AD CS collector coverage without a directory' {
    BeforeEach {
        Mock Get-EvidencePath { Join-Path $TestDrive $Name }
        Mock Write-Both {}
        Mock Register-ADAuditNotAssessed {}
        Mock Get-ADRootDSE { [pscustomobject]@{configurationNamingContext='CN=Configuration,DC=test'} }
        Mock Get-ADObject { @() }
        Mock Invoke-WebRequest { throw 'No network access permitted in this test' }
    }
    It 'preserves a typed empty template inventory when no enterprise CA exists' {
        Get-ADCSVulns
        (Get-Content -LiteralPath (Join-Path $TestDrive 'adcs_templates.csv') -First 1) | Should Be '"Template","PublishedBy","Rule","Status","Severity","Trustees","Detail"'
        Assert-MockCalled Invoke-WebRequest -Times 0 -Exactly
    }
    It 'records inventory failure rather than returning a clean result' {
        Mock Get-ADRootDSE { throw 'Access denied' }
        Get-ADCSVulns
        Assert-MockCalled Register-ADAuditNotAssessed -Times 1 -Exactly
        Assert-MockCalled Invoke-WebRequest -Times 0 -Exactly
    }
}

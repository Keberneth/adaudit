$repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $repo 'Checks/Invoke-PasswordPolicyCheck.ps1')
. (Join-Path $repo 'Checks/Invoke-InactiveComputersCheck.ps1')
. (Join-Path $repo 'Checks/Invoke-LapsCheck.ps1')
. (Join-Path $repo 'Checks/Invoke-KerberoastCheck.ps1')
. (Join-Path $repo 'Checks/Invoke-AsRepRoastCheck.ps1')
. (Join-Path $repo 'Checks/Invoke-AccountsCheck.ps1')

# Offline command seams: no AD module or connection is loaded by these tests.
function Get-EvidencePath { param($Name) Join-Path $TestDrive $Name }
function Write-Both { param($Message) }
function Write-ADAuditProgress { param($Activity,$Status,$PercentComplete) }
function Register-ADAuditNotAssessed { param($Name,$Switch,$Target,$Reason) }
function Write-Nessus-Finding { param($Name,$KB,$Content,$Severity) }
function Import-ADAuditModule { param($Name,[switch]$Required) $true }
function Get-ADDomainController { param($Discover,$ErrorAction) }
function Get-ADDomain { param($Server,$Identity,$ErrorAction) }
function Get-ADForest { param($Server,$ErrorAction) }
function Get-ADGroup { param($Identity,$Server,$Filter,$ErrorAction) }
function Get-ADGroupMember { param($Identity,[switch]$Recursive,$Server,$ErrorAction) }
function Get-ADUser { param($Server,$LDAPFilter,$Filter,$Properties,$ErrorAction) }
function Get-ADDefaultDomainPasswordPolicy {}
function Get-ADFineGrainedPasswordPolicy { param($Filter) }
function Get-ADAuditRemoteRegistryDword { param($ComputerName,$SubKey,$ValueName) }
function Convert-ADAuditFileTime { param($Value) if ($Value -gt 0) { [datetime]::FromFileTimeUtc([long]$Value) } }

Describe 'Typed password evidence preserves account state without Users.csv' {
    It 'separates disabled, enabled and unknown empty-password rows from PASSWD_NOTREQD' {
        $empty = [byte[]](49,214,207,224,209,106,233,49,183,60,89,215,224,192,137,192)
        $accounts = @(
            [pscustomobject]@{SamAccountName='active';LogonName='LAB\active';Enabled=$true;NTHash=$empty},
            [pscustomobject]@{SamAccountName='disabled';LogonName='LAB\disabled';UserAccountControl=514;NTHash=$empty},
            [pscustomobject]@{SamAccountName='passwordless';LogonName='LAB\passwordless';Enabled=$true;NTHash=$null}
        )
        $quality = [pscustomobject]@{ EmptyPassword=@('LAB\active','LAB\disabled','LAB\passwordless','unresolved'); PasswordNotRequired=@('LAB\active') }
        $rows = @(ConvertTo-ADAuditPasswordQualityFinding -Quality $quality -Accounts $accounts)
        ($rows | Where-Object { $_.SamAccountName -eq 'disabled' }).AccountStatus | Should Be 'Disabled'
        ($rows | Where-Object { $_.SamAccountName -eq 'unresolved' }).AccountStatus | Should Be 'Unknown'
        ($rows | Where-Object { $_.SamAccountName -eq 'passwordless' }).PasswordEvidence | Should Be 'NoNtHash'
        ($rows | Where-Object { $_.SamAccountName -eq 'active' -and $_.Category -eq 'EmptyPassword' }).PasswordEvidence | Should Be 'EmptyNtHash'
        @($rows | Where-Object Category -eq 'PasswordNotRequired').Count | Should Be 1
        ($rows | ConvertTo-Json) | Should Not Match '31D6CFE0'
    }
    It 'exports disabled-only findings as review evidence without active Critical Nessus findings' {
        Mock Write-Nessus-Finding {}
        Mock Register-ADAuditNotAssessed {}
        $quality = [pscustomobject]@{ EmptyPassword=@('disabled') }
        Export-ADAuditPasswordQualityEvidence -Quality $quality -Accounts @([pscustomobject]@{SamAccountName='disabled';Enabled=$false;NTHash=$null})
        (Import-Csv (Get-EvidencePath 'password_quality_findings.csv')).AccountStatus | Should Be 'Disabled'
        Assert-MockCalled Write-Nessus-Finding -Times 0 -ParameterFilter { $Severity -eq 'Critical' }
        Assert-MockCalled Write-Nessus-Finding -Times 1 -ParameterFilter { $Severity -eq 'Info' }
    }
    It 'keeps duplicate-password group boundaries in structured data' {
        $groups = [System.Collections.Generic.List[object]]::new()
        $groups.Add(@('one','two')); $groups.Add(@('three','four'))
        $quality = [pscustomobject]@{DuplicatePasswordGroups=$groups}
        $rows = @(ConvertTo-ADAuditPasswordQualityFinding -Quality $quality -Accounts @())
        $rows.Count | Should Be 4
        @($rows | Group-Object GroupId).Count | Should Be 2
    }
    It 'aligns enabled ASREP and duplicate-password Nessus severities with the customer report' {
        Mock Write-Nessus-Finding {}
        $groups=[System.Collections.Generic.List[object]]::new(); $groups.Add(@('enabled1','enabled2'))
        $quality=[pscustomobject]@{PreAuthNotRequired=@('enabled1');DuplicatePasswordGroups=$groups}
        $accounts=@([pscustomobject]@{SamAccountName='enabled1';Enabled=$true},[pscustomobject]@{SamAccountName='enabled2';Enabled=$true})
        Export-ADAuditPasswordQualityEvidence -Quality $quality -Accounts $accounts
        Assert-MockCalled Write-Nessus-Finding -Times 1 -Exactly -ParameterFilter { $Name -eq 'PasswordQuality_PreAuthNotRequired' -and $Severity -eq 'Critical' }
        Assert-MockCalled Write-Nessus-Finding -Times 1 -Exactly -ParameterFilter { $Name -eq 'PasswordQuality_DuplicatePasswordGroups' -and $Severity -eq 'Critical' }
    }
}

Describe 'Computer activity candidates are conservative' {
    BeforeEach {
        $now = [datetime]'2026-10-25T12:00:00Z'
        $computer = [pscustomobject]@{Name='SERVER01';DNSHostName='server01.lab';DistinguishedName='CN=SERVER01,DC=lab';OperatingSystem='Windows Server 2022';Enabled=$true;whenCreated=$now.AddYears(-2);lastLogonTimestamp=0;pwdLastSet=$now.AddDays(-2).ToFileTimeUtc()}
    }
    It 'does not flag an active server with missing logon timestamp and recent machine-password rotation' {
        @(ConvertTo-ADAuditStaleComputerCandidate -Computer $computer -NowUtc $now).Count | Should Be 0
    }
    It 'does not flag a newly provisioned computer that has never logged on' {
        $computer.whenCreated=$now.AddDays(-1); $computer.pwdLastSet=0
        @(ConvertTo-ADAuditStaleComputerCandidate -Computer $computer -NowUtc $now).Count | Should Be 0
    }
    It 'reports old signals as review candidates rather than proven inactivity' {
        $computer.pwdLastSet=$now.AddDays(-200).ToFileTimeUtc()
        $row=ConvertTo-ADAuditStaleComputerCandidate -Computer $computer -NowUtc $now
        $row.Assessment | Should Be 'Stale activity candidate'
        $row.Reason | Should Match 'do not prove inactivity'
    }
}

Describe 'LAPS migration applicability' {
    It 'accepts Windows LAPS evidence without also requiring legacy LAPS metadata' {
        $computer=[pscustomobject]@{Name='PC01';DistinguishedName='CN=PC01';OperatingSystem='Windows 11';'msLAPS-PasswordExpirationTime'=[datetime]::UtcNow.AddDays(10).ToFileTimeUtc();'ms-Mcs-AdmPwdExpirationTime'=$null}
        $result=Get-ADAuditLapsBackupState -Computer $computer
        $result.Assessment | Should Be 'AD expiration evidence present'
        $result.Generation | Should Be 'Windows LAPS'
    }
    It 'treats absent AD metadata as an unverified backup destination' {
        $computer=[pscustomobject]@{Name='PC01';DistinguishedName='CN=PC01';OperatingSystem='Windows 11'}
        (Get-ADAuditLapsBackupState -Computer $computer).Assessment | Should Be 'Backup destination unverified'
    }
}

Describe 'Kerberoast membership and ASREP failure behavior' {
    It 'uses SID-based recursive membership and detects a deeply nested enabled SPN user' {
        Mock Get-ADDomain { [pscustomobject]@{DomainSID='S-1-5-21-10';DNSRoot='lab'} }
        Mock Get-ADForest { [pscustomobject]@{RootDomain='lab'} }
        Mock Get-ADGroup { if ($Identity) { [pscustomobject]@{SID=$Identity;Name='Localized admins';DistinguishedName='CN=Localized admins,DC=lab'} } }
        Mock Get-ADGroupMember { if ($Recursive) { [pscustomobject]@{SID='S-1-5-21-10-1100';SamAccountName='nestedService'} } }
        Mock Get-ADUser { [pscustomobject]@{SID='S-1-5-21-10-1100';SamAccountName='nestedService';DistinguishedName='CN=nestedService,DC=lab';servicePrincipalName=@('HTTP/service')} }
        Mock Write-Nessus-Finding {}
        Get-SPNs -Server 'dc.lab'
        Assert-MockCalled Get-ADGroupMember -ParameterFilter { $Recursive } -Times 1
        Assert-MockCalled Get-ADGroup -ParameterFilter { $Identity -eq 'S-1-5-21-10-512' } -Times 1
        Assert-MockCalled Get-ADUser -ParameterFilter { $LDAPFilter -match 'objectCategory=person' -and $LDAPFilter -match 'objectClass=user' } -Times 1
        (Get-Content (Get-EvidencePath 'SPNs.txt') -Raw) | Should Match 'nestedService'
        (Get-Content (Get-EvidencePath 'SPNs.txt') -Raw) | Should Match 'not a proven weak'
    }
}

Describe 'ASREP failed collection' {
    It 'does not print a clean ASREP result when both AD queries fail' {
        function Get-ADUser { param($Filter,$LDAPFilter,$Properties,$ErrorAction) throw 'Directory unavailable' }
        Mock Write-Both {}
        $caught = $false
        try { Get-ADUsersWithoutPreAuth } catch { $caught = $true }
        $caught | Should Be $true
        Assert-MockCalled Write-Both -Times 0 -ParameterFilter { $Message -match 'No ASREP' }
    }
}

Describe 'RC4 default uncertainty' {
    It 'keeps unset encryption attributes unknown when DC defaults cannot be read' {
        function Get-ADUser {
            param($Filter,$Properties,$ErrorAction)
            [pscustomobject]@{SamAccountName='unset';Enabled=$true;DistinguishedName='CN=unset';ObjectClass='user';'msDS-SupportedEncryptionTypes'=$null;PasswordLastSet=[datetime]::UtcNow;ServicePrincipalName=@('HTTP/app')}
            [pscustomobject]@{SamAccountName='rc4';Enabled=$true;DistinguishedName='CN=rc4';ObjectClass='user';'msDS-SupportedEncryptionTypes'=4;PasswordLastSet=[datetime]::UtcNow;ServicePrincipalName=@('HTTP/oldapp')}
        }
        function Get-ADComputer { param($Filter,$Properties,$ErrorAction) }
        function Get-ADDomainController { param($Filter,$ErrorAction) [pscustomobject]@{HostName='dc.lab'} }
        function Get-ADAuditRemoteRegistryDword { param($ComputerName,$SubKey,$ValueName) [pscustomobject]@{Success=$false;Value=$null;Error='denied'} }
        function Get-WinEvent { param($ComputerName,$FilterHashtable,$MaxEvents,$ErrorAction) throw 'blocked by offline test' }
        Get-RC4OnlyAccounts
        (Import-Csv (Get-EvidencePath 'kerberos_encryption_unverified.csv')).SamAccountName | Should Be 'unset'
        (Import-Csv (Get-EvidencePath 'rc4_only_accounts.csv')).SamAccountName | Should Be 'rc4'
        (Import-Csv (Get-EvidencePath 'kerberos_dc_defaults.csv')).State | Should Be 'Unreadable'
    }
}

Describe 'LM hash storage configuration evidence' {
    BeforeEach {
        Mock Get-ADDefaultDomainPasswordPolicy { [pscustomobject]@{ComplexityEnabled=$true;LockoutThreshold=10;MinPasswordLength=14;ReversibleEncryptionEnabled=$false;MaxPasswordAge=[timespan]::FromDays(90);PasswordHistoryCount=24} }
        Mock Get-ADFineGrainedPasswordPolicy {}
        Mock Get-ADDomain { [pscustomobject]@{PDCEmulator='dc.lab'} }
        Mock Write-Nessus-Finding {}
        Mock Register-ADAuditNotAssessed {}
    }
    It 'treats an absent NoLmHash value as unknown rather than a stored-password finding' {
        Mock Get-ADAuditRemoteRegistryDword { [pscustomobject]@{Success=$true;Value=$null;Error=$null} }
        Get-PasswordPolicy
        Assert-MockCalled Register-ADAuditNotAssessed -Times 1 -ParameterFilter { $Name -eq 'LM hash storage policy' }
        Assert-MockCalled Write-Nessus-Finding -Times 0 -ParameterFilter { $KB -eq 'KB510' }
    }
    It 'describes NoLmHash zero as permission to store rather than actual stored LM hashes' {
        Mock Get-ADAuditRemoteRegistryDword { [pscustomobject]@{Success=$true;Value=0;Error=$null} }
        Get-PasswordPolicy
        Assert-MockCalled Write-Nessus-Finding -Times 1 -ParameterFilter { $KB -eq 'KB510' -and $Name -eq 'LMHashStoragePermitted' -and $Content -match 'does not prove' }
    }
}

Describe 'Standalone paid password audit reporting' {
    BeforeEach { Import-Module (Join-Path $repo 'Password Audit/PasswordAuditCommon.psm1') -Force }
    It 'marks missing NT material and failed lookups as partial and excludes secrets from HTML' {
        $path=Join-Path $TestDrive 'paid.csv'
        'placeholder' | Set-Content -LiteralPath $path
        $rows=@(
            [pscustomobject]@{SamAccountName='<script>alert(1)</script>';AccountStatus='Disabled';Pwned='Yes';NTHash='NEVER-EXPORT-THIS-HASH';Comment='review'},
            [pscustomobject]@{SamAccountName='unknown';AccountStatus='Unknown';Pwned='LookupFailed';Comment='retry'}
        )
        Export-PasswordAuditSummary -OutCsv $path -Mode Pwned -Server 'dc.lab' -ReturnedCount 3 -ProcessedCount 2 -MissingHashCount 1 -LookupFailedCount 1 -HibpRequested -Results $rows
        $summary=Import-Csv ([IO.Path]::ChangeExtension($path,'summary.csv'))
        $summary.Coverage | Should Be 'Partial'
        $summary.DisabledFindingAccounts | Should Be 1
        $summary.EnabledFindingAccounts | Should Be 0
        $html=Get-Content ([IO.Path]::ChangeExtension($path,'html')) -Raw
        $html | Should Not Match 'NEVER-EXPORT-THIS-HASH'
        $html | Should Not Match '<script>alert'
        $html | Should Match '&lt;script&gt;'
    }
    It 'does not call an empty processed set a completed or clean audit' {
        $path=Join-Path $TestDrive 'empty.csv'
        Export-PasswordAuditSummary -OutCsv $path -Mode Duplicate -Server 'dc.lab' -ReturnedCount 2 -ProcessedCount 0 -MissingHashCount 2 -Results @()
        (Import-Csv ([IO.Path]::ChangeExtension($path,'summary.csv'))).Coverage | Should Be 'Not assessed'
    }
    It 'explains successful HIBP coverage separately from disabled accounts without NT material' {
        $path=Join-Path $TestDrive 'successful-with-unavailable.csv'
        $rows=@(
            [pscustomobject]@{SamAccountName='available';AccountStatus='Active';Pwned='Yes';Comment='match'},
            [pscustomobject]@{SamAccountName='unavailable';AccountStatus='Disabled';Pwned='NotAssessed';Comment='No NT material'}
        )
        Export-PasswordAuditSummary -OutCsv $path -Mode Pwned -Server 'dc.lab' -ReturnedCount 2 -ProcessedCount 1 -MissingHashCount 1 -HibpRequested -HibpCheckedCount 1 -Results $rows
        $summary=Import-Csv ([IO.Path]::ChangeExtension($path,'summary.csv'))
        $summary.Coverage | Should Be 'Partial'
        $summary.HIBPStatus | Should Be 'Completed'
        $summary.MissingNTDisabledAccounts | Should Be 1
        $summary.MissingNTEnabledAccounts | Should Be 0
        $summary.CoverageReasons | Should Match '0 enabled, 1 disabled'
        $html=Get-Content ([IO.Path]::ChangeExtension($path,'html')) -Raw
        $html | Should Match 'prefers-color-scheme:dark'
        $html | Should Match 'data-theme="dark"'
        $html | Should Match '<option value="dark">Dark</option>'
        $html.IndexOf('>available</td>') | Should BeLessThan $html.IndexOf('>unavailable</td>')
        $html | Should Match 'Unavailable checks and additional evidence'
    }
    It 'makes a skipped optional HIBP lookup explicit in a completed local comparison' {
        $path=Join-Path $TestDrive 'local-only.csv'
        $rows=@([pscustomobject]@{SamAccountName='shared';AccountStatus='Active';DuplicatePasswordGroup=1;Pwned='NotChecked';Comment='Shared material'})
        Export-PasswordAuditSummary -OutCsv $path -Mode Duplicate -Server 'dc.lab' -ReturnedCount 1 -ProcessedCount 1 -Results $rows
        $summary=Import-Csv ([IO.Path]::ChangeExtension($path,'summary.csv'))
        $summary.HIBPStatus | Should Be 'Not requested'
        $summary.Coverage | Should Be 'Complete for selected scope'
        (Get-Content ([IO.Path]::ChangeExtension($path,'html')) -Raw) | Should Match 'NotChecked is expected'
    }
    It 'runs both standalone report paths offline with mixed account states and unavailable password material' {
        # Suppress only module loading and external reads. Report code and shared
        # helpers execute unchanged, including strict mode and CSV/HTML writing.
        function Import-Module { param($Name,[switch]$Force,$ErrorAction) }
        function Get-ADDomain { param($Server,$ErrorAction) [pscustomobject]@{DistinguishedName='DC=lab'} }
        function Get-ReplicatedAccountHashes {
            param($Server,$NamingContext)
            [pscustomobject]@{SamAccountName='enabled';Enabled=$true;NTHash=[byte[]](1..16)}
            [pscustomobject]@{SamAccountName='disabled';Enabled=$false;NTHash=[byte[]](1..16)}
            [pscustomobject]@{SamAccountName='missing';Enabled=$true;NTHash=$null}
        }
        function Get-PwnedResultsForHashes {
            param($Hashes,$UserAgent)
            $map=@{}; foreach($hash in $Hashes){$map[$hash]=[pscustomobject]@{Pwned='Yes';PwnedCount=10}}; return $map
        }
        $pwned=Join-Path $TestDrive 'integration-pwned.csv'
        & (Join-Path $repo 'Password Audit/Invoke-PwnedPasswordCheck.ps1') -Server 'dc.lab' -OutCsv $pwned
        $summary=Import-Csv ([IO.Path]::ChangeExtension($pwned,'summary.csv'))
        $summary.Coverage | Should Be 'Partial'
        $summary.EnabledFindingAccounts | Should Be 1
        $summary.DisabledFindingAccounts | Should Be 1
        $summary.MissingNTPasswordMaterial | Should Be 1
        @(Import-Csv $pwned | Where-Object Pwned -eq 'NotAssessed').Count | Should Be 1
        $duplicate=Join-Path $TestDrive 'integration-duplicate.csv'
        & (Join-Path $repo 'Password Audit/Invoke-SamePasswordCheck.ps1') -Server 'dc.lab' -OutCsv $duplicate -Pwned
        $summary=Import-Csv ([IO.Path]::ChangeExtension($duplicate,'summary.csv'))
        $summary.DuplicateGroups | Should Be 1
        $summary.DisabledFindingAccounts | Should Be 1
        $summary.HIBPSuccessfulAccounts | Should Be 2
        (Get-Content $duplicate -Raw) | Should Not Match '0102030405060708'
    }
}

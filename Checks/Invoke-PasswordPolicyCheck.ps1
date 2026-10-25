<#
    .SYNOPSIS
        ADAudit check: Password Information Audit

    .DESCRIPTION
        Part of AdAudit-PS7.ps1 (switch -passwordpolicy). This file defines the functions of the
        check and is dot-sourced by the runner, which supplies the shared helpers from
        Library\ADAudit.Common.ps1 (output folders, logging, failure / not-assessed tracking,
        Nessus export) and builds the HTML reports afterwards.

        Run this check on its own (same output folders and reports as the full audit):
            .\Checks\Invoke-PasswordPolicyCheck.ps1 [any AdAudit-PS7.ps1 option]
        which is the same as:
            .\AdAudit-PS7.ps1 -select passwordpolicy [options]

    .NOTES
        Entry point: Invoke-PasswordPolicyCheck (called by the runner through Invoke-AuditCheck).
        The check functions were moved verbatim from AdAudit-PS7.ps1 v9.0 when the toolkit was
        split into Library / Checks files. Required modules: ActiveDirectory, DSInternals.
#>
Function Get-PasswordPolicy {
    Write-Both "    [+] Checking default password policy"
    # Query the default domain password policy once and reuse it - the previous version
    # called Get-ADDefaultDomainPasswordPolicy up to nine times per run.
    $pol = Get-ADDefaultDomainPasswordPolicy
    if (!$pol.ComplexityEnabled) {
        Write-Both "    [!] Password Complexity not enabled (KB262)"
        Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled"
    }
    if ($pol.LockoutThreshold -lt 5) {
        Write-Both "    [!] Lockout threshold is less than 5, currently set to $($pol.LockoutThreshold) (KB263)"
        Write-Nessus-Finding "LockoutThreshold" "KB263" "Lockout threshold is less than 5, currently set to $($pol.LockoutThreshold)"
    }
    if ($pol.MinPasswordLength -lt 14) {
        Write-Both "    [!] Minimum password length is less than 14, currently set to $($pol.MinPasswordLength) (KB262)"
        Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length is less than 14, currently set to $($pol.MinPasswordLength)"
    }
    if ($pol.ReversibleEncryptionEnabled) {
        Write-Both "    [!] Reversible encryption is enabled"
    }
    if ($pol.MaxPasswordAge -eq "00:00:00") {
        Write-Both "    [!] Passwords do not expire (KB254)"
        Write-Nessus-Finding "PasswordsDoNotExpire" "KB254" "Passwords do not expire"
    }
    if ($pol.PasswordHistoryCount -lt 12) {
        Write-Both "    [!] Passwords history is less than 12, currently set to $($pol.PasswordHistoryCount) (KB262)"
        Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history is less than 12, currently set to $($pol.PasswordHistoryCount)"
    }
    # NoLmHash is a per-DC machine setting. Read it from the PDC emulator rather than
    # the local host (on a jump server the local value is the jump server's, not a DC's).
    $pdc = try { (Get-ADDomain).PDCEmulator } catch { $null }
    if (-not $pdc) {
        Register-ADAuditNotAssessed -Name 'Get-PasswordPolicy' -Switch 'passwordpolicy' -Reason "Could not determine the PDC emulator to read the NoLmHash (LM hash storage) setting."
    }
    else {
        $noLm = Get-ADAuditRemoteRegistryDword -ComputerName $pdc -SubKey 'SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'NoLmHash'
        if (-not $noLm.Success) {
            Register-ADAuditNotAssessed -Name 'Get-PasswordPolicy' -Switch 'passwordpolicy' -Target $pdc -RequiresRemotePS -Reason "Could not read NoLmHash from the PDC emulator's registry (remote registry over CIM/DCOM/WinRM unavailable): $($noLm.Error)"
        }
        elseif ($null -eq $noLm.Value) {
            Register-ADAuditNotAssessed -Name 'LM hash storage policy' -Switch 'passwordpolicy' -Target $pdc -Reason 'NoLmHash is absent. Effective OS/policy behavior was not established; this does not prove that LM hashes are stored.'
        }
        elseif ($noLm.Value -eq 0) {
            Write-Both "    [!] LM hash storage is permitted by configuration (NoLmHash=0) on $pdc; actual stored hashes require separate evidence. (KB510)"
            Write-Nessus-Finding 'LMHashStoragePermitted' 'KB510' "LM hash storage prevention is disabled (NoLmHash=0) on $pdc. This configuration permits legacy storage; it does not prove any account currently has an LM hash. Use the separate DSInternals LMHash results to establish actual stored credentials."
        }
    }
    Write-Both "    [-] Finished checking default password policy"
    Write-Both "    [+] Checking fine-grained password policies if they exist"
    foreach ($finegrainedpolicy in Get-ADFineGrainedPasswordPolicy -Filter *) {
        $finegrainedpolicyappliesto = $finegrainedpolicy.AppliesTo
        Write-Both "    [!] Policy: $finegrainedpolicy"
        Write-Both "    [!] AppliesTo: $($finegrainedpolicyappliesto)"
        if (-not $finegrainedpolicy.ComplexityEnabled) {
            Write-Both "    [!] Password Complexity not enabled (KB262)"
            Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled for $finegrainedpolicy"
        }
        if (($finegrainedpolicy).LockoutThreshold -lt 5) {
            Write-Both "    [!] Lockout threshold is less than 5, currently set to $(($finegrainedpolicy).LockoutThreshold) (KB263)"
            Write-Nessus-Finding "LockoutThreshold" "KB263" " Lockout threshold for $finegrainedpolicy is less than 5, currently set to $(($finegrainedpolicy).LockoutThreshold)"
        }
        if (($finegrainedpolicy).MinPasswordLength -lt 14) {
            Write-Both "    [!] Minimum password length is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength) (KB262)"
            Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length for $finegrainedpolicy is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength)"
        }
        if (($finegrainedpolicy).ReversibleEncryptionEnabled) {
            Write-Both "    [!] Reversible encryption is enabled"
        }
        if (($finegrainedpolicy).MaxPasswordAge -eq "00:00:00") {
            Write-Both "    [!] Passwords do not expire (KB254)"
        }
        if (($finegrainedpolicy).PasswordHistoryCount -lt 12) {
            Write-Both "    [!] Passwords history is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount) (KB262)"
            Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history for $finegrainedpolicy is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount)"
        }
    }
    Write-Both "    [-] Finished checking fine-grained password policy"
}

Function Get-UserPasswordNotChangedRecently {
    #Reports users that haven't changed passwords in more than 90 days
    $count = 0
    $DaysAgo = (Get-Date).AddDays(-90)
    $accountsoldpasswords = Get-ADUser -Filter { PwdLastSet -lt $DaysAgo -and Enabled -eq "true" } -Properties PasswordLastSet
    $totalcount = ($accountsoldpasswords | Measure-Object | Select-Object Count).count
    foreach ($account in $accountsoldpasswords) {
        if ($totalcount -eq 0) { break }
        Write-ADAuditProgress -Activity "Searching for passwords older than 90days..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)
        if ($account.PasswordLastSet) {
            $datelastchanged = $account.PasswordLastSet
        }
        else {
            $datelastchanged = "Never"
        }
        Add-Content -Path (Get-EvidencePath 'accounts_with_old_passwords.txt') -Value "User $($account.SamAccountName) ($($account.Name)) has not changed their password since $datelastchanged"
        $count++
    }
    Write-ADAuditProgress -Activity "Searching for passwords older than 90days..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count accounts with passwords older than 90days, see accounts_with_old_passwords.txt (KB550)"
        Write-Nessus-Finding "AccountsWithOldPasswords" "KB550" ([System.IO.File]::ReadAllText((Get-EvidencePath 'accounts_with_old_passwords.txt')))
    }
    $krbtgtPasswordDate = (Get-ADUser -Filter { SamAccountName -eq "krbtgt" } -Properties PasswordLastSet).PasswordLastSet
    if ($krbtgtPasswordDate -lt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] krbtgt password not changed since $krbtgtPasswordDate! (KB253)"
        Write-Nessus-Finding "krbtgtPasswordNotChanged" "KB253" "krbtgt password not changed since $krbtgtPasswordDate"
    }
}

Function Get-AccountPassDontExpire {
    #Lists accounts who's passwords dont expire
    $count = 0
    $nonexpiringpasswords = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object { $_.Enabled -eq $true }
    $totalcount = ($nonexpiringpasswords | Measure-Object | Select-Object Count).count
    foreach ($account in $nonexpiringpasswords) {
        if ($totalcount -eq 0) { break }
        Write-ADAuditProgress -Activity "Searching for users with passwords that dont expire..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'accounts_passdontexpire.txt') -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-ADAuditProgress -Activity "Searching for users with passwords that dont expire..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts that don't expire, see accounts_passdontexpire.txt (KB254)"
        Write-Nessus-Finding "AccountsThatDontExpire" "KB254" ([System.IO.File]::ReadAllText((Get-EvidencePath 'accounts_passdontexpire.txt')))
    }
}

Function Remove-StringLatinCharacters {
    #Removes latin characters
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}

function Add-KerberoastExplanationToPasswordQualityReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,
        [Parameter(Mandatory = $false)]
        [string]$DomainController
    )

    if (-not (Test-Path -LiteralPath $ReportPath)) { return }

    $lines = Get-Content -LiteralPath $ReportPath
    $header = 'These accounts are susceptible to the Kerberoasting attack:'

    # Find the simple list block under the header
    $headerIndex = [array]::IndexOf($lines, $header)
    if ($headerIndex -lt 0) { return }

    # Collect the simple list items that follow the header (until a blank line)
    $simpleList = @()
    for ($i = $headerIndex + 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if (-not $line) { break }
        $simpleList += $lines[$i]
    }

    if ($simpleList.Count -eq 0) { return }

    # Normalize SAM names
    $kerberoastAccounts = @()
    foreach ($l in $simpleList) {
        $trimmed = $l.Trim()
        if ($trimmed) { $kerberoastAccounts += $trimmed }
    }

    # Split into krbtgt vs service accounts
    $krbtgtAccounts  = @()
    $serviceAccounts = @()
    foreach ($acct in $kerberoastAccounts) {
        $sam = $acct
        if ($acct -like '*\*') {
            $parts = $acct.Split('\', 2)
            $sam   = $parts[1]
        }
        if ($sam -ieq 'krbtgt') { $krbtgtAccounts += $acct } else { $serviceAccounts += $acct }
    }

    # Build replacement
    $replacement = New-Object System.Collections.Generic.List[string]
    $replacement.Add($header)

    if ($krbtgtAccounts.Count -gt 0) {
        $replacement.Add('  Password not changed in at least 180 days for the built-in krbtgt account (Golden Ticket / ticket-forgery risk):')
        foreach ($acct in $krbtgtAccounts) { $replacement.Add(("    {0}" -f $acct)) }
        $replacement.Add('  Reference: Microsoft guidance "Reset the krbtgt account password".')
        $replacement.Add('')
    }

    if ($serviceAccounts.Count -gt 0) {
        $replacement.Add('  The account is a user or service account with a password that could be weak / brute-forceable (Kerberoastable due to SPN / service ticket exposure):')
        foreach ($acct in $serviceAccounts) { $replacement.Add(("    {0}" -f $acct)) }
        $replacement.Add('  Reference: Microsoft security guidance on mitigating Kerberoasting.')
        $replacement.Add('')
    }

    # Splice into file
    $endOfBlock = $headerIndex + 1 + $simpleList.Count
    $newContent = @()
    if ($headerIndex -gt 0) { $newContent += $lines[0..($headerIndex-1)] }
    $newContent += $replacement
    if ($endOfBlock -lt $lines.Count) { $newContent += $lines[$endOfBlock..($lines.Count-1)] }

    Set-Content -LiteralPath $ReportPath -Value $newContent
}

Function Get-PasswordQuality {
    # Use DSInternals to evaluate password quality (supports remote execution)
    # Output is split into category-specific files for easier consumption and reporting.
    if (Import-ADAuditModule -Name DSInternals) {
        try {
            $cfgNC = (Get-ADRootDSE).ConfigurationNamingContext

            $sites = Get-ADObject `
                -LDAPFilter '(objectClass=site)' `
                -SearchBase $cfgNC `
                -ErrorAction Stop

            $totalSite = ($sites | Measure-Object).Count
            $count = 0

            foreach ($site in $sites) {
                if ($site.Name -eq (Remove-StringLatinCharacters $site.Name)) {
                    $count++
                }
            }

            if ($count -ne $totalSite) {
                    Register-ADAuditNotAssessed -Name 'Get-PasswordQuality' -Switch 'passwordpolicy' -Reason 'Password quality was skipped because a site name failed the legacy character validation.'
                return
            }
        }
        catch {
            Register-ADAuditNotAssessed -Name 'Get-PasswordQuality' -Switch 'passwordpolicy' -Reason "Could not enumerate AD sites: $($_.Exception.Message)"
            return
        }

        # Determine a single DC to query (fallback chain to ensure we get a plain string)
        $dcObj = if ($script:ADAuditIsolatedClone) { Get-ADDomainController -Identity $env:COMPUTERNAME -Server $env:COMPUTERNAME -ErrorAction Stop } else { Get-ADDomainController -Discover }
        $dc = $dcObj.DNSHostName
        if (-not $dc) { $dc = $dcObj.HostName }
        if (-not $dc) { $dc = $dcObj.Name }
        if (-not $dc -or [string]::IsNullOrWhiteSpace($dc)) {
            Register-ADAuditNotAssessed -Name 'Get-PasswordQuality' -Switch 'passwordpolicy' -Reason 'Could not determine a domain controller hostname.'
            return
        }
        $dc = [string]$dc

        try {
            $domain = Get-ADDomain
            $domainDN = $domain.DistinguishedName

            $accounts = Get-ADAuditReplAccountsCached -Server $dc -NamingContext $domainDN

            if ($accounts) {
                # Run DSInternals password quality test and capture the full report
                $passwordQualityPath = Get-EvidencePath 'password_quality.txt'

                Write-ADAuditProgress -Activity 'Password quality: DSInternals analysis' -Status "Evaluating $(@($accounts).Count) replicated accounts; this operation does not expose per-account completion" -PercentComplete -1
                $quality = $accounts | Test-PasswordQuality -IncludeDisabledAccounts -ErrorAction Stop
                $quality | Out-File -FilePath $passwordQualityPath

                if (Test-Path $passwordQualityPath) {
                    Write-Both "    [!] Password quality test done, see password_quality.txt"

                    # Split the combined report into category files FIRST, on the raw
                    # DSInternals output. Doing this before the Kerberoast annotation below
                    # keeps the explanatory prose out of pq_kerberoastable.txt (otherwise
                    # each sentence is mis-counted as a Kerberoastable account).
                    try {
                        Write-ADAuditProgress -Activity 'Password quality: evidence export' -Status 'Separating categories and account states' -PercentComplete -1
                        Export-ADAuditPasswordQualityEvidence -Quality $quality -Accounts @($accounts)
                    }
                    catch {
                        Register-ADAuditNotAssessed -Name 'Password quality evidence' -Switch 'passwordpolicy' -Reason "Could not create structured password-quality evidence: $($_.Exception.Message)"
                    }

                    # Then annotate the combined human-readable report to clarify why accounts
                    # are marked Kerberoastable. This runs after the split so it does not affect
                    # the category evidence files.
                    try {
                        Add-KerberoastExplanationToPasswordQualityReport `
                            -ReportPath $passwordQualityPath `
                            -DomainController $dc
                    }
                    catch {
                        Write-Both "    [*] Failed to append Kerberoast clarification to password quality report: $($_.Exception.Message)"
                    }
                }
                else {
                    Write-Both "    [!] Password quality test ran but output file was not created."
                }
            }
            else {
                Register-ADAuditNotAssessed -Name 'Get-PasswordQuality' -Switch 'passwordpolicy' -Target $dc -Reason 'No replication accounts retrieved; password quality was not assessed.'
            }
        }
        catch {
            # Delimit $dc to avoid $dc: being parsed as an (invalid) scope qualifier
            Register-ADAuditNotAssessed -Name 'Get-PasswordQuality' -Switch 'passwordpolicy' -Target $dc -Reason "Password quality collection failed: $($_.Exception.Message)"
        }
    }
    else {
        Register-ADAuditNotAssessed -Name 'Get-PasswordQuality' -Switch 'passwordpolicy' -Reason 'DSInternals module not available; password quality was not assessed.'
    }
}

function Get-ADAuditPasswordAccountState {
    param([AllowNull()][object]$Account)
    if ($null -eq $Account) { return 'Unknown' }
    $enabled = $Account.PSObject.Properties['Enabled']
    if ($enabled -and $enabled.Value -is [bool]) {
        if ($enabled.Value) { return 'Enabled' }
        return 'Disabled'
    }
    $uac = $Account.PSObject.Properties['UserAccountControl']
    if ($uac -and $null -ne $uac.Value) {
        try { if (([int64]$uac.Value -band 2) -ne 0) { return 'Disabled' }; return 'Enabled' } catch { }
    }
    return 'Unknown'
}

function ConvertTo-ADAuditPasswordQualityFinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Quality, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Accounts)
    # DSInternals returns typed collections of LogonName values. Join those to the
    # replication objects, not optional Users.csv or formatted console output.
    $lookup = @{}
    foreach ($account in $Accounts) {
        foreach ($keyName in @('LogonName','SamAccountName','DistinguishedName')) {
            $property = $account.PSObject.Properties[$keyName]
            if ($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                $key = [string]$property.Value
                # Ambiguous short names must not inherit another account's state.
                if ($lookup.ContainsKey($key) -and $lookup[$key] -ne $account) { $lookup[$key] = $null }
                else { $lookup[$key] = $account }
            }
        }
    }
    $categories = @('ClearTextPassword','LMHash','EmptyPassword','WeakPassword','WeakPasswordHistory',
        'DuplicatePasswordGroups','DefaultComputerPassword','AESKeysMissing','PreAuthNotRequired',
        'DESEncryptionOnly','DelegatableAdmins','PasswordNeverExpires','PasswordNotRequired',
        'Kerberoastable','SamAccountNameAsPassword','SmartCardUsersWithPassword')
    foreach ($category in $categories) {
        $property = $Quality.PSObject.Properties[$category]
        if (-not $property) { continue }
        $groupNumber = 0
        foreach ($entry in $property.Value) {
            $groupNumber++
            $names = if ($category -eq 'DuplicatePasswordGroups') { @($entry) } else { @([string]$entry) }
            foreach ($name in $names) {
                $name = [string]$name
                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                $account = $lookup[$name]
                $sam = if ($account) { [string]$account.SamAccountName } else { $name }
                $detail = 'Reported by DSInternals Test-PasswordQuality.'
                $passwordEvidence = 'NotApplicable'
                if ($category -eq 'PasswordNotRequired') {
                    $detail = 'PASSWD_NOTREQD is set; this flag does not establish that the current password is empty.'
                } elseif ($category -eq 'EmptyPassword') {
                    $hashProperty = if ($account) { $account.PSObject.Properties['NTHash'] } else { $null }
                    if ($hashProperty -and $null -ne $hashProperty.Value) {
                        $hashHex = -join (@($hashProperty.Value) | ForEach-Object { ([byte]$_).ToString('X2') })
                        $passwordEvidence = if ($hashHex -eq '31D6CFE0D16AE931B73C59D7E0C089C0') { 'EmptyNtHash' } else { 'Unknown' }
                        $detail = if ($passwordEvidence -eq 'EmptyNtHash') {
                            'The replicated NT hash matches an empty password.'
                        } else { 'DSInternals reported no password; verify the account credential configuration.' }
                    } else {
                        $passwordEvidence = 'NoNtHash'
                        $detail = 'No NT hash was available in the replication result; this does not prove that a blank-password logon succeeds.'
                    }
                }
                $objectClass = ''
                if ($account) {
                    if ($account.PSObject.Properties['ObjectClass']) { $objectClass = [string]$account.ObjectClass }
                    elseif ($account.PSObject.Properties['SamAccountType']) { $objectClass = [string]$account.SamAccountType }
                }
                [pscustomobject][ordered]@{
                    Category = $category
                    SamAccountName = $sam
                    DistinguishedName = $(if ($account -and $account.PSObject.Properties['DistinguishedName']) { [string]$account.DistinguishedName } else { '' })
                    AccountStatus = Get-ADAuditPasswordAccountState -Account $account
                    ObjectClass = $objectClass
                    GroupId = $(if ($category -eq 'DuplicatePasswordGroups') { 'PWD-REUSE-{0:d3}' -f $groupNumber } else { '' })
                    EvidenceSource = 'DSInternals Test-PasswordQuality'
                    EvidenceDetail = $detail
                    PasswordEvidence = $passwordEvidence
                }
            }
        }
    }
}

function Export-ADAuditPasswordQualityEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Quality, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Accounts)
    $rows = @(ConvertTo-ADAuditPasswordQualityFinding -Quality $Quality -Accounts $Accounts)
    $csvPath = Get-EvidencePath 'password_quality_findings.csv'
    # Always create the schema, including a successfully assessed empty result.
    '"Category","SamAccountName","DistinguishedName","AccountStatus","ObjectClass","GroupId","EvidenceSource","EvidenceDetail","PasswordEvidence"' | Set-Content -LiteralPath $csvPath -Encoding UTF8
    if ($rows.Count) { $rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 }
    $categoryMap = [ordered]@{
        ClearTextPassword = @('pq_reversible_encryption.txt','KB997','Critical','reversible encryption')
        LMHash = @('pq_lm_hashes.txt','KB998','Critical','LM hashes present')
        EmptyPassword = @('pq_no_password.txt','KB999','Critical','empty or absent NT password credential')
        WeakPassword = @('pq_dictionary_passwords.txt','KB1000','Critical','dictionary passwords')
        WeakPasswordHistory = @('pq_historical_dictionary.txt','KB1001','Medium','historical dictionary passwords')
        DuplicatePasswordGroups = @('pq_duplicate_passwords.txt','KB1002','Critical','duplicate passwords')
        DefaultComputerPassword = @('pq_default_computer_passwords.txt','KB1003','High','default computer passwords')
        AESKeysMissing = @('pq_missing_aes_keys.txt','KB1004','Medium','missing Kerberos AES keys')
        PreAuthNotRequired = @('pq_no_preauth.txt','KB1005','Critical','Kerberos pre-auth not required')
        DESEncryptionOnly = @('pq_des_only.txt','KB1006','Critical','DES-only encryption')
        DelegatableAdmins = @('pq_admin_delegation.txt','KB1007','High','admin accounts delegatable')
        PasswordNeverExpires = @('pq_password_never_expires.txt','KB1008','Medium','password never expires')
        PasswordNotRequired = @('pq_password_not_required.txt','KB1009','High','password not required flag')
        Kerberoastable = @('pq_kerberoastable.txt','KB1010','High','Kerberoastable accounts')
        SamAccountNameAsPassword = @('pq_username_passwords.txt','KB1011','Critical','account name used as password')
        SmartCardUsersWithPassword = @('pq_smartcard_passwords.txt','KB1012','Medium','smart-card accounts with password credentials')
    }
    foreach ($category in $categoryMap.Keys) {
        $meta = $categoryMap[$category]
        $path = Get-EvidencePath $meta[0]
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        $entries = @($rows | Where-Object Category -eq $category)
        if (-not $entries.Count) { continue }
        $enabled = @($entries | Where-Object { $_.AccountStatus -eq 'Enabled' -and ($_.Category -ne 'EmptyPassword' -or $_.PasswordEvidence -eq 'EmptyNtHash') })
        $disabled = @($entries | Where-Object AccountStatus -eq 'Disabled')
        $unknown = @($entries | Where-Object { $_.AccountStatus -eq 'Unknown' -or ($_.Category -eq 'EmptyPassword' -and $_.PasswordEvidence -ne 'EmptyNtHash') })
        $content = @("PASSWORD QUALITY: $($meta[3])", "Enabled: $($enabled.Count); Disabled: $($disabled.Count); Unknown: $($unknown.Count)",
            'Disabled accounts are hygiene items; unknown state is not assumed enabled.',
            'Source: DSInternals typed results; see password_quality_findings.csv for authoritative account state.', '')
        $content += @($entries | ForEach-Object { "[$($_.AccountStatus)] $($_.SamAccountName) $($_.GroupId) $($_.DistinguishedName) -- $($_.EvidenceDetail)" })
        $content | Set-Content -LiteralPath $path -Encoding UTF8
        if ($enabled.Count) {
            $activeContent = ($enabled | ForEach-Object { "$($_.SamAccountName) $($_.GroupId) -- $($_.EvidenceDetail)" }) -join "`n"
            Write-Nessus-Finding "PasswordQuality_$category" $meta[1] $activeContent $meta[2]
        }
        if ($disabled.Count -or $unknown.Count) { Write-Nessus-Finding "PasswordQuality_${category}_Review" $meta[1] ($content -join "`n") 'Info' }
    }
    if (@($rows | Where-Object AccountStatus -eq 'Unknown').Count) {
        Register-ADAuditNotAssessed -Name 'Password quality account state' -Switch 'passwordpolicy' -Reason 'Some typed findings could not be joined to a replicated account with known enabled/disabled state; see password_quality_findings.csv.'
    }
    Write-Both "    [+] Password quality state preserved for $($rows.Count) category/account rows in password_quality_findings.csv"
}

function Split-PasswordQualityReport {
    # Parses the combined password_quality.txt from DSInternals Test-PasswordQuality and writes
    # each section into a dedicated evidence file.  The original combined file is kept intact.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath
    )

    if (-not (Test-Path -LiteralPath $ReportPath)) { return }

    $allLines = @(Get-Content -LiteralPath $ReportPath -ErrorAction Stop)
    if ($allLines.Count -eq 0) { return }

    # Map each DSInternals section header to a target evidence file name and a nessus KB id
    $sectionMap = [ordered]@{
        'Passwords of these accounts are stored using reversible encryption:'                    = @{ File = 'pq_reversible_encryption.txt';       KB = 'KB997';  Severity = 'Critical'; Label = 'reversible encryption' }
        'LM hashes of passwords of these accounts are present:'                                 = @{ File = 'pq_lm_hashes.txt';                   KB = 'KB998';  Severity = 'Critical'; Label = 'LM hashes present' }
        'These accounts have no password set:'                                                  = @{ File = 'pq_no_password.txt';                 KB = 'KB999';  Severity = 'Critical'; Label = 'no password set' }
        'Passwords of these accounts have been found in the dictionary:'                        = @{ File = 'pq_dictionary_passwords.txt';        KB = 'KB1000'; Severity = 'Critical'; Label = 'dictionary passwords' }
        'Historical passwords of these accounts have been found in the dictionary:'             = @{ File = 'pq_historical_dictionary.txt';       KB = 'KB1001'; Severity = 'Medium';   Label = 'historical dictionary passwords' }
        'These groups of accounts have the same passwords:'                                     = @{ File = 'pq_duplicate_passwords.txt';         KB = 'KB1002'; Severity = 'High';     Label = 'duplicate passwords' }
        'These computer accounts have default passwords:'                                       = @{ File = 'pq_default_computer_passwords.txt';  KB = 'KB1003'; Severity = 'High';     Label = 'default computer passwords' }
        'Kerberos AES keys are missing from these accounts:'                                    = @{ File = 'pq_missing_aes_keys.txt';            KB = 'KB1004'; Severity = 'Medium';   Label = 'missing Kerberos AES keys' }
        'Kerberos pre-authentication is not required for these accounts:'                       = @{ File = 'pq_no_preauth.txt';                  KB = 'KB1005'; Severity = 'High';     Label = 'Kerberos pre-auth not required' }
        'Only DES encryption is allowed to be used with these accounts:'                        = @{ File = 'pq_des_only.txt';                    KB = 'KB1006'; Severity = 'Critical'; Label = 'DES-only encryption' }
        'These administrative accounts are allowed to be delegated to a service:'               = @{ File = 'pq_admin_delegation.txt';            KB = 'KB1007'; Severity = 'High';     Label = 'admin accounts delegatable' }
        'Passwords of these accounts will never expire:'                                        = @{ File = 'pq_password_never_expires.txt';      KB = 'KB1008'; Severity = 'Medium';   Label = 'password never expires' }
        'These accounts are not required to have a password:'                                   = @{ File = 'pq_password_not_required.txt';       KB = 'KB1009'; Severity = 'High';     Label = 'password not required' }
        'These accounts are susceptible to the Kerberoasting attack:'                           = @{ File = 'pq_kerberoastable.txt';              KB = 'KB1010'; Severity = 'High';     Label = 'Kerberoastable accounts' }
    }

    # Build a list of known headers for quick lookup
    $knownHeaders = $sectionMap.Keys

    # Parse the file into sections
    $sections = [ordered]@{}
    $currentHeader = $null
    $currentLines  = New-Object 'System.Collections.Generic.List[string]'

    foreach ($line in $allLines) {
        $trimmed = $line.Trim()

        # Check if this line is a known section header
        $matchedHeader = $null
        foreach ($h in $knownHeaders) {
            if ($trimmed -eq $h) {
                $matchedHeader = $h
                break
            }
        }

        if ($matchedHeader) {
            # Save previous section if any
            if ($currentHeader) {
                $sections[$currentHeader] = $currentLines.ToArray()
            }
            $currentHeader = $matchedHeader
            $currentLines  = New-Object 'System.Collections.Generic.List[string]'
        }
        elseif ($currentHeader) {
            if ($line -match '^\S' -and $trimmed.EndsWith(':')) {
                # Unknown section header - close the current section instead of absorbing it
                $sections[$currentHeader] = $currentLines.ToArray()
                $currentHeader = $null
                $currentLines  = New-Object 'System.Collections.Generic.List[string]'
            }
            else {
                $currentLines.Add($line) | Out-Null
            }
        }
    }
    # Save last section
    if ($currentHeader) {
        $sections[$currentHeader] = $currentLines.ToArray()
    }

    $filesWritten = 0

    foreach ($header in $sections.Keys) {
        $bodyLines = $sections[$header]
        # Strip leading/trailing blank lines and get account entries
        $accountEntries = @($bodyLines | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })

        if ($accountEntries.Count -eq 0) { continue }

        $meta = $sectionMap[$header]
        if (-not $meta) { continue }

        $targetPath = Get-EvidencePath $meta.File

        $fileContent = @"
=====================================================================
 PASSWORD QUALITY: $($meta.Label.ToUpper())
=====================================================================
 Source    : DSInternals Test-PasswordQuality
 Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
 Accounts  : $($accountEntries.Count)
---------------------------------------------------------------------

$header

"@
        # For "groups of accounts have the same passwords" the format is different (grouped)
        # so we write the raw block preserving structure, plus an explanatory note
        # about NTLM hash equality and the security risk it represents.
        if ($header -match 'groups of accounts have the same passwords') {
            $fileContent += @"
WHY THIS MATTERS
---------------------------------------------------------------------
DSInternals identified the accounts below by comparing NTLM password
hashes pulled from NTDS.dit. Every account listed in the same group
has the IDENTICAL NTLM hash, which means they share the EXACT SAME
plaintext password (NTLM is an unsalted MD4 over the UTF-16 password,
so equal hash <=> equal password).

Risk:
  - One credential compromise unlocks every account in the group at
    once. An attacker who obtains the NTLM hash from one account
    (Mimikatz, DCSync, kerberoasting, LSASS dump, etc.) can pass-the-
    hash to every other account that shares it - including across
    privilege tiers if a low-tier account happens to share a password
    with a high-tier one.
  - Service accounts and admin accounts that share a password with
    user accounts are an immediate lateral-movement path.
  - Password reuse across users defeats lockout, auditing per-user
    accountability, and any "rotate one account's password" response.

Each blank-line-separated block below is one group of accounts that
share the same NTLM hash (i.e. the same password):

---------------------------------------------------------------------

"@
            $fileContent += ($bodyLines -join "`n")
        }
        else {
            foreach ($entry in $accountEntries) {
                $fileContent += "  $entry`n"
            }
        }

        $fileContent += @"

---------------------------------------------------------------------
 Total accounts: $($accountEntries.Count)
=====================================================================
"@

        Set-Content -LiteralPath $targetPath -Value $fileContent -Encoding UTF8
        $filesWritten++

        Write-Both "    [+] Password quality category: $($meta.Label) - $($accountEntries.Count) accounts -> $($meta.File)"

        # Write nessus finding for each non-empty category
        Write-Nessus-Finding "PasswordQuality_$($meta.Label -replace '\s+','_')" $meta.KB $fileContent
    }

    if ($filesWritten -gt 0) {
        Write-Both "    [+] Password quality report split into $filesWritten category files"
    }
}

function Invoke-PasswordPolicyCheck {
    Write-ADAuditProgress -Activity 'Password policy checks' -Status 'Starting collection' -PercentComplete -1
    try {
        Invoke-AuditStep -Name 'Get-AccountPassDontExpire' -Switch 'passwordpolicy' -Body { Get-AccountPassDontExpire }
        Invoke-AuditStep -Name 'Get-UserPasswordNotChangedRecently' -Switch 'passwordpolicy' -Body { Get-UserPasswordNotChangedRecently }
        Invoke-AuditStep -Name 'Get-PasswordPolicy' -Switch 'passwordpolicy' -Body { Get-PasswordPolicy }
        Invoke-AuditStep -Name 'Get-PasswordQuality' -Switch 'passwordpolicy' -Body { Get-PasswordQuality }
    } finally {
        Write-ADAuditProgress -Activity 'Password policy checks' -Completed
    }
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select passwordpolicy @args
}

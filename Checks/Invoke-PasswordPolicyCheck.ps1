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
        elseif ($noLm.Value -eq 0) {
            Write-Both "    [!] LM Hashes are stored on $pdc! (KB510)"
            Write-Nessus-Finding "LMHashesAreStored" "KB510" "LM Hashes are stored (NoLmHash=0) on $pdc"
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
        Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)
        if ($account.PasswordLastSet) {
            $datelastchanged = $account.PasswordLastSet
        }
        else {
            $datelastchanged = "Never"
        }
        Add-Content -Path (Get-EvidencePath 'accounts_with_old_passwords.txt') -Value "User $($account.SamAccountName) ($($account.Name)) has not changed their password since $datelastchanged"
        $count++
    }
    Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Ready" -Completed
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
        Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path (Get-EvidencePath 'accounts_passdontexpire.txt') -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Ready" -Completed
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
                Write-Both "    [!] One or more sites have illegal characters in their name, can't get password quality!"
                return
            }
        }
        catch {
            Write-Both "    [!] Failed to enumerate AD sites for password quality test: $($_.Exception.Message)"
            return
        }

        # Determine a single DC to query (fallback chain to ensure we get a plain string)
        $dcObj = Get-ADDomainController -Discover
        $dc = $dcObj.DNSHostName
        if (-not $dc) { $dc = $dcObj.HostName }
        if (-not $dc) { $dc = $dcObj.Name }
        if (-not $dc -or [string]::IsNullOrWhiteSpace($dc)) {
            Write-Both "    [!] Could not determine a domain controller hostname for password quality test."
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

                $accounts |
                    Test-PasswordQuality -IncludeDisabledAccounts |
                    Out-File -FilePath $passwordQualityPath

                if (Test-Path $passwordQualityPath) {
                    Write-Both "    [!] Password quality test done, see password_quality.txt"

                    # Split the combined report into category files FIRST, on the raw
                    # DSInternals output. Doing this before the Kerberoast annotation below
                    # keeps the explanatory prose out of pq_kerberoastable.txt (otherwise
                    # each sentence is mis-counted as a Kerberoastable account).
                    try {
                        Split-PasswordQualityReport -ReportPath $passwordQualityPath
                    }
                    catch {
                        Write-Both "    [*] Failed to split password quality report into category files: $($_.Exception.Message)"
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
                Write-Both "    [!] No replication accounts retrieved from DC $dc; skipping password quality test."
            }
        }
        catch {
            # Delimit $dc to avoid $dc: being parsed as an (invalid) scope qualifier
            Write-Both "    [!] Failed password quality test on DC ${dc}: $($_.Exception.Message)"
        }
    }
    else {
        Write-Both "    [!] DSInternals module not available; skipping password quality test."
    }
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
    Invoke-AuditStep -Name 'Get-AccountPassDontExpire' -Switch 'passwordpolicy' -Body { Get-AccountPassDontExpire }
    Invoke-AuditStep -Name 'Get-UserPasswordNotChangedRecently' -Switch 'passwordpolicy' -Body { Get-UserPasswordNotChangedRecently }
    Invoke-AuditStep -Name 'Get-PasswordPolicy' -Switch 'passwordpolicy' -Body { Get-PasswordPolicy }
    Invoke-AuditStep -Name 'Get-PasswordQuality' -Switch 'passwordpolicy' -Body { Get-PasswordQuality }
}

# ---- Standalone launch --------------------------------------------------------------------
# Dot-sourced by AdAudit-PS7.ps1 this file only defines functions. Started directly it hands
# over to the runner so the output folders, Nessus export and HTML reports are identical.
if ($MyInvocation.InvocationName -ne '.') {
    & (Join-Path (Split-Path -Parent $PSScriptRoot) 'AdAudit-PS7.ps1') -select passwordpolicy @args
}
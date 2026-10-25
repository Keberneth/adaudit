# Password Audit

Two standalone scripts that read NTLM hashes through DSInternals replication (`Get-ADReplAccount`, so the account running them needs replication rights). They are deliberately **separate from the audit run**: `AdAudit-PS7.ps1 -all` never runs them. Start them from the GUI (`ADAudit-GUI.ps1`, section "Password Audit") or from a PowerShell 7 prompt:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Invoke-PwnedPasswordCheck.ps1 [-Server dc01.contoso.local] [-OutCsv <path>] [-IncludeComputers]
.\Invoke-SamePasswordCheck.ps1  [-Server dc01.contoso.local] [-OutCsv <path>] [-UsersOnly] [-Pwned]
```

| Script | What it reports | Default output |
|---|---|---|
| `Invoke-PwnedPasswordCheck.ps1` | Accounts whose NTLM hash appears in the Have I Been Pwned corpus (`Yes` / `No` / `LookupFailed`) | `PWNED_PASSWORD_HASH.csv` next to the script (the GUI writes to `<COMPUTERNAME>\Password Audit\`) |
| `Invoke-SamePasswordCheck.ps1` | Accounts that share the same password (identical NTLM hash), grouped; `-Pwned` also checks each duplicate hash against Have I Been Pwned | `DUPLICATE_PASSWORDS.csv` next to the script (the GUI writes to `<COMPUTERNAME>\Password Audit\`) |

`PasswordAuditCommon.psm1` holds the shared helpers (replication read, hash conversion, HIBP range lookup). NTLM hashes are kept in memory only and are never written to the CSV files.

## Customer report and coverage

Each script writes an offline HTML report and a one-row coverage CSV alongside the requested account CSV. For example, `PWNED_PASSWORD_HASH.csv` also produces `PWNED_PASSWORD_HASH.html` and `PWNED_PASSWORD_HASH.summary.csv`. The HTML is self-contained and does not call external services when opened. Its appearance follows the system theme by default; the Appearance selector also supports Light and Dark. Confirmed findings appear first, while unavailable checks remain accessible in an expandable evidence section.

The reports distinguish enabled (`Active` in the existing CSV schema), disabled, and unknown account states. Enabled findings are prioritized for remediation; disabled findings are retained for cleanup and reactivation review. `NotAssessed` identifies accounts whose NT password material was unavailable. Missing password material does not establish a blank password. API failures remain `LookupFailed`, never `No`.

Coverage includes returned accounts, exclusions, missing account names, processed accounts by state, unavailable NT password material, successful HIBP lookups, and failed lookups. A partial or unassessed run is clearly labelled. In duplicate-only mode, all processed accounts are compared locally, while HIBP counts cover duplicate groups only when `-Pwned` was selected. Accounts excluded by `-UsersOnly` / default user scope are identified by the existing trailing-`$` rule; review service-account scope if this naming heuristic is unsuitable.

`CoverageReasons` explains why overall coverage is partial. Missing NT material is broken down into enabled, disabled and unknown-state counts. `HIBPStatus` independently reports whether the API check was completed, partial, failed, not requested, or had no eligible accounts. For example, a run with successful API lookups and disabled accounts lacking NT material has partial overall coverage but a completed HIBP check. This is not a connectivity failure. Collection reflects the selected controller's data; an isolated or cloned controller may contain historical password and account state.

A HIBP match means the password appears in its corpus; it does not prove the customer's account was breached. A negative match is not a password-strength guarantee. Coordinate rotations with application owners, prioritize privileged and service accounts, and review disabled identities before reactivation. Duplicate-group identifiers only identify groups within the current run. These paid add-on scripts remain separate from the standard audit and its existing password-quality checks.

Network requirements remain AD replication connectivity to the selected DC (including RPC endpoint mapper and the configured dynamic/static RPC endpoints), AD discovery/administration access, and outbound HTTPS to `api.pwnedpasswords.com` when HIBP checks are requested. Use the customer's approved management paths and account with the necessary replication rights. No additional inbound service or report hosting is required.

## Progress and troubleshooting

Both scripts print timestamped stages for module loading, domain lookup, replication, account preparation, HIBP lookup where requested, and report writing. Replication shows received account counts as DSInternals yields records; its total is unknown and the first result can take several minutes. HIBP progress shows completed/total range requests, failed ranges and elapsed time. Console updates are also emitted periodically between completed operations, so the current stage remains visible when progress bars are hidden. A blocked request cannot provide a new count until it returns or times out; HIBP requests have a 30-second timeout and report retry delays.

Interpret the result before changing connectivity settings:

- `NotAssessed`: NT password material was unavailable for that account. Inspect its state and collection rights; this does not prove an empty password and is not an API failure.
- `NotChecked` in a duplicate report: the optional HIBP lookup was not selected. Use `Invoke-SamePasswordCheck.ps1 -Pwned` to check the shared-password groups as well.
- `LookupFailed`: an HTTPS request failed or the returned range body was empty/malformed. The account's corpus status remains unknown. Console warnings distinguish HTTP errors from network/TLS errors without logging queried password prefixes or response bodies.
- `Test-NetConnection api.pwnedpasswords.com -Port 443` tests TCP connectivity. A successful result does not validate TLS, an authentic HIBP range response, or proxy authentication. Check the actual script lookup status and the customer's approved HTTPS/proxy path before diagnosing a network failure.

Outputs are findings plus unavailable evidence, not a full account inventory. The coverage CSV records successful negative HIBP checks even though individual negative accounts are omitted from the account CSV.

## How the Have I Been Pwned lookup works

`Invoke-PwnedPasswordCheck.ps1` checks Active Directory account NTLM hashes against the  
https://api.pwnedpasswords.com service using a **k-anonymity range query**.

This ensures the script **never sends the full NTLM hash over the network**.

---

## How it works

### Example

Full NTLM hash extracted from AD:

8846F7EAEE8FB117AD06BDD830B7586C

The script splits the hash into:

- **Prefix (first 5 characters)** → sent to API  
  8846F

- **Suffix (remaining 27 characters)** → kept locally  
  7EAEE8FB117AD06BDD830B7586C

---

### API request

https://api.pwnedpasswords.com/range/8846F?mode=ntlm

Only the **5-character prefix** is sent.

The shared prefix reduces disclosure compared with sending the complete hash. Prefix queries still reveal limited information about the tested set; use them only within the agreed audit scope.

---

## What comes back

The API returns **many suffixes** that share the same prefix, along with how many times they appear in breach data:

7EAEE8FB117AD06BDD830B7586C:12345
<br>
A1B2C3D4E5F60718293A4B5C6D7:2

Each line consists of:<br>
`<SUFFIX>:<COUNT>`

- `SUFFIX` = remaining 27 characters of the NTLM hash  
- `COUNT` = number of times this password appears in breach datasets  

---

## Finding pwned passwords

The script:

1. Receives all suffixes from the API
2. Compares them **locally** with the stored suffix
3. Determines if there is a match

---

## Report output

- `Yes` → NTLM hash found in breach corpus  
- `No` → Not found in breach corpus  
- `LookupFailed` → API/network error during lookup  

---

## Security model

This approach uses **k-anonymity**:

- The full NTLM hash is **never transmitted**
- The API only sees a shared prefix
- Matching is performed **locally**

---

## Notes

- Only **NTLM hashes** are used (`mode=ntlm`)
- Each unique hash is queried **once** (results are cached)
- Optional padding (`Add-Padding: true`) is used to prevent response size analysis

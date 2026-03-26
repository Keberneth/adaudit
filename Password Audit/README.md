# Script description
Run scripts:
**Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & "FULL PATH TO SCRIPT"**
<br>
`pwned_passwd_prof.ps1` checks Active Directory account NTLM hashes against the  
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

This is not enough to reconstruct the original hash or password.

---

## What comes back

The API returns **many suffixes** that share the same prefix, along with how many times they appear in breach data:

7EAEE8FB117AD06BDD830B7586C:12345
A1B2C3D4E5F60718293A4B5C6D7:2

Each line consists of:

<SUFFIX>:<COUNT>

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

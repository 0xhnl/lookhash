# lookhash

DFIR tooling for NTDS/secretsdump credential analysis.

- **`lookhash.py`** — extract NT hashes → crack them (ntlm.pw API and/or custom passwords) → Excel report → export creds.
- **`mfa.py`** — take the exported creds and check Office 365 / Entra ID MFA status for each account.

## Requirements

```bash
pip install requests pandas openpyxl
```

Python 3.8+. MD4 works even on OpenSSL 3 builds (built-in fallback), so no extra crypto deps.

---

## lookhash.py

One script for the whole pipeline. Input is a secretsdump-style file (`domain\user:rid:lm:nt:::`), or a file of bare 32-char NT hashes.

### Crack via ntlm.pw (online lookup)

```bash
python3 lookhash.py dump.txt -o report.xlsx
```

Extracts unique NT hashes, looks them up against ntlm.pw (300/request, rate-limit aware), writes the report.

```
[*] Extracting NT hashes from dump.txt...
[+] Extracted 1472 unique NT hashes
[*] Looking up 1-300 of 1472...
    [+] a1b2...c3d4:Summer2024!
    [+] e5f6...a7b8:P@ssw0rd123
[*] Looking up 301-600 of 1472...
...
[+] Cracked 318 of 1472 hashes
[+] Sheet 1 - All_Hashes: 1472 entries
[+] Sheet 2 - Cracked_Passwords: 318 entries
[+] Excel report created: report.xlsx
```

### Check custom passwords (offline, no API)

Hash candidate passwords locally and flag accounts that use them:

```bash
python3 lookhash.py dump.txt -o report.xlsx -p 'P@ssw0rd123' --no-lookup
python3 lookhash.py dump.txt -o report.xlsx -p 'Summer2024!' -p 'Welcome1' --no-lookup
```

`-p` is repeatable. Drop `--no-lookup` to run ntlm.pw **and** custom passwords in one pass.

```
[*] Extracting NT hashes from dump.txt...
[+] Extracted 1472 unique NT hashes
[*] Testing password 'P@ssw0rd123' (NT hash: e5f6...a7b8)...
    [+] match: e5f6...a7b8:P@ssw0rd123
[+] Custom check: 1 of 1 password(s) matched
[+] Sheet 2 - Cracked_Passwords: 14 entries
[+] Excel report created: report.xlsx
```

### Build report without cracking

```bash
python3 lookhash.py dump.txt -o report.xlsx --no-lookup
```

### Export cracked creds to text

`domain:username:password`, one per line (deduplicated) — from a report `.xlsx`:

```bash
python3 lookhash.py -f report.xlsx -export -o creds.txt
```

```
[+] Exported 318 domain:username:password lines -> creds.txt
```

…or from a raw `hash:password` results file (needs the dump to resolve usernames):

```bash
python3 lookhash.py dump.txt -f results.txt -export -o creds.txt
```

### Options

| Flag | Description |
|------|-------------|
| `dump` | Input hash file (positional; required except for `-export` from `.xlsx`) |
| `-o, --output` | Output file — `.xlsx` report, or `.txt` with `-export` (required) |
| `-p, --password` | Candidate password to test locally; repeat for several |
| `-t, --type` | Hash type for ntlm.pw: `nt` (default), `lm`, `md5`, `sha1`, `sha256` |
| `--no-lookup` | Skip the ntlm.pw lookup |
| `-f, --file` | Export-mode input: a report `.xlsx` or a `hash:password` file |
| `-export` | Export `domain:username:password` to `-o` instead of a report |

The report has two sheets: **All_Hashes** (domain, username, UID, LM, NT) and **Cracked_Passwords** (domain, username, password).

---

## mfa.py

Feed the exported creds in to see which accounts have MFA enabled. Uses the Microsoft OAuth2 ROPC endpoint over HTTPS (port 443).

```bash
python3 mfa.py -f creds.txt
```

```
[*] Processing accounts via HTTPS (Port 443)...
[*] Target File: creds.txt

DOMAIN               | FULL EMAIL (UPN)                    | STATUS
--------------------------------------------------------------------------------
corp.local           | alice@corp.local                    | MFA ENABLED / ENFORCED
corp.local           | bob@corp.local                      | SUCCESS (No MFA Required / Password Valid)
corp.local           | svc_backup@corp.local               | FAILED (Invalid Password)
```

Input lines are `domain:username:password` (the `lookhash.py -export` format). Status per account:

- `SUCCESS (No MFA Required / Password Valid)` — token issued, no MFA in the way
- `MFA ENABLED / ENFORCED` — AADSTS50076 / 50079
- `BLOCKED (Conditional Access Policy / MFA Enforced)` — AADSTS53003
- `FAILED (Invalid Password)` — AADSTS50126

---

## End-to-end example

```bash
# 1. Crack NTDS dump
python3 lookhash.py all-dump.txt -o report.xlsx

# 2. Export the cracked accounts
python3 lookhash.py -f report.xlsx -export -o creds.txt

# 3. Check MFA posture of those accounts
python3 mfa.py -f creds.txt
```

> For authorized DFIR / internal security assessments only.

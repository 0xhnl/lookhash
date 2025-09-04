# Hash Lookup Tool

A Python-based command-line tool to perform hash lookups using the ntlm.pw API . This tool supports multiple hash types (nt, lm, md5, sha1, sha256) and allows both single and bulk hash lookups. Results can be displayed live in the terminal or saved to an output file.

# Features

- Multiple Hash Types : Supports nt, lm, md5, sha1, and sha256.
- Single and Bulk Lookups : Perform lookups for individual hashes or process large files with up to 300 hashes per request.
- Live Results : View results in real-time as they are fetched from the API.
- Output to File : Save results to a file while still displaying them in the terminal.
- Rate-Limited Requests : Ensures compliance with API rate limits by introducing a 5-second delay between bulk requests.

# Installation

- Clone the repository:

```
git clone https://github.com/0xhnl/lookhash.git
cd lookhash
```

- Split the hashes and lookup those hashes using ntlm.pw:

```bash
$ python3 lookhash.py -t nt -f secretdump.txt -o results.txt
[*] Extracting NT hashes from secretdump.txt...
    [+] Extracted: a1231231231231231231223123123123
    [+] Extracted: b1231231231231231231223123123123
    [+] Extracted: c1231231231231231231223123123123
    [+] Extracted: d1231231231231231231223123123123
    [+] Extracted: e1231231231231231231223123123123
    [+] Extracted: f1231231231231231231223123123123
    [+] Extracted: g1231231231231231231223123123123
    [+] Extracted: h1231231231231231231223123123123
    [+] Extracted: i1231231231231231231223123123123
....
[+] Extracted 1472 unique NT hashes to extracted_nt_hashes.txt
[*] Splitting extracted hashes into chunks...
[+] Wrote 500 lines to temp_split/raw-hash-01
[+] Wrote 500 lines to temp_split/raw-hash-02
[+] Wrote 312 lines to temp_split/raw-hash-03
[*] Performing hash lookups...
[*] Processing temp_split/raw-hash-01...
```

- Lookup the custom passwords:

```bash
$ python3 cuslook.py -f "hash-sploit-folder/*" -p 'P@ssw0rd123' -o cus.txt -a 
Found 9 files to process
Generated NTLM hash for password 'P@ssw0rd123': 123123123123123123123123123
Processing hash-sploit-folder/raw-hash-01...
Processing hash-sploit-folder/raw-hash-06...
Processing hash-sploit-folder/raw-hash-08...
Processing hash-sploit-folder/raw-hash-09...
Processing hash-sploit-folder/raw-hash-07...
Processing hash-sploit-folder/raw-hash-05...
Processing hash-sploit-folder/raw-hash-02...
Processing hash-sploit-folder/raw-hash-03...
Processing hash-sploit-folder/raw-hash-04...
Total hashes processed: 4449
Appending to cus.txt
Found 1 matches out of 4449 hashes
```

- And then create excel report using this:

```bash
$ python3 report.py -f secretdump.txt -p results.txt -cp cus.txt -o full-report.xlsx
Parsing hash file: cus-dcsync.txt
Found 3000 hash entries
Parsing cracked passwords file: output.txt
Found 67 cracked passwords (excluding [not found])
Matching passwords with hashes...
Successfully matched 67 passwords
Sheet 1 - All_Hashes: 3000 entries
Sheet 2 - Cracked_Passwords: 67 entries
Excel file successfully created with Titillium Web font: full-report.xlsx
``` 

- Perform a lookup for a single hash:

```bash
$ python3 script.py -t nt -x 66sd423103a39234df59ff82134ccfb20
66sd423103a39234df59ff82134ccfb20:$ecureP@ssw112
```

# Acknowledgments

- Thanks to the ntlm.pw API for providing the hash lookup service.
- Inspired by the need for efficient hash lookup tools in cybersecurity workflows.

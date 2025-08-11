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

- Split the hashes file before lookup:

```bash
$ python3 split.py -f sort-raw-hash.txt -o output
[+] Wrote 500 lines to output/raw-hash-01
[+] Wrote 500 lines to output/raw-hash-02
[+] Wrote 500 lines to output/raw-hash-03
[+] Wrote 500 lines to output/raw-hash-04
[+] Wrote 500 lines to output/raw-hash-05
[+] Wrote 500 lines to output/raw-hash-06
[+] Wrote 500 lines to output/raw-hash-07
[+] Wrote 500 lines to output/raw-hash-08
[+] Wrote 191 lines to output/raw-hash-09
```

- Perform a lookup for a single hash:

```bash
$ python3 script.py -t nt -x 66sd423103a39234df59ff82134ccfb20
66sd423103a39234df59ff82134ccfb20:$ecureP@ssw112
```

- Bulk Hash Lookup with Output File:

```bash
$ python3 lookhash.py -t nt -f hashes.txt -o output.txt
3f52147afd48d6dc736be621d77badee:[not found]
24aec733b52a2342b225bba08ea69111:[not found]
...
```

# Acknowledgments

- Thanks to the ntlm.pw API for providing the hash lookup service.
- Inspired by the need for efficient hash lookup tools in cybersecurity workflows.

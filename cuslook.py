#!/usr/bin/env python3

import argparse
import hashlib
import sys
import os
import glob

def generate_ntlm_hash(password):
    """Generate NTLM hash from a password"""
    # Convert password to UTF-16LE bytes
    password_bytes = password.encode('utf-16le')
    # Generate MD4 hash
    ntlm_hash = hashlib.new('md4', password_bytes).hexdigest()
    return ntlm_hash.lower()

def read_hashes_from_file(filename):
    """Read NTLM hashes from file"""
    hashes = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract hash (handle various formats)
                    if ':' in line:
                        # If in format username:hash or hash:other_data
                        parts = line.split(':')
                        hash_part = parts[1] if len(parts) > 1 else parts[0]
                    else:
                        hash_part = line
                    
                    # Validate hash format (should be 32 hex characters)
                    if len(hash_part) == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_part):
                        hashes.append((hash_part.lower(), line))  # (clean_hash, original_line)
                    else:
                        print(f"Warning: Skipping invalid hash format in {filename}: {line}", file=sys.stderr)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found", file=sys.stderr)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}", file=sys.stderr)
    
    return hashes

def process_multiple_files(file_pattern, password, output_file, append_mode=False):
    """Process multiple hash files"""
    # Get all files matching the pattern
    files = glob.glob(file_pattern)
    
    if not files:
        print(f"Error: No files found matching pattern '{file_pattern}'", file=sys.stderr)
        sys.exit(1)
    
    print(f"Found {len(files)} files to process")
    
    # Generate NTLM hash for the provided password
    password_ntlm_hash = generate_ntlm_hash(password)
    print(f"Generated NTLM hash for password '{password}': {password_ntlm_hash}")
    
    # Collect all hashes from all files
    all_hashes = []
    for file_path in files:
        print(f"Processing {file_path}...")
        hashes = read_hashes_from_file(file_path)
        all_hashes.extend(hashes)
    
    if not all_hashes:
        print("No valid hashes found in the input files", file=sys.stderr)
        sys.exit(1)
    
    print(f"Total hashes processed: {len(all_hashes)}")
    
    # Determine write mode
    write_mode = 'a' if append_mode else 'w'
    mode_text = "Appending to" if append_mode else "Writing to"
    
    # Process each hash and write results
    try:
        with open(output_file, write_mode) as output:
            for clean_hash, original_line in all_hashes:
                if clean_hash.lower() == password_ntlm_hash.lower():
                    result = f"{clean_hash}:{password}\n"
                else:
                    result = f"{clean_hash}:[not found]\n"
                output.write(result)
        
        print(f"{mode_text} {output_file}")
        
        # Count matches
        matches = sum(1 for clean_hash, _ in all_hashes if clean_hash.lower() == password_ntlm_hash.lower())
        print(f"Found {matches} matches out of {len(all_hashes)} hashes")
        
    except Exception as e:
        print(f"Error writing to output file '{output_file}': {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Recover NTLM hashes to plaintext passwords')
    parser.add_argument('-f', '--file', required=True, help='File pattern containing NTLM hashes (e.g., "temp_split/raw-hash-*")')
    parser.add_argument('-p', '--password', required=True, help='Password to test against hashes')
    parser.add_argument('-o', '--output', required=True, help='Output file for results')
    parser.add_argument('-a', '--append', action='store_true', help='Append to output file instead of overwriting')
    
    args = parser.parse_args()
    
    process_multiple_files(args.file, args.password, args.output, args.append)

if __name__ == "__main__":
    main()

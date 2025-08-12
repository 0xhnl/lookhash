#!/usr/bin/env python3

import os
import argparse
import requests
import sys
import time
from datetime import datetime

# Base URL for the API
API_BASE_URL = "https://ntlm.pw/api/lookup"

def split_file(input_file, output_dir, lines_per_file=500):
    """Split a large file into smaller chunks."""
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    total_lines = len(lines)
    chunks = (total_lines + lines_per_file - 1) // lines_per_file

    split_files = []
    for i in range(chunks):
        chunk_lines = lines[i * lines_per_file: (i + 1) * lines_per_file]
        file_index = str(i + 1).zfill(2)
        output_file = os.path.join(output_dir, f'raw-hash-{file_index}')
        with open(output_file, 'w', encoding='utf-8') as out_f:
            out_f.writelines(chunk_lines)
        print(f"[+] Wrote {len(chunk_lines)} lines to {output_file}")
        split_files.append(output_file)
    
    return split_files

def single_lookup(hash_type, hash_value, output_file=None):
    """
    Perform a single hash lookup using the API.
    """
    url = f"{API_BASE_URL}/{hash_type}/{hash_value}"
    try:
        response = requests.get(url)
        # Handle HTTP 204 (No Content)
        if response.status_code == 204:
            result = f"{hash_value}:[not found]\n"
            print(result, end="")  # Print to terminal
            if output_file:
                output_file.write(result)  # Write to file
            return

        # Process the plain text response
        if response.status_code == 200:
            lines = response.text.strip().split("\n")
            for line in lines:
                print(line)  # Print to terminal
                if output_file:
                    output_file.write(line + "\n")  # Write to file
        else:
            error_message = f"Error: Unexpected status code {response.status_code}\n"
            print(error_message, file=sys.stderr)
            if output_file:
                output_file.write(error_message)

    except requests.exceptions.RequestException as e:
        error_message = f"Error during single lookup: {e}\n"
        print(error_message, file=sys.stderr)
        if output_file:
            output_file.write(error_message)

def bulk_lookup(hash_type, file_path, output_file=None):
    """
    Perform a bulk hash lookup using the API, sending 300 hashes per request with rate limit handling.
    """
    try:
        with open(file_path, 'r') as file:
            hashes = [line.strip() for line in file if line.strip()]

        # Process hashes in chunks of 300
        i = 0
        while i < len(hashes):
            chunk = hashes[i:i + 300]
            url = f"{API_BASE_URL}?hashtype={hash_type}"
            try:
                response = requests.post(url, headers={"Content-Type": "text/plain"}, data="\n".join(chunk))

                # Process the plain text response
                if response.status_code == 200:
                    lines = response.text.strip().split("\n")
                    for line in lines:
                        print(line)  # Print to terminal
                        if output_file:
                            output_file.write(line + "\n")  # Write to file
                    i += 300  # Move to next chunk only on success
                elif response.status_code == 429:
                    # Rate limited - wait 15 minutes and retry same chunk
                    error_message = f"[!] Rate limit hit (429). Waiting 15 minutes before retrying...\n"
                    print(error_message, file=sys.stderr)
                    if output_file:
                        output_file.write(error_message)
                    
                    # Wait for 15 minutes (900 seconds)
                    time.sleep(900)
                    # Don't increment i, so we retry the same chunk
                else:
                    error_message = f"Error: Unexpected status code {response.status_code}\n"
                    print(error_message, file=sys.stderr)
                    if output_file:
                        output_file.write(error_message)
                    i += 300  # Move to next chunk even on other errors

                # Introduce a 5-second delay between requests (unless we're retrying due to 429)
                if response.status_code != 429:
                    time.sleep(5)

            except requests.exceptions.RequestException as e:
                error_message = f"Error during bulk lookup: {e}\n"
                print(error_message, file=sys.stderr)
                if output_file:
                    output_file.write(error_message)
                i += 300  # Move to next chunk on network errors
    except FileNotFoundError:
        error_message = f"File not found: {file_path}\n"
        print(error_message, file=sys.stderr)
        if output_file:
            output_file.write(error_message)

def main():
    parser = argparse.ArgumentParser(description="Split hash file and perform lookups using the ntlm.pw API.")
    parser.add_argument(
        "-t", "--type",
        required=True,
        choices=["nt", "lm", "md5", "sha1", "sha256"],
        help="Hash type (supported: nt, lm, md5, sha1, sha256)."
    )
    parser.add_argument("-f", "--file", required=True, help="Input file containing hashes to lookup")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("--no-split", action="store_true", help="Skip file splitting and process directly")

    args = parser.parse_args()

    # Open the output file if specified
    output_file = None
    if args.output:
        try:
            output_file = open(args.output, "w")
        except IOError as e:
            print(f"Error opening output file: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        if args.no_split:
            # Direct lookup without splitting
            bulk_lookup(args.type, args.file, output_file)
        else:
            # Split the file first, then process each chunk
            print("[*] Splitting file into chunks...")
            split_files = split_file(args.file, "temp_split", 500)
            
            print("[*] Performing hash lookups...")
            for split_file_path in split_files:
                print(f"[*] Processing {split_file_path}...")
                bulk_lookup(args.type, split_file_path, output_file)
            
            # Clean up temporary files
            print("[*] Cleaning up temporary files...")
            for split_file_path in split_files:
                os.remove(split_file_path)
            os.rmdir("temp_split")
            
    finally:
        # Ensure the output file is closed if it was opened
        if output_file:
            output_file.close()

if __name__ == "__main__":
    main()

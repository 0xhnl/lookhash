#!/usr/bin/env python3

import argparse
import requests
import sys
import time  # Import the time module for delays

# Base URL for the API
API_BASE_URL = "https://ntlm.pw/api/lookup"

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
    Perform a bulk hash lookup using the API, sending 300 hashes per request with a 5-second delay between requests.
    """
    try:
        with open(file_path, 'r') as file:
            hashes = [line.strip() for line in file if line.strip()]
        
        # Process hashes in chunks of 300
        for i in range(0, len(hashes), 300):
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
                else:
                    error_message = f"Error: Unexpected status code {response.status_code}\n"
                    print(error_message, file=sys.stderr)
                    if output_file:
                        output_file.write(error_message)

                # Introduce a 5-second delay between requests
                time.sleep(5)

            except requests.exceptions.RequestException as e:
                error_message = f"Error during bulk lookup: {e}\n"
                print(error_message, file=sys.stderr)
                if output_file:
                    output_file.write(error_message)
    except FileNotFoundError:
        error_message = f"File not found: {file_path}\n"
        print(error_message, file=sys.stderr)
        if output_file:
            output_file.write(error_message)

def main():
    parser = argparse.ArgumentParser(description="Perform hash lookups using the ntlm.pw API.")
    parser.add_argument(
        "-t", "--type", 
        required=True, 
        choices=["nt", "lm", "md5", "sha1", "sha256"], 
        help="Hash type (supported: nt, lm, md5, sha1, sha256)."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="File containing hashes for bulk lookup.")
    group.add_argument("-x", "--hash", help="Single hash for lookup.")
    parser.add_argument("-o", "--output", help="Output file to save results.")

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
        if args.file:
            bulk_lookup(args.type, args.file, output_file)
        elif args.hash:
            single_lookup(args.type, args.hash, output_file)
    finally:
        # Ensure the output file is closed if it was opened
        if output_file:
            output_file.close()

if __name__ == "__main__":
    main()

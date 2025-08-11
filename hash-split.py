import os
import argparse

def split_file(input_file, output_dir, lines_per_file=500):
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    total_lines = len(lines)
    chunks = (total_lines + lines_per_file - 1) // lines_per_file

    for i in range(chunks):
        chunk_lines = lines[i * lines_per_file: (i + 1) * lines_per_file]
        file_index = str(i + 1).zfill(2)
        output_file = os.path.join(output_dir, f'raw-hash-{file_index}')
        with open(output_file, 'w', encoding='utf-8') as out_f:
            out_f.writelines(chunk_lines)
        print(f"[+] Wrote {len(chunk_lines)} lines to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Split a text file into multiple files of 500 lines each.")
    parser.add_argument("-f", "--file", required=True, help="Input file to split")
    parser.add_argument("-o", "--output", required=True, help="Output directory for split files")

    args = parser.parse_args()

    split_file(args.file, args.output)

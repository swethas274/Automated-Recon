#!/usr/bin/env python3
"""
Nano Recon Automator
Usage: python3 recon_nano.py <domain>
"""

import os
import sys
import subprocess
from pathlib import Path

# 1) Check for command-line argument
if len(sys.argv) != 2:
    print("Usage: python3 recon_nano.py <domain>")
    sys.exit(1)

target = sys.argv[1]
base_dir = Path.home() / "Desktop" / "Recon" / target
base_dir.mkdir(parents=True, exist_ok=True)

# Define file paths
curl_raw = base_dir / "curl_raw.txt"
curl_final = base_dir / "curl_final.txt"
subfinder_raw = base_dir / "subfinder_raw.txt"
subfinder_final = base_dir / "subfinder_final.txt"
amass_raw = base_dir / "amass_raw.txt"
amass_final = base_dir / "amass_final.txt"
all_subs = base_dir / "all_subs_combined.txt"

print(f"[+] Starting recon on {target}")
print(f"[+] Output directory: {base_dir}")

# 2) Run cURL to fetch from web.archive.org, jq, sed, and sort
try:
    print("[+] Running cURL + jq + sed pipeline...")
    # This is the pipeline you described, executed in one go.
    curl_cmd = f"curl -s 'http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey' | jq -r '.[][]' | sed 's/.*\\/\///' | sort -u > {curl_raw}"
    subprocess.run(curl_cmd, shell=True, check=True, executable='/bin/bash')

    # Read, dedupe, and write the final curl list
    with open(curl_raw, 'r') as f:
        curl_subs = sorted(set([line.strip() for line in f if line.strip()]))
    with open(curl_final, 'w') as f:
        f.write("\n".join(curl_subs))
    print(f"[+] cURL done. Found {len(curl_subs)} unique items.")

except subprocess.CalledProcessError as e:
    print(f"[-] cURL command failed: {e}")
except FileNotFoundError:
    print("[-] Error: 'curl', 'jq', or 'sed' is not installed. Please install them.")

# 3) Run SubFinder
try:
    print("[+] Running SubFinder...")
    result = subprocess.run(['subfinder', '-d', target, '-silent'], 
                          capture_output=True, text=True, check=True)
    subfinder_results = result.stdout.splitlines()
    
    with open(subfinder_raw, 'w') as f:
        f.write(result.stdout)
    
    # Process Subfinder results: dedupe
    subfinder_final_list = sorted(set(subfinder_results))
    with open(subfinder_final, 'w') as f:
        f.write("\n".join(subfinder_final_list))
    print(f"[+] SubFinder done. Found {len(subfinder_final_list)} unique subdomains.")

except subprocess.CalledProcessError as e:
    print(f"[-] SubFinder run failed. Is it installed and in your PATH? Error: {e}")
except FileNotFoundError:
    print("[-] Error: 'subfinder' not found. Please install it (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest).")

# 4) Run Amass
try:
    print("[+] Running Amass (passive mode)...")
    # Run amass passively for speed
    result = subprocess.run(['amass', 'enum', '-passive', '-d', target], 
                          capture_output=True, text=True, check=True)
    amass_results = result.stdout.splitlines()
    
    with open(amass_raw, 'w') as f:
        f.write(result.stdout)
    
    # Process Amass results: dedupe and filter
    amass_final_list = sorted(set(amass_results))
    # FILTERING: You can add more filters here.
    # This is a basic filter to remove common noise, adjust as needed.
    filtered_amass_list = [sub for sub in amass_final_list if not sub.startswith('_') and not '._tcp' in sub and not '._udp' in sub]
    
    with open(amass_final, 'w') as f:
        f.write("\n".join(filtered_amass_list))
    print(f"[+] Amass done. Found {len(filtered_amass_list)} filtered subdomains.")

except subprocess.CalledProcessError as e:
    print(f"[-] Amass run failed. Is it installed? Error: {e.stderr}")
except FileNotFoundError:
    print("[-] Error: 'amass' not found. Please install it (go install -v github.com/owasp-amass/amass/v3/...@master).")

# 5) Combine all final results into one master list
print("[+] Combining all results into a master list...")
all_subdomains = set()

# Read from each tool's final output file if it exists and is not empty
files_to_combine = [curl_final, subfinder_final, amass_final]
for file_path in files_to_combine:
    if file_path.exists():
        with open(file_path, 'r') as f:
            all_subdomains.update([line.strip() for line in f if line.strip()])

# Write the combined, deduplicated list
with open(all_subs, 'w') as f:
    f.write("\n".join(sorted(all_subdomains)))

print(f"[+] Recon complete! Total unique subdomains found: {len(all_subdomains)}")
print(f"[+] Master list: {all_subs}")

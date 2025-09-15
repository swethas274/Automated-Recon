#!/usr/bin/env python3
"""
Super Recon Automator (Subfinder, Assetfinder, Amass, Findomain, Naabu)
Usage: python3 super_recon.py <domain>
"""

import os
import sys
import subprocess
from pathlib import Path

# =============================================================================
# 1) Configuration and Setup
# =============================================================================
if len(sys.argv) != 2:
    print("Usage: python3 super_recon.py <domain>")
    sys.exit(1)

target = sys.argv[1]
base_dir = Path.home() / "Recon" / target
base_dir.mkdir(parents=True, exist_ok=True)

# Define file paths
subfinder_file = base_dir / "subfinder.txt"
assetfinder_file = base_dir / "assetfinder.txt"
amass_file = base_dir / "amass.txt"
findomain_file = base_dir / "findomain.txt"
all_subs_raw = base_dir / "subs.txt"         # Raw combined output from all tools
naabu_results = base_dir / "naabu_results.txt"
final_file = base_dir / "final.txt"          # Final cleaned and verified list

print(f"[+] Starting recon on {target}")
print(f"[+] Output directory: {base_dir}")

# =============================================================================
# 2) Run Passive Subdomain Enumeration Tools
# =============================================================================
tools = {
    'subfinder': ['subfinder', '-d', target, '-silent'],
    'assetfinder': ['assetfinder', '--subs-only', target],
    'amass': ['amass', 'enum', '-passive', '-d', target],
    'findomain': ['findomain', '-t', target, '-q']
}

# Run each tool and save its output
for tool_name, command in tools.items():
    print(f"[+] Running {tool_name}...")
    output_file = base_dir / f"{tool_name}.txt"
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            # Write raw output to tool-specific file
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            print(f"    [+] {tool_name} found {len(result.stdout.splitlines())} lines.")
        else:
            print(f"    [-] {tool_name} failed with return code {result.returncode}")
            print(f"        Error: {result.stderr}")
    except FileNotFoundError:
        print(f"    [-] Error: '{tool_name}' is not installed. Skipping.")
    except subprocess.TimeoutExpired:
        print(f"    [-] {tool_name} timed out. Skipping.")
    except Exception as e:
        print(f"    [-] An unexpected error occurred with {tool_name}: {e}")

# =============================================================================
# 3) Combine Results into subs.txt
# =============================================================================
print("[+] Combining results into subs.txt...")
all_subdomains = set()

# List of files to combine (from the tools we ran)
files_to_combine = [subfinder_file, assetfinder_file, amass_file, findomain_file]

for file_path in files_to_combine:
    if file_path.exists():
        with open(file_path, 'r') as f:
            for line in f:
                sub = line.strip()
                if sub:  # Skip empty lines
                    all_subdomains.add(sub)

# Write all unique subdomains to the raw combined file
with open(all_subs_raw, 'w') as f:
    f.write("\n".join(sorted(all_subdomains)))

print(f"[+] Combined {len(all_subdomains)} unique subdomains into {all_subs_raw}")

# =============================================================================
# 4) Filter & Probe with HTTPX and Naabu
# =============================================================================
# First, let's find which subdomains are alive (HTTP/HTTPS)
print("[+] Probing for alive subdomains with HTTPX...")
alive_subdomains = set()

try:
    # Run httpx on the combined list to find live web hosts
    httpx_cmd = ['httpx', '-l', str(all_subs_raw), '-silent', '-ports', '80,443,8080,8443,3000,9000']
    result = subprocess.run(httpx_cmd, capture_output=True, text=True, check=True)
    alive_hosts = result.stdout.splitlines()
    alive_subdomains.update(alive_hosts)
    print(f"    [+] HTTPX found {len(alive_hosts)} alive web hosts.")

except subprocess.CalledProcessError as e:
    print(f"    [-] HTTPX failed: {e}")
except FileNotFoundError:
    print("    [-] Error: 'httpx' is not installed. Skipping HTTP probing.")

# Now, run Naabu for port scanning on the original subdomain list
print("[+] Running Naabu for port scanning...")
try:
    # Run naabu on the combined list, skip typical HTTP ports since we already probed them
    naabu_cmd = ['naabu', '-list', str(all_subs_raw), '-silent', '-exclude-ports', '80,443,8080,8443,3000,9000']
    result = subprocess.run(naabu_cmd, capture_output=True, text=True, check=True)
    
    # Write Naabu's results (host:port) to its own file
    with open(naabu_results, 'w') as f:
        f.write(result.stdout)
    
    # Add Naabu's discovered hosts (without port) to our alive set for final.txt
    naabu_hosts = set()
    for line in result.stdout.splitlines():
        if ':' in line:
            host = line.split(':')[0]
            naabu_hosts.add(host)
    alive_subdomains.update(naabu_hosts)
    print(f"    [+] Naabu found {len(naabu_hosts)} hosts with interesting ports.")

except subprocess.CalledProcessError as e:
    print(f"    [-] Naabu failed: {e}")
except FileNotFoundError:
    print("    [-] Error: 'naabu' is not installed. Skipping port scanning.")

# =============================================================================
# 5) Clean and Write Final Results
# =============================================================================
print("[+] Filtering out wildcards and noise...")
cleaned_final_list = set()

for host in alive_subdomains:
    # Basic filtering: Remove common noise and wildcard indicators
    if host and not host.startswith(('*', '_')) and not '._tcp' in host and not '._udp' in host:
        cleaned_final_list.add(host)

# Write the final cleaned list of active hosts
with open(final_file, 'w') as f:
    f.write("\n".join(sorted(cleaned_final_list)))

print(f"[+] Recon complete!")
print(f"[+] Raw subdomains: {all_subs_raw}")
print(f"[+] Active hosts & ports: {naabu_results}")
print(f"[+] Final cleaned list: {final_file}")
print(f"[+] Total active targets: {len(cleaned_final_list)}")

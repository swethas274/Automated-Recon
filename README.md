# Automated Recon 🔍

A lightweight, automated reconnaissance tool written in Python. It's designed for bug bounty hunters and penetration testers to quickly discover subdomains and map out a target's attack surface.

## Features

*   **Multi-Tool Enumeration:** Leverages `curl` (via Wayback Machine), `subfinder`, and `amass` for comprehensive coverage.
*   **Automated Pipeline:** Automates the tedious process of running tools individually and parsing their output.
*   **Smart Filtering:** Cleans and filters results from `amass` to remove common noise (e.g., DNS TXT records).
*   **Results Consolidation:** Combines results from all tools into a single, deduplicated master list.
*   ** Organized Output:** Saves raw and processed outputs into a structured directory tree.

## Installation

1.  **Prerequisites:** Ensure you have the following installed:
    *   `Python 3`
    *   `subfinder`: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
    *   `amass`: `go install -v github.com/owasp-amass/amass/v3/...@master`
    *   `jq`, `curl`, `sed` (usually pre-installed on Linux/macOS)

## Usage

Run the tool against a target domain:
```bash
python3 src/nano_recon.py example.com

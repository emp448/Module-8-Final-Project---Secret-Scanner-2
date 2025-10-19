Secret Scanner CLI

A Python-based command-line tool that scans files or directories for hardcoded secrets such as API keys, passwords, tokens, and private keys.

Description

This tool helps detect sensitive information that may have been accidentally included in code. It searches through files using regular expressions (regex) and reports any matches that look like secrets.

It can scan a single file or an entire directory and produces a clear report showing:

The filename

The line number

The type of secret

The matched string

Features

Accepts a file or directory as input

Uses regex to detect common secret patterns

Outputs findings with filename, line number, and match

Includes logging and a simple CLI interface using argparse

Detected Patterns

The scanner checks for:

AWS Access Keys (e.g., AKIA...)

Google API Keys (e.g., AIza...)

Slack Tokens (e.g., xoxb-...)

Private Key Blocks (e.g., -----BEGIN PRIVATE KEY-----)

Password Assignments (e.g., password = "mypassword")

Usage

Run the tool from your terminal:

python3 secret_scanner.py <path>

Optional arguments:
Flag	Description
-o <file>	Save results to a report file
-v	Enable verbose logging
Examples:
# Scan a single file
python3 secret_scanner.py app.py

# Scan a directory and save a report
python3 secret_scanner.py ./project -o secrets_report.txt

Example Output
INFO: Scanning directory: ./project

Found 3 potential secret(s):

config.py:12  [Password Assignment]  →  password = "mypassword"
keys.txt:5    [AWS Access Key]       →  AKIA1234567890ABCD12
private.pem:1 [Private Key]          →  -----BEGIN PRIVATE KEY-----

Notes

This tool uses regex-only detection, so it may show false positives.

Always review findings before assuming they are real secrets.

For professional security scanning, tools like Gitleaks or TruffleHog are recommended.

References

Patterns and examples were inspired by:

Gitleaks Regex Patterns

Secrets Patterns DB

Common API Key Format Collections

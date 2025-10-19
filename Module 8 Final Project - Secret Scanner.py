#!/usr/bin/env python3
"""
secret_scanner.py
Scans files or directories for common hardcoded secrets using regex.
"""

import os
import re
import argparse
import logging

# ------------------------------
# Configure logging
# ------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger("SecretScanner")

# ------------------------------
# Secret Patterns
# ------------------------------
PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH)? ?PRIVATE KEY-----",
    "Password Assignment": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([A-Za-z0-9@#\$%\^&\*\-_]{6,})['\"]?"
}

# ------------------------------
# Helper Functions
# ------------------------------
def scan_file(file_path):
    """Scan a single file for secrets."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, start=1):
                for name, pattern in PATTERNS.items():
                    for match in re.findall(pattern, line):
                        findings.append((file_path, i, name, match))
    except Exception as e:
        logger.debug(f"Error reading {file_path}: {e}")
    return findings


def scan_directory(directory):
    """Recursively scan a directory."""
    all_findings = []
    for root, _, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)
            all_findings.extend(scan_file(path))
    return all_findings


def scan_target(target):
    """Scan a file or directory."""
    if os.path.isfile(target):
        logger.info(f"Scanning file: {target}")
        return scan_file(target)
    elif os.path.isdir(target):
        logger.info(f"Scanning directory: {target}")
        return scan_directory(target)
    else:
        logger.error(f"Invalid path: {target}")
        return []


# ------------------------------
# CLI Interface
# ------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Scan files or directories for hardcoded secrets (API keys, passwords, tokens, etc.)"
    )
    parser.add_argument("path", help="Path to file or directory")
    parser.add_argument(
        "-o", "--output", help="Optional output file for report", default=None
    )
    parser.add_argument(
        "-v", "--verbose", help="Enable debug logging", action="store_true"
    )
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    results = scan_target(args.path)

    if not results:
        logger.info("No secrets found.")
    else:
        logger.info(f"\nFound {len(results)} potential secret(s):\n")
        for file, line, name, match in results:
            print(f"{file}:{line}  [{name}]  →  {match}")

        if args.output:
            with open(args.output, "w") as f:
                for file, line, name, match in results:
                    f.write(f"{file}:{line} [{name}] {match}\n")
            logger.info(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()

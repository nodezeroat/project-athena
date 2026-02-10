#!/usr/bin/env python3
"""
Assignment 1: API Endpoint Discovery - Complete Solution

This solution demonstrates file parsing, regex pattern matching,
and automated API endpoint testing to discover hidden flags.
"""

import re
import requests

# Configuration
url = "http://localhost:5000"

# Regex pattern for UUID-based API endpoints
# Format: /api/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# Where x is a hexadecimal digit (0-9, a-f)
pattern = re.compile(
    r"(\/api\/[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12})"
)

print("=" * 60)
print("API Endpoint Discovery - Solution")
print("=" * 60)

# Read the minified JavaScript file and search for UUID endpoints
print("\n[*] Reading app.min.js...")

with open("app.min.js", "r") as file:
    endpoints_tested = 0

    for line in file.readlines():
        # Find all UUID endpoints in this line
        matches = pattern.findall(line)

        # Test each endpoint found
        for match in matches:
            endpoints_tested += 1

            # Print progress every 100 endpoints
            if endpoints_tested % 100 == 0:
                print(f"[*] Tested {endpoints_tested} endpoints...")

            # Make GET request to the endpoint
            r = requests.get(f"{url}{match}")

            # Check if the response contains the flag
            if "FLAG{" in r.text:
                print(f"\n[+] Found flag at endpoint: {match}")
                print("\n" + "=" * 60)
                print(r.text)
                print("=" * 60)
                break

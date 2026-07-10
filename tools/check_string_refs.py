#!/usr/bin/env python3
"""Check string-ref results."""
import json
import os

path = "output/string_ref_patterns.json"
if os.path.exists(path):
    with open(path) as f:
        d = json.load(f)
    print(f"Found via string refs: {len(d)}")
    for name, data in d.items():
        sig = data.get("sig", "")
        print(f"  {name}: {sig[:40]}...")
else:
    print("No string ref results found")

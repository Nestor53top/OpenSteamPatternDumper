#!/usr/bin/env python3
"""Merge all patterns into final TOML."""
import json
import os
import sys


def main():
    # Load our scanned patterns
    with open("output/steamclient64.toml") as f:
        lines = f.readlines()

    # Load string ref patterns
    string_ref = {}
    if os.path.exists("output/string_ref_patterns.json"):
        with open("output/string_ref_patterns.json") as f:
            string_ref = json.load(f)

    # Add string ref patterns to the end
    for name, data in string_ref.items():
        lines.append(f"[{name}]\n")
        lines.append(f'sig = "{data["sig"]}"\n')
        lines.append(f'rva = "{data["rva"]}"\n')
        lines.append(f'source = "string_ref"\n')
        lines.append("\n")

    # Write final
    with open("output/steamclient64_final.toml", "w") as f:
        f.writelines(lines)

    print(f"Total patterns: 50 + {len(string_ref)} = {50 + len(string_ref)}")


if __name__ == "__main__":
    main()

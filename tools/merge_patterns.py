#!/usr/bin/env python3
"""Merge all downloaded pattern TOML files into a single JSON reference."""

import os
import re
import glob
import json


def load_patterns_from_toml(path):
    functions = {}
    if not os.path.exists(path):
        return functions
    current_entry = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^\[[0-9A-Fa-fx]+\]$", line)
            if m:
                if current_entry.get("name") and current_entry.get("sig"):
                    functions[current_entry["name"]] = {"sig": current_entry["sig"]}
                current_entry = {}
                continue
            kv = re.match(r'^(\w+)\s*=\s*"(.*)"$', line)
            if kv:
                current_entry[kv.group(1)] = kv.group(2)
    if current_entry.get("name") and current_entry.get("sig"):
        functions[current_entry["name"]] = {"sig": current_entry["sig"]}
    return functions


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--patterns-dir", default="patterns_ref")
    parser.add_argument("--output", default="output/merged_reference.json")
    args = parser.parse_args()

    all_funcs = {}
    for comp in ["steamclient", "steamui"]:
        pattern_dir = os.path.join(args.patterns_dir, comp)
        if not os.path.isdir(pattern_dir):
            print(f"Directory not found: {pattern_dir}")
            continue
        for f in sorted(glob.glob(os.path.join(pattern_dir, "*.toml"))):
            funcs = load_patterns_from_toml(f)
            for name, info in funcs.items():
                if name not in all_funcs:
                    all_funcs[name] = info

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(all_funcs, f, indent=2)

    print(f"Merged {len(all_funcs)} unique functions from all patterns")


if __name__ == "__main__":
    main()

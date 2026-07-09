#!/usr/bin/env python3
"""Build comprehensive function list by merging patterns + exports."""

import os
import json
import glob
import re


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
    parser.add_argument("--exports-dir", default="output")
    parser.add_argument("--output", default="output/all_functions.json")
    args = parser.parse_args()

    merged = {}

    for comp in ["steamclient", "steamui"]:
        pattern_dir = os.path.join(args.patterns_dir, comp)
        if os.path.isdir(pattern_dir):
            for f in sorted(glob.glob(os.path.join(pattern_dir, "*.toml"))):
                funcs = load_patterns_from_toml(f)
                for name, info in funcs.items():
                    if name not in merged:
                        merged[name] = info

    for comp in ["steamclient", "steamui"]:
        exports_file = os.path.join(args.exports_dir, f"exports_{comp}.json")
        if os.path.exists(exports_file):
            with open(exports_file) as f:
                exports = json.load(f)
            for name, info in exports.items():
                if name not in merged:
                    merged[name] = {"sig": info["sig"]}

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(merged, f, indent=2)

    print(f"Total functions: {len(merged)}")


if __name__ == "__main__":
    main()

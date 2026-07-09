#!/usr/bin/env python3
"""
OpenSteam Pattern Dumper - Signature Scanner v2
Extracts patterns from Steam DLLs using exports + known signatures.
"""

import os
import sys
import json
import hashlib
import struct
import re
import glob
import argparse
from typing import Dict, List, Optional

try:
    import pefile
except ImportError:
    os.system(f"{sys.executable} -m pip install pefile -q")
    import pefile


def compute_sha256(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_name_hash(name: str) -> int:
    hash_val = 0x811C9DC5
    for byte in name.encode("utf-8"):
        hash_val ^= byte
        hash_val = (hash_val * 0x01000193) & 0xFFFFFFFF
    return hash_val


def parse_signature(sig_str: str) -> tuple:
    parts = sig_str.strip().split()
    result = bytearray()
    wildcards = bytearray()
    for part in parts:
        if part.lower() == "??" or part == "?":
            result.append(0x00)
            wildcards.append(1)
        else:
            result.append(int(part, 16))
            wildcards.append(0)
    return bytes(result), bytes(wildcards)


def scan_for_pattern(data: bytes, pattern: bytes, wildcards: bytes) -> List[int]:
    results = []
    pat_len = len(pattern)
    if pat_len == 0 or pat_len != len(wildcards):
        return results

    first_byte = None
    first_wildcard = None
    for i in range(pat_len):
        if wildcards[i] == 0:
            first_byte = pattern[i]
            first_wildcard = i
            break

    if first_byte is None:
        return results

    search_start = 0
    while True:
        idx = data.find(first_byte, search_start)
        if idx == -1:
            break
        offset = idx - first_wildcard
        if offset < 0:
            search_start = idx + 1
            continue
        match = True
        for i in range(pat_len):
            if wildcards[i] == 0 and data[offset + i] != pattern[i]:
                match = False
                break
        if match:
            results.append(offset)
        search_start = idx + 1
    return results


def extract_export_signatures(pe: pefile.PE, code_data: bytes, code_rva: int) -> Dict[str, dict]:
    """Extract signatures from PE exported functions."""
    exports = {}
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return exports

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name is None:
            continue
        name = exp.name.decode("utf-8", errors="ignore")
        if not name or name.startswith(ordinal_ordinal):
            continue

        func_rva = exp.address
        if func_rva == 0:
            continue

        offset_in_code = func_rva - code_rva
        if offset_in_code < 0 or offset_in_code >= len(code_data) - 32:
            continue

        sig_bytes = code_data[offset_in_code:offset_in_code + 32]
        sig_parts = []
        for b in sig_bytes:
            sig_parts.append(f"{b:02X}")
        sig_str = " ".join(sig_parts)

        exports[name] = {
            "name": name,
            "rva": f"0x{func_rva:X}",
            "sig": sig_str,
        }

    return exports


def load_patterns_from_toml(toml_path: str) -> Dict[str, dict]:
    """Load patterns from a TOML file, keyed by function name."""
    functions = {}
    if not os.path.exists(toml_path):
        return functions

    current_entry = {}
    with open(toml_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^\[([0-9A-Fa-fx]+)\]$", line)
            if match:
                if current_entry.get("name") and current_entry.get("sig"):
                    functions[current_entry["name"]] = {
                        "sig": current_entry["sig"],
                    }
                current_entry = {}
                continue
            kv_match = re.match(r'^(\w+)\s*=\s*"(.*)"$', line)
            if kv_match:
                current_entry[kv_match.group(1)] = kv_match.group(2)

        if current_entry.get("name") and current_entry.get("sig"):
            functions[current_entry["name"]] = {"sig": current_entry["sig"]}

    return functions


def load_all_patterns_from_dir(patterns_dir: str) -> Dict[str, dict]:
    """Load and merge all pattern TOML files from a directory."""
    merged = {}
    if not os.path.isdir(patterns_dir):
        return merged

    toml_files = glob.glob(os.path.join(patterns_dir, "*.toml"))
    for toml_path in sorted(toml_files):
        funcs = load_patterns_from_toml(toml_path)
        for name, info in funcs.items():
            if name not in merged:
                merged[name] = info
    return merged


def load_functions_json(json_path: str) -> Dict[str, dict]:
    """Load function definitions from a JSON file."""
    if not os.path.exists(json_path):
        return {}
    with open(json_path, "r") as f:
        return json.load(f)


def scan_dll(dll_path: str, known_functions: Dict[str, dict], component: str) -> Dict[str, dict]:
    print(f"\n{'='*60}")
    print(f"Scanning: {dll_path}")
    print(f"Component: {component}")
    print(f"Known functions to scan: {len(known_functions)}")

    pe = pefile.PE(dll_path)

    code_sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode(errors="ignore")
        if name in (".text", ".code"):
            code_sections.append(section)

    if not code_sections:
        code_sections = pe.sections

    code_data = bytearray()
    section_map = []
    for section in code_sections:
        offset = len(code_data)
        raw_data = section.get_data()
        code_data.extend(raw_data)
        section_map.append((offset, section.VirtualAddress, len(raw_data)))

    code_bytes = bytes(code_data)
    print(f"Code sections total size: {len(code_bytes)} bytes")

    results = {}
    found_count = 0
    not_found = []

    for func_name, func_info in known_functions.items():
        sig_str = func_info.get("sig", "")
        if not sig_str:
            continue

        pattern, wildcards = parse_signature(sig_str)
        if len(pattern) == 0:
            continue

        matches = scan_for_pattern(code_bytes, pattern, wildcards)

        if matches:
            file_offset = matches[0]
            rva = 0
            for blob_offset, section_rva, section_size in section_map:
                if blob_offset <= file_offset < blob_offset + section_size:
                    rva = section_rva + (file_offset - blob_offset)
                    break

            if rva == 0:
                try:
                    rva = pe.get_rva_from_offset(file_offset)
                except Exception:
                    rva = 0

            name_hash = compute_name_hash(func_name)
            results[name_hash] = {
                "name": func_name,
                "rva": f"0x{rva:X}",
                "sig": sig_str,
            }
            found_count += 1
            print(f"  [OK]   {func_name}: RVA=0x{rva:X} (hash=0x{name_hash:08X})")
        else:
            not_found.append(func_name)
            print(f"  [FAIL] {func_name}")

    print(f"\nResults: {found_count}/{len(known_functions)} functions found")

    pe.close()
    return results


def generate_toml(patterns: Dict[str, dict]) -> str:
    lines = []
    for hash_key in sorted(patterns.keys()):
        entry = patterns[hash_key]
        lines.append(f"[{hash_key}]")
        lines.append(f'name = "{entry["name"]}"')
        lines.append(f'rva = "{entry["rva"]}"')
        lines.append(f'sig = "{entry["sig"]}"')
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Scan Steam DLLs for function patterns")
    parser.add_argument("--dll", required=True, help="Path to DLL to scan")
    parser.add_argument("--component", required=True, choices=["steamclient", "steamui"])
    parser.add_argument("--output", required=True, help="Output TOML file path")
    parser.add_argument("--existing-patterns", nargs="*", help="Pattern TOML files to use as reference")
    parser.add_argument("--patterns-dir", help="Directory containing pattern TOML files")
    parser.add_argument("--functions-json", help="JSON file with function definitions")
    args = parser.parse_args()

    known_functions = {}

    if args.patterns_dir:
        print(f"Loading all patterns from directory: {args.patterns_dir}")
        dir_funcs = load_all_patterns_from_dir(args.patterns_dir)
        known_functions.update(dir_funcs)
        print(f"Loaded {len(dir_funcs)} unique functions from patterns directory")

    if args.existing_patterns:
        for pattern_file in args.existing_patterns:
            print(f"Loading patterns from: {pattern_file}")
            funcs = load_patterns_from_toml(pattern_file)
            for name, info in funcs.items():
                if name not in known_functions:
                    known_functions[name] = info
        print(f"Total unique functions: {len(known_functions)}")

    if args.functions_json:
        print(f"Loading functions from JSON: {args.functions_json}")
        json_funcs = load_functions_json(args.functions_json)
        for name, info in json_funcs.items():
            if name not in known_functions:
                known_functions[name] = info
        print(f"Total functions to scan: {len(known_functions)}")

    if not known_functions:
        print("ERROR: No functions to scan. Provide --patterns-dir, --existing-patterns, or --functions-json")
        sys.exit(1)

    results = scan_dll(args.dll, known_functions, args.component)

    toml_content = generate_toml(results)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(toml_content)

    print(f"\nOutput saved to: {args.output}")
    print(f"Total patterns: {len(results)}")
    return results


if __name__ == "__main__":
    main()

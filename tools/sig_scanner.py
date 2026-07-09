#!/usr/bin/env python3
"""
OpenSteam Pattern Dumper - Signature Scanner
Scans Steam DLLs for known function signatures and generates TOML pattern files.
"""

import os
import sys
import json
import hashlib
import struct
import re
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional

try:
    import pefile
except ImportError:
    print("Installing pefile...")
    os.system(f"{sys.executable} -m pip install pefile -q")
    import pefile


def compute_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def parse_signature(sig_str: str) -> bytes:
    """Parse a signature string like '48 89 5C 24 ?? 57' into bytes with wildcards."""
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
    """Scan binary data for a pattern with wildcards. Returns list of offsets."""
    results = []
    pat_len = len(pattern)
    if pat_len == 0 or pat_len != len(wildcards):
        return results

    # Use the first non-wildcard byte as a fast filter
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

        # Check if the full pattern matches from this position
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


def resolve_rva(pe: pefile.PE, offset: int) -> int:
    """Convert a file offset to RVA."""
    try:
        rva = pe.get_rva_from_offset(offset)
        return rva
    except Exception:
        return 0


def load_existing_patterns(toml_path: str) -> Dict[str, dict]:
    """Load existing patterns from a TOML file."""
    patterns = {}
    if not os.path.exists(toml_path):
        return patterns

    current_hash = None
    current_entry = {}

    with open(toml_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Section header like [0xD05E26A2]
            match = re.match(r"^\[([0-9A-Fa-f]+)\]$", line)
            if match:
                if current_hash and current_entry:
                    patterns[current_hash] = current_entry
                current_hash = match.group(1)
                current_entry = {}
                continue

            # key = "value"
            kv_match = re.match(r'^(\w+)\s*=\s*"(.*)"$', line)
            if kv_match and current_hash:
                key, value = kv_match.group(1), kv_match.group(2)
                current_entry[key] = value

        if current_hash and current_entry:
            patterns[current_hash] = current_entry

    return patterns


def generate_toml(patterns: Dict[str, dict]) -> str:
    """Generate TOML content from patterns dict."""
    lines = []
    for hash_key in sorted(patterns.keys()):
        entry = patterns[hash_key]
        lines.append(f"[{hash_key}]")
        if "name" in entry:
            lines.append(f'name = "{entry["name"]}"')
        if "rva" in entry:
            lines.append(f'rva = "{entry["rva"]}"')
        if "sig" in entry:
            lines.append(f'sig = "{entry["sig"]}"')
        lines.append("")
    return "\n".join(lines)


def scan_dll(
    dll_path: str,
    known_functions: Dict[str, dict],
    component: str,
) -> Dict[str, dict]:
    """
    Scan a DLL for known function signatures.

    known_functions: dict of {function_name: {"sig": "48 89 ...", "rva_hint": "0x..."}}
    component: "steamclient" or "steamui"
    """
    print(f"\n{'='*60}")
    print(f"Scanning: {dll_path}")
    print(f"Component: {component}")
    print(f"Known functions to scan: {len(known_functions)}")
    print(f"{'='*60}")

    pe = pefile.PE(dll_path)

    # Get the .text section (code section)
    code_sections = []
    for section in pe.sections:
        if section.Name.rstrip(b"\x00").decode(errors="ignore") in (".text", ".code"):
            code_sections.append(section)

    if not code_sections:
        # Fallback: use all sections
        code_sections = pe.sections

    # Combine all code sections into one searchable blob
    code_data = bytearray()
    section_map = []  # (offset_in_blob, rva_offset, size)

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
            print(f"  [SKIP] {func_name}: no signature defined")
            continue

        pattern, wildcards = parse_signature(sig_str)
        if len(pattern) == 0:
            print(f"  [SKIP] {func_name}: empty pattern")
            continue

        matches = scan_for_pattern(code_bytes, pattern, wildcards)

        if matches:
            # Take the first match
            file_offset = matches[0]

            # Convert file offset to RVA
            rva = 0
            for blob_offset, section_rva, section_size in section_map:
                if blob_offset <= file_offset < blob_offset + section_size:
                    rva = section_rva + (file_offset - blob_offset)
                    break

            if rva == 0:
                rva = resolve_rva(pe, file_offset)

            # Compute CRC32-like hash of function name
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
            print(f"  [FAIL] {func_name}: signature not found in {component}")

    print(f"\nResults: {found_count}/{len(known_functions)} functions found")
    if not_found:
        print(f"Not found: {', '.join(not_found)}")

    pe.close()
    return results


def compute_name_hash(name: str) -> int:
    """Compute a CRC32-like hash of a function name (matching OpenSteamTool's FNV-1a)."""
    # FNV-1a 32-bit hash
    hash_val = 0x811C9DC5
    for byte in name.encode("utf-8"):
        hash_val ^= byte
        hash_val = (hash_val * 0x01000193) & 0xFFFFFFFF
    return hash_val


def load_known_functions_from_patterns(patterns: Dict[str, dict]) -> Dict[str, dict]:
    """Extract function names and signatures from existing pattern files."""
    functions = {}
    for hash_key, entry in patterns.items():
        name = entry.get("name", "")
        sig = entry.get("sig", "")
        if name and sig:
            functions[name] = {"sig": sig}
    return functions


def main():
    parser = argparse.ArgumentParser(description="Scan Steam DLLs for function patterns")
    parser.add_argument("--dll", required=True, help="Path to DLL to scan")
    parser.add_argument("--component", required=True, choices=["steamclient", "steamui"])
    parser.add_argument("--output", required=True, help="Output TOML file path")
    parser.add_argument("--existing-patterns", help="Path to existing pattern TOML for function list")
    parser.add_argument("--functions-json", help="JSON file with function definitions")
    args = parser.parse_args()

    # Load known functions
    known_functions = {}

    if args.existing_patterns:
        print(f"Loading existing patterns from: {args.existing_patterns}")
        existing = load_existing_patterns(args.existing_patterns)
        known_functions = load_known_functions_from_patterns(existing)
        print(f"Loaded {len(known_functions)} function definitions from existing patterns")

    if args.functions_json:
        print(f"Loading functions from JSON: {args.functions_json}")
        with open(args.functions_json, "r") as f:
            json_funcs = json.load(f)
        for name, info in json_funcs.items():
            if name not in known_functions:
                known_functions[name] = info
        print(f"Total functions to scan: {len(known_functions)}")

    if not known_functions:
        print("ERROR: No functions to scan. Provide --existing-patterns or --functions-json")
        sys.exit(1)

    # Scan the DLL
    results = scan_dll(args.dll, known_functions, args.component)

    # Generate TOML
    toml_content = generate_toml(results)

    # Save output
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(toml_content)

    print(f"\nOutput saved to: {args.output}")
    print(f"Total patterns: {len(results)}")

    return results


if __name__ == "__main__":
    main()

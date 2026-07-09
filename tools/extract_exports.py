#!/usr/bin/env python3
"""
Extract ALL exported functions from PE DLLs.
Generates comprehensive function signatures for pattern matching.
"""

import os
import sys
import json
import hashlib
import struct
import argparse
from typing import Dict, List, Optional

try:
    import pefile
except ImportError:
    os.system(f"{sys.executable} -m pip install pefile -q")
    import pefile


def compute_name_hash(name: str) -> int:
    hash_val = 0x811C9DC5
    for byte in name.encode("utf-8"):
        hash_val ^= byte
        hash_val = (hash_val * 0x01000193) & 0xFFFFFFFF
    return hash_val


def extract_all_exports(dll_path: str) -> Dict[str, dict]:
    """Extract all exported functions with their RVAs and prologue signatures."""
    pe = pefile.PE(dll_path)

    code_section = None
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode(errors="ignore")
        if name in (".text", ".code"):
            code_section = section
            break

    if not code_section:
        code_section = pe.sections[0]

    code_data = code_section.get_data()
    code_rva = code_section.VirtualAddress
    code_size = len(code_data)

    exports = {}

    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        pe.close()
        return exports

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name is None:
            continue
        name = exp.name.decode("utf-8", errors="ignore")
        if not name:
            continue

        func_rva = exp.address
        if func_rva == 0:
            continue

        offset_in_code = func_rva - code_rva
        if offset_in_code < 0 or offset_in_code >= code_size - 32:
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
            "hash": f"0x{compute_name_hash(name):08X}",
        }

    pe.close()
    return exports


def extract_imported_strings(dll_path: str, search_patterns: List[str]) -> Dict[str, List[int]]:
    """Find function name strings in the binary."""
    pe = pefile.PE(dll_path)
    results = {}

    for pattern in search_patterns:
        found_rvas = []
        search_bytes = pattern.encode("utf-8")
        for section in pe.sections:
            data = section.get_data()
            offset = 0
            while True:
                idx = data.find(search_bytes, offset)
                if idx == -1:
                    break
                file_offset = section.PointerToRawData + idx
                try:
                    rva = pe.get_rva_from_offset(file_offset)
                    found_rvas.append(rva)
                except Exception:
                    pass
                offset = idx + 1
        if found_rvas:
            results[pattern] = found_rvas

    pe.close()
    return results


def main():
    parser = argparse.ArgumentParser(description="Extract all exports from PE DLLs")
    parser.add_argument("--dll", required=True, help="Path to DLL")
    parser.add_argument("--component", required=True, choices=["steamclient", "steamui"])
    parser.add_argument("--output", required=True, help="Output JSON file")
    args = parser.parse_args()

    print(f"Extracting exports from: {args.dll}")
    exports = extract_all_exports(args.dll)
    print(f"Found {len(exports)} exported functions")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(exports, f, indent=2)

    print(f"Saved to: {args.output}")

    categories = {}
    for name, info in exports.items():
        prefix = name.split("_")[0] if "_" in name else name[:4]
        if prefix not in categories:
            categories[prefix] = []
        categories[prefix].append(name)

    print(f"\nTop categories:")
    for prefix, names in sorted(categories.items(), key=lambda x: -len(x[1]))[:10]:
        print(f"  {prefix}: {len(names)} functions")


if __name__ == "__main__":
    main()

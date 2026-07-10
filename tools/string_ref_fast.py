#!/usr/bin/env python3
"""
Fast string-reference pattern finder.
Finds function patterns by locating string references in code.
"""

import os
import sys
import re
import json
import struct
import argparse
from typing import Dict, List, Tuple, Optional

try:
    import pefile
except ImportError:
    os.system(f"{sys.executable} -m pip install pefile -q")
    import pefile


def extract_strings_from_section(data: bytes, offset: int, size: int, min_len: int = 4) -> Dict[int, str]:
    """Extract ASCII strings from a section."""
    strings = {}
    current = b""
    start = 0

    for i in range(size):
        byte = data[offset + i]
        if 32 <= byte <= 126:
            if not current:
                start = i
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                rva = offset + start
                try:
                    strings[rva] = current.decode("ascii")
                except:
                    pass
            current = b""

    if len(current) >= min_len:
        rva = offset + start
        try:
            strings[rva] = current.decode("ascii")
        except:
            pass

    return strings


def find_string_references(text_data: bytes, text_offset: int, text_size: int,
                           string_rva: int, image_base: int) -> List[int]:
    """Find LEA instructions that reference a string address.

    In x64, LEA reg, [rip + offset] is encoded as:
    48 8D 0D XX XX XX XX  (lea rcx, [rip+disp32])
    4C 8D 05 XX XX XX XX  (lea r8, [rip+disp32])
    etc.

    The displacement is: target_va - (instruction_va + instruction_size)
    """
    refs = []

    # Scan for all possible LEA opcode prefixes
    # 48 8D / 4C 8D
    i = 0
    while i < text_size - 7:
        # Check for REX.W prefix (0x48 or 0x4C) + LEA (0x8D)
        if text_data[i] in (0x48, 0x4C) and text_data[i + 1] == 0x8D:
            # ModR/M byte
            modrm = text_data[i + 2]
            mod = (modrm >> 6) & 3
            rm = modrm & 7

            # For RIP-relative addressing: mod=00, rm=101 (5)
            if mod == 0 and rm == 5:
                # disp32 is at bytes 3-6
                disp32 = struct.unpack_from("<i", text_data, i + 3)[0]

                # Calculate the instruction VA (relative to image base)
                instr_va = text_offset + i

                # Target VA = instruction_va + 7 + disp32
                target_va = instr_va + 7 + disp32

                # Check if this targets our string
                if target_va == string_rva:
                    refs.append(instr_va)

        i += 1

    return refs


def find_function_prologue(text_data: bytes, func_offset: int, max_search: int = 2048) -> Optional[int]:
    """Find the function prologue before the given offset.

    Common x64 prologues:
    - 48 89 5C 24 XX    (mov [rsp+XX], rbx)
    - 48 8B C4          (mov rax, rsp)
    - 48 83 EC XX       (sub rsp, XX)
    - 55                (push rbp)
    - 48 8D AC 24 XX    (lea rbp, [rsp+XX])
    """
    prologues = [
        bytes([0x48, 0x89, 0x5C, 0x24]),      # mov [rsp+XX], rbx
        bytes([0x48, 0x8B, 0xC4]),              # mov rax, rsp
        bytes([0x48, 0x83, 0xEC]),              # sub rsp, XX
        bytes([0x48, 0x81, 0xEC]),              # sub rsp, XXXX
        bytes([0x55]),                            # push rbp
        bytes([0x48, 0x8D, 0xAC, 0x24]),       # lea rbp, [rsp+XX]
        bytes([0x40, 0x53]),                     # push rbx
        bytes([0x40, 0x55]),                     # push rbp
        bytes([0x40, 0x57]),                     # push rdi
    ]

    # Search backwards for a prologue
    search_start = max(0, func_offset - max_search)
    best_prologue = None

    for i in range(func_offset, search_start, -1):
        for prologue in prologues:
            if text_data[i:i + len(prologue)] == prologue:
                # Check if this looks like a valid prologue
                # (not in the middle of an instruction)
                best_prologue = i
                break
        if best_prologue is not None:
            break

    return best_prologue


def extract_pattern_from_prologue(text_data: bytes, prologue_offset: int, size: int = 32) -> str:
    """Extract a pattern from the function prologue."""
    pattern_bytes = text_data[prologue_offset:prologue_offset + size]
    return " ".join(f"{b:02X}" for b in pattern_bytes)


def find_function_by_string_ref(pe: pefile.PE, string_name: str) -> Optional[Tuple[int, str]]:
    """Find a function pattern by its string reference.

    Returns (rva, pattern) or None.
    """
    # Get sections
    text_section = None
    rdata_section = None

    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
        if name == ".text":
            text_section = section
        elif name == ".rdata":
            rdata_section = section

    if not text_section or not rdata_section:
        return None

    # Extract strings from .rdata
    rdata_data = rdata_section.get_data()
    rdata_va = rdata_section.VirtualAddress
    strings = extract_strings_from_section(rdata_data, 0, len(rdata_data), 4)

    # Find our target string
    target_rva = None
    for rva, s in strings.items():
        # Match function name as a string (with null terminator)
        if s == string_name or s.startswith(string_name + "\x00"):
            target_rva = rdata_va + rva
            break
        # Also try with prefix/suffix variations
        if string_name in s:
            target_rva = rdata_va + rva
            break

    if target_rva is None:
        return None

    # Get .text data
    text_data = text_section.get_data()
    text_va = text_section.VirtualAddress

    # Find references to this string
    refs = find_string_references(text_data, 0, len(text_data), target_rva, pe.OPTIONAL_HEADER.ImageBase)

    if not refs:
        return None

    # For each reference, find the function prologue
    for ref in refs:
        prologue = find_function_prologue(text_data, ref)
        if prologue is not None:
            rva = text_va + prologue
            pattern = extract_pattern_from_prologue(text_data, prologue)
            return (rva, pattern)

    return None


def scan_dll_for_functions(dll_path: str, function_names: List[str]) -> Dict[str, dict]:
    """Scan a DLL for function patterns using string references."""
    print(f"Loading {dll_path}...")
    pe = pefile.PE(dll_path)
    print(f"  Image base: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")

    results = {}
    found = 0
    not_found = 0

    for name in function_names:
        result = find_function_by_string_ref(pe, name)
        if result:
            rva, pattern = result
            results[name] = {
                "rva": f"0x{rva:X}",
                "sig": pattern,
                "source": "string_ref"
            }
            found += 1
            print(f"  FOUND: {name} -> RVA 0x{rva:X}")
        else:
            not_found += 1
            print(f"  NOT FOUND: {name}")

    pe.close()
    print(f"\nResults: {found} found, {not_found} not found out of {len(function_names)}")
    return results


def main():
    parser = argparse.ArgumentParser(description="String Reference Pattern Finder")
    parser.add_argument("--dll", required=True, help="Path to DLL")
    parser.add_argument("--functions-json", help="JSON file with function names")
    parser.add_argument("--functions", nargs="+", help="Specific function names")
    parser.add_argument("--output", required=True, help="Output JSON file")
    args = parser.parse_args()

    # Collect function names
    function_names = []

    if args.functions_json:
        with open(args.functions_json) as f:
            data = json.load(f)
            if isinstance(data, dict):
                function_names = list(data.keys())
            elif isinstance(data, list):
                function_names = data

    if args.functions:
        function_names.extend(args.functions)

    if not function_names:
        print("No function names provided!")
        return

    print(f"Scanning for {len(function_names)} functions...")
    results = scan_dll_for_functions(args.dll, function_names)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nOutput: {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
OpenSteam Pattern Dumper - IPC Extractor
Extracts IPC interface vtable layouts from Steam DLLs.
"""

import os
import sys
import hashlib
import struct
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional

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
    """FNV-1a 32-bit hash."""
    hash_val = 0x811C9DC5
    for byte in name.encode("utf-8"):
        hash_val ^= byte
        hash_val = (hash_val * 0x01000193) & 0xFFFFFFFF
    return hash_val


def find_string_in_pe(pe: pefile.PE, search_string: str) -> List[int]:
    """Find all occurrences of a string in the PE's data directories and sections."""
    results = []
    search_bytes = search_string.encode("utf-8")

    # Search in all sections
    for section in pe.sections:
        data = section.get_data()
        offset = 0
        while True:
            idx = data.find(search_bytes, offset)
            if idx == -1:
                break
            # Convert to RVA
            file_offset = section.PointerToRawData + idx
            try:
                rva = pe.get_rva_from_offset(file_offset)
                results.append(rva)
            except Exception:
                pass
            offset = idx + 1

    return results


def find_vtable_pattern(pe: pefile.PE, interface_name: str) -> Optional[dict]:
    """
    Attempt to find a vtable for an IPC interface.
    This is a heuristic approach - looks for patterns typical of vtable construction.
    """
    # Known IPC interface names from steam-monitor
    ipc_interfaces = {
        "IClientUser": {"interface_id": 0},
        "IClientUtils": {"interface_id": 1},
        "IClientApps": {"interface_id": 2},
        "IClientShortcuts": {"interface_id": 3},
        "IClientNetworking": {"interface_id": 4},
        "IClientRemoteStorage": {"interface_id": 5},
        "IClientScreenshots": {"interface_id": 6},
        "IClientHTTP": {"interface_id": 7},
        "IClientUnifiedMessages": {"interface_id": 8},
        "IClientController": {"interface_id": 9},
        "IClientAppDisableUpdate": {"interface_id": 10},
        "IClientParentalSettings": {"interface_id": 11},
        "IClientSteamHelper": {"interface_id": 12},
        "IClientDepotBuilder": {"interface_id": 13},
        "IClientConfigStore": {"interface_id": 14},
        "IClientUserStats": {"interface_id": 15},
        "IClientNetworkingSockets": {"interface_id": 16},
        "IClientRemoteClientManager": {"interface_id": 17},
        "IClientStreamingClient": {"interface_id": 18},
        "IClientRemoteControlManager": {"interface_id": 19},
        "IClientControllerSerialized": {"interface_id": 20},
        "IClientBrowser": {"interface_id": 21},
        "IClientVideo": {"interface_id": 22},
        "IClientVirtualController": {"interface_id": 23},
        "IClientParties": {"interface_id": 24},
        "IClientNetworkingUtils": {"interface_id": 25},
        "IClientNetworkingMessages": {"interface_id": 26},
        "IClientNetworkingSocketsSerialized": {"interface_id": 27},
        "IClientAppCache": {"interface_id": 28},
        "IClientNetworkingSocketsTools": {"interface_id": 29},
    }

    if interface_name not in ipc_interfaces:
        return None

    info = ipc_interfaces[interface_name]

    # Look for the interface name string in the binary
    string_rvas = find_string_in_pe(pe, interface_name)
    if not string_rvas:
        return None

    # For each string reference, try to find nearby vtable patterns
    # A vtable is typically an array of function pointers (64-bit pointers on x64)
    # preceded by a type_info pointer

    for string_rva in string_rvas:
        # Get the code section containing this RVA
        containing_section = None
        for section in pe.sections:
            if (section.VirtualAddress <= string_rva <
                section.VirtualAddress + section.Misc_VirtualSize):
                containing_section = section
                break

        if not containing_section:
            continue

        # Read data around the string reference
        section_data = containing_section.get_data()
        section_offset = string_rva - containing_section.VirtualAddress

        # Look for RIP-relative LEA instructions that reference this string
        # Pattern: 48 8D 0D xx xx xx xx (LEA RCX, [RIP+disp32])
        for i in range(max(0, section_offset - 0x1000),
                       min(len(section_data) - 7, section_offset + 0x1000)):
            # Check for LEA RCX/RDX/R8/R9, [RIP+disp32]
            if section_data[i] in (0x48, 0x4C):
                if section_data[i+1] == 0x8D:
                    modrm = section_data[i+2]
                    if (modrm & 0xC7) == 0x05:  # RIP-relative addressing
                        reg = (modrm >> 3) & 7
                        if reg in (0, 1, 2, 3):  # RCX, RDX, R8, R9
                            disp = struct.unpack_from("<i", section_data, i+3)[0]
                            target_rva = string_rva
                            ref_rva = containing_section.VirtualAddress + i

                            # Check if this LEA references our string
                            if ref_rva + 7 + disp == target_rva:
                                # Found a reference to the interface name
                                # Now look backward for vtable setup patterns
                                pass

    return None


def extract_ipc_from_pattern_file(patterns: Dict[str, dict]) -> Dict[str, dict]:
    """
    Extract IPC information from existing pattern TOML patterns.
    This provides a baseline using known function names.
    """
    ipc_data = {}

    # Map function names to IPC interfaces
    function_to_interface = {
        "GetSteamID": ("IClientUser", "GetSteamID", 10),
        "GetAppOwnershipTicketExtendedData": ("IClientUser", "GetAppOwnershipTicketExtendedData", 105),
        "RequestEncryptedAppTicket": ("IClientUser", "RequestEncryptedAppTicket", 106),
        "GetEncryptedAppTicket": ("IClientUser", "GetEncryptedAppTicket", 107),
        "GetAppID": ("IClientUtils", "GetAppID", 0),
        "GetAPICallResult": ("IClientUtils", "GetAPICallResult", 1),
    }

    for func_name, info in patterns.items():
        name = info.get("name", "")
        if name in function_to_interface:
            iface, method, index = function_to_interface[name]
            if iface not in ipc_data:
                ipc_data[iface] = {"interface_id": 0, "methods": {}}
            ipc_data[iface]["methods"][method] = {
                "method_index": index,
                "funcHash": f"0x{compute_name_hash(name):08X}",
                "wrapper_rva": info.get("rva", "0x0"),
            }

    return ipc_data


def generate_ipc_toml(ipc_data: Dict[str, dict]) -> str:
    """Generate IPC TOML content."""
    lines = []

    for iface_name in sorted(ipc_data.keys()):
        iface_info = ipc_data[iface_name]
        lines.append(f"[{iface_name}]")
        lines.append(f'interface_id = {iface_info.get("interface_id", 0)}')
        if "vtable_rva" in iface_info:
            lines.append(f'vtable_rva = "{iface_info["vtable_rva"]}"')
        lines.append("")

        for method_name in sorted(iface_info.get("methods", {}).keys()):
            method_info = iface_info["methods"][method_name]
            lines.append(f"[{iface_name}.{method_name}]")
            lines.append(f'method_index = {method_info.get("method_index", 0)}')
            if "funcHash" in method_info:
                lines.append(f'funcHash = "{method_info["funcHash"]}"')
            if "wrapper_rva" in method_info:
                lines.append(f'wrapper_rva = "{method_info["wrapper_rva"]}"')
            if "fencepost" in method_info:
                lines.append(f'fencepost = "{method_info["fencepost"]}"')
            if "argc" in method_info:
                lines.append(f'argc = {method_info["argc"]}')
            lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Extract IPC interface layouts from Steam DLLs")
    parser.add_argument("--dll", required=True, help="Path to steamclient64.dll")
    parser.add_argument("--output", required=True, help="Output TOML file path")
    parser.add_argument("--pattern-toml", help="Existing pattern TOML for function hints")
    parser.add_argument("--functions-json", help="JSON file with function definitions")
    args = parser.parse_args()

    print(f"IPC Extractor")
    print(f"DLL: {args.dll}")
    print(f"{'='*60}")

    # Load existing patterns for hints
    existing_patterns = {}
    if args.pattern_toml and os.path.exists(args.pattern_toml):
        print(f"Loading existing patterns: {args.pattern_toml}")
        # Import from sig_scanner
        sys.path.insert(0, os.path.dirname(__file__))
        from sig_scanner import load_existing_patterns
        existing_patterns = load_existing_patterns(args.pattern_toml)
        print(f"Loaded {len(existing_patterns)} patterns")

    # Extract IPC data from existing patterns
    ipc_data = extract_ipc_from_pattern_file(existing_patterns)

    # If we have a DLL, try to extract additional info
    if os.path.exists(args.dll):
        print(f"\nAnalyzing DLL: {args.dll}")
        pe = pefile.PE(args.dll)
        print(f"Image base: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
        print(f"Number of sections: {len(pe.sections)}")

        # Try to find vtable patterns for known interfaces
        for interface_name in list(ipc_data.keys()):
            result = find_vtable_pattern(pe, interface_name)
            if result:
                ipc_data[interface_name].update(result)
                print(f"  Found vtable for {interface_name}")

        pe.close()

    # Generate TOML
    toml_content = generate_ipc_toml(ipc_data)

    # Save output
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(toml_content)

    print(f"\nOutput saved to: {args.output}")
    print(f"Total interfaces: {len(ipc_data)}")
    for iface_name, info in sorted(ipc_data.items()):
        method_count = len(info.get("methods", {}))
        print(f"  {iface_name}: {method_count} methods")


if __name__ == "__main__":
    main()

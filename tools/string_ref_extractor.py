#!/usr/bin/env python3
"""
OpenSteam Pattern Dumper - String Reference Extractor
Finds function patterns by locating string references in the binary.
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


def find_function_prologue(data: bytes, offset: int, search_backward: int = 0x1000) -> Optional[int]:
    """
    Find a function prologue by searching backward from a string reference.
    Returns the offset of the function prologue or None.
    """
    # x64 function prologues
    prologue_patterns = [
        bytes([0x48, 0x89, 0x5C, 0x24]),  # mov [rsp+...], rbx
        bytes([0x48, 0x89, 0x5C, 0x24, 0x08]),  # mov [rsp+8], rbx
        bytes([0x48, 0x89, 0x5C, 0x24, 0x10]),  # mov [rsp+16], rbx
        bytes([0x48, 0x89, 0x5C, 0x24, 0x18]),  # mov [rsp+24], rbx
        bytes([0x48, 0x89, 0x6C, 0x24]),  # mov [rsp+...], rbp
        bytes([0x48, 0x89, 0x74, 0x24]),  # mov [rsp+...], rsi
        bytes([0x48, 0x89, 0x7C, 0x24]),  # mov [rsp+...], rdi
        bytes([0x40, 0x53]),  # push rbx
        bytes([0x40, 0x55]),  # push rbp
        bytes([0x40, 0x56]),  # push rsi
        bytes([0x40, 0x57]),  # push rdi
        bytes([0x53]),  # push rbx
        bytes([0x55]),  # push rbp
        bytes([0x56]),  # push rsi
        bytes([0x57]),  # push rdi
    ]
    
    # Search backward for a function prologue
    search_start = max(0, offset - search_backward)
    search_end = offset
    
    for i in range(search_end - 1, search_start - 1, -1):
        for pattern in prologue_patterns:
            if data[i:i+len(pattern)] == pattern:
                return i
    
    return None


def extract_function_signature(data: bytes, prologue_offset: int, max_length: int = 64) -> str:
    """Extract a signature from a function prologue."""
    sig_bytes = data[prologue_offset:prologue_offset + max_length]
    sig_parts = []
    for b in sig_bytes:
        sig_parts.append(f"{b:02X}")
    return " ".join(sig_parts)


def extract_function_pattern(dll_path: str, function_name: str) -> Optional[dict]:
    """
    Extract a function pattern by finding its string reference and analyzing the code.
    """
    try:
        pe = pefile.PE(dll_path)
    except Exception as e:
        print(f"  Error opening DLL: {e}")
        return None
    
    # Find the function name string
    string_rvas = find_string_in_pe(pe, function_name)
    if not string_rvas:
        print(f"  String '{function_name}' not found in DLL")
        pe.close()
        return None
    
    print(f"  Found {len(string_rvas)} string reference(s) for '{function_name}'")
    
    for string_rva in string_rvas:
        # Find the section containing this string
        containing_section = None
        for section in pe.sections:
            if (section.VirtualAddress <= string_rva < 
                section.VirtualAddress + section.Misc_VirtualSize):
                containing_section = section
                break
        
        if not containing_section:
            continue
        
        # Get the section data
        section_data = containing_section.get_data()
        section_offset = string_rva - containing_section.VirtualAddress
        
        # Look for LEA instructions referencing this string
        # Pattern: 48 8D 0D xx xx xx xx (LEA RCX, [RIP+disp32])
        for i in range(max(0, section_offset - 0x2000),
                       min(len(section_data) - 7, section_offset + 0x2000)):
            # Check for LEA RCX/RDX/R8/R9, [RIP+disp32]
            if section_data[i] in (0x48, 0x4C):
                if section_data[i+1] == 0x8D:
                    modrm = section_data[i+2]
                    if (modrm & 0xC7) == 0x05:  # RIP-relative addressing
                        reg = (modrm >> 3) & 7
                        if reg in (0, 1, 2, 3):  # RCX, RDX, R8, R9
                            disp = struct.unpack_from("<i", section_data, i+3)[0]
                            ref_rva = containing_section.VirtualAddress + i
                            target_rva = ref_rva + 7 + disp
                            
                            if target_rva == string_rva:
                                # Found a reference to the string
                                # Search backward for function prologue
                                file_offset = section.PointerToRawData + i
                                prologue_offset = find_function_prologue(
                                    section_data, section_offset, 0x1000
                                )
                                
                                if prologue_offset is not None:
                                    # Extract signature
                                    sig = extract_function_signature(
                                        section_data, prologue_offset, 64
                                    )
                                    rva = containing_section.VirtualAddress + prologue_offset
                                    
                                    pe.close()
                                    return {
                                        "name": function_name,
                                        "rva": f"0x{rva:X}",
                                        "sig": sig,
                                        "string_rva": f"0x{string_rva:X}",
                                        "reference_rva": f"0x{ref_rva:X}",
                                    }
    
    pe.close()
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Extract function patterns from Steam DLLs using string references"
    )
    parser.add_argument("--dll", required=True, help="Path to DLL to scan")
    parser.add_argument("--component", required=True, choices=["steamclient", "steamui"])
    parser.add_argument("--output", required=True, help="Output TOML file path")
    parser.add_argument("--functions", nargs="+", help="Function names to extract")
    args = parser.parse_args()
    
    # Default function list
    default_functions = {
        "steamclient": [
            "CheckAppOwnership", "GetAppOwnershipTicketExtendedData",
            "RequestEncryptedAppTicket", "GetEncryptedAppTicket",
            "GetSteamID", "BLoggedOn", "GetConsoleSteamID",
            "ValidateSignedLicenseTicket", "IsSubscribedApp",
            "GetDLCRestrictions", "GetAppUserDefinedInfo", "GetAppBuildDir",
            "GetAllInstalledDLC", "GetAppInstalledSize", "GetAppLanguage",
            "RequestAppCallbacks", "RequestAppCallbacksV2",
            "SetAllowAutoLogin", "IsVACBanned", "GetCurrentSessionID",
            "GetTargetIDForDLC", "GetConnectingSocket", "GetListenSocketToRelay",
            "InitiateGameConnectionLegacy", "InitiateGameConnection2",
            "AuthenticateGameConnection", "TerminateGameConnection",
            "SendUserConnectAndAuthenticateLegacy", "SendUserConnectAndAuthenticate2",
            "GetAuthSessionTicket", "GetAuthTicketForWebApi",
            "GetAppOwnershipProof", "GetAppOwnershipTicket",
            "GetMarketEligibility", "GetDurationControl",
            "BSetExpandedClientInfo", "GetPartnerAccountInfo",
            "GetAppOwnerDebugDetails", "GetNumRunningApps", "GetRunningAppIDs",
            "GetGamepadConfiguratorStatus", "GetPrimaryGamepadIndex",
        ],
        "steamui": [
            "FillInAppOverview", "GetAppBuildID", "GetAppSortOrder",
            "GetAppData", "GetAllApps", "GetAppList", "GetAppCount",
            "GetAppInfo", "GetAppState", "GetAppUpdateInfo",
            "BIsAppInstalled", "GetInstallDir", "GetLaunchCommandLine",
            "BIsSubscribedApp", "GetDLCCount", "GetDLCDataByIndex",
        ],
    }
    
    functions = args.functions or default_functions.get(args.component, [])
    
    print(f"Extracting patterns from {args.dll}")
    print(f"Component: {args.component}")
    print(f"Functions to extract: {len(functions)}")
    print("=" * 60)
    
    results = {}
    found_count = 0
    
    for func_name in functions:
        print(f"\nProcessing: {func_name}")
        result = extract_function_pattern(args.dll, func_name)
        
        if result:
            name_hash = compute_name_hash(func_name)
            results[name_hash] = result
            found_count += 1
            print(f"  Found: RVA={result['rva']}")
        else:
            print(f"  Not found")
    
    print(f"\n{'=' * 60}")
    print(f"Results: {found_count}/{len(functions)} functions found")
    
    # Generate TOML
    lines = []
    for hash_key in sorted(results.keys()):
        entry = results[hash_key]
        lines.append(f"[{hash_key}]")
        lines.append(f'name = "{entry["name"]}"')
        lines.append(f'rva = "{entry["rva"]}"')
        lines.append(f'sig = "{entry["sig"]}"')
        lines.append("")
    
    toml_content = "\n".join(lines)
    
    # Save output
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(toml_content)
    
    print(f"\nOutput saved to: {args.output}")
    print(f"Total patterns: {len(results)}")


if __name__ == "__main__":
    main()

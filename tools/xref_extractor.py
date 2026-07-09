#!/usr/bin/env python3
"""
OpenSteam Pattern Dumper - Cross-Reference Extractor
Extracts function patterns by finding string references and analyzing the code.
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
                results.append(rva)
            except Exception:
                pass
            offset = idx + 1

    return results


def find_code_references_to_rva(pe: pefile.PE, target_rva: int) -> List[int]:
    """
    Find code references to a specific RVA.
    Looks for MOV/LEA instructions that reference the target.
    """
    references = []
    
    # Get the code section
    code_section = None
    for section in pe.sections:
        if section.Name.rstrip(b"\x00").decode(errors="ignore") in (".text", ".code"):
            code_section = section
            break
    
    if not code_section:
        return references
    
    code_data = code_section.get_data()
    code_rva = code_section.VirtualAddress
    
    # Search for references to the target RVA
    # Look for RIP-relative addressing (x64)
    for i in range(len(code_data) - 7):
        # Check for LEA instruction with RIP-relative addressing
        if code_data[i] in (0x48, 0x4C):  # REX.W or REX.WR
            if code_data[i+1] == 0x8D:  # LEA
                modrm = code_data[i+2]
                if (modrm & 0xC7) == 0x05:  # RIP-relative addressing
                    reg = (modrm >> 3) & 7
                    if reg in (0, 1, 2, 3):  # RCX, RDX, R8, R9
                        disp = struct.unpack_from("<i", code_data, i+3)[0]
                        ref_rva = code_rva + i
                        target = ref_rva + 7 + disp
                        if target == target_rva:
                            references.append(ref_rva)
        
        # Check for MOV instruction with RIP-relative addressing
        if code_data[i] in (0x48, 0x4C):  # REX.W or REX.WR
            if code_data[i+1] == 0x8B:  # MOV
                modrm = code_data[i+2]
                if (modrm & 0xC7) == 0x05:  # RIP-relative addressing
                    reg = (modrm >> 3) & 7
                    if reg in (0, 1, 2, 3, 4, 5, 6, 7):  # Any register
                        disp = struct.unpack_from("<i", code_data, i+3)[0]
                        ref_rva = code_rva + i
                        target = ref_rva + 7 + disp
                        if target == target_rva:
                            references.append(ref_rva)
    
    return references


def find_function_start(code_data: bytes, offset: int, max_search: int = 0x2000) -> Optional[int]:
    """
    Find the start of a function by searching backward for a function prologue.
    """
    # Common x64 function prologues
    prologue_patterns = [
        bytes([0x48, 0x89, 0x5C, 0x24]),  # mov [rsp+...], rbx
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
    
    search_start = max(0, offset - max_search)
    search_end = offset
    
    for i in range(search_end - 1, search_start - 1, -1):
        for pattern in prologue_patterns:
            if code_data[i:i+len(pattern)] == pattern:
                return i
    
    return None


def extract_pattern_from_function(code_data: bytes, func_start: int, max_length: int = 64) -> str:
    """Extract a signature pattern from a function start."""
    sig_bytes = code_data[func_start:func_start + max_length]
    sig_parts = []
    for b in sig_bytes:
        sig_parts.append(f"{b:02X}")
    return " ".join(sig_parts)


def extract_function_by_string_reference(dll_path: str, function_name: str) -> Optional[dict]:
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
    
    print(f"  Found {len(string_rvas)} string reference(s)")
    
    # Find the code section
    code_section = None
    for section in pe.sections:
        if section.Name.rstrip(b"\x00").decode(errors="ignore") in (".text", ".code"):
            code_section = section
            break
    
    if not code_section:
        print(f"  No code section found")
        pe.close()
        return None
    
    code_data = code_section.get_data()
    code_rva = code_section.VirtualAddress
    
    for string_rva in string_rvas:
        # Find code references to this string
        references = find_code_references_to_rva(pe, string_rva)
        
        for ref_rva in references:
            # Convert RVA to offset in code_data
            if code_rva <= ref_rva < code_rva + len(code_data):
                offset_in_code = ref_rva - code_rva
                
                # Find function start
                func_start = find_function_start(code_data, offset_in_code)
                if func_start is not None:
                    # Extract pattern
                    pattern = extract_pattern_from_function(code_data, func_start, 64)
                    func_rva = code_rva + func_start
                    
                    pe.close()
                    return {
                        "name": function_name,
                        "rva": f"0x{func_rva:X}",
                        "sig": pattern,
                        "string_rva": f"0x{string_rva:X}",
                        "reference_rva": f"0x{ref_rva:X}",
                    }
    
    pe.close()
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Extract function patterns using string cross-references"
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
            "BBuildAndAsyncSendFrame", "BuildDepotDependency",
            "BuildSpawnEnvBlock", "CUtlBufferEnsureCapacity", "CUtlMemoryGrow",
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
        result = extract_function_by_string_reference(args.dll, func_name)
        
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

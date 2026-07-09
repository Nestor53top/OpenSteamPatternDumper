#!/usr/bin/env python3
"""
OpenSteam Pattern Dumper - IPC Extractor v2
Extracts IPC interface vtable layouts from Steam client DLLs.
"""

import os
import sys
import hashlib
import struct
import re
import json
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


def load_patterns_from_toml(toml_path: str) -> Dict[str, dict]:
    patterns = {}
    if not os.path.exists(toml_path):
        return patterns
    current_entry = {}
    current_hash = None
    with open(toml_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^\[([0-9A-Fa-fx]+)\]$", line)
            if m:
                if current_hash and current_entry:
                    patterns[current_hash] = current_entry
                current_hash = m.group(1)
                current_entry = {}
                continue
            kv = re.match(r'^(\w+)\s*=\s*"(.*)"$', line)
            if kv:
                current_entry[kv.group(1)] = kv.group(2)
    if current_hash and current_entry:
        patterns[current_hash] = current_entry
    return patterns


def find_string_in_pe(pe: pefile.PE, search_string: str) -> List[int]:
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


def find_string_in_pe_data(pe: pefile.PE, search_string: str) -> List[int]:
    """Find string only in data sections (.rdata, .data)."""
    results = []
    search_bytes = search_string.encode("utf-8")
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode(errors="ignore")
        if name in (".text", ".code"):
            continue
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


# IPC interface definitions matching OpenSteamTool
IPC_INTERFACES = {
    "IClientUser": {"interface_id": 0, "methods": {}},
    "IClientUtils": {"interface_id": 1, "methods": {}},
    "IClientApps": {"interface_id": 2, "methods": {}},
    "IClientShortcuts": {"interface_id": 3, "methods": {}},
    "IClientNetworking": {"interface_id": 4, "methods": {}},
    "IClientRemoteStorage": {"interface_id": 5, "methods": {}},
    "IClientScreenshots": {"interface_id": 6, "methods": {}},
    "IClientHTTP": {"interface_id": 7, "methods": {}},
    "IClientUnifiedMessages": {"interface_id": 8, "methods": {}},
    "IClientController": {"interface_id": 9, "methods": {}},
    "IClientAppDisableUpdate": {"interface_id": 10, "methods": {}},
    "IClientParentalSettings": {"interface_id": 11, "methods": {}},
    "IClientSteamHelper": {"interface_id": 12, "methods": {}},
    "IClientDepotBuilder": {"interface_id": 13, "methods": {}},
    "IClientConfigStore": {"interface_id": 14, "methods": {}},
    "IClientUserStats": {"interface_id": 15, "methods": {}},
    "IClientNetworkingSockets": {"interface_id": 16, "methods": {}},
    "IClientRemoteClientManager": {"interface_id": 17, "methods": {}},
    "IClientStreamingClient": {"interface_id": 18, "methods": {}},
    "IClientRemoteControlManager": {"interface_id": 19, "methods": {}},
    "IClientControllerSerialized": {"interface_id": 20, "methods": {}},
    "IClientBrowser": {"interface_id": 21, "methods": {}},
    "IClientVideo": {"interface_id": 22, "methods": {}},
    "IClientVirtualController": {"interface_id": 23, "methods": {}},
    "IClientParties": {"interface_id": 24, "methods": {}},
    "IClientNetworkingUtils": {"interface_id": 25, "methods": {}},
    "IClientNetworkingMessages": {"interface_id": 26, "methods": {}},
    "IClientNetworkingSocketsSerialized": {"interface_id": 27, "methods": {}},
    "IClientAppCache": {"interface_id": 28, "methods": {}},
    "IClientNetworkingSocketsTools": {"interface_id": 29, "methods": {}},
}

# Known method mappings (function name -> interface, method, index)
KNOWN_METHOD_MAPPINGS = {
    "GetSteamID": ("IClientUser", "GetSteamID", 10),
    "BLoggedOn": ("IClientUser", "BLoggedOn", 8),
    "GetAppOwnershipTicketExtendedData": ("IClientUser", "GetAppOwnershipTicketExtendedData", 105),
    "RequestEncryptedAppTicket": ("IClientUser", "RequestEncryptedAppTicket", 106),
    "GetEncryptedAppTicket": ("IClientUser", "GetEncryptedAppTicket", 107),
    "GetAppID": ("IClientUtils", "GetAppID", 0),
    "GetAPICallResult": ("IClientUtils", "GetAPICallResult", 1),
    "CheckAppOwnership": ("IClientUser", "CheckAppOwnership", 104),
    "IsSubscribedApp": ("IClientUser", "IsSubscribedApp", 103),
    "GetConsoleSteamID": ("IClientUser", "GetConsoleSteamID", 11),
    "ValidateSignedLicenseTicket": ("IClientUser", "ValidateSignedLicenseTicket", 108),
    "GetDLCRestrictions": ("IClientUser", "GetDLCRestrictions", 110),
    "GetAppUserDefinedInfo": ("IClientUser", "GetAppUserDefinedInfo", 111),
    "GetAppBuildDir": ("IClientUtils", "GetAppBuildDir", 10),
    "GetAllInstalledDLC": ("IClientUser", "GetAllInstalledDLC", 112),
    "GetAppInstalledSize": ("IClientUser", "GetAppInstalledSize", 113),
    "GetAppLanguage": ("IClientUser", "GetAppLanguage", 114),
    "RequestAppCallbacks": ("IClientUser", "RequestAppCallbacks", 115),
    "RequestAppCallbacksV2": ("IClientUser", "RequestAppCallbacksV2", 116),
    "SetAllowAutoLogin": ("IClientUser", "SetAllowAutoLogin", 117),
    "IsVACBanned": ("IClientUser", "IsVACBanned", 118),
    "GetCurrentSessionID": ("IClientUser", "GetCurrentSessionID", 119),
    "GetTargetIDForDLC": ("IClientUser", "GetTargetIDForDLC", 120),
    "GetConnectingSocket": ("IClientNetworking", "GetConnectingSocket", 1),
    "GetListenSocketToRelay": ("IClientNetworking", "GetListenSocketToRelay", 2),
    "InitiateGameConnectionLegacy": ("IClientUser", "InitiateGameConnectionLegacy", 121),
    "InitiateGameConnection2": ("IClientUser", "InitiateGameConnection2", 122),
    "AuthenticateGameConnection": ("IClientUser", "AuthenticateGameConnection", 123),
    "TerminateGameConnection": ("IClientUser", "TerminateGameConnection", 124),
    "SendUserConnectAndAuthenticateLegacy": ("IClientUser", "SendUserConnectAndAuthenticateLegacy", 125),
    "SendUserConnectAndAuthenticate2": ("IClientUser", "SendUserConnectAndAuthenticate2", 126),
    "GetAuthSessionTicket": ("IClientUser", "GetAuthSessionTicket", 127),
    "GetAuthTicketForWebApi": ("IClientUser", "GetAuthTicketForWebApi", 128),
    "GetAppOwnershipProof": ("IClientUser", "GetAppOwnershipProof", 129),
    "GetAppOwnershipTicket": ("IClientUser", "GetAppOwnershipTicket", 130),
    "GetMarketEligibility": ("IClientUser", "GetMarketEligibility", 131),
    "GetDurationControl": ("IClientUser", "GetDurationControl", 132),
    "BSetExpandedClientInfo": ("IClientUser", "BSetExpandedClientInfo", 133),
    "GetPartnerAccountInfo": ("IClientUser", "GetPartnerAccountInfo", 134),
    "GetAppOwnerDebugDetails": ("IClientUser", "GetAppOwnerDebugDetails", 135),
    "GetNumRunningApps": ("IClientUtils", "GetNumRunningApps", 11),
    "GetRunningAppIDs": ("IClientUtils", "GetRunningAppIDs", 12),
    "FillInAppOverview": ("IClientApps", "FillInAppOverview", 0),
    "GetAppBuildID": ("IClientApps", "GetAppBuildID", 1),
    "GetAllApps": ("IClientApps", "GetAllApps", 2),
    "GetAppList": ("IClientApps", "GetAppList", 3),
    "GetAppCount": ("IClientApps", "GetAppCount", 4),
    "BIsAppInstalled": ("IClientApps", "BIsAppInstalled", 5),
    "GetDLCCount": ("IClientApps", "GetDLCCount", 6),
    "GetDLCDataByIndex": ("IClientApps", "GetDLCDataByIndex", 7),
    "BBuildAndAsyncSendFrame": ("IClientDepotBuilder", "BBuildAndAsyncSendFrame", 0),
    "BuildDepotDependency": ("IClientDepotBuilder", "BuildDepotDependency", 1),
    "BuildSpawnEnvBlock": ("IClientDepotBuilder", "BuildSpawnEnvBlock", 2),
}


def extract_ipc_from_patterns(patterns: Dict[str, dict]) -> Dict[str, dict]:
    """Build IPC data from pattern file entries."""
    ipc_data = {}

    for hash_key, entry in patterns.items():
        name = entry.get("name", "")
        if name not in KNOWN_METHOD_MAPPINGS:
            continue

        iface_name, method_name, method_index = KNOWN_METHOD_MAPPINGS[name]
        if iface_name not in ipc_data:
            ipc_data[iface_name] = {
                "interface_id": IPC_INTERFACES.get(iface_name, {}).get("interface_id", 0),
                "methods": {},
            }

        ipc_data[iface_name]["methods"][method_name] = {
            "method_index": method_index,
            "funcHash": f"0x{compute_name_hash(name):08X}",
            "wrapper_rva": entry.get("rva", "0x0"),
        }

    return ipc_data


def find_ipc_interface_strings(pe: pefile.PE) -> Dict[str, int]:
    """Find IPC interface name strings in the binary."""
    results = {}
    for iface_name in IPC_INTERFACES:
        string_rvas = find_string_in_pe_data(pe, iface_name)
        if string_rvas:
            results[iface_name] = string_rvas[0]
    return results


def generate_ipc_toml(ipc_data: Dict[str, dict]) -> str:
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
            lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Extract IPC interface layouts")
    parser.add_argument("--dll", required=True, help="Path to steamclient64.dll")
    parser.add_argument("--output", required=True, help="Output TOML file path")
    parser.add_argument("--pattern-toml", help="Existing pattern TOML for function hints")
    args = parser.parse_args()

    print(f"IPC Extractor v2")
    print(f"DLL: {args.dll}")
    print(f"{'='*60}")

    patterns = {}
    if args.pattern_toml and os.path.exists(args.pattern_toml):
        print(f"Loading patterns: {args.pattern_toml}")
        patterns = load_patterns_from_toml(args.pattern_toml)
        print(f"Loaded {len(patterns)} patterns")

    ipc_data = extract_ipc_from_patterns(patterns)
    print(f"Extracted {len(ipc_data)} IPC interfaces from patterns")

    if os.path.exists(args.dll):
        print(f"\nAnalyzing DLL for interface strings...")
        pe = pefile.PE(args.dll)
        interface_strings = find_ipc_interface_strings(pe)
        print(f"Found {len(interface_strings)} interface name strings in binary")
        for iface_name, rva in interface_strings.items():
            print(f"  {iface_name}: RVA=0x{rva:X}")
        pe.close()

    toml_content = generate_ipc_toml(ipc_data)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(toml_content)

    print(f"\nOutput saved to: {args.output}")
    print(f"Total interfaces: {len(ipc_data)}")
    total_methods = 0
    for iface_name, info in sorted(ipc_data.items()):
        method_count = len(info.get("methods", {}))
        total_methods += method_count
        print(f"  {iface_name}: {method_count} methods")
    print(f"Total methods: {total_methods}")


if __name__ == "__main__":
    main()

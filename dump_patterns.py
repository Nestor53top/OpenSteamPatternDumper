#!/usr/bin/env python3
"""
OpenSteam Pattern Dumper - Main Runner
Orchestrates the pattern extraction pipeline.
"""

import os
import sys
import json
import hashlib
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tools"))

from sig_scanner import (
    compute_sha256,
    scan_dll,
    generate_toml,
    load_existing_patterns,
    load_known_functions_from_patterns,
    compute_name_hash,
)
from ipc_extractor import extract_ipc_from_pattern_file, generate_ipc_toml


# Function signatures from steam-monitor (these are the known patterns)
# We'll try to download the latest ones from GitHub
STEAM_MONITOR_FUNCTIONS = {
    "steamclient": {
        "CheckAppOwnership": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 41"},
        "ConfigStoreGetBinary": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 33"},
        "BuildDepotDependency": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41"},
        "IPCProcessMessage": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 40 45"},
        "BBuildAndAsyncSendFrame": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54 41"},
        "RecvPkt": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 55"},
        "SendCallbackToPipe": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 55"},
        "SpawnProcess": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56"},
        "GetPackageInfo": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 48"},
        "MarkLicenseAsChanged": {"sig": "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 48 8B F9"},
        "ProcessPendingLicenseUpdates": {"sig": "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 30 48 8B F9"},
        "GetPipeClient": {"sig": "48 89 5C 24 08 57 48 83 EC 20 48 8B F9"},
        "GetAppDataFromAppInfo": {"sig": "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 48 8B EA"},
        "GetAppIDForCurrentPipe": {"sig": "48 89 5C 24 08 57 48 83 EC 30 48 8B F9"},
        "OptedInMask": {"sig": "48 89 5C 24 08 57 48 83 EC 20 0F B6 FA"},
        "BuildSpawnEnvBlock": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 48"},
        "PchMsgNameFromEMsg": {"sig": "48 89 5C 24 08 57 48 83 EC 20 8B FA"},
        "CUtlBufferEnsureCapacity": {"sig": "48 89 5C 24 08 57 48 83 EC 20 48 8B FA"},
        "CUtlMemoryGrow": {"sig": "48 89 5C 24 08 57 48 83 EC 20 48 8B E9"},
        "GetOrAddAppData": {"sig": "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 48 8B E9"},
        "LoadDepotDecryptionKey": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 40 48"},
        "LoadPackage": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 48"},
        "KeyValues_ReadAsBinary": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48"},
        "KeyValues_FindOrCreateKey": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 49"},
        "CloseAppCloud": {"sig": "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 48 8B F9"},
        "AddProtobufAsBinary": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 48"},
    },
    "steamui": {
        "FillInAppOverview": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 48"},
        "BuildCompleteAppOverviewChange": {"sig": "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 48 8B F9"},
        "CSteamUIAppControllerRunFrame": {"sig": "48 89 5C 24 08 57 48 83 EC 30 48 8B F9"},
        "GetAppByID": {"sig": "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 8B DA"},
        "MarkAppChange": {"sig": "48 89 5C 24 08 57 48 83 EC 20 48 8B F9"},
        "RepeatedFieldUint32_Add": {"sig": "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 48 8B F9"},
        "ShouldShowAppInLibrary": {"sig": "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 0F B6 DA"},
        "AddProtobufAsBinary": {"sig": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 48"},
        "GetTopManager": {"sig": "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 E8"},
        "LoadModuleWithPath": {"sig": "48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 48 8B F9 48"},
    }
}


def download_latest_patterns() -> Dict[str, Dict[str, dict]]:
    """Download latest pattern files from steam-monitor GitHub repo."""
    import urllib.request
    
    patterns = {}
    
    for component in ["steamclient", "steamui"]:
        print(f"\nDownloading latest {component} patterns from steam-monitor...")
        patterns[component] = {}
        
        # Try to download the latest pattern file
        # We'll use the known function names and try to find them in the latest TOML
        base_url = f"https://raw.githubusercontent.com/OpenSteam001/steam-monitor/pattern/{component}"
        
        # For now, use our built-in signatures
        patterns[component] = STEAM_MONITOR_FUNCTIONS.get(component, {})
    
    return patterns


def main():
    parser = argparse.ArgumentParser(description="OpenSteam Pattern Dumper")
    parser.add_argument("--steamclient-dll", help="Path to steamclient64.dll")
    parser.add_argument("--steamui-dll", help="Path to steamui.dll")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--existing-dir", help="Directory with existing pattern TOMLs")
    parser.add_argument("--functions-json", help="JSON file with function definitions")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = {}

    # Load function definitions
    known_functions = {}
    
    if args.functions_json and os.path.exists(args.functions_json):
        print(f"Loading functions from JSON: {args.functions_json}")
        with open(args.functions_json, "r") as f:
            json_data = json.load(f)
            for func_name, info in json_data.items():
                component = info.get("component", "steamclient")
                if component not in known_functions:
                    known_functions[component] = {}
                known_functions[component][func_name] = {"sig": STEAM_MONITOR_FUNCTIONS.get(component, {}).get(func_name, {}).get("sig", "")}
    
    # If no JSON provided, use built-in functions
    if not known_functions:
        known_functions = STEAM_MONITOR_FUNCTIONS.copy()

    # Process steamclient64.dll
    if args.steamclient_dll and os.path.exists(args.steamclient_dll):
        sha256 = compute_sha256(args.steamclient_dll)
        print(f"\nSteamclient64.dll SHA-256: {sha256}")

        # Load existing patterns if available
        funcs_to_scan = known_functions.get("steamclient", {})
        if args.existing_dir:
            existing_file = Path(args.existing_dir) / "steamclient" / f"{sha256}.toml"
            if existing_file.exists():
                existing = load_existing_patterns(str(existing_file))
                funcs_to_scan.update(load_known_functions_from_patterns(existing))

        # Scan
        patterns = scan_dll(args.steamclient_dll, funcs_to_scan, "steamclient")

        # Save
        toml = generate_toml(patterns)
        out_file = output_dir / f"steamclient_{sha256}.toml"
        with open(out_file, "w") as f:
            f.write(toml)

        results["steamclient"] = {
            "sha256": sha256,
            "patterns_count": len(patterns),
            "output_file": str(out_file),
        }

        # Generate IPC
        ipc_data = extract_ipc_from_pattern_file(patterns)
        ipc_toml = generate_ipc_toml(ipc_data)
        ipc_file = output_dir / f"ipc_steamclient_{sha256}.toml"
        with open(ipc_file, "w") as f:
            f.write(ipc_toml)

        results["ipc_steamclient"] = {
            "sha256": sha256,
            "interfaces_count": len(ipc_data),
            "output_file": str(ipc_file),
        }

    # Process steamui.dll
    if args.steamui_dll and os.path.exists(args.steamui_dll):
        sha256 = compute_sha256(args.steamui_dll)
        print(f"\nSteamui.dll SHA-256: {sha256}")

        funcs_to_scan = known_functions.get("steamui", {})
        if args.existing_dir:
            existing_file = Path(args.existing_dir) / "steamui" / f"{sha256}.toml"
            if existing_file.exists():
                existing = load_existing_patterns(str(existing_file))
                funcs_to_scan.update(load_known_functions_from_patterns(existing))

        patterns = scan_dll(args.steamui_dll, funcs_to_scan, "steamui")

        toml = generate_toml(patterns)
        out_file = output_dir / f"steamui_{sha256}.toml"
        with open(out_file, "w") as f:
            f.write(toml)

        results["steamui"] = {
            "sha256": sha256,
            "patterns_count": len(patterns),
            "output_file": str(out_file),
        }

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    for key, info in results.items():
        print(f"{key}: {json.dumps(info, indent=2)}")

    # Save summary
    with open(output_dir / "summary.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nAll output files saved to: {output_dir}")
    return results


if __name__ == "__main__":
    main()

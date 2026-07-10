#!/usr/bin/env python3
"""
IPC Extractor v3 - merges steam-monitor IPC data with DLL analysis.
"""

import os
import sys
import re
import json
import argparse
from typing import Dict

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


def load_ipc_from_toml(toml_path: str) -> Dict[str, dict]:
    """Load IPC data from a TOML file."""
    ipc_data = {}
    if not os.path.exists(toml_path):
        return ipc_data

    current_iface = None
    current_method = None
    current_entry = {}

    with open(toml_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Top-level interface: [IClientUser]
            m = re.match(r"^\[(\w+)\]$", line)
            if m:
                current_iface = m.group(1)
                current_method = None
                current_entry = {}
                if current_iface not in ipc_data:
                    ipc_data[current_iface] = {"methods": {}}
                continue

            # Method: [IClientUser.GetSteamID]
            m = re.match(r"^(\w+)\.(\w+)$", line.strip("[]"))
            if m:
                current_iface = m.group(1)
                current_method = m.group(2)
                current_entry = {}
                if current_iface not in ipc_data:
                    ipc_data[current_iface] = {"methods": {}}
                if current_method not in ipc_data[current_iface]["methods"]:
                    ipc_data[current_iface]["methods"][current_method] = {}
                continue

            # key = value
            kv = re.match(r'^(\w+)\s*=\s*"?([^"]*)"?$', line)
            if kv:
                key = kv.group(1)
                value = kv.group(2).strip('"')

                if current_method and current_iface:
                    ipc_data[current_iface]["methods"][current_method][key] = value
                elif current_iface:
                    ipc_data[current_iface][key] = value

    return ipc_data


def merge_ipc_data(base: Dict, override: Dict) -> Dict:
    """Merge IPC data, override has priority."""
    result = {}
    all_ifaces = set(list(base.keys()) + list(override.keys()))

    for iface in all_ifaces:
        result[iface] = {"methods": {}}

        if iface in base:
            for k, v in base[iface].items():
                if k != "methods":
                    result[iface][k] = v
            for method, data in base[iface].get("methods", {}).items():
                result[iface]["methods"][method] = data.copy()

        if iface in override:
            for k, v in override[iface].items():
                if k != "methods":
                    result[iface][k] = v
            for method, data in override[iface].get("methods", {}).items():
                result[iface]["methods"][method] = data.copy()

    return result


def generate_ipc_toml(ipc_data: Dict[str, dict]) -> str:
    lines = []
    for iface_name in sorted(ipc_data.keys()):
        iface_info = ipc_data[iface_name]
        lines.append(f"[{iface_name}]")
        if "interface_id" in iface_info:
            lines.append(f'interface_id = {iface_info["interface_id"]}')
        if "vtable_rva" in iface_info:
            lines.append(f'vtable_rva = "{iface_info["vtable_rva"]}"')
        lines.append("")

        for method_name in sorted(iface_info.get("methods", {}).keys()):
            method_info = iface_info["methods"][method_name]
            lines.append(f"[{iface_name}.{method_name}]")
            for key in ["method_index", "funcHash", "wrapper_rva", "fencepost", "argc", "rva"]:
                if key in method_info:
                    val = method_info[key]
                    if key in ("funcHash", "fencepost", "wrapper_rva", "rva"):
                        lines.append(f'{key} = "{val}"')
                    else:
                        lines.append(f'{key} = {val}')
            lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="IPC Extractor v3")
    parser.add_argument("--dll", help="Path to steamclient64.dll")
    parser.add_argument("--output", required=True, help="Output TOML file")
    parser.add_argument("--pattern-toml", help="Our scanned patterns")
    parser.add_argument("--steam-monitor-ipc-dir", help="Directory with steam-monitor IPC TOML files")
    args = parser.parse_args()

    print("IPC Extractor v3")
    print("=" * 60)

    merged = {}

    # 1. Load all steam-monitor IPC files (find newest by hash)
    if args.steam_monitor_ipc_dir and os.path.isdir(args.steam_monitor_ipc_dir):
        print(f"\nLoading steam-monitor IPC data from: {args.steam_monitor_ipc_dir}")
        newest_file = None
        newest_mtime = 0
        for f in os.listdir(args.steam_monitor_ipc_dir):
            if f.endswith(".toml"):
                fpath = os.path.join(args.steam_monitor_ipc_dir, f)
                mtime = os.path.getmtime(fpath)
                if mtime > newest_mtime:
                    newest_mtime = mtime
                    newest_file = fpath

        if newest_file:
            print(f"  Using newest IPC file: {os.path.basename(newest_file)}")
            sm_ipc = load_ipc_from_toml(newest_file)
            merged = merge_ipc_data(merged, sm_ipc)
            total_methods = sum(len(v.get("methods", {})) for v in sm_ipc.values())
            print(f"  Loaded {len(sm_ipc)} interfaces, {total_methods} methods")

    # 2. Load our scanned patterns for additional method info
    if args.pattern_toml and os.path.exists(args.pattern_toml):
        print(f"\nLoading our scanned patterns: {args.pattern_toml}")
        # Import from sig_scanner
        sys.path.insert(0, os.path.dirname(__file__))
        from sig_scanner import load_patterns_from_toml
        patterns = load_patterns_from_toml(args.pattern_toml)
        print(f"  Loaded {len(patterns)} patterns")

    # 3. Analyze DLL if available
    if args.dll and os.path.exists(args.dll):
        print(f"\nAnalyzing DLL: {args.dll}")
        pe = pefile.PE(args.dll)
        print(f"  Image base: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
        pe.close()

    # Generate output
    toml_content = generate_ipc_toml(merged)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(toml_content)

    print(f"\nOutput: {args.output}")
    total_ifaces = len(merged)
    total_methods = sum(len(v.get("methods", {})) for v in merged.values())
    print(f"Total: {total_ifaces} interfaces, {total_methods} methods")


if __name__ == "__main__":
    main()

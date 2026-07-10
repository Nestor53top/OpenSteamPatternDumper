#!/usr/bin/env python3
"""
Download ALL branches from steam-monitor: pattern, ipc, protobuf.
"""

import os
import sys
import json
import urllib.request
import urllib.error
import base64


def fetch_json(url, token=None):
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "OpenSteamPatternDumper",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"  Error: {e}")
        return None


def fetch_raw_content(url, token=None):
    headers = {
        "Accept": "application/vnd.github.v3.raw",
        "User-Agent": "OpenSteamPatternDumper",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except Exception as e:
        print(f"  Error: {e}")
        return None


def fetch_base64_content(url, token=None):
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "OpenSteamPatternDumper",
    }
    if token:
        headers["Authorization"] = f"token {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if "content" in data:
                return base64.b64decode(data["content"]).decode("utf-8")
    except Exception as e:
        print(f"  Error: {e}")
    return None


def list_dir(repo, branch, path, token=None):
    url = f"https://api.github.com/repos/{repo}/contents/{path}?ref={branch}"
    data = fetch_json(url, token)
    if isinstance(data, list):
        return data
    return []


def download_branch(repo, branch, component, output_dir, token=None, extensions=None):
    """Download all files from a branch/path."""
    if extensions is None:
        extensions = [".toml", ".proto"]

    files = list_dir(repo, branch, component, token)
    count = 0

    for item in files:
        name = item.get("name", "")
        item_type = item.get("type", "")

        if item_type == "dir":
            sub_count = download_branch(
                repo, branch, f"{component}/{name}", output_dir, token, extensions
            )
            count += sub_count
            continue

        if not any(name.endswith(ext) for ext in extensions):
            continue

        raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{component}/{name}"
        content = fetch_raw_content(raw_url, token)
        if content:
            out_path = os.path.join(output_dir, name)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w") as f:
                f.write(content)
            count += 1

    return count


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="OpenSteam001/steam-monitor")
    parser.add_argument("--output-dir", default="steam_monitor_data")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    args = parser.parse_args()

    total = 0

    # 1. Pattern branch
    print("=== Downloading PATTERN branch ===")
    for comp in ["steamclient", "steamui"]:
        out_dir = os.path.join(args.output_dir, "pattern", comp)
        count = download_branch(args.repo, "pattern", comp, out_dir, args.token, [".toml"])
        print(f"  {comp}: {count} files")
        total += count

    # 2. IPC branch
    print("\n=== Downloading IPC branch ===")
    out_dir = os.path.join(args.output_dir, "ipc", "steamclient")
    count = download_branch(args.repo, "ipc", "steamclient", out_dir, args.token, [".toml"])
    print(f"  steamclient: {count} files")
    total += count

    # 3. Protobuf branch
    print("\n=== Downloading PROTOBUF branch ===")
    for comp in ["steamclient", "steamui"]:
        out_dir = os.path.join(args.output_dir, "protobuf", comp)
        count = download_branch(args.repo, "protobuf", comp, out_dir, args.token, [".proto"])
        print(f"  {comp}: {count} files")
        total += count

    print(f"\nTotal: {total} files downloaded")
    return total


if __name__ == "__main__":
    main()

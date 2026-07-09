#!/usr/bin/env python3
"""
Download all known patterns from steam-monitor repository.
Used by GitHub Actions workflow to build reference pattern set.
"""

import os
import sys
import json
import urllib.request
import urllib.error


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
        print(f"  Error fetching {url}: {e}")
        return None


def fetch_raw(url, token=None):
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
        print(f"  Error fetching {url}: {e}")
        return None


def download_patterns(repo, branch, component, output_dir, token=None):
    """Download all pattern files for a component."""
    url = f"https://api.github.com/repos/{repo}/contents/{component}?ref={branch}"
    print(f"Fetching {component} pattern list from {repo}...")

    data = fetch_json(url, token)
    if not data or not isinstance(data, list):
        print(f"  Failed to list {component} patterns")
        return 0

    os.makedirs(output_dir, exist_ok=True)
    count = 0

    for item in data:
        name = item.get("name", "")
        if not name.endswith(".toml"):
            continue

        raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{component}/{name}"
        content = fetch_raw(raw_url, token)
        if content:
            out_path = os.path.join(output_dir, name)
            with open(out_path, "w") as f:
                f.write(content)
            count += 1

    print(f"  Downloaded {count} {component} pattern files")
    return count


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="OpenSteam001/steam-monitor")
    parser.add_argument("--branch", default="pattern")
    parser.add_argument("--output-dir", default="patterns_ref")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    args = parser.parse_args()

    total = 0
    for component in ["steamclient", "steamui"]:
        out_dir = os.path.join(args.output_dir, component)
        count = download_patterns(args.repo, args.branch, component, out_dir, args.token)
        total += count

    print(f"\nTotal: {total} pattern files downloaded")
    return total


if __name__ == "__main__":
    main()

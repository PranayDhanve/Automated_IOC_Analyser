#!/usr/bin/env python3

import base64
import csv
import ipaddress
import json
import os
import re
import sys
import time

import requests
from dotenv import load_dotenv

load_dotenv()

INPUT_CSV = "sample_iocs.csv"
OUTPUT_CSV = "scan_results.csv"
CACHE_FILE = "ioc_cache.json"
VT_DELAY_SECONDS = 15  
VT_BASE = "https://www.virustotal.com/api/v3"


api_key = os.getenv("Vir_ttl_API")
if not api_key:
    print(
        "ERROR: VirusTotal API key not found.\n"
        "  → Set 'Vir_ttl_API' in your .env file or as an environment variable.",
        file=sys.stderr,
    )
    sys.exit(1)

headers = {
    "x-apikey": api_key,
    "accept": "application/json",
}

# Caching

def cache_key(ioc: str) -> str:
    """Normalize IOC for caching (refang, lower)."""
    return refang(ioc.strip()).lower()

def load_cache(filepath: str) -> dict:
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}

def save_cache(filepath: str, cache_data: dict) -> None:
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2)
    except OSError as e:
        print(f"  [!] Failed to save cache: {e}")

# Defanging / Classification 

def refang(value: str) -> str:
    """Convert  to their real form."""
    value = value.replace("[.]", ".").replace("(.)",".")
    value = value.replace("[@]", "@").replace("(@)","@")
    value = value.replace("hxxp://", "http://").replace("hxxps://", "https://")
    value = value.replace("hXXp://", "http://").replace("hXXps://", "https://")
    return value.strip()


def classify_ioc(raw: str) -> tuple[str, str]:
    """  Types: hash, url, domain, ip, email  """
    
    value = refang(raw.strip())
    if not value:
        raise ValueError("Please give IOCs ")

    lower = value.lower()

    # URLs
    if lower.startswith(("http://", "https://")):
        return "url", value

    # Hashes: MD5 (32), SHA-1 (40), SHA-256 (64)
    if re.fullmatch(r"[A-Fa-f0-9]{32}", value):
        return "hash", value.lower()
    if re.fullmatch(r"[A-Fa-f0-9]{40}", value):
        return "hash", value.lower()
    if re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        return "hash", value.lower()

    # Email addresses → extract and scan the domain
    if "@" in value:
        domain_part = value.split("@", 1)[1].strip()
        if domain_part:
            return "domain", domain_part.lower()

    # IP addresses
    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass

    # Domain / hostname
    host = value.rstrip(".")
    if re.fullmatch(
        r"(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
        host,
    ):
        return "domain", host.lower()

    raise ValueError(f"unrecognized IOC type: {value!r}")



def vt_url_id(url: str) -> str:
    """VirusTotal URL identifier: URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def vt_endpoint(ioc_type: str, value: str) -> str:
    """Return the correct VT v3 endpoint for a given IOC type."""
    endpoints = {
        "hash":   f"{VT_BASE}/files/{value}",
        "ip":     f"{VT_BASE}/ip_addresses/{value}",
        "domain": f"{VT_BASE}/domains/{value}",
        "url":    f"{VT_BASE}/urls/{vt_url_id(value)}",
    }
    if ioc_type not in endpoints:
        raise ValueError(f"unknown IOC type: {ioc_type}")
    return endpoints[ioc_type]


# CSV I/O 

KNOWN_COLUMNS = {"ioc", "indicator", "indicators", "hash", "url", "domain", "ip", "value"}

def read_iocs(filepath: str) -> list[str]:
    """Read IOCs from a CSV. Auto-detects the IOC column by header name."""
    iocs = []
    with open(filepath, mode="r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return iocs
        
        # Find the IOC column (first column whose header matches a known name)
        ioc_col = None
        for col in reader.fieldnames:
            if col.strip().lower() in KNOWN_COLUMNS:
                ioc_col = col
                break

        # Fallback: use the first column
        if ioc_col is None:
            ioc_col = reader.fieldnames[0]

        for row in reader:
            val = row.get(ioc_col, "").strip()
            if val:
                iocs.append(val)
    return iocs


def write_results(filepath: str, rows: list[dict]) -> str:
    import pathlib, datetime
    base = pathlib.Path(filepath)
    candidates = [base] + [base.with_stem(f"{base.stem}_{i}") for i in range(1, 6)]
    for path in candidates:
        try:
            with open(path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["ioc", "type", "score", "verdict"])
                writer.writeheader()
                writer.writerows(rows)
            if str(path) != filepath:
                print(f"  [!] {filepath} is locked, wrote to {path} instead")
            return str(path)
        except PermissionError:
            continue
    # Last resort: timestamped file
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fallback = base.with_stem(f"{base.stem}_{ts}")
    with open(fallback, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ioc", "type", "score", "verdict"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"  [!] {filepath} is locked, wrote to {fallback} instead")
    return str(fallback)


# Scoring 

def format_score(stats: dict) -> tuple[str, str]:
    """
    Convert last_analysis_stats into a human-readable score and verdict.
    Returns ("malicious/total", verdict)
    """
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values())

    score = f"{malicious} out of {total}"

    if malicious > 0:
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return score, verdict


# Lookup 

def lookup_ioc(raw_ioc: str) -> dict:
    """Query VirusTotal for a single IOC and return the result row."""
    result = {"ioc": raw_ioc, "type": "unknown", "score": "N/A", "verdict": "ERROR"}

    try:
        ioc_type, normalized = classify_ioc(raw_ioc)
    except ValueError as exc:
        result["verdict"] = f"ERROR: {exc}"
        return result

    result["type"] = ioc_type
    url = vt_endpoint(ioc_type, normalized)

    try:
        response = requests.get(url, headers=headers, timeout=60)
    except requests.RequestException as exc:
        print(f"  [!] Network error: {exc}")
        result["verdict"] = f"ERROR: {exc}"
        return result

    if response.status_code == 404:
        result["verdict"] = "NOT_FOUND"
        return result

    if response.status_code == 429:
        result["verdict"] = "RATE_LIMITED"
        return result

    if response.status_code != 200:
        msg = f"HTTP {response.status_code}"
        print(f"  [!] {msg}")
        result["verdict"] = f"ERROR: {msg}"
        return result

    try:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        result["score"], result["verdict"] = format_score(stats)
    except (KeyError, TypeError, ValueError) as exc:
        print(f"  [!] Parse error: {exc}")
        result["verdict"] = f"ERROR: bad response ({exc})"

    return result


# Main 

def main() -> None:
    ioc_list = read_iocs(INPUT_CSV)
    if not ioc_list:
        print(f"No IOCs found in {INPUT_CSV}.", file=sys.stderr)
        sys.exit(1)

    # Load persistent cache
    cache = load_cache(CACHE_FILE)
    cached_count = sum(1 for ioc in ioc_list if cache_key(ioc) in cache)
    to_scan = len(ioc_list) - cached_count

    print(f"Loaded {len(ioc_list)} IOC(s) from {INPUT_CSV}")
    print(f"  {cached_count} found in cache, {to_scan} need API lookup")
    if to_scan > 0:
        est_min = (to_scan * VT_DELAY_SECONDS) / 60
        print(f"  Estimated time: ~{est_min:.1f} minutes (free-tier rate limit)")
    print()

    results: list[dict] = []
    api_calls_made = 0

    for idx, raw_ioc in enumerate(ioc_list, start=1):
        # Classify for display
        try:
            ioc_type, _ = classify_ioc(raw_ioc)
            label = ioc_type.upper()
        except ValueError:
            label = "???"

        display = raw_ioc if len(raw_ioc) <= 50 else raw_ioc[:47] + "..."
        key = cache_key(raw_ioc)

        # Check cache first
        if key in cache:
            row = cache[key].copy()
            row["ioc"] = raw_ioc  # preserve original formatting
            results.append(row)
            print(f"[{idx}/{len(ioc_list)}] [{label}] {display} -> {row['score']}  ({row['verdict']})  [CACHED]")
            continue

        # Rate-limit: wait before API calls (skip for first one)
        if api_calls_made > 0:
            time.sleep(VT_DELAY_SECONDS)

        print(f"[{idx}/{len(ioc_list)}] [{label}] {display}", end=" ")
        
        row = lookup_ioc(raw_ioc)
        results.append(row)
        api_calls_made += 1
        print(f"-> {row['score']}  ({row['verdict']})")

        # Save to cache (skip errors that are worth retrying)
        if row["verdict"] not in ("RATE_LIMITED",) and not row["verdict"].startswith("ERROR"):
            cache[key] = {"ioc": raw_ioc, "type": row["type"], "score": row["score"], "verdict": row["verdict"]}
            save_cache(CACHE_FILE, cache)

        # Checkpoint after every lookup
        write_results(OUTPUT_CSV, results)

    print(f"\nDone. {api_calls_made} API call(s) made, {cached_count} served from cache.")
    print(f"Results written to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()

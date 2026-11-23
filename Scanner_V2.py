#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import sys
import time
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from openpyxl import load_workbook


VT_BASE = "https://www.virustotal.com/api/v3"
CACHE_VERSION = 1
DEFAULT_DELAY_SECONDS = 15.0
DEFAULT_CACHE_TTL_HOURS = 168.0
KNOWN_COLUMNS = {"ioc", "indicator", "indicators", "hash", "url", "domain", "ip", "value"}
DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)


class RateLimitedError(RuntimeError):
    """Raised when VirusTotal asks the scanner to slow down."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(f"VirusTotal rate limited this scan; retry after {retry_after} seconds.")
        self.retry_after = retry_after


@dataclass(frozen=True)
class Settings:
    input_path: Path
    output_path: Path
    cache_path: Path
    delay_seconds: float
    cache_ttl: timedelta


@dataclass
class ScanSummary:
    """Results and operational counts from one scan."""

    results: list[dict[str, str]]
    output_path: Path
    api_calls: int
    cached_count: int
    invalid_count: int
    rate_limited_retry_after: int | None = None


def refang(value: str) -> str:
    """Convert common defanged URL, domain, and email forms to standard syntax."""
    value = value.replace("[.]", ".").replace("(.)", ".")
    value = value.replace("[@]", "@").replace("(@)", "@")
    value = re.sub(r"(?i)^hxxps://", "https://", value)
    value = re.sub(r"(?i)^hxxp://", "http://", value)
    return value.strip()


def _is_domain(value: str) -> bool:
    return bool(DOMAIN_PATTERN.fullmatch(value.rstrip(".")))


def classify_ioc(raw: str) -> tuple[str, str]:
    """Classify and normalize a hash, URL, domain, IP address, or email IOC."""
    value = refang(raw)
    if not value:
        raise ValueError("empty IOC")

    lowered = value.lower()
    if lowered.startswith(("http://", "https://")):
        parsed = requests.utils.urlparse(value)
        if not parsed.netloc:
            raise ValueError(f"invalid URL: {value!r}")
        return "url", value

    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
        return "hash", lowered

    if "@" in value:
        local, separator, domain = value.rpartition("@")
        if not separator or not local or not _is_domain(domain):
            raise ValueError(f"invalid email IOC: {value!r}")
        return "domain", domain.rstrip(".").lower()

    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass

    if _is_domain(value):
        return "domain", value.rstrip(".").lower()
    raise ValueError(f"unrecognized IOC type: {value!r}")


def cache_key(ioc_type: str, normalized_ioc: str) -> str:
    """Create a canonical cache key after IOC classification."""
    return f"{ioc_type}:{normalized_ioc.lower()}"


def vt_url_id(url: str) -> str:
    """Return VirusTotal's URL-safe base64 identifier for a URL."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def vt_endpoint(ioc_type: str, value: str) -> str:
    """Return the VirusTotal v3 endpoint for a normalized IOC."""
    endpoints = {
        "hash": f"{VT_BASE}/files/{value}",
        "ip": f"{VT_BASE}/ip_addresses/{value}",
        "domain": f"{VT_BASE}/domains/{value}",
        "url": f"{VT_BASE}/urls/{vt_url_id(value)}",
    }
    try:
        return endpoints[ioc_type]
    except KeyError as exc:
        raise ValueError(f"unknown IOC type: {ioc_type}") from exc


def _ioc_column(fieldnames: list[str]) -> str:
    for column in fieldnames:
        if column.strip().lower() in KNOWN_COLUMNS:
            return column
    return fieldnames[0]


def _read_csv(path: Path) -> list[str]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return []
        column = _ioc_column(reader.fieldnames)
        return [row.get(column, "").strip() for row in reader if row.get(column, "").strip()]


def _read_xlsx(path: Path) -> list[str]:
    # Pass a binary stream so valid workbooks remain readable even when users
    # have given them an incorrect .csv extension.
    with path.open("rb") as handle:
        workbook = load_workbook(handle, read_only=True, data_only=True)
        try:
            sheet = workbook.active
            rows = sheet.iter_rows(values_only=True)
            header = next(rows, None)
            if not header:
                return []
            fieldnames = [str(value).strip() if value is not None else "" for value in header]
            column = _ioc_column(fieldnames)
            column_index = fieldnames.index(column)
            return [str(row[column_index]).strip() for row in rows if len(row) > column_index and row[column_index] is not None and str(row[column_index]).strip()]
        finally:
            workbook.close()


def read_iocs(filepath: str | Path) -> list[str]:
    """Read IOCs from a UTF-8 CSV or an XLSX workbook, regardless of suffix."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"input file not found: {path}")
    if path.suffix.lower() in {".xlsx", ".xlsm"} or zipfile.is_zipfile(path):
        return _read_xlsx(path)
    return _read_csv(path)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def load_cache(filepath: Path) -> dict[str, dict[str, Any]]:
    """Load a versioned cache. Invalid or legacy cache data is safely ignored."""
    if not filepath.exists():
        return {}
    try:
        with filepath.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        if payload.get("version") != CACHE_VERSION or not isinstance(payload.get("entries"), dict):
            print(f"  [!] Ignoring unsupported cache format: {filepath}", file=sys.stderr)
            return {}
        return payload["entries"]
    except (json.JSONDecodeError, OSError, AttributeError) as exc:
        print(f"  [!] Ignoring unreadable cache {filepath}: {exc}", file=sys.stderr)
        return {}


def save_cache(filepath: Path, entries: dict[str, dict[str, Any]]) -> None:
    """Atomically save the versioned cache without risking partial JSON writes."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    temporary = filepath.with_suffix(f"{filepath.suffix}.tmp")
    payload = {"version": CACHE_VERSION, "entries": entries}
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    os.replace(temporary, filepath)


def cached_result(entry: dict[str, Any] | None, ttl: timedelta) -> dict[str, str] | None:
    """Return a non-expired cached result, or None when it must be refreshed."""
    if not entry:
        return None
    try:
        cached_at = datetime.fromisoformat(entry["cached_at"])
        result = entry["result"]
        if cached_at.tzinfo is None or _utc_now() - cached_at > ttl:
            return None
        if not isinstance(result, dict):
            return None
        return result
    except (KeyError, TypeError, ValueError):
        return None


def format_score(stats: dict[str, Any]) -> tuple[str, str]:
    """Convert VirusTotal analysis statistics into a score and verdict."""
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(value) for value in stats.values())
    if malicious:
        verdict = "MALICIOUS"
    elif suspicious:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"
    return f"{malicious} out of {total}", verdict


class VirusTotalClient:
    """Small reusable VirusTotal HTTP client with explicit rate-limit handling."""

    def __init__(self, api_key: str, session: requests.Session | None = None) -> None:
        self.session = session or requests.Session()
        self.headers = {"x-apikey": api_key, "accept": "application/json"}

    def lookup(self, raw_ioc: str, ioc_type: str, normalized_ioc: str) -> dict[str, str]:
        result = {"ioc": raw_ioc, "type": ioc_type, "score": "N/A", "verdict": "ERROR"}
        try:
            response = self.session.get(vt_endpoint(ioc_type, normalized_ioc), headers=self.headers, timeout=30)
        except requests.RequestException as exc:
            result["verdict"] = f"ERROR: network failure ({exc.__class__.__name__})"
            return result
        if response.status_code == 404:
            result["verdict"] = "NOT_FOUND"
            return result
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "60")
            try:
                seconds = max(1, int(retry_after))
            except ValueError:
                seconds = 60
            raise RateLimitedError(seconds)
        if response.status_code != 200:
            result["verdict"] = f"ERROR: HTTP {response.status_code}"
            return result
        try:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            result["score"], result["verdict"] = format_score(stats)
        except (KeyError, TypeError, ValueError, requests.JSONDecodeError):
            result["verdict"] = "ERROR: invalid VirusTotal response"
        return result


def write_results(filepath: Path, rows: list[dict[str, str]]) -> Path:
    """Atomically write results, choosing a nearby fallback when the file is locked."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    candidates = [filepath] + [filepath.with_stem(f"{filepath.stem}_{index}") for index in range(1, 6)]
    for candidate in candidates:
        temporary = candidate.with_suffix(f"{candidate.suffix}.tmp")
        try:
            with temporary.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["ioc", "type", "score", "verdict"])
                writer.writeheader()
                writer.writerows(rows)
            os.replace(temporary, candidate)
            return candidate
        except PermissionError:
            temporary.unlink(missing_ok=True)
    timestamp = _utc_now().strftime("%Y%m%d_%H%M%S")
    fallback = filepath.with_stem(f"{filepath.stem}_{timestamp}")
    with fallback.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ioc", "type", "score", "verdict"])
        writer.writeheader()
        writer.writerows(rows)
    return fallback


def parse_args(argv: list[str] | None = None) -> Settings:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("sample_iocs.csv"), help="CSV or XLSX IOC input file")
    parser.add_argument("--output", type=Path, default=Path("output/scan_results.csv"), help="results CSV path")
    parser.add_argument("--cache", type=Path, default=Path(".cache/ioc_cache.json"), help="persistent cache path")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY_SECONDS, help="seconds between API calls")
    parser.add_argument("--cache-ttl-hours", type=float, default=DEFAULT_CACHE_TTL_HOURS, help="maximum age of cached results")
    args = parser.parse_args(argv)
    if args.delay < 0 or args.cache_ttl_hours <= 0:
        parser.error("--delay must be non-negative and --cache-ttl-hours must be positive")
    return Settings(args.input, args.output, args.cache, args.delay, timedelta(hours=args.cache_ttl_hours))


def get_api_key() -> str:
    
    load_dotenv()
    return os.getenv("Vir_ttl_API") or ""


def scan_iocs(
    iocs: list[str], settings: Settings, client: VirusTotalClient
) -> ScanSummary:
    """Scan classified IOCs, checkpointing every result and stopping on HTTP 429."""
    cache = load_cache(settings.cache_path)
    results: list[dict[str, str]] = []
    api_calls = cached_count = invalid_count = 0
    result_path = settings.output_path

    for raw_ioc in iocs:
        try:
            ioc_type, normalized = classify_ioc(raw_ioc)
        except ValueError as exc:
            invalid_count += 1
            results.append({"ioc": raw_ioc, "type": "unknown", "score": "N/A", "verdict": f"ERROR: {exc}"})
            result_path = write_results(settings.output_path, results)
            continue

        key = cache_key(ioc_type, normalized)
        cached = cached_result(cache.get(key), settings.cache_ttl)
        if cached:
            results.append({**cached, "ioc": raw_ioc})
            cached_count += 1
            result_path = write_results(settings.output_path, results)
            continue

        if api_calls:
            time.sleep(settings.delay_seconds)
        try:
            row = client.lookup(raw_ioc, ioc_type, normalized)
        except RateLimitedError as exc:
            results.append({"ioc": raw_ioc, "type": ioc_type, "score": "N/A", "verdict": "RATE_LIMITED"})
            result_path = write_results(settings.output_path, results)
            return ScanSummary(results, result_path, api_calls, cached_count, invalid_count, exc.retry_after)

        api_calls += 1
        results.append(row)
        if not row["verdict"].startswith("ERROR"):
            cache[key] = {"cached_at": _utc_now().isoformat(), "result": row}
            save_cache(settings.cache_path, cache)
        result_path = write_results(settings.output_path, results)

    return ScanSummary(results, result_path, api_calls, cached_count, invalid_count)


def main(argv: list[str] | None = None) -> int:
    settings = parse_args(argv)
    api_key = get_api_key()
    if not api_key:
        print("ERROR: Set VT_API_KEY in .env or the environment.", file=sys.stderr)
        return 1
    try:
        iocs = read_iocs(settings.input_path)
    except (OSError, ValueError) as exc:
        print(f"ERROR: Could not read {settings.input_path}: {exc}", file=sys.stderr)
        return 1
    if not iocs:
        print(f"ERROR: No IOCs found in {settings.input_path}.", file=sys.stderr)
        return 1

    summary = scan_iocs(iocs, settings, VirusTotalClient(api_key))
    if summary.rate_limited_retry_after is not None:
        print(
            f"ERROR: VirusTotal rate limited this scan; retry after {summary.rate_limited_retry_after} seconds.\n"
            f"Partial results written to {summary.output_path}",
            file=sys.stderr,
        )
        return 2
    print(f"Done. {summary.api_calls} API call(s), {summary.cached_count} cached, {summary.invalid_count} invalid.")
    print(f"Results written to {summary.output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

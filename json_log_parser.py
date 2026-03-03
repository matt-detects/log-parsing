import json
import csv
import logging
import argparse
import sys
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


# Fields to extract and their source key in the raw log entry.
# Extend this map to add new fields without touching parsing logic.
FIELD_MAP: dict[str, str] = {
    "ip":        "source_ip",
    "user":      "user",
    "timestamp": "timestamp",
    "event":     "event_type",
}


def parse_entry(entry: dict[str, Any], index: int) -> dict[str, Any] | None:
    """
    Extract and validate a single log entry.
    Returns None and logs a warning if the entry is missing critical fields.
    """
    if not isinstance(entry, dict):
        log.warning("Entry %d is not a dict (got %s) — skipping", index, type(entry).__name__)
        return None

    parsed = {output_key: entry.get(source_key) for output_key, source_key in FIELD_MAP.items()}

    # Treat entries missing both timestamp and event type as unparseable —
    # adjust this threshold to match your data quality requirements.
    if parsed["timestamp"] is None and parsed["event"] is None:
        log.warning("Entry %d missing timestamp and event_type — skipping: %s", index, entry)
        return None

    return parsed


def load_logs(file_path: Path) -> list[dict[str, Any]]:
    """
    Load logs from a JSON file. Supports both:
      - A JSON array:              [ {...}, {...} ]
      - Newline-delimited JSON:    {...}\n{...}\n
    """
    try:
        raw = file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        log.error("Log file not found: %s", file_path)
        sys.exit(1)
    except PermissionError:
        log.error("Permission denied reading: %s", file_path)
        sys.exit(1)
    except OSError as exc:
        log.error("Failed to read %s: %s", file_path, exc)
        sys.exit(1)

    # Try JSON array first, fall back to NDJSON
    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            log.error("Expected a JSON array at top level, got %s", type(data).__name__)
            sys.exit(1)
        return data
    except json.JSONDecodeError:
        pass

    # NDJSON fallback — parse line by line, skip blank lines and malformed entries
    log.info("JSON array parse failed — attempting NDJSON format")
    entries = []
    for line_num, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as exc:
            log.warning("Line %d is not valid JSON — skipping: %s", line_num, exc)
    return entries


def parse_logs(file_path: Path) -> list[dict[str, Any]]:
    """Load and parse all log entries, skipping unparseable ones."""
    raw_entries = load_logs(file_path)

    if not raw_entries:
        log.warning("No log entries found in %s", file_path)
        return []

    parsed = []
    skipped = 0
    for index, entry in enumerate(raw_entries):
        result = parse_entry(entry, index)
        if result is not None:
            parsed.append(result)
        else:
            skipped += 1

    log.info(
        "Parsed %d entries from %s (%d skipped)",
        len(parsed), file_path, skipped
    )
    return parsed


def write_to_csv(data: list[dict[str, Any]], output_path: Path) -> None:
    """Write parsed log entries to a CSV file."""
    if not data:
        log.warning("No data to write — CSV output skipped")
        return

    try:
        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(FIELD_MAP.keys()))
            writer.writeheader()
            writer.writerows(data)
        log.info("Wrote %d rows to %s", len(data), output_path)
    except PermissionError:
        log.error("Permission denied writing to: %s", output_path)
        sys.exit(1)
    except OSError as exc:
        log.error("Failed to write %s: %s", output_path, exc)
        sys.exit(1)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse JSON/NDJSON security logs to CSV",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Path to the input JSON or NDJSON log file",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("parsed_output.csv"),
        help="Path for the output CSV file",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    parsed = parse_logs(args.input)
    write_to_csv(parsed, args.output)

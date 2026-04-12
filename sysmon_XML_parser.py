import xml.etree.ElementTree as ET
import json
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# Sysmon XML namespaces
SYSMON_NS = {
    "ns": "http://schemas.microsoft.com/win/2004/08/events/event"
}

# Human-readable names for Sysmon event IDs relevant to detection work
EVENT_ID_LABELS = {
    "1":  "ProcessCreate",
    "3":  "NetworkConnection",
    "5":  "ProcessTerminate",
    "7":  "ImageLoad",
    "8":  "CreateRemoteThread",
    "10": "ProcessAccess",
    "11": "FileCreate",
    "12": "RegistryCreate",
    "13": "RegistrySet",
    "15": "FileCreateStreamHash",
    "17": "PipeCreated",
    "18": "PipeConnected",
    "19": "WmiEventFilter",
    "20": "WmiEventConsumer",
    "21": "WmiEventConsumerBinding",
    "22": "DNSQuery",
    "23": "FileDelete",
    "25": "ProcessTampering",
}


def parse_sysmon_event(xml_string: str) -> dict | None:
    """
    Parse a single Sysmon event from raw XML string.
    Returns a flat dict of fields, or None if parsing fails.
    """
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as exc:
        log.warning("Failed to parse XML: %s", exc)
        return None

    # Extract System block fields
    system = root.find("ns:System", SYSMON_NS)
    if system is None:
        log.warning("No System block found in event XML")
        return None

    def sys_text(tag: str) -> str | None:
        el = system.find(f"ns:{tag}", SYSMON_NS)
        return el.text if el is not None else None

    def sys_attr(tag: str, attr: str) -> str | None:
        el = system.find(f"ns:{tag}", SYSMON_NS)
        return el.get(attr) if el is not None else None

    event_id = sys_text("EventID")

    event = {
        "provider":        sys_attr("Provider", "Name"),
        "event_id":        event_id,
        "event_label":     EVENT_ID_LABELS.get(event_id, f"UnknownEID_{event_id}"),
        "version":         sys_text("Version"),
        "level":           sys_text("Level"),
        "event_record_id": sys_text("EventRecordID"),
        "time_created":    sys_attr("TimeCreated", "SystemTime"),
        "computer":        sys_text("Computer"),
        "user_id":         sys_attr("Security", "UserID"),
        "process_id":      sys_attr("Execution", "ProcessID"),
        "thread_id":       sys_attr("Execution", "ThreadID"),
        "channel":         sys_text("Channel"),
    }

    # Extract all EventData Name/Value pairs into the same flat dict
    event_data = root.find("ns:EventData", SYSMON_NS)
    if event_data is not None:
        for data_el in event_data.findall("ns:Data", SYSMON_NS):
            name  = data_el.get("Name")
            value = data_el.text
            if name:
                # Normalise field names to snake_case
                key = name[0].lower() + name[1:]
                event[key] = value if value else None

    return event


def parse_sysmon_file(file_path: Path) -> tuple[list[dict], int]:
    """
    Parse a file containing one or more Sysmon events.
    Supports:
      - A single XML event
      - A file with multiple events wrapped in a root element
      - One XML event per line (common in log forwarding pipelines)
    Returns (parsed_events, skip_count).
    """
    try:
        content = file_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        log.error("File not found: %s", file_path)
        return [], 0
    except OSError as exc:
        log.error("Could not read %s: %s", file_path, exc)
        return [], 0

    parsed  = []
    skipped = 0

    # Try as a single document first (single event or wrapped collection)
    try:
        root = ET.fromstring(content)
        # If the root IS an Event, parse it directly
        if root.tag.endswith("Event"):
            result = parse_sysmon_event(content)
            if result:
                parsed.append(result)
            else:
                skipped += 1
        else:
            # Root is a wrapper — find all Event children
            for event_el in root.iter("{http://schemas.microsoft.com/win/2004/08/events/event}Event"):
                xml_str = ET.tostring(event_el, encoding="unicode")
                result  = parse_sysmon_event(xml_str)
                if result:
                    parsed.append(result)
                else:
                    skipped += 1
    except ET.ParseError:
        # Fall back to one-event-per-line
        log.info("Multi-document XML parse failed — attempting line-by-line")
        for line_num, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            result = parse_sysmon_event(line)
            if result:
                parsed.append(result)
            else:
                skipped += 1
                log.debug("Line %d did not yield a valid event", line_num)

    log.info(
        "Parsed %d Sysmon events from %s (%d skipped)",
        len(parsed), file_path, skipped
    )
    return parsed, skipped


def filter_by_event_id(events: list[dict], event_ids: list[str]) -> list[dict]:
    """Return only events matching the given event ID list."""
    return [e for e in events if e.get("event_id") in event_ids]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Parse Sysmon XML event logs to JSON",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("input", type=Path, help="Sysmon XML log file")
    parser.add_argument(
        "--event-ids", nargs="+", metavar="ID",
        help="Filter output to specific Sysmon event IDs (e.g. 20 21 3)"
    )
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Write JSON output to file instead of stdout"
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    events, skipped = parse_sysmon_file(args.input)

    if args.event_ids:
        events = filter_by_event_id(events, args.event_ids)
        log.info("After event ID filter (%s): %d events", args.event_ids, len(events))

    output_json = json.dumps(events, indent=2, default=str)

    if args.output:
        args.output.write_text(output_json, encoding="utf-8")
        log.info("Wrote %d events to %s", len(events), args.output)
    else:
        print(output_json)

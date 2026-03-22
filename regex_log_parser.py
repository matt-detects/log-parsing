import re
import logging
from ipaddress import ip_address, AddressValueError
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# Extended Common Log Format / Combined Log Format pattern.
# Captures: ip, timestamp, method, path, protocol, status,
#           size, referrer, user_agent
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'   # IP address
    r' - - '
    r'\[(?P<timestamp>[^\]]+)\]'           # Timestamp inside brackets
    r' "'
    r'(?P<method>\S+)'                     # HTTP method
    r' (?P<path>\S+)'                      # Request path
    r' (?P<protocol>[^"]+)'                # Protocol (e.g. HTTP/1.1)
    r'"'
    r' (?P<status>\d{3})'                  # Status code
    r' (?P<size>\S+)'                      # Response size or '-'
    r'(?: "(?P<referrer>[^"]*)"'           # Referrer (optional)
    r' "(?P<user_agent>[^"]*)")?'          # User agent (optional)
)


def validate_ip(ip_str):
    """Return True if ip_str is a valid IP address, False otherwise."""
    try:
        ip_address(ip_str)
        return True
    except (AddressValueError, ValueError):
        return False


def parse_line(line):
    """
    Parse a single Combined Log Format line.
    Returns a dict of fields on success, None if the line doesn't match.
    """
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()

    # Validate the IP before returning
    if not validate_ip(data["ip"]):
        log.warning("Matched line has invalid IP '%s' — skipping", data["ip"])
        return None

    # Type status code as int so callers can do numeric comparisons
    try:
        data["status"] = int(data["status"])
    except (ValueError, TypeError):
        data["status"] = None

    # Normalise response size — CLF uses '-' for empty responses
    raw_size = data.get("size", "-")
    data["size"] = 0 if raw_size == "-" else int(raw_size) if raw_size.isdigit() else None

    return data


def parse_file(file_path):
    """
    Parse all lines in a log file.
    Returns a tuple of (parsed_entries, skip_count).
    """
    path = Path(file_path)

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        log.error("Log file not found: %s", file_path)
        return [], 0
    except OSError as exc:
        log.error("Could not read %s: %s", file_path, exc)
        return [], 0

    parsed = []
    skipped = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue
        result = parse_line(line)
        if result:
            parsed.append(result)
        else:
            skipped += 1
            log.debug("No match: %s", line)

    log.info(
        "Parsed %d lines from %s (%d skipped)",
        len(parsed), file_path, skipped
    )
    return parsed, skipped


if __name__ == "__main__":
    entries, skipped = parse_file("access.log")
    for entry in entries[:5]:
        print(entry)
    print(f"\nTotal parsed: {len(entries)}, skipped: {skipped}")
```

---

## Example Input / Output

Given a log line like:
```
192.168.1.1 - - [18/Feb/2026:15:42:11 +0000] "GET /index.html HTTP/1.1" 200 512 "https://example.com" "Mozilla/5.0"

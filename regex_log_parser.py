import re

log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)"'
)

def parse_line(line):
    match = log_pattern.search(line)
    if match:
        return match.groupdict()
    return None

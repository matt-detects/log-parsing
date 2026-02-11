import json
import csv

def parse_logs(file_path):
    with open(file_path, 'r') as f:
        logs = json.load(f)

    parsed = []
    for entry in logs:
        parsed.append({
            "ip": entry.get("source_ip"),
            "user": entry.get("user"),
            "timestamp": entry.get("timestamp"),
            "event": entry.get("event_type")
        })

    return parsed

def write_to_csv(data, output_file):
    keys = data[0].keys()
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)

if __name__ == "__main__":
    logs = parse_logs("logs/sample_logs.json")
    write_to_csv(logs, "parsed_output.csv")

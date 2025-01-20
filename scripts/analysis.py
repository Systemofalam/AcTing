import os
import re
from datetime import datetime

LOG_DIR = "../logs"

def parse_log_file(file_path):
    """Parse a single log file."""
    events = []
    with open(file_path, "r") as log_file:
        for line in log_file:
            match = re.match(r"\[(.*?)\] Node (\d+): (.*)", line)
            if match:
                timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                node_id = int(match.group(2))
                event = match.group(3)
                events.append({"timestamp": timestamp, "node_id": node_id, "event": event})
    return events

def analyze_logs():
    """Analyze all logs and generate a report."""
    all_events = []
    for log_file in os.listdir(LOG_DIR):
        if log_file.endswith(".log"):
            file_path = os.path.join(LOG_DIR, log_file)
            all_events.extend(parse_log_file(file_path))

    # Sort events by timestamp
    all_events.sort(key=lambda e: e["timestamp"])

    # Example analysis: Count received chunks
    received_chunks = {}
    for event in all_events:
        if "Received chunk" in event["event"]:
            node_id = event["node_id"]
            received_chunks[node_id] = received_chunks.get(node_id, 0) + 1

    # Print the analysis report
    print("Dissemination Analysis Report")
    print("=============================")
    for node_id, count in received_chunks.items():
        print(f"Node {node_id}: Received {count} chunks")

if __name__ == "__main__":
    analyze_logs()

import os
import json
import hashlib
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor

class TamperEvidentLogs:
    def __init__(self, input_dir="files", output_dir="logs", input_file=None):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.input_file = input_file
        self.setup_directories()

    def setup_directories(self):
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"Output directory '{self.output_dir}' is ready.")

    def get_pcap_files(self):
        if self.input_file:
            return [self.input_file] if os.path.isfile(self.input_file) else []
        print(f"Scanning for PCAP files in directory: {self.input_dir}")
        return [os.path.join(self.input_dir, f) for f in os.listdir(self.input_dir) if f.endswith(".pcap")]

    def read_pcap(self, pcap_file):
        try:
            print(f"Reading PCAP file: {pcap_file}")
            return rdpcap(pcap_file)
        except Exception as e:
            print(f"Error reading {pcap_file}: {e}")
            return []

    def make_json_serializable(self, data):
        if isinstance(data, bytes):
            return data.hex()
        elif isinstance(data, float):
            return float(data)
        elif isinstance(data, (list, dict, int, str)):
            return data
        else:
            return str(data)

    def extract_field(self, raw_data, field_marker):
        try:
            data_str = bytes.fromhex(raw_data).decode(errors="ignore")
            field_start = data_str.find(field_marker)
            if field_start != -1:
                field_end = data_str.find('|', field_start)
                if field_end == -1:
                    field_end = len(data_str)
                return data_str[field_start + len(field_marker):field_end].strip()
        except Exception as e:
            return f"Error extracting field {field_marker}: {e}"
        return "Unknown"

    def generate_log_entry(self, packet, seq_number, previous_hash):
        try:
            timestamp = self.make_json_serializable(getattr(packet, "time", "Unknown"))
            source_ip = packet[IP].src if IP in packet else "Unknown"
            dest_ip = packet[IP].dst if IP in packet else "Unknown"
            sport = packet.sport if TCP in packet or UDP in packet else "Unknown"
            dport = packet.dport if TCP in packet or UDP in packet else "Unknown"
            protocol = packet[IP].proto if IP in packet else "Unknown"
            raw_data = self.make_json_serializable(bytes(packet))

            state = self.extract_field(raw_data, "Header:")
            chunk_id = self.extract_field(raw_data, "Seq:")

            ck = {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "source_port": sport,
                "dest_port": dport,
                "protocol": protocol,
                "raw_data": raw_data,
                "state": state,
                "chunk_id": chunk_id,
            }

            entry_hash = hashlib.sha256(f"{previous_hash}{seq_number}packet{raw_data}".encode()).hexdigest()
            authenticator = hashlib.sha256(f"auth:{entry_hash}".encode()).hexdigest()

            return {
                "sequence_number": seq_number,
                "type": "packet",
                "content": ck,
                "hash": entry_hash,
                "authenticator": authenticator,
            }

        except Exception as e:
            return {
                "sequence_number": seq_number,
                "type": "error",
                "content": {"error": str(e)},
                "hash": None,
                "authenticator": None,
            }

    def process_pcap_file(self, pcap_file):
        print(f"Processing PCAP file: {pcap_file}")
        packets = self.read_pcap(pcap_file)
        if not packets:
            print(f"No packets to process in {pcap_file}.")
            return

        log_entries = []
        previous_hash = "0" * 64
        seq_number = 1

        for packet in packets:
            entry = self.generate_log_entry(packet, seq_number, previous_hash)
            log_entries.append(entry)
            previous_hash = entry["hash"]
            seq_number += 1

        log_file = os.path.join(self.output_dir, os.path.basename(pcap_file).replace(".pcap", "_log.json"))
        with open(log_file, "w") as f:
            json.dump(log_entries, f, indent=4, default=str)
        print(f"Saved tamper-evident log to {log_file}")

    def run(self, max_threads=4):
        pcap_files = self.get_pcap_files()
        if not pcap_files:
            print("No PCAP files found. Exiting.")
            return

        print(f"Starting processing with {max_threads} thread(s).")
        with ThreadPoolExecutor(max_threads) as executor:
            for pcap_file in pcap_files:
                executor.submit(self.process_pcap_file, pcap_file)
        print("All files processed.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Tamper-Evident Logs Generator")
    parser.add_argument("--input-dir", type=str, default="files", help="Directory containing PCAP files")
    parser.add_argument("--output-dir", type=str, default="logs", help="Directory to save logs")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads for processing")
    parser.add_argument("--input-file", type=str, help="Specific PCAP file to process")

    args = parser.parse_args()

    tel = TamperEvidentLogs(input_dir=args.input_dir, output_dir=args.output_dir, input_file=args.input_file)
    tel.run(max_threads=args.threads)

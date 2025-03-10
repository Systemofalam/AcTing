#!/usr/bin/env python3
import os
import json
import hashlib
import re
from scapy.all import rdpcap, IP, TCP, UDP
from concurrent.futures import ThreadPoolExecutor

# Try to import LinuxSLL; if not available, use CookedLinux as a fallback.
try:
    from scapy.layers.l2 import LinuxSLL
except ImportError:
    from scapy.layers.l2 import CookedLinux as LinuxSLL

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
            if self.input_file.lower().endswith(".pcap"):
                return [self.input_file]
            else:
                print(f"Specified input file '{self.input_file}' is not a PCAP file. Ignoring.")
                return []
        print(f"Scanning for PCAP files in directory: {self.input_dir}")
        return [os.path.join(self.input_dir, f)
                for f in os.listdir(self.input_dir) if f.lower().endswith(".pcap") and "_log.json" not in f]

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
        """
        Extracts a field from the raw_data (hex string) using the provided field_marker.
        For chunk IDs (i.e. when field_marker is "Seq:"), extra non-digit characters are removed.
        """
        try:
            # Convert hex string back to bytes then decode (ignoring errors)
            data_str = bytes.fromhex(raw_data).decode(errors="ignore")
            field_start = data_str.find(field_marker)
            if field_start != -1:
                field_end = data_str.find('|', field_start)
                if field_end == -1:
                    field_end = len(data_str)
                extracted = data_str[field_start + len(field_marker):field_end]
                # First filter out non-printable characters.
                extracted = ''.join(ch for ch in extracted if ch.isprintable()).strip()
                # If this field is a chunk ID, keep only digits.
                if field_marker == "Seq:":
                    extracted = ''.join(filter(str.isdigit, extracted))
                return extracted
        except Exception as e:
            return f"Error extracting field {field_marker}: {e}"
        return "Unknown"

    def generate_log_entry(self, packet, seq_number, previous_hash):
        try:
            # Get timestamp from the packet.
            timestamp = self.make_json_serializable(getattr(packet, "time", "Unknown"))
            
            # Try to extract the IP layer (directly or via LinuxSLL/CookedLinux).
            if packet.haslayer(IP):
                ip_layer = packet[IP]
            elif packet.haslayer(LinuxSLL) and packet[LinuxSLL].haslayer(IP):
                ip_layer = packet[LinuxSLL][IP]
            else:
                ip_layer = None

            if ip_layer:
                source_ip = ip_layer.src
                dest_ip = ip_layer.dst
                protocol = ip_layer.proto
                if ip_layer.haslayer(TCP):
                    sport = ip_layer[TCP].sport
                    dport = ip_layer[TCP].dport
                elif ip_layer.haslayer(UDP):
                    sport = ip_layer[UDP].sport
                    dport = ip_layer[UDP].dport
                else:
                    sport = "Unknown"
                    dport = "Unknown"
            else:
                source_ip = "Unknown"
                dest_ip = "Unknown"
                protocol = "Unknown"
                sport = "Unknown"
                dport = "Unknown"

            # Get raw packet data as hex.
            raw_data = self.make_json_serializable(bytes(packet))
            # Extract state using "Header:".
            state = self.extract_field(raw_data, "Header:")
            if state not in ["Propose", "Push", "Pull"]:
                return None
            # Extract chunk id using "Seq:".
            chunk_id = self.extract_field(raw_data, "Seq:")

            content = {
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
            # Compute the hash chain.
            entry_hash = hashlib.sha256(f"{previous_hash}{seq_number}packet{raw_data}".encode()).hexdigest()
            authenticator = hashlib.sha256(f"auth:{entry_hash}".encode()).hexdigest()

            return {
                "sequence_number": seq_number,
                "type": "packet",
                "content": content,
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
            if entry is not None:
                log_entries.append(entry)
                previous_hash = entry["hash"]
                seq_number += 1

        # Generate a log file name by replacing .pcap with _log.json.
        base, _ = os.path.splitext(os.path.basename(pcap_file))
        log_file = os.path.join(self.output_dir, f"{base}_log.json")
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
    parser.add_argument("--output-dir", type=str, default="/home/Project/ansible/logs", help="Directory to save logs")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads for processing")
    parser.add_argument("--input-file", type=str, help="Specific PCAP file to process")

    args = parser.parse_args()

    tel = TamperEvidentLogs(input_dir=args.input_dir, output_dir=args.output_dir, input_file=args.input_file)
    tel.run(max_threads=args.threads)

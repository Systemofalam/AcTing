import os
import json
import hashlib
from scapy.all import *
from concurrent.futures import ThreadPoolExecutor

class TamperEvidentLogs:
    def __init__(self, input_dir="files", output_dir="logs"):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.setup_directories()

    def setup_directories(self):
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"Output directory '{self.output_dir}' is ready.")

    def get_pcap_files(self):
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
        """
        Converts non-serializable objects into a serializable format.
        """
        if isinstance(data, bytes):
            return data.hex()
        elif isinstance(data, float):  # Handle potential EDecimal issue
            return float(data)
        elif isinstance(data, (list, dict, int, str)):
            return data
        else:
            return str(data)  # Fallback to string representation

    def extract_state_from_raw_data(self, raw_data):
        """
        Extracts the state (e.g., 'Propose', 'Pull') from the raw packet data.
        Assumes the state is encoded as a header field like 'Header:State'.
        """
        try:
            # Convert raw data from hex to string
            data_str = bytes.fromhex(raw_data).decode(errors="ignore")
            # Look for the 'Header:' field
            state_marker = "Header:"
            state_start = data_str.find(state_marker)
            if state_start != -1:
                state_end = data_str.find('|', state_start)
                if state_end == -1:
                    state_end = len(data_str)
                return data_str[state_start + len(state_marker):state_end].strip()
        except Exception as e:
            return f"Error extracting state: {e}"
        return "Unknown"

    def generate_log_entry(self, packet, seq_number, previous_hash):
        """
        Creates a tamper-evident log entry for a packet.
        """
        try:
            timestamp = self.make_json_serializable(getattr(packet, "time", "Unknown"))
            source_ip = packet[IP].src if IP in packet else "Unknown"
            dest_ip = packet[IP].dst if IP in packet else "Unknown"
            sport = packet.sport if TCP in packet or UDP in packet else "Unknown"
            dport = packet.dport if TCP in packet or UDP in packet else "Unknown"
            protocol = packet[IP].proto if IP in packet else "Unknown"
            raw_data = self.make_json_serializable(bytes(packet))
            
            # Extract state from raw data
            state = self.extract_state_from_raw_data(raw_data)

            # Log type and content
            tk = "packet"
            ck = {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "source_port": sport,
                "dest_port": dport,
                "protocol": protocol,
                "raw_data": raw_data,
                "state": state,  # Add extracted state to the content
            }


            entry_hash = hashlib.sha256(f"{previous_hash}{seq_number}{tk}{raw_data}".encode()).hexdigest()

            # Authenticator (mocked as a simple signature for this example)
            authenticator = hashlib.sha256(f"auth:{entry_hash}".encode()).hexdigest()

            return {
                "sequence_number": seq_number,
                "type": tk,
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
        """
        Processes a single PCAP file and creates tamper-evident logs.
        """
        print(f"Processing PCAP file: {pcap_file}")
        packets = self.read_pcap(pcap_file)
        if not packets:
            print(f"No packets to process in {pcap_file}.")
            return

        log_entries = []
        previous_hash = "0" * 64  # Base hash
        seq_number = 1

        for packet in packets:
            entry = self.generate_log_entry(packet, seq_number, previous_hash)
            log_entries.append(entry)
            previous_hash = entry["hash"]
            seq_number += 1

        # Save the log to a file
        log_file = os.path.join(self.output_dir, os.path.basename(pcap_file).replace(".pcap", "_log.json"))
        with open(log_file, "w") as f:
            json.dump(log_entries, f, indent=4, default=str)
        print(f"Saved tamper-evident log to {log_file}")

    def run(self, max_threads=4):
        """
        Executes the process for all PCAP files in the input directory.
        """
        pcap_files = self.get_pcap_files()
        if not pcap_files:
            print("No PCAP files found. Exiting.")
            return

        print(f"Starting processing with {max_threads} thread(s).")
        with ThreadPoolExecutor(max_threads) as executor:
            for pcap_file in pcap_files:
                executor.submit(self.process_pcap_file, pcap_file)
        print("All files processed.")

# Main execution
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Tamper-Evident Logs Generator")
    parser.add_argument("--input-dir", type=str, default="files", help="Directory containing PCAP files")
    parser.add_argument("--output-dir", type=str, default="logs", help="Directory to save logs")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads for processing")

    args = parser.parse_args()

    tel = TamperEvidentLogs(input_dir=args.input_dir, output_dir=args.output_dir)
    tel.run(max_threads=args.threads)

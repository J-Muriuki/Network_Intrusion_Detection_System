import logging
import os
from collections import defaultdict
import pandas as pd

# Setup logging for detected traffic
log_handler = logging.FileHandler('C:/Users/EFAC/PycharmProjects/NIDS/logs/detected_traffic.log')
logging.basicConfig(handlers=[log_handler], level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# DataFrame for traffic log (normal/attacks)
traffic_log_columns = ['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Traffic Type', 'Timestamp']
traffic_log = pd.DataFrame(columns=traffic_log_columns)

# Attack signatures (for detecting known attacks)
attack_signatures = [
    {'attack_name': 'SYN Flood', 'protocol': 'TCP', 'flags': 'S', 'description': 'Multiple SYN packets without handshake'},
    {'attack_name': 'Port Scanning', 'protocol': 'TCP', 'flags': 'S', 'description': 'Multiple SYN packets sent to different ports'},
]

# Thresholds and counts for SYN Flood and Port Scanning detection
syn_count = defaultdict(int)  # Tracks SYN packet count for each source IP
port_scan_count = defaultdict(set)  # Tracks unique destination ports per source IP
syn_threshold = 20  # Threshold for detecting SYN Flood
port_scan_threshold = 10  # Threshold for detecting Port Scanning

def detect_attack(packet):
    """
    Detects attacks based on predefined signatures and logs the traffic.
    Detects SYN Floods and Port Scanning.
    """
    global traffic_log, syn_count, port_scan_count

    if packet.haslayer('TCP'):
        flags = packet.sprintf('%TCP.flags%')
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport
        timestamp = pd.Timestamp.now()

        # Default traffic type (normal if no attack detected)
        traffic_type = 'Normal'

        # Track SYN packet count for SYN Flood detection
        if 'S' in flags and 'A' not in flags:  # SYN packet without ACK (part of the handshake)
            syn_count[src_ip] += 1
            if syn_count[src_ip] > syn_threshold:
                traffic_type = 'SYN Flood'
                logging.warning(f"SYN Flood detected from {src_ip}")

        # Track unique ports for Port Scanning detection
        if 'S' in flags:  # Only track SYN packets
            port_scan_count[src_ip].add(dst_port)
            if len(port_scan_count[src_ip]) > port_scan_threshold:
                traffic_type = 'Port Scanning'
                logging.warning(f"Port Scanning detected from {src_ip}")

        # Check for other attack signatures (like SYN Flood or Port Scanning)
        for signature in attack_signatures:
            if signature['protocol'] == 'TCP' and flags == signature['flags']:
                traffic_type = signature['attack_name']
                break

        # Log the traffic (Normal or Attack)
        traffic_data = pd.DataFrame([[src_ip, src_port, dst_ip, dst_port, traffic_type, timestamp]],
                                    columns=traffic_log_columns)
        traffic_log = pd.concat([traffic_log, traffic_data], ignore_index=True)

        # Print and log the traffic
        logging.info(f"Traffic logged: {traffic_data}")
        print(f"Traffic logged: {traffic_data}")

def save_traffic_log():
    """
    Saves the traffic log (both normal and attack traffic) to a CSV file.
    """
    if not traffic_log.empty:
        # Ensure the traffic log is saved even if it's only normal traffic
        traffic_log.to_csv('C:/Users/EFAC/PycharmProjects/NIDS/logs/traffic_log.csv', mode='a',
                           header=not os.path.exists('logs/traffic_log.csv'), index=False)
        print("Traffic log saved to logs/traffic_log.csv")
    else:
        print("No traffic data to save.")

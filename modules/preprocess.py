import pandas as pd
from scapy.layers.inet import TCP, UDP, IP, ICMP
import os
import math
from collections import Counter

# Initialize an empty DataFrame to store extracted features
columns = ['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol',
          'Packet Size', 'Flags', 'Sequence Number', 'Acknowledgment Number', 'Payload Data',
          'Timestamp', 'Payload Length', 'Payload Entropy', 'Byte Frequency Total',
          'Byte Frequency Entropy', 'Source IP (original)', 'Destination IP (original)']
packet_features = pd.DataFrame(columns=columns)


def calculate_entropy(data):
    """
    Calculate the Shannon entropy of the payload data.
    """
    if not data:
        return 0
    byte_freqs = Counter(data)
    total_bytes = len(data)
    entropy = 0
    for count in byte_freqs.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)
    return entropy


def extract_features(packet):
    """
    Extracts key features from a packet (TCP, UDP, ICMP) and adds them to the DataFrame.
    """
    global packet_features  # Declare the global variable

    # Check for IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)  # Total size of the packet (bytes)
        timestamp = packet.time  # Timestamp when the packet was captured
        protocol = None
        src_port = None
        dst_port = None
        flags = None
        seq_num = None
        ack_num = None
        payload_data = packet[IP].payload.load if hasattr(packet[IP].payload, 'load') else None
        payload_length = len(payload_data) if payload_data else 0
        payload_entropy = calculate_entropy(payload_data) if payload_data else 0
        if payload_data:
            byte_frequencies = dict(Counter(payload_data))  # Calculate byte frequencies
            byte_frequency_total = sum(byte_frequencies.values())  # Total count of all bytes
            byte_frequency_entropy = calculate_entropy(list(byte_frequencies.values()))  # Entropy of frequencies
        else:
            byte_frequencies = {}
            byte_frequency_total = 0
            byte_frequency_entropy = 0

        # Check for TCP
        if packet.haslayer(TCP):
            protocol = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet.sprintf("%TCP.flags%")  # TCP flags
            seq_num = packet[TCP].seq  # Sequence number
            ack_num = packet[TCP].ack  # Acknowledgment number

        # Check for UDP
        elif packet.haslayer(UDP):
            protocol = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Check for ICMP
        elif packet.haslayer(ICMP):
            protocol = 'ICMP'
            src_port = None  # ICMP does not use ports
            dst_port = None

        # Create DataFrame for the extracted features
        packet_data = pd.DataFrame([[src_ip, src_port, dst_ip, dst_port, protocol, packet_size, flags,
                                     seq_num, ack_num, payload_data, timestamp, payload_length,
                                     payload_entropy, byte_frequency_total, byte_frequency_entropy, src_ip, dst_ip]],
                                   columns=packet_features.columns)

        # Add default values for missing features
        required_columns =[
                               'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol',
                               'Packet Size', 'Flags', 'Sequence Number', 'Acknowledgment Number', 'Payload Data',
                               'Timestamp', 'Payload Length', 'Payload Entropy', 'Byte Frequency Total',
                               'Byte Frequency Entropy', 'Source IP (original)', 'Destination IP (original)']
        for col in required_columns:
            if col not in packet_data.columns:
                packet_data[col] = 0  # Default placeholder value

        # Align columns to match the training dataset
        packet_data = packet_data[required_columns]

        # Check if packet_data has valid entries
        if not packet_data.empty:
            packet_features = pd.concat([packet_features, packet_data], ignore_index=True)

            # Debugging: Print the extracted features to console
            print(
                f"Extracted Features: {src_ip} -> {dst_ip}, Protocol: {protocol}, Size: {packet_size}, Payload Length: {payload_length}, Entropy: {payload_entropy}")
            print(packet_features.head())
            print(f"Payload Data: {payload_data}")

    return packet_data


def save_extracted_features_to_csv(data, filename='logs/extracted_features.csv'):
    """
    Saves a DataFrame of extracted features to a CSV file.
    Appends new entries without overwriting the file.
    """
    if data.empty:
        print("Warning: No features to save. DataFrame is empty.")
        return
    file_exists = os.path.isfile(filename)
    data.to_csv(filename, mode='a', header=not file_exists, index=False)
    print(f"Extracted features saved to {filename}")

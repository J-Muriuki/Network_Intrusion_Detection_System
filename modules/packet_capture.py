import os
import json
import logging
import numpy as np
import pandas as pd
import joblib
from scapy.all import sniff
from scapy.layers.inet import TCP, IP

from modules.detection_engine import detect_attack, save_traffic_log
from modules.preprocess import extract_features, save_extracted_features_to_csv
from modules.interfaces import get_active_interface
from logging.handlers import RotatingFileHandler

# from backend.socketio_config import socketio  # ✅ Import WebSocket properly

# Ensure the logs directory exists
log_dir = os.path.join("C:/Users/EFAC/PycharmProjects/NIDS/logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Setup rotating logging for packet logging
packet_log_handler = RotatingFileHandler(os.path.join(log_dir, 'packet_log.txt'), maxBytes=1000000, backupCount=5)
logging.basicConfig(handlers=[packet_log_handler], level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load the trained Isolation Forest model
model_path = os.path.join(log_dir, "best_isolation_forest_model.joblib")
best_model = joblib.load(model_path)
print(f"Loaded model from {model_path}")

# Load feature order and scaler
features_filepath = "C:/Users/EFAC/PycharmProjects/NIDS/logs/feature_order.json"
scaler_filepath = "C:/Users/EFAC/PycharmProjects/NIDS/logs/scaler.joblib"
with open(features_filepath, 'r') as f:
    expected_features = json.load(f)
scaler = joblib.load(scaler_filepath)


# Load saved label encoders
def load_encoders(encoders_dir):
    encoders = {}
    for file in os.listdir(encoders_dir):
        if file.endswith("_encoder.joblib"):
            column = file.replace("_encoder.joblib", "")
            encoder_path = os.path.join(encoders_dir, file)
            encoders[column] = joblib.load(encoder_path)
    return encoders


encoders_dir = "C:/Users/EFAC/PycharmProjects/NIDS/logs/encoders"
label_encoders = load_encoders(encoders_dir)
print(f"Loaded encoders: {list(label_encoders.keys())}")

# DataFrame for captured packet data
columns = ['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Flags']
packet_log_data = []  # Temporary storage for packet data
# total_packets = 0  # ✅ Initialize packet counter

# Buffer for storing extracted features before saving
feature_buffer = pd.DataFrame(columns=[
    'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol',
    'Packet Size', 'Flags', 'Sequence Number', 'Acknowledgment Number', 'Payload Data',
    'Timestamp', 'Payload Length', 'Payload Entropy', 'Byte Frequency Total',
    'Byte Frequency Entropy', 'Source IP (original)', 'Destination IP (original)'
])


def extract_features_from_packet(packet):
    global feature_buffer

    # Extract features using the preprocess module
    packet_features = extract_features(packet)

    # Validate for null values
    if packet_features.isnull().any().any():
        logging.warning(f"Null values found in columns: {packet_features.columns[packet_features.isnull().any()]}")
        return pd.DataFrame()  # Skip further processing if null values are present

    # Check if the packet already exists in the feature buffer
    if not feature_buffer.empty and any(
            feature_buffer['Sequence Number'] == packet_features['Sequence Number'].iloc[0]):
        logging.info("Duplicate packet detected. Skipping.")
        return

    if not packet_features.empty:
        # Save original IPs for logging and analysis
        if 'Source IP (original)' not in packet_features.columns:
            packet_features['Source IP (original)'] = packet_features['Source IP']
        if 'Destination IP (original)' not in packet_features.columns:
            packet_features['Destination IP (original)'] = packet_features['Destination IP']

        # Align packet_features with the schema of feature_buffer
        missing_cols = [col for col in feature_buffer.columns if col not in packet_features.columns]
        for col in missing_cols:
            packet_features[col] = np.nan  # Add missing columns

        # Drop extra columns not in the feature buffer
        extra_cols = [col for col in packet_features.columns if col not in feature_buffer.columns]
        if extra_cols:
            logging.warning(f"Extra columns detected and removed: {extra_cols}")
            packet_features = packet_features.drop(columns=extra_cols, errors='ignore')

        # Align column order
        packet_features = packet_features[feature_buffer.columns]

        # Append to the feature buffer
        feature_buffer = pd.concat([feature_buffer, packet_features], ignore_index=True)
        logging.debug(f"Current buffer size: {len(feature_buffer)}")
        print(f"Current buffer size: {len(feature_buffer)}")

        # Save buffer to CSV periodically (after 10 packets, for example)
        if len(feature_buffer) >= 2:  # Adjust threshold as needed
            save_extracted_features_to_csv(feature_buffer)
            feature_buffer = feature_buffer.iloc[0:0]  # Clear buffer

    return packet_features


def predict_anomaly(packet_features):
    try:
        # Use the saved encoders for non-numeric columns
        for column, encoder in label_encoders.items():
            if column in packet_features.columns:
                # Add support for unseen labels
                unique_labels = packet_features[column].unique()
                for label in unique_labels:
                    if label not in encoder.classes_:
                        encoder.classes_ = np.append(encoder.classes_, label)

                # Create a copy for encoded columns
                encoded_column = f'{column} (encoded)'
                packet_features[encoded_column] = encoder.transform(packet_features[column])

        # Align features to the expected order
        for col in expected_features:
            if col not in packet_features.columns:
                packet_features[col] = 0  # Default value for missing columns
        packet_features_encoded = packet_features[[col for col in expected_features if col in packet_features.columns]]

        # Scale features
        scaled_features = scaler.transform(packet_features_encoded)

        # Predict anomaly
        prediction = best_model.predict(scaled_features)
        return prediction[0]
    except Exception as e:
        logging.error(f"Prediction error: {e}")
        return None


def packet_callback(packet):
    """
    Processes each packet captured by Scapy.
    Logs TCP packet information, extracts features, and predicts anomalies.
    """
    try:
        # Debug: Print a summary of the captured packet

        print(f"Captured packet: {packet.summary()}")

        if packet.haslayer(IP) and packet.haslayer(TCP):  # Check if the packet has IP and TCP layers
            # Extract packet information
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet.sprintf("%TCP.flags%")

            # Append packet data to the list
            packet_log_data.append([src_ip, src_port, dst_ip, dst_port, flags])
            packet_log_df = pd.DataFrame(packet_log_data, columns=columns)
            save_dataframe_to_csv(packet_log_df, f'{log_dir}/packet_log.csv')

            # Log the packet information
            logging.info(f"Packet logged: {src_ip} -> {dst_ip} (Flags: {flags})")

            # Extract features from the packet
            packet_features = extract_features_from_packet(packet)
            print("Extracted features:", packet_features)  # Debugging output
            detect_attack(packet)
            save_traffic_log()

    except Exception as e:
        logging.error(f"Error processing packet: {e}")


def save_dataframe_to_csv(dataframe, filename):
    """
    Save the DataFrame to a CSV file, appending if the file already exists.
    """
    if not dataframe.empty:
        dataframe.to_csv(filename, mode='a', header=not os.path.isfile(filename), index=False)
        print(f"DataFrame saved to {filename}")


def start_sniffing(interface=None, packet_count=20):
    """
    Starts packet capture on the specified network interface or an active one if not specified.
    """
    if interface is None:
        interfaces_dict = get_active_interface()
        interfaces2 = interfaces_dict['interface']
        active_interface = interfaces2
        if active_interface is None:
            print("No active interface found.")
            logging.error("No active interface found.")
            return
    else:
        active_interface = interface

    print(f"Starting packet capture on interface: {active_interface}")
    logging.info(f"Starting packet capture on interface: {active_interface}")

    try:
        sniff(iface=active_interface, prn=packet_callback, count=packet_count, filter="ip")
    except Exception as e:
        print(f"Error: Unable to start sniffing on {active_interface}.")
        logging.error(f"Error during packet capture: {e}")


def stop_sniffing():
    return None

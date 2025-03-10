import subprocess
import logging
import os
# from modules.?packet_capture import get_active_interfaces
from modules.interfaces import get_active_interface
# Define the log directory
log_dir = 'C:/Users/EFAC/PycharmProjects/NIDS/logs'

# Ensure the logs directory exists
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_nmap_scan(target_ip=None, output_format='xml'):
    """
    Runs an Nmap scan on the specified target IP address and saves the output in the desired format.
    If no target IP is provided, prompts the user for input.
    """
    if target_ip is None:
        target_ip = get_active_interface()
    try:
        # Prompt for target IP if not provided
        if not target_ip:
            target_ip = get_active_interface()

        # Define the output file name based on the format
        output_file = os.path.join(log_dir, f'nmap_scan_results.{output_format}')

        # Create the command for Nmap
        if output_format == 'xml':
            command = ['nmap', '-sS', '-O', '-sV', '-oX', output_file, target_ip]
        elif output_format == 'txt':
            command = ['nmap', '-sS', '-O', '-sV', '-oN', output_file, target_ip]
        else:
            raise ValueError("Invalid output format. Use 'xml' or 'txt'.")

        # Log the command for debugging purposes
        logging.info(f"Running Nmap scan: {' '.join(command)}")

        # Run the Nmap command using subprocess
        subprocess.run(command, check=True)

        logging.info(f"Nmap scan completed. Results saved to {output_file}")
        print(f"Nmap scan completed. Results saved to {output_file}")
        return output_file

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Nmap scan: {e}")
        print(f"Error: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}")
        return None


if __name__ == "__main__":
    # Here we Scan
    interfaces_dict2 = get_active_interface()
    interfaces2 = interfaces_dict2['ip_addresses']
    target_ip = interfaces2
    output_format = input("Enter the output format ('xml' or 'txt'): ").lower()

    # Run the Nmap scan with the user-provided inputs
    run_nmap_scan(target_ip, output_format)

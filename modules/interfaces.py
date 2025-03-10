import wmi
import pythoncom

def get_active_interface():
    """
    Get the first active network interface with details.
    Returns:
        dict: Information about the active interface (description, connection type, IP address).
              Returns None if no active interface is found.
    """
    # Initialize WMI client
    pythoncom.CoInitialize()  # Initialize COM for WMI
    wmi_client = wmi.WMI()

    # Iterate through active network interfaces
    for nic in wmi_client.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        interface = nic.Description  # Interface description
        ip_addresses = nic.IPAddress  # List of IPs (if multiple)

        # Determine connection type
        if "Wireless LAN adapter" in interface or "Wi-Fi" in interface:
            connection_type = "Wi-Fi"
        else:
            connection_type = "Ethernet"

        # Return details of the first active interface
        return {
            "interface": interface,
            "connection_type": connection_type,
            "ip_addresses": ip_addresses[0]
        }

    # If no active interface is found, return None
    return None


# Example usage
active_interface = get_active_interface()

if active_interface:
    print(f"Interface: {active_interface['interface']}")
    print(f"Connection Type: {active_interface['connection_type']}")
    print(f"IP Addresses: {active_interface['ip_addresses']}")
else:
    print("No active interface found.")

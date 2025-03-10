import netifaces
from modules.packet_capture import start_sniffing



if __name__ == "__main__":

       # packet_count = 20
        start_sniffing(interface=None)
else:
        print("Cannot start sniffing: No active network interface detected.")

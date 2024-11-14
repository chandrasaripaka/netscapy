import argparse
import re
import datetime
from scapy.all import sniff, IP, TCP, UDP
from colorama import Fore, Style

class KeywordDetector:
    def __init__(self, interface, keywords):
        self.interface = interface
        self.keywords = keywords
        self.log_file = "keyword_log.txt"

    def log_keyword_found(self, keyword, payload, packet):
        """Create a log entry when a keyword is found."""
        with open(self.log_file, "a") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - Keyword found: {keyword}\n")
            f.write(f"Packet: {payload}\n")
            f.write(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}\n")
            f.write(f"Protocol: {packet[IP].proto}\n\n")

    def packet_callback(self, packet):
        """Callback function called for each packet received."""
        if packet.haslayer("Raw") and packet.haslayer(IP):
            try:
                payload = packet["Raw"].load.decode(errors='ignore')
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = self.get_protocol(packet)

                for keyword in self.keywords:
                    if re.search(re.escape(keyword), payload, re.IGNORECASE):
                        print(f"{Fore.GREEN}Keyword found: {keyword}{Style.RESET_ALL} - Packet: {payload}")
                        print(f"{Fore.CYAN}Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}{Style.RESET_ALL}")
                        self.log_keyword_found(keyword, payload, packet)
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def get_protocol(self, packet):
        """Determine the protocol of the packet."""
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        else:
            return "Other"

    def start_sniffing(self):
        """Start sniffing packets."""
        print(f"{Fore.BLUE}Starting sniffing on: {self.interface}{Style.RESET_ALL}")
        sniff(iface=self.interface, prn=self.packet_callback, store=0)

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="A tool to detect keywords in network traffic.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to listen on (e.g., 'wlan0').")
    parser.add_argument("-k", "--keywords", nargs='+', required=True, help="Keywords to detect (space-separated).")

    args = parser.parse_args()

    detector = KeywordDetector(args.interface, args.keywords)
    detector.start_sniffing()

if __name__ == "__main__":
    main()

import logging
from scapy.all import sniff

def capture_packets(interface, packet_buffer):
    """
    Captures network packets from the specified interface and puts them into a buffer.
    Runs in a separate thread.

    Args:
        interface (str): The network interface to capture packets from (e.g., "eth0", "en0").
        packet_buffer (deque): Thread-safe queue to store captured packets.
    """
    def packet_handler(packet):
        # Convert Scapy packet to raw bytes and append to buffer
        packet_buffer.append(bytes(packet))

    try:
        logging.info(f"Packet capture started on interface {interface}")
        sniff(iface=interface, prn=packet_handler, store=False)
    except Exception as e:
        logging.error(f"Error in capture_packets: {e}")
        print(f"Error: {e}")
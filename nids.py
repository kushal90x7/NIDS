import socket
import struct
import datetime
import logging
import threading
import time
from collections import deque
from scapy.all import sniff

# Configuration
LOG_FILE = "intrusion_detection.log"
LOG_LEVEL = logging.INFO  # You can change this to DEBUG for more detailed logging
PACKET_BUFFER_SIZE = 1000  # Size of the packet buffer
ALERT_THRESHOLD = 10     # Number of alerts within TIME_WINDOW to trigger a significant event
TIME_WINDOW = 60       # Time window in seconds for alert threshold
PORT_WHITELIST = [22, 80, 443, 53] # Example whitelist of common ports

# Initialize logging
logging.basicConfig(filename=LOG_FILE, level=LOG_LEVEL,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_local_ip():
    """
    Retrieves the non-loopback local IP address.
    Useful in environments where the exact interface may vary.
    """
    try:
        # Create a socket and connect to a known external server.
        # This doesn't send any data, it's just used to get the local address.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's public DNS server
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error as e:
        logging.error(f"Error getting local IP: {e}")
        return "127.0.0.1"  # Fallback to loopback

def analyze_packet(packet, alert_queue, local_ip):
    """
    Analyzes a single network packet for potential intrusion attempts.
    This is where your core detection logic resides.

    Args:
        packet (bytes): The raw network packet data.
        alert_queue (deque):  Thread-safe queue to store alerts.
        local_ip (str): The IP address of the system running the IDS.
    """
    try:
        # Ethernet Header (14 bytes)
        eth_header = packet[:14]
        eth_protocol = struct.unpack("!6s6sH", eth_header)[2]

        # Only process IP packets (0x0800)
        if eth_protocol == 0x0800:
            # IP Header (20 bytes minimum)
            ip_header = packet[14:34]
            ip_version, ip_header_length, ip_tos, ip_total_length, \
                ip_id, ip_frag_offset, ip_ttl, ip_protocol, \
                ip_checksum, ip_source_address, ip_destination_address = struct.unpack("!BBHHHBBHII", ip_header)

            # Convert IP addresses from binary to string format
            source_address = socket.inet_ntoa(struct.pack("!I", ip_source_address))
            destination_address = socket.inet_ntoa(struct.pack("!I", ip_destination_address))
            
            # Check if the destination is the local machine.  Do not analyze outgoing packets
            if destination_address != local_ip:

                # TCP Protocol (6)
                if ip_protocol == 6:
                    tcp_header_start = 14 + (ip_header_length >> 2) * 4
                    tcp_header = packet[tcp_header_start:tcp_header_start+20]
                    (tcp_source_port, tcp_destination_port, tcp_sequence,
                     tcp_acknowledgement, tcp_offset_reserved_flags, tcp_window,
                     tcp_checksum, tcp_urgent_pointer) = struct.unpack("!HHLLBBHH", tcp_header)
                    
                    # Check for suspicious port activity (example rule)
                    if tcp_destination_port not in PORT_WHITELIST:
                        alert_message = f"Possible intrusion: Suspicious traffic to port {tcp_destination_port} from {source_address}"
                        logging.warning(alert_message)
                        alert_queue.append((datetime.datetime.now(), alert_message))

                    # SYN Flood Detection (Example)
                    if (tcp_offset_reserved_flags & 0x02) and not (tcp_offset_reserved_flags & 0x10):  # SYN set, ACK not set
                         alert_message = f"Possible SYN flood attack from {source_address} to port {tcp_destination_port}"
                         logging.warning(alert_message)
                         alert_queue.append((datetime.datetime.now(), alert_message))
                
                # UDP Protocol (17)
                elif ip_protocol == 17:
                    udp_header_start = 14 + (ip_header_length >> 2) * 4
                    udp_header = packet[udp_header_start:udp_header_start+8]
                    (udp_source_port, udp_destination_port, udp_length, udp_checksum) = struct.unpack("!HHHH", udp_header)
                    if udp_destination_port not in PORT_WHITELIST:
                        alert_message = f"Possible intrusion: Suspicious traffic to port {udp_destination_port} from {source_address}"
                        logging.warning(alert_message)
                        alert_queue.append((datetime.datetime.now(), alert_message))
                
                #ICMP Protocol (1)
                elif ip_protocol == 1:
                    icmp_header_start = 14 + (ip_header_length >> 2) * 4
                    icmp_header = packet[icmp_header_start:icmp_header_start+4]
                    icmp_type, icmp_code, icmp_checksum = struct.unpack("!BBH", icmp_header)
                    
                    if icmp_type == 8: # Echo Request
                        alert_message = f"Possible ICMP Echo Request from {source_address}"
                        logging.warning(alert_message)
                        alert_queue.append((datetime.datetime.now(), alert_message))

    except Exception as e:
        logging.error(f"Error analyzing packet: {e}")
        # It's crucial to handle exceptions within the packet analysis
        # to prevent the entire program from crashing.  Log the error
        # and continue processing other packets.

def process_alerts(alert_queue):
    """
    Processes the alert queue, checks for excessive alerts, and logs them.
    Runs in a separate thread.

    Args:
        alert_queue (deque): Thread-safe queue containing alerts.
    """
    alert_times = deque()
    while True:
        if alert_queue:
            timestamp, message = alert_queue.popleft()
            alert_times.append(timestamp)
            logging.info(message)  # Log each individual alert

            # Remove alerts older than the time window
            while alert_times and (alert_times[0] < (timestamp - datetime.timedelta(seconds=TIME_WINDOW))):
                alert_times.popleft()

            # Check for excessive alerts within the time window
            if len(alert_times) > ALERT_THRESHOLD:
                significant_event_message = f"Possible intrusion: Excessive alerts detected ({len(alert_times)} alerts in {TIME_WINDOW} seconds)"
                logging.critical(significant_event_message)  # Log as critical
                print(significant_event_message) # Print to console as well.
        else:
            time.sleep(1)  # Sleep to reduce CPU usage, but check queue frequently

def capture_packets(interface, packet_buffer, local_ip):
    """
    Captures network packets from the specified interface and puts them into a buffer.
    Runs in a separate thread.

    Args:
        interface (str): The network interface to capture packets from (e.g., "eth0", "en0").
        packet_buffer (deque): Thread-safe queue to store captured packets.
        local_ip (str): The IP address of the system.
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

def process_packets(packet_buffer, alert_queue, local_ip):
    """
    Processes packets from the buffer.  Runs in a separate thread.

    Args:
        packet_buffer (deque): Thread-safe queue containing captured packets.
        alert_queue (deque): Thread-safe queue to store alerts.
        local_ip (str): The IP address of the system.
    """
    while True:
        if packet_buffer:
            packet = packet_buffer.popleft()
            analyze_packet(packet, alert_queue, local_ip)
        else:
            time.sleep(0.01)  # Sleep to reduce CPU usage, but check buffer frequently

def main():
    """
    Main function to start the network intrusion detection system.
    """
    # Get the network interface to capture packets from.
    interface = input("Enter the network interface to monitor (e.g., eth0, en0, wlan0): ")
    
    # Get the local IP address
    local_ip = get_local_ip()
    logging.info(f"Local IP address: {local_ip}")
    print(f"Listening on {interface} and analyzing traffic for {local_ip}")

    # Create thread-safe queues for packets and alerts
    packet_buffer = deque(maxlen=PACKET_BUFFER_SIZE)
    alert_queue = deque()

    # Create threads for packet capture, processing, and alert handling
    capture_thread = threading.Thread(target=capture_packets, args=(interface, packet_buffer, local_ip))
    process_thread = threading.Thread(target=process_packets, args=(packet_buffer, alert_queue, local_ip))
    alert_thread = threading.Thread(target=process_alerts, args=(alert_queue,))

    # Start the threads
    capture_thread.start()
    process_thread.start()
    alert_thread.start()

    # Keep the main thread alive to allow the others to continue running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Program terminated by user.")
        print("Program terminated by user.")
        # Optionally, you can add code here to gracefully stop the threads
        # (e.g., setting a flag that the threads check).  For simplicity,
        # in this example, the threads will be interrupted when the main
        # program exits.

if __name__ == "__main__":
    main()

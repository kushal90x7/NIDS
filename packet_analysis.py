import socket
import struct
import logging
import datetime

PORT_WHITELIST = [22, 80, 443, 53]  # Example whitelist of common ports

def analyze_packet(packet, alert_queue, local_ip):
    """
    Analyzes a single network packet for potential intrusion attempts.

    Args:
        packet (bytes): The raw network packet data.
        alert_queue (deque): Thread-safe queue to store alerts.
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
            
            # Check if the destination is the local machine. Do not analyze outgoing packets
            if destination_address != local_ip:
                # TCP Protocol (6)
                if ip_protocol == 6:
                    tcp_header_start = 14 + (ip_header_length >> 2) * 4
                    tcp_header = packet[tcp_header_start:tcp_header_start+20]
                    (tcp_source_port, tcp_destination_port, tcp_sequence,
                     tcp_acknowledgement, tcp_offset_reserved_flags, tcp_window,
                     tcp_checksum, tcp_urgent_pointer) = struct.unpack("!HHLLBBHH", tcp_header)
                    
                    # Check for suspicious port activity
                    if tcp_destination_port not in PORT_WHITELIST:
                        alert_message = f"Possible intrusion: Suspicious traffic to port {tcp_destination_port} from {source_address}"
                        logging.warning(alert_message)
                        alert_queue.append((datetime.datetime.now(), alert_message))

                    # SYN Flood Detection
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
                
                # ICMP Protocol (1)
                elif ip_protocol == 1:
                    icmp_header_start = 14 + (ip_header_length >> 2) * 4
                    icmp_header = packet[icmp_header_start:icmp_header_start+4]
                    icmp_type, icmp_code, icmp_checksum = struct.unpack("!BBH", icmp_header)
                    
                    if icmp_type == 8:  # Echo Request
                        alert_message = f"Possible ICMP Echo Request from {source_address}"
                        logging.warning(alert_message)
                        alert_queue.append((datetime.datetime.now(), alert_message))

    except Exception as e:
        logging.error(f"Error analyzing packet: {e}")
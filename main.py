import threading
import time
from collections import deque
from packet_capture import capture_packets
from packet_analysis import analyze_packet
from alert_logging import process_alerts
from alert_correlation import correlate_alerts

def main():
    """
    Main function to start the network intrusion detection system.
    """
    # Get the network interface to capture packets from.
    interface = input("Enter the network interface to monitor (e.g., eth0, en0, wlan0): ")
    
    # Get the local IP address
    local_ip = "127.0.0.1"  # Replace with a function to get the local IP if needed
    print(f"Listening on {interface} and analyzing traffic for {local_ip}")

    # Create thread-safe queues for packets and alerts
    packet_buffer = deque(maxlen=1000)
    alert_queue = deque()

    # Create threads for packet capture, processing, alert handling, and alert correlation
    capture_thread = threading.Thread(target=capture_packets, args=(interface, packet_buffer))
    process_thread = threading.Thread(target=process_packets, args=(packet_buffer, alert_queue, local_ip))
    alert_thread = threading.Thread(target=process_alerts, args=(alert_queue,))
    correlation_thread = threading.Thread(target=correlate_alerts, args=(alert_queue,))

    # Start the threads
    capture_thread.start()
    process_thread.start()
    alert_thread.start()
    correlation_thread.start()

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Program terminated by user.")

def process_packets(packet_buffer, alert_queue, local_ip):
    """
    Processes packets from the buffer. Runs in a separate thread.

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
            time.sleep(0.01)

if __name__ == "__main__":
    main()
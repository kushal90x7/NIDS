import logging
import datetime
from collections import defaultdict
import time

def correlate_alerts(alert_queue, correlation_window=300):
    """
    Correlates alerts to identify patterns of suspicious activity.
    Runs in a separate thread.

    Args:
        alert_queue (deque): Thread-safe queue containing alerts.
        correlation_window (int): Time window in seconds for correlating alerts.
    """
    correlated_alerts = defaultdict(list)  # Dictionary to store alerts by source IP
    while True:
        if alert_queue:
            timestamp, message = alert_queue.popleft()
            logging.info(f"Processing alert for correlation: {message}")

            # Extract source IP from the alert message (assuming a consistent format)
            source_ip = extract_source_ip(message)
            if source_ip:
                correlated_alerts[source_ip].append((timestamp, message))

                # Remove alerts older than the correlation window
                correlated_alerts[source_ip] = [
                    (ts, msg) for ts, msg in correlated_alerts[source_ip]
                    if ts >= (timestamp - datetime.timedelta(seconds=correlation_window))
                ]

                # Check for patterns (e.g., multiple alerts from the same source IP)
                if len(correlated_alerts[source_ip]) > 5:  # Example threshold
                    pattern_message = f"Correlated alert: Multiple suspicious activities detected from {source_ip} within {correlation_window} seconds."
                    logging.critical(pattern_message)
                    print(pattern_message)
        else:
            time.sleep(1)  # Sleep to reduce CPU usage

def extract_source_ip(message):
    """
    Extracts the source IP address from an alert message.

    Args:
        message (str): The alert message.

    Returns:
        str: The extracted source IP address, or None if not found.
    """
    try:
        # Assuming the message contains "from <source_ip>"
        if "from" in message:
            parts = message.split("from")
            if len(parts) > 1:
                return parts[1].strip().split()[0]
    except Exception as e:
        logging.error(f"Error extracting source IP: {e}")
    return None
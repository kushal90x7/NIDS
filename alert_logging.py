import logging
import datetime
import time
from collections import deque

ALERT_THRESHOLD = 10
TIME_WINDOW = 60

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
                logging.critical(significant_event_message)
                print(significant_event_message)
        else:
            time.sleep(1)  # Sleep to reduce CPU usage
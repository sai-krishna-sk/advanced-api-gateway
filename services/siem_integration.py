import os
import requests

def send_to_siem(event):
    try:
        siem_endpoint = os.getenv("SIEM_ENDPOINT", "http://siem.example.com/events")
        headers = {
            'Content-Type': 'application/json',
            # Optionally add authorization headers for Splunk HEC or similar
        }
        response = requests.post(siem_endpoint, json=event, headers=headers)
        print("Event sent to SIEM system, status code:", response.status_code)
    except Exception as e:
        print("Error sending event to SIEM:", e)


import email
import re
import time
import dns.resolver
import requests
import threading
import logging
from email import policy
from email.parser import BytesParser

from vt_api_key import VT_API_KEY  # Import your VirusTotal API Key
from nessus_api_key import NESSUS_API_KEY, NESSUS_URL  # Import your Nessus API credentials

VT_URL = "https://www.virustotal.com/api/v3/urls"
NESSUS_SCAN_URL = f"{NESSUS_URL}/scans"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def extract_headers(email_path):
    """Extracts headers from the email file."""
    try:
        with open(email_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return msg
    except Exception as e:
        logging.error(f"Error reading email file: {e}")
        return None

# Nessus Integration
def scan_url_nessus(url):
    """Submits a phishing URL to Nessus for scanning."""
    headers = {
        "X-ApiKeys": f"accessKey={NESSUS_API_KEY}"  # Add your Nessus authentication
    }
    data = {
        "url": url
    }
    try:
        response = requests.post(NESSUS_SCAN_URL, headers=headers, json=data)
        if response.status_code == 200:
            scan_id = response.json().get("scan_id")
            return f"Nessus Scan Initiated: {scan_id}"
        return f"Error initiating Nessus scan: {response.text}"
    except requests.RequestException as e:
        return f"Nessus Request Failed: {e}"

# SIEM Log Forwarding
def forward_to_siem(log_data):
    """Sends phishing detection logs to SIEM (e.g., Splunk, QRadar, ELK)."""
    siem_url = "http://siem-server/logs"  # Replace with actual SIEM endpoint
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(siem_url, headers=headers, json=log_data)
        if response.status_code == 200:
            return "Log successfully forwarded to SIEM"
        return "Failed to send log to SIEM"
    except requests.RequestException as e:
        return f"SIEM Log Forwarding Failed: {e}"

def extract_urls(email_body):
    """Extracts URLs from the email body."""
    return re.findall(r'(https?://[\w./-]+)', email_body)

def analyze_email(email_path):
    """Main function to analyze an email."""
    msg = extract_headers(email_path)
    if not msg:
        logging.error("Invalid email file. Exiting.")
        return

    sender = msg.get("From", "Unknown")
    domain = sender.split('@')[-1] if '@' in sender else "Unknown"

    logging.info(f"Sender: {sender}")
    
    email_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                try:
                    email_body += part.get_payload(decode=True).decode(errors="ignore")
                except Exception as e:
                    logging.warning(f"Error decoding email part: {e}")
    else:
        email_body = msg.get_payload(decode=True).decode(errors="ignore")

    urls = extract_urls(email_body)
    if urls:
        logging.info("Extracted URLs:")
        threads = []
        results = {}

        def process_url(url):
            nessus_scan = scan_url_nessus(url)
            log_data = {"url": url, "nessus_scan_result": nessus_scan}
            siem_result = forward_to_siem(log_data)
            results[url] = {"nessus_scan": nessus_scan, "siem_log": siem_result}

        for url in urls:
            logging.info(f"Checking URL: {url}")
            thread = threading.Thread(target=process_url, args=(url,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        for url, result in results.items():
            logging.info(f"URL: {url}\nNessus Scan: {result['nessus_scan']}\nSIEM Log: {result['siem_log']}")
    else:
        logging.info("No URLs found in the email.")

if __name__ == "__main__":
    email_file = input("Enter path to email file (.eml): ")
    analyze_email(email_file)
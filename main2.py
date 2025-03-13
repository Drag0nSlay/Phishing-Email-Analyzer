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

VT_URL = "https://www.virustotal.com/api/v3/urls"

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

def check_spf(domain):
    """Checks SPF record for the sender's domain."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for txt_record in answers:
            if "spf1" in txt_record.to_text():
                return txt_record.to_text()
        return "No SPF record found"
    except Exception as e:
        return f"SPF Check Failed: {e}"

def check_dkim(email_headers):
    """Checks for DKIM signature in headers."""
    return email_headers.get("DKIM-Signature", "No DKIM Signature Found")

def check_dmarc(domain):
    """Checks DMARC record for the sender's domain."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for txt_record in answers:
            return txt_record.to_text()
        return "No DMARC record found"
    except Exception as e:
        return f"DMARC Check Failed: {e}"

def check_url_malicious(url):
    """Submits a URL to VirusTotal and retrieves the scan result."""
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}

    try:
        response = requests.post(VT_URL, headers=headers, data=data)
        if response.status_code == 200:
            result = response.json()
            analysis_id = result.get("data", {}).get("id")

            if analysis_id:
                time.sleep(15)  # Wait for VirusTotal to process
                basic_report = get_vt_report(analysis_id)
                detailed_report = get_vt_analysis_details(analysis_id)
                return {"basic_report": basic_report, "detailed_report": detailed_report}

        return "Error Checking URL"
    except requests.RequestException as e:
        return f"VirusTotal Request Failed: {e}"

def get_vt_report(analysis_id):
    """Fetches the basic VirusTotal scan report."""
    headers = {"x-apikey": VT_API_KEY}
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    try:
        response = requests.get(report_url, headers=headers)
        if response.status_code == 200:
            report_data = response.json().get("data", {}).get("attributes", {})
            stats = report_data.get("stats", {})
            scan_results = report_data.get("results", {})

            formatted_results = "\n--- Basic VirusTotal Analysis ---\n"
            formatted_results += f"✓ Harmless: {stats.get('harmless', 0)}\n"
            formatted_results += f"✗ Malicious: {stats.get('malicious', 0)}\n"
            formatted_results += f"! Suspicious: {stats.get('suspicious', 0)}\n"
            formatted_results += f"⚠ Undetected: {stats.get('undetected', 0)}\n\n"

            formatted_results += ">>> Scan Engine Results:\n"
            for engine, details in scan_results.items():
                formatted_results += f"[{engine}] → {details.get('category', 'Unknown')}\n"

            return formatted_results

        return "Error Retrieving Basic VirusTotal Report"
    except requests.RequestException as e:
        return f"Error Fetching Basic VirusTotal Report: {e}"

def get_vt_analysis_details(analysis_id):
    """Fetches detailed analysis results for a submitted URL."""
    headers = {"x-apikey": VT_API_KEY}
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    
    report_response = requests.get(report_url, headers=headers)
    if report_response.status_code == 200:
        report_data = report_response.json()
        attributes = report_data.get("data", {}).get("attributes", {})

        return {
            "status": attributes.get("status", "Unknown"),
            "malicious_count": attributes.get("stats", {}).get("malicious", 0),
            "total_scanners": sum(attributes.get("stats", {}).values()),
            "last_analysis": attributes.get("date", "N/A"),
            "categories": attributes.get("tags", [])
        }
    return "Error Retrieving Detailed Analysis"

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
    logging.info(f"SPF Record: {check_spf(domain)}")
    logging.info(f"DKIM: {check_dkim(msg)}")
    logging.info(f"DMARC: {check_dmarc(domain)}")

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
            result = check_url_malicious(url)
            results[url] = result

        for url in urls:
            logging.info(f"Checking URL: {url}")
            thread = threading.Thread(target=process_url, args=(url,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        for url, result in results.items():
            logging.info(f"URL: {url}\n{result['basic_report']}")
            logging.info(f"Detailed Analysis: {result['detailed_report']}")
    else:
        logging.info("No URLs found in the email.")

if __name__ == "__main__":
    email_file = input("Enter path to email file (.eml): ")
    analyze_email(email_file)

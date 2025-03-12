import email
import re
import time
import dns.resolver
import requests
from email import policy
from email.parser import BytesParser

# Import VirusTotal API key from external file
from vt_api_key import VT_API_KEY

VT_URL = "https://www.virustotal.com/api/v3/urls"

def extract_headers(email_path):
    """Extracts headers from the email file."""
    with open(email_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

def check_spf(domain):
    """Checks SPF record for the sender's domain."""
    try:
        answers = dns.resolver.resolve(f"{domain}", 'TXT')
        for txt_record in answers:
            if "spf1" in txt_record.to_text():
                return txt_record.to_text()
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
    except Exception as e:
        return f"DMARC Check Failed: {e}"

def check_url_malicious(url):
    """Submits a URL to VirusTotal and retrieves the scan result."""
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}

    # Submit URL for scanning
    response = requests.post(VT_URL, headers=headers, data=data)
    
    if response.status_code == 200:
        result = response.json()
        analysis_id = result.get("data", {}).get("id")

        if analysis_id:
            time.sleep(15)  # Wait for VirusTotal to process the URL
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report_response = requests.get(report_url, headers=headers)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                return report_data.get("data", {}).get("attributes", {}).get("stats", {})
    
    return "Error Checking URL"


def extract_urls(email_body):
    """Extracts URLs from the email body."""
    urls = re.findall(r'(https?://[\w./-]+)', email_body)
    return urls

def analyze_email(email_path):
    """Main function to analyze an email."""
    msg = extract_headers(email_path)
    sender = msg.get("From")
    domain = sender.split('@')[-1] if '@' in sender else "Unknown"
    print(f"Sender: {sender}")
    print(f"SPF Record: {check_spf(domain)}")
    print(f"DKIM: {check_dkim(msg)}")
    print(f"DMARC: {check_dmarc(domain)}")
    
    print("\nExtracting URLs...")
    email_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" or part.get_content_type() == "text/html":
                try:
                    email_body += part.get_payload(decode=True).decode(errors="ignore")
                except Exception:
                    pass
    else:
        email_body = msg.get_payload(decode=True).decode(errors="ignore")
    
    urls = extract_urls(email_body)
    if urls:
        for url in urls:
            print(f"Checking URL: {url}")
            print(check_url_malicious(url))
    else:
        print("No URLs found in the email.")
    
if __name__ == "__main__":
    email_file = input("Enter path to email file (.eml): ")
    analyze_email(email_file)

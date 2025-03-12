# Swift Incident Response: Strategies for Effective Defense - Phishing Email Analyzer

## Overview
Swift Incident Response: Strategies for Effective Defense is a cybersecurity project developed under the **Experimental Project-Based Learning (EPBL) initiative by SmartBridge**. It focuses on detecting and analyzing phishing emails to enhance incident response capabilities.

## Project Description
Phishing Email Analyzer is a Python-based tool that extracts and analyzes email headers, checks SPF/DKIM/DMARC records, and verifies URLs using VirusTotal to detect phishing attempts. A sample phishing email (`test_sample_message.eml`) is included for testing and better experience.

## Features
- Extract sender details from email headers
- Validate SPF, DKIM, and DMARC authentication
- Identify and analyze suspicious URLs
- Integrate VirusTotal API for threat intelligence

## Installation
```bash
pip install dnspython requests
```

## Setup
1. **Create a file** `vt_api_key.py` and add:
```python
VT_API_KEY = "your_virustotal_api_key"
```
2. **Download the sample phishing email:**
   - [Sample Email (.eml)](https://www.phpclasses.org/browse/file/14672.html)
3. **Run the script:**
```bash
python main.py
```

## Usage
- Enter the path to an `.eml` file when prompted.
- The script will analyze the email and report potential phishing indicators.

## License
MIT License

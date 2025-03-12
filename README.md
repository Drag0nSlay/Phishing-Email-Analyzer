# Phishing Email Analyzer

## Overview
Phishing Email Analyzer is a Python-based tool that extracts and analyzes email headers, checks SPF/DKIM/DMARC records, and verifies URLs using VirusTotal to detect phishing attempts. The project offers both **CLI-based** and **GUI-based** versions for user flexibility.

## Features
- Extract sender details from email headers
- Validate SPF, DKIM, and DMARC authentication
- Identify and analyze suspicious URLs
- Integrate VirusTotal API for threat intelligence
- **CLI and GUI versions available**

## Installation
```bash
pip install dnspython requests tkinter
```

## Setup
1. **Create a file** `vt_api_key.py` and add:
```python
VT_API_KEY = "your_virustotal_api_key"
```
2. **Download the sample phishing email:**
   - [Sample Email (.eml)](https://www.phpclasses.org/browse/file/14672.html)
3. **Run the CLI version:**
```bash
python cli/main.py
```
4. **Run the GUI version:**
```bash
python gui/main.py
```

## Project Structure
```
Phishing_Email_Analyzer/
│── cli/       # CLI-based version
│   ├── main.py
│── gui/       # GUI-based version
│   ├── main.py
│── vt_api_key.py  # API Key (ignored in Git)
│── .gitignore  # Ignore credentials and unnecessary files
│── README.md
```

## .gitignore (Add these to avoid exposing sensitive files)
```
vt_api_key.py
__pycache__/
*.log
*.env
```

## License
MIT License

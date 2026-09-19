# Python Security Log Analyzer

A Python-based security log analysis tool that detects failed login attempts, identifies suspicious IP addresses, detects brute-force activity, and assigns security risk levels.

## Features

- Detects failed login attempts
- Counts failed attempts per IP address
- Identifies private and public IP addresses
- Detects rapid repeated login failures
- Generates brute-force alerts
- Assigns risk levels: LOW, MEDIUM, HIGH
- Makes security decisions: ALLOW, INVESTIGATE, BLOCK
- Generates a security report

## How It Works

1. Reads security logs from `security.log`
2. Detects failed login attempts
3. Extracts the source IP address
4. Counts failed attempts for each IP
5. Checks whether the IP is private or public
6. Detects rapid repeated failures
7. Assigns a risk level
8. Generates a security decision
9. Creates `security_report.txt` with the analysis results

## Project Structure

```text
SECURITY/
│
├── main.py
├── security.log
├── security_report.txt
├── README.md
└── .gitignore

## Technologies Used

- Python
- Python `ipaddress` module
- Python `datetime` module
- File handling
- VS Code

## Usage

1. Place security logs in `security.log`
2. Run the analyzer:

```bash
python main.py

## Example Output

```text
========== SECURITY REPORT ==========

Most Failed IP: 192.168.1.20
Failed Attempts: 5
Total Failed Attempts: 8
Brute-Force Alerts: 4

Suspicious IPs:
192.168.1.20 -> 4 brute-force alerts

IP ANALYSIS:

192.168.1.20
    Status: PRIVATE
    Failed Attempts: 5
    Risk: HIGH
    Decision: BLOCK

BLOCKED IPS:
192.168.1.20 -> BLOCKED

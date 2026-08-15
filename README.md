# Log Analysis & Threat Detection Tool

A Python-based security tool that parses authentication log files to identify malicious activities such as brute-force password guessing, credential stuffing, probing of sensitive administrative accounts (e.g., `root`, `admin`), and success-after-failure anomalies (compromise risks).

---

## Features

- **Regular Expression Parser**: Parses common server log entries extracting timestamp, source IP, auth status, username, and log details.
- **Brute Force Detection**: Scans and identifies IPs exceeding a configurable number of failed attempts within a defined sliding time window (e.g., 5 failures in 60s).
- **Probing Detection**: Alerts when sensitive usernames (`root`, `admin`, `administrator`, `guest`) are targeted.
- **Compromise Risk Indicators**: Raises a critical flag if a successful login occurs from an IP that has previously generated multiple failures.
- **Structured Visual Report**: Groups alerts by severity:
  - **CRITICAL**: Successful logins after brute force failures.
  - **HIGH**: Threshold-crossing brute force attempts.
  - **MEDIUM**: Sensitive account probing.
- **Sample Simulator**: Automatically ships with a `sample.log` simulating normal and attack logs to test the tool immediately.

---

## Installation

Ensure you have **Python 3.8+** installed. No external dependencies are needed.

1. Clone this repository:
   ```bash
   git clone https://github.com/kalpana5438/log_analyzer.git
   cd log_analyzer
   ```

2. Run the application:
   ```bash
   python main.py
   ```

---

## Technical Alert Thresholds

- **USER_PROBING (Medium)**: Triggered whenever a login is attempted on accounts like `root`, `admin`, `administrator`, or `guest`.
- **BRUTE_FORCE (High)**: Triggered when an IP fails $N$ times (default: 5) within a window of $T$ seconds (default: 60).
- **COMPROMISE_RISK (Critical)**: Triggered when an IP has a status of `SUCCESS` after generating 3 or more failed login attempts.

---

## Usage Example

### Running a scan on the demo `sample.log`:
```text
=================================================================
                 LOG ANALYSIS & THREAT DETECTION                 
=================================================================
Current Log File: E:\KALPANA\Projects\log_analyzer\sample.log
-----------------------------------------------------------------
1. Scan log file for brute-force attacks and anomalies
2. Change target log file path
3. Exit

Select an option (1-3): 1
Enter failure threshold for brute force (default 5): 5
Enter sliding window time in seconds (default 60): 60

Parsing and analyzing logs...

=================================================================
                    LOG FILE ANALYSIS REPORT                    
=================================================================
Total Log Lines:      18
Successfully Parsed:  18
Successful Logins:    6
Failed Logins:        12
Unique IP Addresses:  5
-----------------------------------------------------------------

Security Alerts Detected (3):
-----------------------------------------------------------------
[MEDIUM]   IP: 198.51.100.12   2026-08-15 10:05:12
  IP probed sensitive account: 'root'
-----------------------------------------------------------------
[HIGH]     IP: 203.0.113.45    2026-08-15 10:15:20
  Potential Brute Force: 8 failed logins within 60 seconds
-----------------------------------------------------------------
[CRITICAL] IP: 198.51.100.50   2026-08-15 10:20:15
  SUCCESSFUL login after 3 failed attempts (Possible Compromise)
-----------------------------------------------------------------
=================================================================
```

---

## License

This project is open-source and licensed under the [MIT License](LICENSE).

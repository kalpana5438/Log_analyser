import re
from collections import defaultdict
from datetime import datetime

class LogAnalyzer:
    # Pattern matching: [timestamp] IP STATUS username details
    # E.g., [2026-08-15 12:01:22] 192.168.1.105 FAILED admin Incorrect password
    LOG_PATTERN = r"^\[(?P<timestamp>[^\]]+)\]\s+(?P<ip>[^\s]+)\s+(?P<status>SUCCESS|FAILED)\s+(?P<username>[^\s]+)(?:\s+(?P<details>.*))?$"

    def __init__(self, log_filepath: str):
        self.log_filepath = log_filepath
        self.failed_attempts_by_ip = defaultdict(list) # IP -> list of timestamps
        self.successful_logins_by_ip = defaultdict(list)
        self.root_probing_ips = set()
        self.alerts = []
        self.stats = {
            "total_lines": 0,
            "parsed_lines": 0,
            "failed_count": 0,
            "success_count": 0,
            "unique_ips": set()
        }

    def parse_timestamp(self, ts_str: str) -> datetime:
        try:
            return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            # Fallback if other timestamp format
            return datetime.now()

    def run_analysis(self, brute_force_threshold: int = 5, window_seconds: int = 60) -> dict:
        self.alerts = []
        self.stats["total_lines"] = 0
        self.stats["parsed_lines"] = 0
        self.stats["failed_count"] = 0
        self.stats["success_count"] = 0
        self.stats["unique_ips"] = set()
        self.failed_attempts_by_ip.clear()
        self.successful_logins_by_ip.clear()
        self.root_probing_ips.clear()

        with open(self.log_filepath, "r") as f:
            for line in f:
                self.stats["total_lines"] += 1
                match = re.match(self.LOG_PATTERN, line.strip())
                if not match:
                    continue

                self.stats["parsed_lines"] += 1
                data = match.groupdict()
                ip = data["ip"]
                status = data["status"]
                username = data["username"]
                timestamp = self.parse_timestamp(data["timestamp"])

                self.stats["unique_ips"].add(ip)

                if status == "FAILED":
                    self.stats["failed_count"] += 1
                    self.failed_attempts_by_ip[ip].append(timestamp)
                    
                    # Alert: Probe of sensitive username (e.g. root, admin)
                    if username.lower() in ("root", "admin", "administrator", "guest"):
                        self.root_probing_ips.add(ip)
                        self.alerts.append({
                            "type": "USER_PROBING",
                            "severity": "MEDIUM",
                            "ip": ip,
                            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                            "message": f"IP probed sensitive account: '{username}'"
                        })
                else:
                    self.stats["success_count"] += 1
                    self.successful_logins_by_ip[ip].append(timestamp)

        # Detect Brute Force Attacks
        # Check if an IP has >= threshold failures within window_seconds
        for ip, attempts in self.failed_attempts_by_ip.items():
            attempts.sort()
            # Sliding window check
            for i in range(len(attempts)):
                window_start = attempts[i]
                count = 0
                for j in range(i, len(attempts)):
                    if (attempts[j] - window_start).total_seconds() <= window_seconds:
                        count += 1
                    else:
                        break
                
                if count >= brute_force_threshold:
                    self.alerts.append({
                        "type": "BRUTE_FORCE",
                        "severity": "HIGH",
                        "ip": ip,
                        "timestamp": window_start.strftime("%Y-%m-%d %H:%M:%S"),
                        "message": f"Potential Brute Force: {count} failed logins within {window_seconds} seconds"
                    })
                    break # Trigger once per IP to avoid alert fatigue

        # Detect Potential Compromise (Success after failed logins)
        for ip, successes in self.successful_logins_by_ip.items():
            failures = self.failed_attempts_by_ip.get(ip, [])
            if failures:
                for success_time in successes:
                    # Count failures before this success
                    failures_before = [f for f in failures if f < success_time]
                    if len(failures_before) >= 3:
                        self.alerts.append({
                            "type": "COMPROMISE_RISK",
                            "severity": "CRITICAL",
                            "ip": ip,
                            "timestamp": success_time.strftime("%Y-%m-%d %H:%M:%S"),
                            "message": f"SUCCESSFUL login after {len(failures_before)} failed attempts (Possible Compromise)"
                        })

        # Remove duplicate alerts and sort by timestamp
        # Converting dictionary representations to tuples for unique set filtering
        seen = set()
        unique_alerts = []
        for alert in self.alerts:
            identifier = (alert["type"], alert["ip"], alert["message"])
            if identifier not in seen:
                seen.add(identifier)
                unique_alerts.append(alert)
                
        unique_alerts.sort(key=lambda x: x["timestamp"])

        return {
            "stats": {
                "total_lines": self.stats["total_lines"],
                "parsed_lines": self.stats["parsed_lines"],
                "failed_count": self.stats["failed_count"],
                "success_count": self.stats["success_count"],
                "unique_ips_count": len(self.stats["unique_ips"])
            },
            "alerts": unique_alerts
        }

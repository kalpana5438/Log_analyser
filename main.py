import os
import sys
from analyzer import LogAnalyzer

# ANSI escape codes for coloring terminal output
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"

def print_header(title):
    print(f"\n{CYAN}{BOLD}{'=' * 65}")
    print(f" {title.center(63)}")
    print(f"{'=' * 65}{RESET}")

def get_severity_color(severity: str) -> str:
    if severity == "CRITICAL":
        return f"\033[1;41;97m" # White on Red Bold
    elif severity == "HIGH":
        return RED
    elif severity == "MEDIUM":
        return YELLOW
    return GREEN

def display_results(res: dict):
    stats = res["stats"]
    alerts = res["alerts"]
    
    print_header("LOG FILE ANALYSIS REPORT")
    print(f"{BOLD}Total Log Lines:{RESET}      {stats['total_lines']}")
    print(f"{BOLD}Successfully Parsed:{RESET}  {stats['parsed_lines']}")
    print(f"{BOLD}Successful Logins:{RESET}    {GREEN}{stats['success_count']}{RESET}")
    print(f"{BOLD}Failed Logins:{RESET}        {RED}{stats['failed_count']}{RESET}")
    print(f"{BOLD}Unique IP Addresses:{RESET}  {stats['unique_ips_count']}")
    print("-" * 65)

    if alerts:
        print(f"\n{RED}{BOLD}Security Alerts Detected ({len(alerts)}):{RESET}")
        print("-" * 65)
        for alert in alerts:
            color = get_severity_color(alert["severity"])
            severity_tag = f"[{alert['severity']}]"
            print(f"{color}{BOLD}{severity_tag:<10}{RESET} {BOLD}IP:{RESET} {alert['ip']:<15} {alert['timestamp']}")
            print(f"  {alert['message']}")
            print("-" * 65)
    else:
        print(f"\n{GREEN}{BOLD}✓ Scan OK: No security alerts or brute force indicators detected.{RESET}")

    print(f"\n{CYAN}{BOLD}{'=' * 65}{RESET}")

def main():
    # Enable ANSI terminal colors on Windows if supported
    if sys.platform == "win32":
        try:
            import colorama
            colorama.init()
        except ImportError:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

    log_file = "sample.log"

    while True:
        print_header("LOG ANALYSIS & THREAT DETECTION")
        print(f"{BOLD}Current Log File:{RESET} {os.path.abspath(log_file)}")
        print("-" * 65)
        print("1. Scan log file for brute-force attacks and anomalies")
        print("2. Change target log file path")
        print("3. Exit")
        
        choice = input(f"\n{BOLD}Select an option (1-3): {RESET}").strip()
        
        if choice == "1":
            try:
                threshold_str = input(f"\nEnter failure threshold for brute force (default 5): {RESET}").strip()
                threshold = int(threshold_str) if threshold_str else 5
                
                window_str = input(f"Enter sliding window time in seconds (default 60): {RESET}").strip()
                window = int(window_str) if window_str else 60
            except ValueError:
                print(f"{RED}Invalid input, using defaults.{RESET}")
                threshold = 5
                window = 60

            if not os.path.exists(log_file):
                print(f"{RED}Error: Log file '{log_file}' does not exist!{RESET}")
                continue

            print(f"\nParsing and analyzing logs...")
            try:
                analyzer = LogAnalyzer(log_file)
                results = analyzer.run_analysis(threshold, window)
                display_results(results)
            except Exception as e:
                print(f"{RED}Analysis failed: {e}{RESET}")
                
        elif choice == "2":
            new_path = input(f"\nEnter target log file path: {RESET}").strip()
            if os.path.exists(new_path) and os.path.isfile(new_path):
                log_file = new_path
                print(f"{GREEN}Log file updated to: {os.path.abspath(log_file)}{RESET}")
            else:
                print(f"{RED}File does not exist or is not a valid file!{RESET}")
                
        elif choice == "3":
            print(f"\n{CYAN}Exiting Log Analyzer. Keep logs clean!{RESET}\n")
            break
        else:
            print(f"{RED}Invalid option, please choose 1, 2, or 3.{RESET}")

if __name__ == "__main__":
    main()

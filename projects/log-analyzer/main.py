import os
import re
import argparse
from colorama import Fore, Style, init
init(autoreset=True)
from collections import defaultdict

# ---------------- ARGPARSE ----------------
parser = argparse.ArgumentParser(description="Log Analyzer - Failed Login Detection")
parser.add_argument("logfile", help="Path to auth.log file")
parser.add_argument("--threshold", type=int, default=5, help="Threshold for suspicious IPs")
args = parser.parse_args()

# ---------------- REGEX ----------------
FAILED_LOGIN_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?Failed password for (?:invalid user )?(?P<username>\w+)"
    r" from (?P<ip>[\d.]+)"
)

# ---------------- CORE FUNCTIONS ----------------
def parse_line(line: str):
    match = FAILED_LOGIN_PATTERN.search(line)
    return match.groupdict() if match else None


def read_log_file(filepath: str):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


# ---------------- STEP 2: COUNT FAILED ATTEMPTS ----------------
def count_failed_attempts(lines):
    ip_counts = defaultdict(int)

    for line in lines:
        parsed = parse_line(line)
        if parsed:
            ip = parsed["ip"]
            ip_counts[ip] += 1

    return ip_counts


# ---------------- TOP 3 IPs (CHALLENGE) ----------------
def print_top_ips(ip_counts):
    print("\nTop 3 Attacking IPs:")

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:3]

    for ip, count in top_ips:
        print(f"{ip} -> {count} attempts")


# ---------------- EXISTING ADVANCED AGGREGATION ----------------
def aggregate_failed_logins(lines):
    results = defaultdict(lambda: {"count": 0, "usernames": set(), "timestamps": []})

    for line in lines:
        parsed = parse_line(line)
        if parsed:
            ip = parsed["ip"]
            results[ip]["count"] += 1
            results[ip]["usernames"].add(parsed["username"])
            results[ip]["timestamps"].append(parsed["timestamp"])

    return dict(results)


def print_summary(results, threshold):
    print("\n" + "=" * 50)
    print("  FAILED LOGIN SUMMARY")
    print("=" * 50)

    if not results:
        print("No failed login attempts detected.")
        return

    sorted_ips = sorted(results.items(), key=lambda x: x[1]["count"], reverse=True)
    print(f"\nThreshold set to: {threshold}\n")

    for ip, data in sorted_ips:
        count = data["count"]
        severity = get_severity(count)
        color = get_color(severity)

        is_suspicious = count >= threshold
        flag = "⚠ SUSPICIOUS" if is_suspicious else ""

        print(color + f"\n[{severity}] IP {ip} — {count} attempts {flag}" + Style.RESET_ALL)
        usernames = ", ".join(data["usernames"])
        print(f"Users tried : {usernames}")
        print(f"First seen  : {data['timestamps'][0]}")
        print(f"Last seen   : {data['timestamps'][-1]}")

def get_severity(count):
    if count >= 10:
        return "HIGH"
    elif count >= 4:
        return "MEDIUM"
    else:
        return "LOW"

def get_color(severity):
    if severity == "HIGH":
        return Fore.RED
    elif severity == "MEDIUM":
        return Fore.YELLOW
    else:
        return Fore.GREEN

# ---------------- MAIN ----------------
if __name__ == "__main__":
    lines = read_log_file(args.logfile)

    print(f"Loaded {len(lines)} log lines")

    # STEP 2 execution
    ip_counts = count_failed_attempts(lines)
    print_top_ips(ip_counts)

    # existing summary
    results = aggregate_failed_logins(lines)
    print_summary(results, args.threshold)


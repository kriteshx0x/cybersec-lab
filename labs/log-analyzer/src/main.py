import os
import re
import argparse
import csv
import json
from datetime import datetime
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

# ---------------- ARGPARSE ----------------
parser = argparse.ArgumentParser(description="Log Analyzer - Failed Login Detection")

parser.add_argument("logfile", help="Path to auth.log file")

parser.add_argument(
    "--threshold",
    type=int,
    default=5,
    help="Threshold for suspicious IPs"
)

parser.add_argument(
    "--output",
    choices=["csv", "json"],
    help="Export format (csv or json)"
)

parser.add_argument(
    "--output-file",
    help="Custom output filename"
)

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


# ---------------- COUNT FAILED ATTEMPTS ----------------
def count_failed_attempts(lines):
    ip_counts = defaultdict(int)

    for line in lines:
        parsed = parse_line(line)
        if parsed:
            ip_counts[parsed["ip"]] += 1

    return ip_counts


# ---------------- TOP 3 IPs ----------------
def print_top_ips(ip_counts):
    print("\nTop 3 Attacking IPs:")
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:3]

    for ip, count in top_ips:
        print(f"{ip} -> {count} attempts")


# ---------------- AGGREGATION ----------------
def aggregate_failed_logins(lines):
    results = defaultdict(lambda: {"count": 0, "usernames": set(), "timestamps": []})

    for line in lines:
        parsed = parse_line(line)
        if parsed:
            ip = parsed["ip"]
            results[ip]["count"] += 1
            results[ip]["usernames"].add(parsed["username"])
            results[ip]["timestamps"].append(parsed["timestamp"])

    # sort timestamps
    for ip in results:
        results[ip]["timestamps"].sort()

    return dict(results)


# ---------------- SEVERITY ----------------
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


# ---------------- SUMMARY ----------------
def print_summary(results, threshold):
    print("\n" + "=" * 50)
    print("  FAILED LOGIN SUMMARY")
    print("=" * 50)

    if not results:
        print("No failed login attempts detected.")
        return

    severity_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

    sorted_ips = sorted(
        results.items(),
        key=lambda x: (
            severity_rank[get_severity(x[1]["count"])],
            x[1]["count"]
        ),
        reverse=True
    )

    print(f"\nThreshold set to: {threshold}\n")

    for ip, data in sorted_ips:
        count = data["count"]
        severity = get_severity(count)
        color = get_color(severity)

        flag = "⚠ SUSPICIOUS" if count >= threshold else ""

        print(color + f"\n[{severity}] IP {ip} — {count} attempts {flag}" + Style.RESET_ALL)

        usernames = ", ".join(data["usernames"])
        print(f"Users tried : {usernames}")
        print(f"First seen  : {data['timestamps'][0]}")
        print(f"Last seen   : {data['timestamps'][-1]}")


# ---------------- PREPARE EXPORT DATA ----------------
def prepare_export_data(results, threshold):
    export_data = []

    for ip, data in results.items():
        count = data["count"]

        if count < threshold:
            continue

        export_data.append({
            "ip": ip,
            "count": count,
            "severity": get_severity(count),
            "first_seen": data["timestamps"][0],
            "last_seen": data["timestamps"][-1]
        })

    return export_data


# ---------------- EXPORT ----------------
def export_results(data, fmt, filename):
    if not data:
        print("No data to export.")
        return

    os.makedirs("output", exist_ok=True)

    # filename handling
    if filename:
        filename = f"output/{filename}.{fmt}"
    else:
        filename = f"output/results.{fmt}"

    if fmt == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["ip", "count", "severity", "first_seen", "last_seen"]
            )
            writer.writeheader()
            writer.writerows(data)

    elif fmt == "json":
        output = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_flagged": len(data),
            "flagged_ips": data
        }

        with open(filename, "w") as f:
            json.dump(output, f, indent=4)

    print(f"\n[+] Exported results → {filename}")


# ---------------- MAIN ----------------
if __name__ == "__main__":
    lines = read_log_file(args.logfile)

    print(f"Loaded {len(lines)} log lines")

    ip_counts = count_failed_attempts(lines)
    print_top_ips(ip_counts)

    results = aggregate_failed_logins(lines)
    print_summary(results, args.threshold)

    if args.output:
        export_data = prepare_export_data(results, args.threshold)
        export_results(export_data, args.output, args.output_file)


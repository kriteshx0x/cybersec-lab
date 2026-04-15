import sys
import os
import re

FAILED_LOGIN_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?Failed password for (?:invalid user )?(?P<username>\w+)"
    r" from (?P<ip>[\d.]+)"
)

def parse_line(line: str) -> dict | None:
    match = FAILED_LOGIN_PATTERN.search(line)
    if match:
        return match.groupdict()
    return None

def read_log_file(filepath: str) -> list[str]:
    """
    Opens and reads a log file line by line.

    Args:
        filepath: Absolute or relative path to the .log file.

    Returns:
        List of raw log lines as strings.

    Raises:
        FileNotFoundError: If the path does not exist.
        PermissionError: If the file cannot be read.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    return [line.strip() for line in lines if line.strip()]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <path_to_logfile>")
        sys.exit(1)

    log_path = sys.argv[1]
    lines = read_log_file(log_path)
    print(f"Loaded {len(lines)} log lines from {log_path}")

failed_attempts = []

for line in lines:
    result = parse_line(line)
    if result:
        failed_attempts.append(result)

print(f"Found {len(failed_attempts)} failed login attempts\n")

for attempt in failed_attempts[:10]:  # show first 10
    print(attempt)


from collections import defaultdict


def aggregate_failed_logins(lines: list[str]) -> dict:
    """
    Parses all log lines and aggregates failed logins by IP address.

    Args:
        lines: List of raw log line strings.

    Returns:
        Dict structure:
        {
            "192.168.1.101": {
                "count": 3,
                "usernames": {"admin", "root"},
                "timestamps": ["May 10 08:12:01", ...]
            }
        }
    """
    results = defaultdict(lambda: {"count": 0, "usernames": set(), "timestamps": []})

    for line in lines:
        parsed = parse_line(line)
        if parsed:
            ip = parsed["ip"]
            results[ip]["count"] += 1
            results[ip]["usernames"].add(parsed["username"])
            results[ip]["timestamps"].append(parsed["timestamp"])

    return dict(results)

def print_summary(results: dict, threshold: int = 3) -> None:
    """
    Prints a formatted summary of failed login attempts by IP.

    Args:
        results: Aggregated dict from aggregate_failed_logins().
        threshold: Flag IPs with >= this many attempts (default 3).
    """
    print("\n" + "="*50)
    print("  FAILED LOGIN SUMMARY")
    print("="*50)

    if not results:
        print("  No failed login attempts detected.")
        return

    sorted_ips = sorted(results.items(), key=lambda x: x[1]["count"], reverse=True)

    for ip, data in sorted_ips:
        flag = " ⚠ SUSPICIOUS" if data["count"] >= threshold else ""
        usernames = ", ".join(data["usernames"])
        first_seen = data["timestamps"][0]
        last_seen = data["timestamps"][-1]

        print(f"\n  IP {ip} — {data['count']} failed attempt(s){flag}")
        print(f"  Users tried : {usernames}")
        print(f"  First seen  : {first_seen}")
        print(f"  Last seen   : {last_seen}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <path_to_logfile>")
        sys.exit(1)

    log_path = sys.argv[1]
    lines = read_log_file(log_path)
    results = aggregate_failed_logins(lines)
    print_summary(results)



import sys
import os


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


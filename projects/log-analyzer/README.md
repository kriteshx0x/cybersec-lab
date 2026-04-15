# log-analyzer

A Python tool that parses Linux authentication logs (auth.log) to detect suspicious activity.

## What it does
- Reads a .log file passed as CLI argument
- Uses regex to extract: timestamp, username, IP address
- Aggregates failed login attempts per IP
- Prints a formatted threat summary

## Usage
    python3 main.py /path/to/auth.log

## Dependencies
    pip install -r requirements.txt

import os
import re
import ipaddress
from datetime import datetime
from collections import Counter

# Regex pattern for Apache logs (Common Log Format with status + size)
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+)'
)

def parse_log_line(line):
    """
    Parse a single log line into a dictionary of fields.
    
    Returns None if the line is invalid.
    """
    match = LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()

    # Validate IP
    try:
        ipaddress.ip_address(data["ip"])
    except ValueError:
        return None

    # Parse timestamp
    try:
        data["timestamp"] = datetime.strptime(
            data["timestamp"], "%d/%b/%Y:%H:%M:%S"
        )
    except ValueError:
        return None

    # Convert numeric fields
    data["status"] = int(data["status"])
    data["size"] = int(data["size"])

    return data

def parse_log_lines(lines):
    """
    Parse a list of log lines into structured dictionaries.
    """
    entries = []
    for line in lines:
        parsed = parse_log_line(line)
        if parsed:
            entries.append(parsed)
    return entries

def log_reader(log_relative_path="sample_logs/access.log"):
    """
    Reads a log file and returns parsed lines as a list of dictionaries.
    """
    # Step 1: Determine the project root directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Step 2: Combine base directory with relative path
    log_path = os.path.join(base_dir, log_relative_path)

    # Step 3: Check if the file exists
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"Log file not found at: {log_path}")

    # Step 4: Read and parse the file line by line
    with open(log_path, "r") as file:
        lines = [line.strip() for line in file]

    return parse_log_lines(lines)


# ----------------------------
# Analysis Functions
# ----------------------------

def count_requests_by_ip(logs):
    """Count number of requests per IP address."""
    ip_counts = Counter()
    for entry in logs:
        ip_counts[entry["ip"]] += 1
    return ip_counts

def count_requests_by_endpoint(logs):
    """Count number of requests per endpoint (URL)."""
    endpoint_counts = Counter()
    for entry in logs:
        endpoint_counts[entry["endpoint"]] += 1
    return endpoint_counts

def count_status_codes(logs):
    """Count occurrences of HTTP status codes."""
    status_counts = Counter()
    for entry in logs:
        status_counts[entry["status"]] += 1
    return status_counts

def detect_failed_logins(logs):
    """
    Detect repeated failed logins (status 401 or 403).
    Returns a dictionary of IP -> failed login count.
    """
    failed = Counter()
    for entry in logs:
        if entry["status"] in (401, 403):
            failed[entry["ip"]] += 1
    return failed

def detect_sensitive_access(logs, sensitive_endpoints=None):
    """
    Detect access to sensitive endpoints (/admin, /config, /.env, etc.)
    Returns a dictionary of IP -> sensitive access count.
    """
    if sensitive_endpoints is None:
        sensitive_endpoints = ["/admin", "/config", "/.env"]

    sensitive = Counter()
    for entry in logs:
        if any(entry["endpoint"].startswith(e) for e in sensitive_endpoints):
            sensitive[entry["ip"]] += 1
    return sensitive

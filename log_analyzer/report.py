import csv
import os
from .utils import ensure_dir


def save_csv(data, headers, filename, folder="reports"):
    """
    Saves a list of dictionaries to a CSV file.
    
    Args:
        data (list): List of dicts to save.
        headers (list): List of column headers for CSV.
        filename (str): Name of the CSV file.
        folder (str): Folder to save the CSV into (default: 'reports').
    """
    # Ensure the folder exists
    os.makedirs(folder, exist_ok=True)
    
    file_path = os.path.join(folder, filename)
    
    with open(file_path, mode="w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        for row in data:
            writer.writerow(row)

    print(f"Report saved: {file_path}")


# ===========================
# Specific report functions
# ===========================

def report_top_ips(ip_counter, filename="top_ips.csv", top_n=20):
    """Generates a CSV of top IP addresses"""
    top = ip_counter.most_common(top_n)
    data = [{"IP": ip, "Requests": count} for ip, count in top]
    save_csv(data, headers=["IP", "Requests"], filename=filename)


def report_top_endpoints(endpoint_counter, filename="top_endpoints.csv", top_n=20):
    """Generates a CSV of top requested endpoints"""
    top = endpoint_counter.most_common(top_n)
    data = [{"Endpoint": ep, "Requests": count} for ep, count in top]
    save_csv(data, headers=["Endpoint", "Requests"], filename=filename)


def report_status_codes(status_counter, filename="status_codes.csv"):
    """Generates a CSV summarizing status codes"""
    data = [{"Status": status, "Count": count} for status, count in status_counter.items()]
    save_csv(data, headers=["Status", "Count"], filename=filename)


def report_suspicious_ips(failed_login_counter, sensitive_access_counter, filename="suspicious_ips.csv"):
    """
    Generates a CSV combining failed logins and sensitive endpoint access.
    Columns: IP, FailedLogins, SensitiveAccessCount
    """
    data = []
    ips = set(failed_login_counter.keys()) | set(sensitive_access_counter.keys())
    for ip in ips:
        failed_count = failed_login_counter.get(ip, 0)
        sensitive_count = sensitive_access_counter.get(ip, 0)
        data.append({
            "IP": ip,
            "FailedLogins": failed_count,
            "SensitiveAccessCount": sensitive_count
        })
    
    save_csv(data, headers=["IP", "FailedLogins", "SensitiveAccessCount"], filename=filename)

# log_analyzer/utils.py
import os

def ensure_dir(path):
    """Ensure a folder exists; create it if it doesn't."""
    os.makedirs(path, exist_ok=True)

def safe_int(value, default=0):
    """Convert a value to int, return default if invalid."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

def is_sensitive_endpoint(endpoint):
    """Check if the endpoint is considered sensitive."""
    sensitive_endpoints = ["/admin", "/config", "/.env"]
    return endpoint in sensitive_endpoints

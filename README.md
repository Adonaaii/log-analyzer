# log-analyzer
# Log Analyzer

A Python tool to analyze Apache access logs. It parses log files, validates entries, identifies suspicious activity, and generates CSV reports.

## Features

- Parse Apache log files.
- Validate IP addresses and timestamps.
- Analyze traffic by IP and endpoint.
- Summarize HTTP status codes.
- Detect repeated failed logins (401/403).
- Identify access to sensitive endpoints (/admin, /config, /.env).
- Process large logs in chunks concurrently.
- Generate CSV reports:
  - `top_ips.csv`
  - `top_endpoints.csv`
  - `status_codes.csv`
  - `suspicious_ips.csv`

## Project Structure

log-analyzer/
├── log_analyzer/
│ ├── init.py
│ ├── analyzer.py
│ ├── report.py
│ ├── utils.py
│ └── chunks.py
├── reports/ # Generated CSV reports
├── sample_logs/ # Example log files
│ └── access.log
├── tests/
│ └── test_analyzer.py
├── main.py
├── requirements.txt
└── README.md
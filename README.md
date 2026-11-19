# Apache Log Analyzer

Python modules for reviewing Apache-style access logs. The parser validates IP addresses and timestamps, and the reporting helpers export traffic summaries and suspicious activity to CSV.

## Try the parser

Run the following from the repository root with Python 3.12. The example uses a documentation-range IP address.

```python
from log_analyzer.analyzer import parse_log_lines, count_status_codes

logs = parse_log_lines([
    '192.0.2.10 - - [10/Oct/2026:13:55:36] "GET /admin HTTP/1.1" 401 256',
])
print(dict(count_status_codes(logs)))
```

Expected output: `{401: 1}`.

- [Parser and analysis](log_analyzer/analyzer.py) count requests by IP, endpoint and status code, and flag 401/403 responses and sensitive paths.
- [CSV reports](log_analyzer/report.py) provide helpers for exporting the summaries.
- [Chunk processing](log_analyzer/chunks.py) contains helpers for splitting log processing into batches.

The parser expects timestamps without a timezone suffix. Treat HTTP status and path matches as investigation signals.

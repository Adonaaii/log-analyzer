from concurrent.futures import ThreadPoolExecutor
from log_analyzer.analyzer import parse_log_lines
import os
def read_log_in_chunks(file_path, chunk_size=1000):
    """
    Generator that reads a log file in chunks of lines.
    
    Args:
        file_path (str): Path to the log file.
        chunk_size (int): Number of lines per chunk.
    
    Yields:
        list: A chunk of lines from the log file.
    """
    with open(file_path, "r") as f:
        chunk = []
        for line in f:
            chunk.append(line.strip())
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk
def process_log_concurrently(file_path, chunk_size=1000, max_workers=4):
    """
    Processes a large log file in chunks concurrently.
    
    Args:
        file_path (str): Path to the log file.
        chunk_size (int): Number of lines per chunk.
        max_workers (int): Number of concurrent workers.
    
    Returns:
        list: All parsed log entries.
    """
    all_entries = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for chunk in read_log_in_chunks(file_path, chunk_size):
            futures.append(executor.submit(parse_log_lines, chunk))
        
        for future in futures:
            all_entries.extend(future.result())
    
    return all_entries
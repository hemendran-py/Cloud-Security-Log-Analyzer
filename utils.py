import re
from datetime import datetime

def parse_log_line(line):
    """
    Parse a single line from auth.log and extract relevant information.

    Args:
        line (str): A line from the log file.

    Returns:
        dict: A dictionary with keys 'timestamp', 'ip', 'status', 'user' if available.
              Returns None if the line doesn't match expected format.
    """
    # Regex pattern for auth.log entries
    # Example: "Jan  1 00:00:00 hostname sshd[123]: Failed password for root from 192.168.1.1 port 22 ssh2"
    pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+\w+\[\d+\]:\s+(Failed password|Accepted password|Invalid user)\s+for\s+(\w+)\s+from\s+(\d+\.\d+\.\d+\.\d+)'
    match = re.match(pattern, line)
    if match:
        month_day_time, status, user, ip = match.groups()
        # Convert timestamp to datetime (assuming current year)
        timestamp_str = f"{datetime.now().year} {month_day_time}"
        timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        return {
            'timestamp': timestamp,
            'ip': ip,
            'status': 'fail' if 'Failed' in status or 'Invalid' in status else 'success',
            'user': user
        }
    return None
from datetime import datetime, timedelta
from collections import defaultdict

class SecurityAnalyzer:
    def __init__(self):
        # Track failed login attempts per IP: IP -> list of timestamps
        self.failed_attempts = defaultdict(list)
        # Track all requests per IP: IP -> list of timestamps
        self.all_requests = defaultdict(list)

    def process_log_entry(self, entry):
        """
        Process a parsed log entry and check for security events.

        Args:
            entry (dict): Parsed log entry with 'timestamp', 'ip', 'status'.

        Returns:
            list: List of alert messages if any events detected.
        """
        alerts = []
        ip = entry['ip']
        timestamp = entry['timestamp']

        # Add to all requests
        self.all_requests[ip].append(timestamp)

        if entry['status'] == 'fail':
            # Add to failed attempts
            self.failed_attempts[ip].append(timestamp)

            # Check for brute-force: >5 failed in 2 minutes
            recent_fails = [t for t in self.failed_attempts[ip] if timestamp - t <= timedelta(minutes=2)]
            if len(recent_fails) > 5:
                alerts.append(f"[ALERT] Possible brute-force attack from {ip}: {len(recent_fails)} failed attempts in 2 minutes")

        # Check for abnormal behavior: >20 requests in 5 minutes
        recent_requests = [t for t in self.all_requests[ip] if timestamp - t <= timedelta(minutes=5)]
        if len(recent_requests) > 20:
            alerts.append(f"[ALERT] Abnormal IP behavior from {ip}: {len(recent_requests)} requests in 5 minutes")

        # Clean up old entries to prevent memory issues (optional)
        self._cleanup_old_entries(ip, timestamp)

        return alerts

    def _cleanup_old_entries(self, ip, current_time):
        """Remove entries older than 10 minutes to save memory."""
        cutoff = current_time - timedelta(minutes=10)
        self.failed_attempts[ip] = [t for t in self.failed_attempts[ip] if t > cutoff]
        self.all_requests[ip] = [t for t in self.all_requests[ip] if t > cutoff]
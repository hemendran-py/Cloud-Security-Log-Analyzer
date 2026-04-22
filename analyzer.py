#!/usr/bin/env python3
"""
Security Log Analyzer - Main script for analyzing auth.log files for security events.
"""

from utils import parse_log_line
from rules import SecurityAnalyzer

def main():
    # Path to the log file
    log_file = 'logs/auth.log'
    alerts_file = 'alerts.txt'

    # Initialize the analyzer
    analyzer = SecurityAnalyzer()

    # List to collect all alerts
    all_alerts = []

    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = parse_log_line(line)
                if entry:
                    alerts = analyzer.process_log_entry(entry)
                    for alert in alerts:
                        print(alert)
                        all_alerts.append(alert)
                else:
                    # Optionally log unparsed lines
                    pass

        # Save alerts to file
        with open(alerts_file, 'w') as f:
            for alert in all_alerts:
                f.write(alert + '\n')

        print(f"\nAnalysis complete. {len(all_alerts)} alerts generated and saved to {alerts_file}")

    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
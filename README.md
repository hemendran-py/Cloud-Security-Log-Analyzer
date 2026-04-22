# Security Log Analyzer



A Python-based cybersecurity tool for analyzing Linux authentication logs (`auth.log`) to detect potential security threats such as brute-force attacks and abnormal IP behavior using rule-based detection.

## 🚀 Features

- **Log Parsing**: Parses `auth.log` style entries using regular expressions
- **Data Extraction**: Extracts timestamps, IP addresses, and login statuses
- **Security Detection**:
  - Brute-force attacks: >5 failed login attempts from same IP within 2 minutes
  - Abnormal IP behavior: >20 requests from same IP within 5 minutes
- **Alert Generation**: Generates SOC-style alerts
- **Output Options**: Prints alerts to console and saves to file
- **Modular Design**: Clean, readable code with separate modules for parsing, rules, and analysis

## 📁 Project Structure

```
security-log-analyzer/
├── analyzer.py          # Main script
├── rules.py            # Detection logic and SecurityAnalyzer class
├── utils.py            # Log parsing utilities
├── logs/
│   └── auth.log        # Sample log file
├── requirements.txt    # Dependencies
├── alerts.txt          # Generated alerts output
└── README.md           # This file
```

## 🚀 Usage

1. Place your `auth.log` file in the `logs/` directory, or modify the path in `analyzer.py`

2. Run the analyzer:

   ```bash
   python analyzer.py
   ```

3. View alerts in console and check `alerts.txt` for saved results

## 📊 Sample Output

```
[ALERT] Possible brute-force attack from 192.168.1.100: 7 failed attempts in 2 minutes
[ALERT] Abnormal IP behavior from 192.168.1.200: 31 requests in 5 minutes

Analysis complete. 39 alerts generated and saved to alerts.txt
```

## 🔍 How It Works

### 1. Log Parsing (`utils.py`)

The `parse_log_line()` function uses regex to extract:

- Timestamp (converted to datetime)
- IP address
- Login status (success/fail)
- Username

### 2. Detection Rules (`rules.py`)

The `SecurityAnalyzer` class tracks:

- Failed attempts per IP with timestamps
- All requests per IP with timestamps

**Brute-force Detection**:

- Counts failed logins within 2-minute windows
- Triggers alert when >5 failures detected

**Abnormal Behavior Detection**:

- Counts total requests within 5-minute windows
- Triggers alert when >20 requests detected

### 3. Alert Generation (`analyzer.py`)

- Processes each log entry
- Applies detection rules
- Generates formatted alerts
- Outputs to console and file

## ⚙️ Customization

### Adjusting Detection Thresholds

Modify values in `rules.py`:

```python
# Change brute-force threshold
if len(recent_fails) > 3:  # Instead of 5

# Change abnormal behavior threshold
if len(recent_requests) > 10:  # Instead of 20
```

### Supporting Different Log Formats

Update regex pattern in `utils.py`:

```python
pattern = r'your_custom_regex_here'
```

### Adding New Detection Rules

Extend `SecurityAnalyzer` class in `rules.py`:

```python
def check_new_rule(self, entry):
    # Your detection logic here
    pass
```

## 📝 Sample Log File

The included `logs/auth.log` contains:

- ✅ Normal successful logins
- 🚨 Simulated brute-force attacks (multiple failures from same IP)
- 🚨 Abnormal traffic patterns (high request volume)

Run the analyzer on this file to see detection in action!

## 🔒 Security Notes

- **Educational Purpose**: This is a basic rule-based analyzer for learning
- **Production Use**: Consider integrating with SIEM systems for real deployments
- **Log Formats**: Real logs may vary; adjust parsing for your environment
- **No Actions Taken**: This tool only analyzes and alerts, doesn't block or respond
- **Privacy**: Ensure compliance with data handling policies when analyzing logs

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

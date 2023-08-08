import re

# List of keywords that might indicate suspicious activity
suspicious_keywords = ['error', 'warning', 'unauthorized', 'denied']

def analyze_log_file(file_path):
    suspicious_lines = []

    with open(file_path, 'r') as log_file:
        for line_number, line in enumerate(log_file, start=1):
            line = line.strip()
            for keyword in suspicious_keywords:
                if re.search(r'\b' + re.escape(keyword) + r'\b', line, re.IGNORECASE):
                    suspicious_lines.append((line_number, line))

    return suspicious_lines
# Replace "path/to/logfile.log" with the name of log file that will be analyzed. 
if __name__ == "__main__":
    log_file_path = "path/to/logfile.log"
    suspicious_lines = analyze_log_file(log_file_path)

    if suspicious_lines:
        print("Suspicious lines found:")
        for line_number, line in suspicious_lines:
            print(f"Line {line_number}: {line}")
    else:
        print("No suspicious activity found in the log file.")
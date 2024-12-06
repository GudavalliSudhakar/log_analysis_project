import re
import csv
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as log_file:
        for line in log_file:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            endpoint_match = re.search(r'"[A-Z]+ (/[^\s]*)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            if "401" in line or "Invalid credentials" in line:
                if ip_match:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def save_to_csv(ip_requests, most_accessed, suspicious_ips, output_file="log_analysis_results.csv"):
    with open(output_file, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        if most_accessed:
            writer.writerow([most_accessed[0], most_accessed[1]])

        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    file_path = "sample.log"
    ip_requests, endpoint_requests, failed_logins = parse_log_file(file_path)

    print("Requests per IP Address:")
    for ip, count in ip_requests.items():
        print(f"{ip}: {count}")

    most_accessed = max(endpoint_requests.items(), key=lambda x: x[1], default=None)
    if most_accessed:
        print(f"\nMost Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    if suspicious_ips:
        print("\nSuspicious Activity Detected:")
        for ip, count in suspicious_ips.items():
            print(f"{ip}: {count}")

    save_to_csv(ip_requests, most_accessed, suspicious_ips)

if __name__ == "__main__":
    main()

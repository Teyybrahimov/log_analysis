import re
import json
import csv
from collections import defaultdict

# Log faylın oxunması
log_file = "webserver.log"  # Log faylın adı

# Regex ifadələri
timestamp_pattern = r"\[(.*?)\]"  # Tarixlərə uyğun regex
ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # IP ünvanlarına uyğun regex
http_method_pattern = r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS)\b"  # HTTP metodları

# Uğursuz cəhd sayıların saxlanması üçün dictionary
failed_attempts = defaultdict(int)
log_entries = []

# Log faylı oxunur
with open(log_file, "r") as file:
    for line in file:
        ip_match = re.search(ip_pattern, line)
        timestamp_match = re.search(timestamp_pattern, line)
        method_match = re.search(http_method_pattern, line)

        if ip_match and timestamp_match and method_match:
            ip = ip_match.group()
            timestamp = timestamp_match.group(1)
            method = method_match.group()

            # Log qeydlərini siyahıda saxlayırıq
            log_entries.append({"ip": ip, "timestamp": timestamp, "method": method})

            # Uğursuz giriş cəhdi təyin olunur (məsələn: 401 status koduna çıxanlar)
            if "401" in line:  # Mətn daxilində 401 status kodunu yoxlayırıq
                failed_attempts[ip] += 1

# 5-dən çox uğursuz giriş olan IP-lərən saxlanması
failed_ips = {ip: count for ip, count in failed_attempts.items() if count > 5}
with open("failed_ips.json", "w") as json_file:
    json.dump(failed_ips, json_file, indent=4)

# IP-ləri və uğursuz cəhd saylarını yeni mətn faylına yazırıq
with open("failed_ips.txt", "w") as text_file:
    for ip, count in failed_ips.items():
        text_file.write(f"{ip}: {count}\n")

# CSV faylı yaradılır
with open("log_analysis.csv", "w", newline="") as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["IP Address", "Date", "HTTP Method", "Failed Attempts"])
    for entry in log_entries:
        ip = entry["ip"]
        timestamp = entry["timestamp"]
        method = entry["method"]
        failed_count = failed_attempts[ip]
        csv_writer.writerow([ip, timestamp, method, failed_count])

print("Analiz tamamlandı. Nəticə fayllara yazıldı.")

import csv
import random
import os

os.makedirs("logs", exist_ok=True)

def generate_logs(file="logs/connection_log.csv", num_entries=100):
    fieldnames = ["ip", "username", "num_requests", "avg_interval", "filename_entropy", "is_fake_session"]
    rows = []

    for i in range(num_entries):
        is_attacker = i >= num_entries // 2 

        ip = f"127.0.0.{i+1}" if is_attacker else f"192.168.1.{i+1}"
        username = random.choice(["alice", "bob", "guest", "admin", "root", "test"])
        if is_attacker:
            num_requests = random.randint(10, 20)
            avg_interval = round(random.uniform(0.2, 0.9), 2)
            entropy = round(random.uniform(6.0, 8.5), 2)
        else:
            num_requests = random.randint(2, 5)
            avg_interval = round(random.uniform(3.5, 6.0), 2)
            entropy = round(random.uniform(2.5, 4.5), 2)

        rows.append({
            "ip": ip,
            "username": username,
            "num_requests": num_requests,
            "avg_interval": avg_interval,
            "filename_entropy": entropy,
            "is_fake_session": int(is_attacker)
        })

    with open(file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {num_entries} synthetic logs to {file}")

if __name__ == "__main__":
    generate_logs()

import re
import sqlite3
import requests
from collections import defaultdict

log_file = "logs.txt"

failed_logins = defaultdict(int)
ip_count = defaultdict(int)

def geolocate_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "org": data.get("org")
        }
    except:
        return None

# Conectar a base de datos
conn = sqlite3.connect("logs.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    ip TEXT,
    status TEXT,
    raw TEXT
)
""")

print("Analizando logs...\n")

with open(log_file, "r") as file:
    for line in file:
        line = line.strip()
        if not line:
            continue

        ip = line.split(" ")[0]
        ip_count[ip] += 1

        cursor.execute(
            "INSERT INTO logs (ip, status, raw) VALUES (?, ?, ?)",
            (ip, "401" if "401" in line else "200", line)
        )

        if "401" in line:
            failed_logins[ip] += 1

        if re.search(r"('|--|OR 1=1)", line, re.IGNORECASE):
            print(f"[CRITICAL] Posible SQL Injection detectado desde IP: {ip}")

conn.commit()
conn.close()
print("Logs guardados en logs.db\n")

print("\nAnalisis de fuerza bruta:")
for ip, count in failed_logins.items():
    if count >= 5:
        print(f"[ALERTA] Posible ataque de fuerza bruta desde {ip} ({count} intentos fallidos)")

print("\nIPs sospechosas:")
for ip in failed_logins:
    if failed_logins[ip] >= 5:
        print(ip)
        info = geolocate_ip(ip)
        if info:
            print(f"IP {ip} -> {info['city']}, {info['country']} ({info['org']})")

print("\nIPs mas activas:")
for ip, count in ip_count.items():
    print(f"{ip} -> {count} peticiones")

conn = sqlite3.connect("logs.db")
cursor = conn.cursor()

cursor.execute("""
SELECT ip, COUNT(*) 
FROM logs 
WHERE status='401'
GROUP BY ip
HAVING COUNT(*) > 3
""")

print("\nIPs con mas de 3 errores 401 (desde DB):")
print(cursor.fetchall())

conn.close()

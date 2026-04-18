# main.py
import re
import sqlite3
import requests
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler

log_file = "logs.txt"
db_file = "logs.db"

def init_db():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            ip TEXT,
            status TEXT,
            raw TEXT
        )
    """)
    conn.commit()
    return conn

def save_logs_to_db(lines):
    conn = init_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    for line in lines:
        ip = line.split(" ")[0]
        parts = line.split('"')
        status = parts[2].strip().split(" ")[0] if len(parts) > 2 else "???"
        cursor.execute("INSERT INTO logs (ip, status, raw) VALUES (?, ?, ?)", (ip, status, line))
    conn.commit()
    conn.close()

def get_db_records():
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT ip, status, raw FROM logs")
        rows = cursor.fetchall()
        conn.close()
        return rows
    except:
        return []

def get_401_attackers():
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, COUNT(*) 
            FROM logs 
            WHERE status='401'
            GROUP BY ip
            HAVING COUNT(*) > 3
        """)
        rows = cursor.fetchall()
        conn.close()
        return rows
    except:
        return []

def geolocate_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "org": data.get("org")
        }
    except:
        return None

def analyze_logs():
    failed_logins = defaultdict(int)
    ip_count = defaultdict(int)
    sql_injections = []
    brute_force = []
    lines = []

    try:
        with open(log_file, "r") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                lines.append(line)
                ip = line.split(" ")[0]
                ip_count[ip] += 1

                if "401" in line:
                    failed_logins[ip] += 1

                if re.search(r"('|--|OR 1=1)", line, re.IGNORECASE):
                    sql_injections.append(ip)
    except FileNotFoundError:
        return None, None, None, None, None

    suspicious_ips = []
    for ip, count in failed_logins.items():
        if count >= 5:
            brute_force.append((ip, count))
            suspicious_ips.append(ip)

    save_logs_to_db(lines)
    return lines, dict(ip_count), sql_injections, brute_force, suspicious_ips

def build_html():
    lines, ip_count, sql_injections, brute_force, suspicious_ips = analyze_logs()

    if lines is None:
        return "<p>logs.txt no encontrado.</p>"

    logs_html = "\n".join(f'<div class="log-line">{line}</div>' for line in lines)

    sql_html = "".join(
        f'<div class="alert critical">&#9888; SQL Injection detectado desde <strong>{ip}</strong></div>'
        for ip in sql_injections
    ) or '<div class="ok">Sin detecciones.</div>'

    bf_html = "".join(
        f'<div class="alert warning">&#128680; Fuerza bruta desde <strong>{ip}</strong> ({count} intentos fallidos)</div>'
        for ip, count in brute_force
    ) or '<div class="ok">Sin detecciones.</div>'

    def suspicious_entry(ip):
        geo = geolocate_ip(ip)
        geo_str = ""
        if geo:
            geo_str = f' <span class="geo">&#127760; {geo["country"]} | {geo["city"]} | {geo["org"]}</span>'
        return f'<div class="alert warning">&#9888; <strong>{ip}</strong>{geo_str}</div>'

    suspicious_html = "".join(
        suspicious_entry(ip) for ip in suspicious_ips
    ) or '<div class="ok">Sin IPs sospechosas.</div>'

    ip_html = "".join(
        f'<div class="ip-row"><span class="ip">{ip}</span><span class="count">{count} peticiones</span></div>'
        for ip, count in ip_count.items()
    )

    db_rows = get_db_records()
    db_html = "".join(
        f'<tr><td>{r[0]}</td><td class="status-{"ok" if r[1] == "200" else "err"}">{r[1]}</td><td class="raw-cell">{r[2]}</td></tr>'
        for r in db_rows
    ) or '<tr><td colspan="3" class="ok">Sin registros.</td></tr>'

    attackers = get_401_attackers()
    attackers_html = "".join(
        f'<div class="alert critical">&#128683; <strong>{r[0]}</strong> &mdash; {r[1]} intentos fallidos</div>'
        for r in attackers
    ) or '<div class="ok">Sin IPs con más de 3 errores 401.</div>'

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Analizador de Logs</title>
  <style>
    body {{ font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; margin: 0; }}
    h1 {{ color: #61dafb; margin-bottom: 5px; }}
    h2 {{ color: #9cdcfe; border-bottom: 1px solid #444; padding-bottom: 6px; margin-top: 30px; }}
    .section {{ background: #252526; border-radius: 8px; padding: 16px; margin-bottom: 20px; }}
    .log-line {{ padding: 3px 0; border-bottom: 1px solid #333; font-size: 13px; }}
    .alert {{ padding: 8px 12px; border-radius: 5px; margin: 6px 0; }}
    .critical {{ background: #3a1a1a; border-left: 4px solid #f44747; color: #f88; }}
    .warning  {{ background: #2d2a0f; border-left: 4px solid #dcdcaa; color: #dcdcaa; }}
    .ok {{ color: #4ec9b0; }}
    .ip-row {{ display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #333; }}
    .ip    {{ color: #9cdcfe; }}
    .count {{ color: #b5cea8; }}
    .geo   {{ color: #9cdcfe; font-size: 12px; margin-left: 8px; opacity: 0.85; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ text-align: left; color: #9cdcfe; border-bottom: 1px solid #444; padding: 4px 8px; }}
    td {{ padding: 4px 8px; border-bottom: 1px solid #333; }}
    .raw-cell {{ color: #888; }}
    .status-ok  {{ color: #4ec9b0; font-weight: bold; }}
    .status-err {{ color: #f88; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>&#128269; Analizador de Logs</h1>

  <h2>&#128196; Contenido de logs.txt</h2>
  <div class="section">{logs_html}</div>

  <h2>&#128680; SQL Injection</h2>
  <div class="section">{sql_html}</div>

  <h2>&#128680; Fuerza Bruta</h2>
  <div class="section">{bf_html}</div>

  <h2>&#9888; IPs sospechosas</h2>
  <div class="section">{suspicious_html}</div>

  <h2>&#128202; IPs más activas</h2>
  <div class="section">{ip_html}</div>

  <h2>&#128683; IPs con más de 3 errores 401 (DB)</h2>
  <div class="section">{attackers_html}</div>

  <h2>&#128190; Base de datos (logs.db)</h2>
  <div class="section">
    <table>
      <thead><tr><th>IP</th><th>Estado</th><th>Raw</th></tr></thead>
      <tbody>{db_html}</tbody>
    </table>
  </div>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = build_html()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 5000), Handler)
    print("Server running on port 5000")
    server.serve_forever()



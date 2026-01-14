from flask import Flask, request, Response, jsonify, render_template
import requests
import pickle
import time
import re
import urllib.parse
import sqlite3
from collections import defaultdict

# --- CONFIGURATION ---
TARGET_URL = "http://localhost:80"
LISTEN_PORT = 8080
MAX_REQUESTS_PER_MINUTE = 60
DB_NAME = "soc_waf.db"

app = Flask(__name__)

# --- 0. BDD ---
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                url TEXT,
                status TEXT,
                score REAL,
                type TEXT
            )
        ''')
        conn.commit()

# --- 1. NETTOYAGE (Gardant les symboles) ---
def clean_url(url):
    url = str(url).lower()
    try:
        decoded = urllib.parse.unquote(url)
        while decoded != url:
            url = decoded
            decoded = urllib.parse.unquote(url)
    except: pass
    url = re.sub(r'https?://(www\.)?', '', url)
    url = re.sub(r'\s+', ' ', url).strip()
    return url

# --- 2. CHARGEMENT IA ---
print("[*] Démarrage du SOC-IA (Version Finale Blindée)...")
try:
    with open('waf_brain.pkl', 'rb') as f:
        brain_pack = pickle.load(f)
    vectorizer = brain_pack['vectorizer']
    clf = brain_pack['classifier']
    anomaly_detector = brain_pack['anomaly_detector']
    print("✅ IA Chargée.")
    init_db()
except Exception as e:
    print(f"❌ ERREUR: {e}")
    exit()

# --- 3. LOGGING ---
ip_counter = defaultdict(list)

def log_request(ip, url, status, score, attack_type):
    timestamp = time.strftime("%H:%M:%S")
    safe_url = url[:100] + "..." if len(url) > 100 else url
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO logs (timestamp, ip, url, status, score, type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, ip, safe_url, status, score, attack_type))
            conn.commit()
    except: pass

# --- 4. PROXY ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    client_ip = request.remote_addr
    full_url = request.url.replace(request.host_url, "/")
    if not full_url.startswith("/"): full_url = "/" + full_url

    # ANTI-DOS
    current_time = time.time()
    ip_counter[client_ip] = [t for t in ip_counter[client_ip] if current_time - t < 60]
    if len(ip_counter[client_ip]) > MAX_REQUESTS_PER_MINUTE:
        log_request(client_ip, "DOS", "BLOCKED", 100, "DoS Flood 🌊")
        return Response("🚫 BANNED", status=429)
    ip_counter[client_ip].append(current_time)

    # PREPARATION
    cleaned_input = clean_url(full_url)
    url_vector = vectorizer.transform([full_url])
    
    # IA PREDICTIONS
    proba_attack = clf.predict_proba(url_vector)[0][1] * 100
    anomaly_pred = anomaly_detector.predict(url_vector)[0]
    is_anomaly = True if anomaly_pred == -1 else False

    # --- MOTEUR DE DECISION ---
    block_reason = None
    final_score = proba_attack
    attack_label = "Normal"

    # 1. REGLES HEURISTIQUES (Comportementales)
    # Règle : Si un caractère se répète plus de 25 fois (ex: AAAAA..., $$$$$...)
    if re.search(r'(.)\1{25,}', full_url):
        block_reason = "Heuristique : Répétition Excessive"
        final_score = 100.0
        attack_label = "💥 Buffer Overflow / Fuzzing"

    # 2. REGLES DURES (Signature)
    elif "select" in cleaned_input and "from" in cleaned_input:
        block_reason = "Hard Rule : SQL Injection"
        final_score = 100.0
        attack_label = "💉 SQL Injection"
    elif "<script>" in full_url.lower() or "javascript:" in full_url.lower():
        block_reason = "Hard Rule : XSS Detected"
        final_score = 100.0
        attack_label = "☠️ XSS Attack"

    # 3. IA SIGNATURE (Attaque connue)
    elif proba_attack > 50:
        block_reason = f"IA Détection ({proba_attack:.1f}%)"
        if "union" in cleaned_input: attack_label = "SQL Injection"
        else: attack_label = "Malicious Payload"

    # 4. IA ZERO-DAY (Anomalie de structure)
    elif is_anomaly:
        block_reason = "IA Isolation Forest : Structure Anormale"
        final_score = 99.9
        attack_label = "⚠️ Zero-Day Anomaly"

    # ACTION
    if block_reason:
        print(f"🚨 BLOCKED: {full_url} -> {block_reason}")
        log_request(client_ip, full_url, "BLOCKED", final_score, attack_label)
        return render_template('block_page.html', score=final_score, reason=block_reason), 403

    # ALLOWED
    print(f"✅ ALLOWED: {full_url}")
    log_request(client_ip, full_url, "ALLOWED", final_score, "Normal Traffic")
    
    try:
        resp = requests.request(
            method=request.method,
            url=f"{TARGET_URL}/{path}",
            headers={k: v for k, v in request.headers if k != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
        return Response(resp.content, resp.status_code, dict(resp.headers))
    except Exception as e:
        return Response(f"Backend Error: {e}", 500)

# DASHBOARD
@app.route('/dashboard')
def dashboard(): return render_template('dashboard.html')
@app.route('/api/stats')
def stats():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM logs")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM logs WHERE status='BLOCKED'")
            blocked = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 50")
            rows = cursor.fetchall()
            logs = [{"timestamp": r["timestamp"], "ip": r["ip"], "url": r["url"], "status": r["status"], "score": f"{r['score']:.1f}%", "type": r["type"]} for r in rows]
            return jsonify({"total": total, "blocked": blocked, "allowed": total - blocked, "logs": logs})
    except: return jsonify({"total":0, "blocked":0, "allowed":0, "logs":[]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=LISTEN_PORT)

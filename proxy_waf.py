import pandas as pd
from flask import Flask, request, Response, render_template
import requests
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import numpy as np
import re
import sqlite3
from urllib.parse import unquote
from datetime import datetime

app = Flask(__name__)

# --- CONFIGURATION (Spécial Windows Docker) ---
# Pointe vers le serveur Python qui tourne sur ton vrai PC (port 8000)
TARGET_URL = "http://host.docker.internal:8000"
DB_FILE = "soc_waf.db"

# Paramètres du modèle (DOIVENT être identiques à ceux de train_deep.py)
MAX_LENGTH = 200 

# --- CHARGEMENT DU CERVEAU DEEP LEARNING ---
print("[*] Démarrage du SOC-IA (Mode Deep Learning)...")
model = None
tokenizer = None

try:
    # 1. Charger le Réseau de Neurones (.h5)
    model = tf.keras.models.load_model('waf_deep_model.h5')
    
    # 2. Charger le Tokenizer (.pickle) pour traduire le texte en nombres
    with open('tokenizer.pickle', 'rb') as handle:
        tokenizer = pickle.load(handle)
        
    print("✅ Cerveau Deep Learning & Tokenizer chargés avec succès.")
except Exception as e:
    print(f"❌ ERREUR CRITIQUE : Impossible de charger l'IA. {e}")
    print("⚠️  Assure-toi d'avoir lancé 'python train_deep.py' avant !")
    # On ne quitte pas pour permettre au serveur de démarrer (mode dégradé)

# --- BASE DE DONNÉES (LOGS) ---
def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS logs 
                     (id INTEGER PRIMARY KEY, timestamp TEXT, ip TEXT, 
                      request_type TEXT, score TEXT, action TEXT, details TEXT)''')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erreur DB: {e}")

init_db()

def log_request(ip, req_type, score, action, details):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%H:%M:%S")
        c.execute("INSERT INTO logs (timestamp, ip, request_type, score, action, details) VALUES (?, ?, ?, ?, ?, ?)",
                  (timestamp, ip, req_type, score, action, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erreur Log: {e}")

# --- ANALYSE DE SÉCURITÉ ---
def clean_url(url):
    """Nettoie l'URL pour l'analyse (décodage + minuscule)"""
    return unquote(url).lower()

def check_hard_rules(url):
    """Layer 1 : Règles strictes (Signatures évidentes)"""
    # SQL Injection Patterns
    sqli_patterns = [
        r"select\s+.*\s+from", r"union\s+select", r"insert\s+into", 
        r"drop\s+table", r"or\s+1=1", r"waitfor\s+delay"
    ]
    for p in sqli_patterns:
        if re.search(p, url): return "SQL Injection (Signature)"
    
    # XSS Patterns
    xss_patterns = [
        r"<script>", r"javascript:", r"onload=", r"onerror="
    ]
    for p in xss_patterns:
        if re.search(p, url): return "XSS Attack (Signature)"
    
    # Heuristique (Buffer Overflow)
    if len(url) > 500 or re.search(r"(.)\1{30,}", url): 
        return "Buffer Overflow / Fuzzing"

    return None

def analyze_request(url):
    """Layer 2 : Cerveau Deep Learning"""
    url_decoded = clean_url(url)

    # 1. HARD RULES (Priorité absolue)
    rule_check = check_hard_rules(url_decoded)
    if rule_check:
        return True, rule_check, "100%"

    # Si le modèle n'est pas chargé, on laisse passer (Fail-Open)
    if model is None or tokenizer is None:
        return False, "IA Non Chargée (Pass-Through)", "0%"

    # 2. DEEP LEARNING PREDICTION
    try:
        # Transformation de l'URL en séquence de nombres
        sequences = tokenizer.texts_to_sequences([url_decoded])
        
        # Padding (remplissage) pour avoir la taille attendue par le modèle
        padded = pad_sequences(sequences, maxlen=MAX_LENGTH, padding='post', truncating='post')
        
        # Prédiction (retourne une probabilité entre 0 et 1)
        # verbose=0 pour éviter de polluer les logs à chaque requête
        prediction = model.predict(padded, verbose=0)[0][0]
        
        confidence_score = round(prediction * 100, 2)
        
        # Seuil de décision (0.5 = 50%)
        if prediction > 0.5:
            return True, "Menace Deep Learning", f"{confidence_score}%"
        
        return False, "Normal Traffic", f"{confidence_score}%"

    except Exception as e:
        print(f"Erreur prédiction: {e}")
        return False, "Erreur Analyse", "0%"

# --- ROUTE DU DASHBOARD ---
@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    logs = c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return render_template('dashboard.html', logs=logs)

# --- ROUTE PRINCIPALE (PROXY) ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    full_path = request.full_path if request.query_string else request.path
    client_ip = request.remote_addr

    if path.startswith('static') or path == 'favicon.ico':
        return Response("Not Found", status=404)

    # --- ANALYSE ---
    is_blocked, threat_type, score = analyze_request(full_path)

    if is_blocked:
        print(f"🚨 BLOQUÉ ({score}): {full_path} -> {threat_type}")
        log_request(client_ip, threat_type, score, "BLOCKED", full_path)
        return render_template('block_page.html', 
                             ip=client_ip, 
                             reason=threat_type, 
                             id=re.sub(r'\D', '', str(datetime.now().timestamp())))

    # --- TRANSMISSION ---
    print(f"✅ AUTORISÉ ({score}): {full_path}")
    log_request(client_ip, threat_type, score, "ALLOWED", full_path)

    target = f"{TARGET_URL}/{path}"
    if request.query_string:
        target += f"?{request.query_string.decode('utf-8')}"

    try:
        resp = requests.request(
            method=request.method,
            url=target,
            headers={key: value for (key, value) in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )

        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items()
                   if name.lower() not in excluded_headers]

        return Response(resp.content, resp.status_code, headers)

    except requests.exceptions.ConnectionError:
        return Response("<h1>Erreur Backend</h1><p>Le WAF est actif mais le serveur cible (port 8000) ne répond pas.</p>", status=502)

if __name__ == '__main__':
    # Écoute sur toutes les interfaces du conteneur
    app.run(host='0.0.0.0', port=8080)

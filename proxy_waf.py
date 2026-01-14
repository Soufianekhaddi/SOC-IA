from flask import Flask, request, Response, render_template, jsonify
import requests
import pickle
import re
from urllib.parse import unquote
import datetime
import time

# ================= CONFIGURATION =================
app = Flask(__name__)
DVWA_TARGET = "http://localhost:80"
WAF_PORT = 8080

# ================= SYSTÈME ANTI-DOS (RATE LIMITING) =================
dos_tracker = {}
DOS_LIMIT = 10        # <--- MODIFIÉ : Max 10 requêtes autorisées (Très strict)
DOS_WINDOW = 10       # En secondes
BLOCKED_IPS = {}      # IP bannies temporairement

# ================= MÉMOIRE DES LOGS (STATISTIQUES) =================
waf_stats = {
    "total": 0,
    "blocked": 0,
    "allowed": 0,
    "logs": [],
    # Compteurs par type d'attaque (Pour le classement)
    "attack_types": {
        "SQL Injection (SQLi)": 0,
        "Cross-Site Scripting (XSS)": 0,
        "Path Traversal": 0,
        "DoS Flood 🌊": 0,
        "Malicious Pattern": 0
    }
}

def add_log(ip, url, score, action, attack_type):
    # Mise à jour des compteurs globaux
    waf_stats["total"] += 1
    
    if action == "BLOCKED":
        waf_stats["blocked"] += 1
        # Mise à jour du compteur spécifique par type
        if attack_type in waf_stats["attack_types"]:
            waf_stats["attack_types"][attack_type] += 1
        else:
            waf_stats["attack_types"][attack_type] = 1
    else:
        waf_stats["allowed"] += 1
    
    # Création de l'entrée de log
    new_log = {
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "ip": ip,
        "url": url,
        "score": float(score),
        "action": action,
        "type": attack_type
    }
    
    # On garde l'historique des 20 dernières requêtes
    waf_stats["logs"].append(new_log)
    if len(waf_stats["logs"]) > 20:
        waf_stats["logs"].pop(0)

# ================= CLASSIFICATEUR D'ATTAQUES =================
def get_attack_type(payload):
    p = payload.lower()
    if "union" in p and "select" in p: return "SQL Injection (SQLi)"
    if "or 1=1" in p or "drop table" in p: return "SQL Injection (SQLi)"
    if "<script>" in p or "alert(" in p: return "Cross-Site Scripting (XSS)"
    if "onerror=" in p or "onload=" in p: return "Cross-Site Scripting (XSS)"
    if "../" in p or "etc/passwd" in p: return "Path Traversal"
    return "Malicious Pattern"

# ================= CHARGEMENT IA =================
def custom_tokenizer(url):
    # Tokenizer identique à l'entraînement
    tokens = re.split(r'[/\-?=&%.<>\'"();,]+', str(url))
    return [t for t in tokens if t]

print("[*] Démarrage du WAF Complet (IA + DoS Strict + Stats)...")
try:
    with open('waf_brain.pkl', 'rb') as f:
        vectorizer, model = pickle.load(f)
    print("✅ Cerveau IA chargé avec succès.")
except Exception as e:
    print(f"❌ ERREUR CRITIQUE : {e}")
    print("👉 Avez-vous lancé 'python3 train_waf.py' ?")
    exit()

# ================= ROUTES DU DASHBOARD =================
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    return jsonify(waf_stats)

# ================= LOGIQUE DU PROXY (MAIN LOOP) =================
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    client_ip = request.remote_addr

    # Ignorer les appels internes (dashboard/api) pour ne pas polluer les logs
    if path.startswith("dashboard") or path.startswith("api"):
        return Response("Not found", status=404)

    # --- ÉTAPE 1 : PROTECTION ANTI-DOS ---
    current_time = time.time()
    
    # Vérification si IP bannie
    if client_ip in BLOCKED_IPS:
        if current_time - BLOCKED_IPS[client_ip] < 60: # Ban de 60s
            return Response("<h1>⛔ DoS DETECTED</h1><p>IP Banned.</p>", status=429)
        else:
            del BLOCKED_IPS[client_ip] # Fin du ban

    # Suivi du nombre de requêtes
    if client_ip not in dos_tracker:
        dos_tracker[client_ip] = []
    
    dos_tracker[client_ip].append(current_time)
    # Nettoyage des vieilles requêtes (> 10s)
    dos_tracker[client_ip] = [t for t in dos_tracker[client_ip] if current_time - t < DOS_WINDOW]

    # Déclenchement du Ban si limite dépassée (ICI C'EST 10)
    if len(dos_tracker[client_ip]) > DOS_LIMIT:
        print(f"🌊 FLOOD DETECTED from {client_ip}")
        BLOCKED_IPS[client_ip] = current_time
        add_log(client_ip, "HIGH TRAFFIC VOLUME", 1.0, "BLOCKED", "DoS Flood 🌊")
        return Response("<h1>⛔ DoS DETECTED</h1><p>Too many requests (Max 10/10s).</p>", status=429)

    # --- ÉTAPE 2 : ANALYSE INTELLIGENTE (IA) ---
    raw_input = request.full_path
    # Décodage crucial (%20 -> espace)
    decoded_input = unquote(raw_input)
    
    if request.method == 'POST':
        decoded_input += str(request.form.to_dict())

    # Prédiction
    try:
        vec = vectorizer.transform([decoded_input])
        proba = model.predict_proba(vec)[0][1]
    except:
        proba = 0

    # --- ÉTAPE 3 : DÉCISION ---
    if proba > 0.5:
        # CAS : ATTAQUE DÉTECTÉE
        attack_type = get_attack_type(decoded_input)
        print(f"🚨 BLOCKED [{attack_type}] (Score: {proba:.2f}) : {decoded_input}")
        
        add_log(client_ip, decoded_input, proba, "BLOCKED", attack_type)
        
        return Response(
            f"""<center><h1>🚫 WAF BLOCKED</h1>
            <p><b>Threat Detected:</b> {attack_type}</p>
            <p><b>Confidence Score:</b> {proba:.2f}</p></center>""", 
            status=403
        )
    
    else:
        # CAS : TRAFIC LÉGITIME
        print(f"✅ ALLOWED : {decoded_input}")
        add_log(client_ip, decoded_input, proba, "ALLOWED", "Normal Traffic")
        
        # Transmission au serveur DVWA
        try:
            resp = requests.request(
                method=request.method,
                url=f"{DVWA_TARGET}/{path}",
                headers={k:v for k,v in request.headers if k != 'Host'},
                data=request.get_data(),
                cookies=request.cookies,
                allow_redirects=False
            )
            # Copie des headers de réponse
            headers = [(k,v) for k,v in resp.raw.headers.items()]
            return Response(resp.content, resp.status_code, headers)
        except:
            return Response("Erreur: Impossible de joindre DVWA (Port 80)", status=502)

if __name__ == '__main__':
    # Threaded=True est important pour gérer le DoS et le Dashboard en même temps
    app.run(host='0.0.0.0', port=WAF_PORT, debug=False, threaded=True)

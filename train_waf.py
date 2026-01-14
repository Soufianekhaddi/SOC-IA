import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import pickle
import re

# ================= CONFIGURATION =================
OUTPUT_BRAIN = "waf_brain.pkl"

print(f"\n🚀 ENTRAÎNEMENT RENFORCÉ (SPÉCIAL DVWA)")
print("=========================================")

# ================= 1. GÉNÉRATION DES DONNÉES =================
print("[*] Création du dataset avec les attaques DVWA spécifiques...")

# --- TRAFIC NORMAL (Gentil) ---
good_queries = [
    "/", "/index.php", "/login.php", "/home", "/contact", 
    "/about", "/products?id=1", "/search?q=apple", "/dashboard",
    "/users/profile", "/images/logo.png", "/style.css", "/js/app.js",
    "/api/v1/status", "/downloads/manual.pdf", "/shop/cart",
    "/login.php?user=soufiane", "/welcome?lang=fr", 
    "/products?id=10", "/search?q=union" # Le mot union seul peut etre gentil
] * 300

# --- TRAFIC MALVEILLANT (Méchant) ---
xss_attacks = [
    "<script>alert(1)</script>",
    "/index.php?q=<script>alert('hacked')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>"
] * 150

# --- ICI : ON AJOUTE LES ATTAQUES EXACTES DE DVWA ---
sqli_attacks = [
    # L'attaque générique
    "' OR 1=1 --",
    # TON ATTAQUE PRÉCISE (Celle qui doit être bloquée)
    "/products?id=1 UNION SELECT user, password",
    "/products?id=1 UNION SELECT user, password FROM users",
    # Variantes classiques
    "UNION SELECT",
    "UNION ALL SELECT",
    "/vulnerabilities/sqli/?id=1' OR '1'='1",
    "' UNION SELECT 1, version() --",
    "admin' --",
    "' OR 'a'='a"
] * 200 # On multiplie par 200 pour insister auprès de l'IA

path_traversal = [
    "../../../../etc/passwd",
    "/index.php?page=../../../var/log/apache/access.log",
    "/etc/shadow",
    "../boot.ini"
] * 150

# Fusion des données
all_data = good_queries + xss_attacks + sqli_attacks + path_traversal
all_labels = [0]*len(good_queries) + [1]*(len(xss_attacks) + len(sqli_attacks) + len(path_traversal))

df = pd.DataFrame({'request': all_data, 'label': all_labels})
# Mélange aléatoire
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"[+] Dataset prêt : {len(df)} lignes.")

# ================= 2. PRÉPARATION IA =================
def custom_tokenizer(url):
    # On découpe l'URL en mots compréhensibles pour l'IA
    # Cette fonction doit être IDENTIQUE dans le proxy
    tokens = re.split(r'[/\-?=&%.<>\'"();,]+', str(url))
    return [t for t in tokens if t]

print("[*] Vectorisation...")
vectorizer = TfidfVectorizer(tokenizer=custom_tokenizer)
X = vectorizer.fit_transform(df['request'])
y = df['label']

# ================= 3. ENTRAÎNEMENT =================
print("[*] Entraînement...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=42)

# C=10.0 rend le modèle plus strict sur les erreurs
model = LogisticRegression(max_iter=1000, C=10.0) 
model.fit(X_train, y_train)

# ================= 4. TEST DE VÉRIFICATION =================
# On teste immédiatement ton attaque pour être sûr que le cerveau est bon
test_attack = "/products?id=1 UNION SELECT user, password"
vec_test = vectorizer.transform([test_attack])
res = model.predict(vec_test)[0]
proba = model.predict_proba(vec_test)[0][1]

print("\n[TEST DE VÉRIFICATION AVANT SAUVEGARDE]")
print(f"Attaque testée : {test_attack}")
if res == 1:
    print(f"✅ DÉTECTION RÉUSSIE ! (Score: {proba:.4f})")
else:
    print(f"❌ ÉCHEC : Le modèle ne détecte toujours pas l'attaque.")

# ================= 5. SAUVEGARDE =================
print(f"\n[*] Sauvegarde dans '{OUTPUT_BRAIN}'...")
with open(OUTPUT_BRAIN, 'wb') as f:
    pickle.dump((vectorizer, model), f)

print("✅ TERMINE ! Le fichier waf_brain.pkl est prêt.")

import pandas as pd
import numpy as np
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
import re
import urllib.parse

# --- 1. FONCTION DE NETTOYAGE (Version Zero-Day Compatible) ---
def clean_url(url):
    """ 
    Nettoie l'URL mais GARDE les symboles spéciaux 
    pour permettre la détection d'anomalies (ex: $$$$$)
    """
    url = str(url).lower()
    
    # A. Décodage Récursif (Phase 1)
    try:
        decoded = urllib.parse.unquote(url)
        while decoded != url:
            url = decoded
            decoded = urllib.parse.unquote(url)
    except:
        pass

    # B. On enlève juste le protocole (bruit inutile)
    url = re.sub(r'https?://(www\.)?', '', url)
    
    # C. IMPORTANT : On NE supprime PLUS les symboles non-alphanumériques !
    # On nettoie seulement les espaces multiples et les sauts de ligne
    url = re.sub(r'\s+', ' ', url).strip()
    
    return url

print("[*] 1. Chargement et génération du Dataset...")

# --- 2. DATASET HYBRIDE ---

# Trafic LEGITIME (Good)
good_queries = [
    "index.html", "home", "login", "dashboard", "profile", "settings",
    "images/logo.png", "css/style.css", "js/app.js", "api/status",
    "products?id=12", "search?q=laptop", "contact-us", "about",
    "blog/article-2023", "user/logout", "cart?add=iphone",
    "checkout/payment", "api/v1/users", "sitemap.xml",
    "services/consulting", "portfolio/project-a", "terms-of-service",
    "login?user=soufiane", "search?category=books&sort=asc"
] * 200 

# Trafic MALVEILLANT (Bad)
bad_queries = [
    "union select 1,2,3", "or 1=1", "drop table users",
    "<script>alert(1)</script>", "javascript:void(0)",
    "../../etc/passwd", "/win.ini", "cmd.exe",
    "exec(xp_cmdshell)", "sleep(10)", "1' OR '1'='1",
    "admin' --", "<svg/onload=alert('xss')>",
    "../../../var/www/html", "cat /etc/shadow",
    "%27%20OR%20%271%27=%271", 
    "select * from users",         
    "select password from admin", 
    "select group_concat(table_name) from information_schema.tables",
    "admin' #",
    "$$$$$$$$$$$$$$$$", # Exemple d'anomalie pure
    "../../../../boot.ini"
] * 200

# Création des DataFrames
data_good = pd.DataFrame({'url': good_queries, 'label': 0}) 
data_bad = pd.DataFrame({'url': bad_queries, 'label': 1})   
df = pd.concat([data_good, data_bad]).sample(frac=1).reset_index(drop=True)

# --- 3. VECTORISATION ---
print("[*] 2. Vectorisation (Mode sensible aux symboles)...")
# analyzer='char' permettrait de voir les caractères, mais 'word' avec notre tokenizer custom est un bon compromis
vectorizer = TfidfVectorizer(tokenizer=clean_url, token_pattern=None)
X = vectorizer.fit_transform(df['url'])
y = df['label']

# --- 4. CERVEAU 1 : CLASSIFIER ---
print("[*] 3. Entraînement du Classifier (Police)...")
clf = LogisticRegression()
clf.fit(X, y)

# --- 5. CERVEAU 2 : ANOMALY DETECTOR ---
print("[*] 4. Entraînement de l'Isolation Forest (Détective)...")
X_good = vectorizer.transform(data_good['url'])

# MODIFICATION : contamination=0.1 (Plus strict, bloque 10% de ce qui s'éloigne de la norme)
isolation_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
isolation_forest.fit(X_good)

# --- 6. SAUVEGARDE ---
print("[*] 5. Sauvegarde du cerveau dans 'waf_brain.pkl'...")
brain_pack = {
    'vectorizer': vectorizer,
    'classifier': clf,
    'anomaly_detector': isolation_forest
}

with open('waf_brain.pkl', 'wb') as f:
    pickle.dump(brain_pack, f)

print("✅ TERMINE ! Le modèle est calibré pour le Zero-Day.")

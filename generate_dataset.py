import pandas as pd
import random

# --- CONFIGURATION ---
DATASET_SIZE = 5000 # Nombre total de lignes
OUTPUT_FILE = 'dataset_waf.csv'

# --- LISTES DE COMPOSANTS ---
# 1. Trafic Normal (Good)
good_paths = ['/login', '/home', '/about', '/contact', '/products', '/api/user', '/dashboard', '/assets/style.css', '/images/logo.png']
good_params = ['?id=123', '?page=1', '?q=search', '?category=books', '?session=xyz', '']

# 2. Trafic Malveillant (Bad - SQLi, XSS, RCE, Path Traversal)
bad_payloads = [
    # SQL Injection
    "' OR 1=1 --", "UNION SELECT user, password FROM users", "; DROP TABLE students", "' OR '1'='1", "admin' --",
    # XSS (Cross-Site Scripting)
    "<script>alert(1)</script>", "<img src=x onerror=alert('hacked')>", "javascript:alert(1)",
    # Path Traversal
    "../../../../etc/passwd", "..\\..\\windows\\system32\\cmd.exe",
    # Command Injection
    "; cat /etc/passwd", "| whoami", "&& netstat -an",
    # Zero-Day like (Fuzzing)
    "$$$$$$$$$$$$", "%00%00%00", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
]

data = []

print(f"[*] Génération de {DATASET_SIZE} exemples de trafic...")

for _ in range(DATASET_SIZE):
    if random.random() > 0.5:
        # --- GÉNÉRER DU TRAFIC NORMAL (Label 0) ---
        path = random.choice(good_paths)
        param = random.choice(good_params)
        # Parfois on ajoute des nombres aléatoires pour varier
        if "id=" in param:
            param = f"?id={random.randint(1, 9999)}"
        
        url = f"{path}{param}"
        data.append([url, 0]) # 0 = Safe
    else:
        # --- GÉNÉRER UNE ATTAQUE (Label 1) ---
        base = random.choice(good_paths)
        payload = random.choice(bad_payloads)
        
        # On insère l'attaque soit dans le path, soit en paramètre
        if random.random() > 0.5:
            url = f"{base}?q={payload}"
        else:
            url = f"/{payload}"
            
        data.append([url, 1]) # 1 = Malicious

# --- SAUVEGARDE ---
df = pd.DataFrame(data, columns=['url', 'label'])
# On mélange tout pour que l'IA n'apprenne pas par ordre
df = df.sample(frac=1).reset_index(drop=True) 

df.to_csv(OUTPUT_FILE, index=False)
print(f"✅ Fichier '{OUTPUT_FILE}' créé avec succès !")
print("👉 Tu peux maintenant lancer 'python train_deep.py'")

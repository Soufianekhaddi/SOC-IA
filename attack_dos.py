import requests
import time
import threading

# Cible : Ton WAF
TARGET_URL = "http://localhost:8080/login.php"
NUMBER_OF_REQUESTS = 100  # On va envoyer 100 requêtes très vite

def send_request(i):
    try:
        response = requests.get(TARGET_URL)
        if response.status_code == 200:
            print(f"[{i}] ✅ Requête acceptée")
        elif response.status_code == 429:
            print(f"[{i}] ⛔ BLOQUÉ PAR LE WAF (DoS Protection)")
        else:
            print(f"[{i}] Statut: {response.status_code}")
    except:
        print(f"[{i}] ❌ Erreur connexion")

print(f"🚀 Lancement de l'attaque DoS sur {TARGET_URL}...")

threads = []
for i in range(NUMBER_OF_REQUESTS):
    t = threading.Thread(target=send_request, args=(i,))
    threads.append(t)
    t.start()
    time.sleep(0.05) # Petite pause pour pas faire exploser ton propre PC

for t in threads:
    t.join()

print("🏁 Attaque terminée.")

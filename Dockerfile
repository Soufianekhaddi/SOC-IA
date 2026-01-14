# 1. On part d'une image Python officielle légère (Linux)
FROM python:3.11-slim

# 2. On définit le dossier de travail dans le conteneur
WORKDIR /app

# 3. On copie le fichier des dépendances
COPY requirements.txt .

# 4. On installe les librairies (sans cache pour alléger)
RUN pip install --no-cache-dir -r requirements.txt

# 5. On copie tout ton code (proxy, train, templates, etc.) dans le conteneur
COPY . .

# 6. On expose le port 8080 (celui du WAF)
EXPOSE 8080

# 7. Commande de démarrage : On lance le proxy
CMD ["python", "proxy_waf.py"]

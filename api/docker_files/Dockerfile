#syntax=docker/dockerfile:1
# Utiliser une image de base plus récente : Python 3.12 sur Debian 12 (Bookworm)
FROM python:3.12-slim-bookworm

WORKDIR /python-docker

# Les sources APT sont déjà correctes, pas besoin de les modifier
# Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y --no-install-recommends \
    nano \
    python3-dev \
    wget \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# --- TÉLÉCHARGEMENT DES DÉPENDANCES FRONTEND ---
# Créer la structure de dossiers standard pour les fichiers statiques de Flask
RUN mkdir -p /python-docker/static/vendor/fonts

# Télécharger Tailwind CSS dans le dossier statique
RUN wget -O /python-docker/static/vendor/tailwindcss.js https://cdn.tailwindcss.com

# Télécharger le CSS de la police Inter
RUN wget -O /python-docker/static/vendor/inter.css "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" --header="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/5.37.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"

# Analyser le CSS, télécharger les fichiers de police réels et mettre à jour les chemins pour qu'ils soient relatifs
RUN cd /python-docker/static/vendor && \
    grep -o 'url(https://[^)]*)' inter.css | \
    sed -e 's/url(//' -e 's/)//' | \
    wget --header="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/5.37.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" -i - -P fonts/ && \
    sed -i 's|https://fonts.gstatic.com/s/inter/v[0-9]*/|../fonts/|g' inter.css
# -----------------------------------------------

# Copier les requirements Python et les installer
COPY docker_files/requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Copier le reste de l'application API
COPY . .

# La commande de démarrage reste la même
CMD [ "python3",  "wapp_server.py"]


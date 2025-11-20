#!/bin/bash

echo "Construction des images locales..."
sudo docker compose build
echo "⬇Téléchargement des images externes..."
sudo docker compose pull
echo "Création de l'archive docker (images.tar)..."
docker save -o images.tar \
    traefik:latest \
    redis:4-alpine \
    wapp-api \
    wapp-worker

sudo chmod 766 images.tar
sudo chown hro:hro images.tar
echo "End"

# Sur machine distante docker load -i images.tar

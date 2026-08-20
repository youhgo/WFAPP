#!/bin/bash

# WFAPP Offline Bundling Script
# This script bundles all required Docker images and configuration files
# into a single compressed archive for offline deployment.

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}======================================================${NC}"
echo -e "${GREEN}      WFAPP Offline Bundling Script                  ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo ""

# 1. Build and Pull Docker Images
echo -e "${GREEN}[1/5] Building local Docker images...${NC}"
docker compose build

echo -e "\n${GREEN}[2/5] Pulling external Docker images...${NC}"
docker compose pull

# 2. Save Images to Tar Archive
echo -e "\n${GREEN}[3/5] Saving Docker images to images.tar...${NC}"
docker save -o images.tar \
    traefik:latest \
    redis:7-alpine \
    wapp-api \
    wapp-worker

# 3. Create Offline Package Directory Structure
echo -e "\n${GREEN}[4/5] Preparing offline distribution directory...${NC}"
DIST_DIR="wfapp_offline_dist"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Move images and configuration files
mv images.tar "$DIST_DIR/"
cp docker-compose.yml "$DIST_DIR/"
cp .env.exemple "$DIST_DIR/"
cp install.sh "$DIST_DIR/"

# Copy Traefik certificates and config dependencies
if [ -d dependencies ]; then
    cp -r dependencies "$DIST_DIR/"
fi

# 4. Compress the Package
echo -e "\n${GREEN}[5/5] Creating compressed archive (wfapp_offline.tar.gz)...${NC}"
tar -czf wfapp_offline.tar.gz "$DIST_DIR"
rm -rf "$DIST_DIR"

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}      Bundling Complete!                              ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "Copy the file ${YELLOW}wfapp_offline.tar.gz${NC} to your offline server."
echo -e "On the offline server, run:"
echo -e "  tar -xzf wfapp_offline.tar.gz"
echo -e "  cd wfapp_offline_dist"
echo -e "  sudo ./install.sh"
echo ""

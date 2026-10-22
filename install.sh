#!/bin/bash

# WFAPP Automated Installation Script (Online & Offline Support)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${GREEN}======================================================${NC}"
echo -e "${GREEN}      WFAPP (Windows Forensic Artifacts Parser)      ${NC}"
echo -e "${GREEN}            Automated Installation Script            ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo ""

# Detect offline mode
OFFLINE_MODE=false
OFFLINE_IMAGE_FILE=""
if [ -f images.tar.gz ]; then
    OFFLINE_MODE=true
    OFFLINE_IMAGE_FILE="images.tar.gz"
elif [ -f images.tar ]; then
    OFFLINE_MODE=true
    OFFLINE_IMAGE_FILE="images.tar"
fi

# 1. Check for Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[!] Docker is not installed.${NC}"
    if [ "$OFFLINE_MODE" = true ]; then
        echo -e "${RED}[-] Offline installation detected, but Docker is missing.${NC}"
        echo -e "${YELLOW}Please install Docker and Docker Compose on this host first (using offline deb/rpm packages) and rerun this script.${NC}"
        exit 1
    fi

    read -p "Would you like to install Docker and Docker Compose for Ubuntu/Debian? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}[+] Installing Docker...${NC}"
        sudo apt-get update
        sudo apt-get install -y ca-certificates curl
        sudo install -m 0755 -d /etc/apt/keyrings
        sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        sudo chmod a+r /etc/apt/keyrings/docker.asc
        
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo \"$VERSION_CODENAME\") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        sudo apt-get update
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        echo -e "${GREEN}[+] Docker installed successfully.${NC}"
    else
        echo -e "${RED}[-] Please install Docker manually and rerun this script.${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}[+] Docker is already installed.${NC}"
fi

# Detect Compose command
if docker compose version &>/dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo -e "${RED}[-] Neither 'docker compose' nor 'docker-compose' was found.${NC}"
    exit 1
fi

# Ensure required external Docker network exists
if ! docker network inspect shared_sec_net &>/dev/null; then
    echo -e "${GREEN}[+] Initializing external network 'shared_sec_net'...${NC}"
    docker network create shared_sec_net >/dev/null || true
fi

# 2. Configure .env
echo -e "\n${GREEN}--- Configuration ---${NC}"
if [ ! -f .env ]; then
    if [ -f .env.exemple ]; then
        cp .env.exemple .env
        echo -e "${GREEN}[+] Created .env file from .env.exemple${NC}"
    else
        echo -e "${YELLOW}[!] .env.exemple not found, creating a basic .env file.${NC}"
        touch .env
    fi
else
    echo -e "${GREEN}[+] .env file already exists. We will update core parameters.${NC}"
fi

read -p "Enter WAPP API HOST (Default: wapp.localhost): " WAPP_HOST_INPUT
WAPP_HOST=${WAPP_HOST_INPUT:-wapp.localhost}

DEFAULT_SHARED_PATH="$HOME/Documents/shared_results"
read -p "Enter Shared Folder Path for Results (Default: $DEFAULT_SHARED_PATH): " SHARED_PATH_INPUT
SHARED_PATH=${SHARED_PATH_INPUT:-$DEFAULT_SHARED_PATH}

read -p "Enter number of parallel workers (Default: 1): " WORKER_COUNT_INPUT
WORKER_COUNT=${WORKER_COUNT_INPUT:-1}

# Create required directories with safe permissions
mkdir -p "$SHARED_PATH" "$SHARED_PATH/redis_db" "$SHARED_PATH/bulk_ingest" api/db

# Determine effective user & group for container volumes
TARGET_USER="${SUDO_USER:-$USER}"
TARGET_UID=$(id -u "$TARGET_USER" 2>/dev/null || echo 1000)
TARGET_GID=$(id -g "$TARGET_USER" 2>/dev/null || echo 1000)

# Function to update or append variables in .env
update_env() {
    local key=$1
    local value=$2
    if grep -q "^${key}=" .env; then
        sed -i "s|^${key}=.*|${key}=${value}|" .env
    else
        echo "${key}=${value}" >> .env
    fi
}

update_env "WAPP_API_HOST" "$WAPP_HOST"
update_env "SHARED_FOLDER_PATH" "$SHARED_PATH"
update_env "BULK_DEPOT_FOLDER_PATH" "\"${SHARED_PATH}/bulk_ingest\""
update_env "BULK_WATCHER_ENABLED" "true"
update_env "BULK_SCAN_INTERVAL" "15"
update_env "BULK_STABILITY_TIME" "5"
update_env "BULK_DEFAULT_CASE" "\"Auto_Bulk\""
update_env "WORKER_COUNT" "$WORKER_COUNT"
update_env "UID" "$TARGET_UID"
update_env "GID" "$TARGET_GID"

# Fix volume permissions for containers running with TARGET_UID:TARGET_GID
chown -R "$TARGET_UID:$TARGET_GID" "$SHARED_PATH" api/db 2>/dev/null || true
chmod -R 775 "$SHARED_PATH" api/db 2>/dev/null || true

# Generate a random SECRET_KEY if it's default or missing
if grep -q 'SECRET_KEY="very long random string"' .env || ! grep -q "^SECRET_KEY=" .env; then
    NEW_SECRET=$(openssl rand -hex 32 2>/dev/null || date +%s | sha256sum | head -c 64)
    update_env "SECRET_KEY" "\"$NEW_SECRET\""
    echo -e "${GREEN}[+] Generated a new secure SECRET_KEY${NC}"
fi

# GUI Admin credentials setup
read -p "Enter GUI Admin Username (Default: admin): " ADMIN_USER_INPUT
ADMIN_USER=${ADMIN_USER_INPUT:-admin}

read -p "Enter GUI Admin Password (leave blank to auto-generate): " ADMIN_PASS_INPUT
if [ -z "$ADMIN_PASS_INPUT" ]; then
    ADMIN_PASS=$(openssl rand -base64 12 2>/dev/null | tr -dc 'a-zA-Z0-9' | head -c 16)
    [ -z "$ADMIN_PASS" ] && ADMIN_PASS=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 16)
    echo -e "${GREEN}[+] Auto-generated secure admin password${NC}"
else
    ADMIN_PASS="$ADMIN_PASS_INPUT"
fi

update_env "WAPP_ADMIN_USER" "\"$ADMIN_USER\""
update_env "WAPP_ADMIN_PASSWORD" "\"$ADMIN_PASS\""

echo -e "${GREEN}[+] Configuration saved to .env${NC}"

# 3. Load Images and Start Containers
if [ "$OFFLINE_MODE" = true ]; then
    echo -e "\n${GREEN}--- Offline Mode Detected (${OFFLINE_IMAGE_FILE} found) ---${NC}"
    echo -e "[+] Loading Docker images from ${OFFLINE_IMAGE_FILE}..."
    docker load -i "$OFFLINE_IMAGE_FILE"
    echo -e "${GREEN}[+] Images loaded successfully.${NC}"
    echo -e "[+] Starting containers (offline mode)..."
    $COMPOSE_CMD up -d
else
    echo -e "\n${GREEN}--- Online Mode: Building and Starting Containers ---${NC}"
    echo -e "Running: $COMPOSE_CMD up --build -d"
    $COMPOSE_CMD up --build -d
fi

# 4. Startup Verification
echo -e "\n${GREEN}--- Verifying Container Status ---${NC}"
sleep 3
$COMPOSE_CMD ps

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}      Installation Complete!                         ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "You can access the Web GUI at: ${YELLOW}https://${WAPP_HOST}${NC}"
echo -e "GUI Admin Credentials:"
echo -e "  Username: ${YELLOW}${ADMIN_USER}${NC}"
echo -e "  Password: ${YELLOW}${ADMIN_PASS}${NC}"
echo -e "API Endpoint: ${YELLOW}https://${WAPP_HOST}/api/${NC}"
echo -e "Your results will be saved in: ${YELLOW}${SHARED_PATH}${NC}"
echo ""
echo -e "${CYAN}Management CLI available:${NC}"
echo -e "  Check status:   ${GREEN}./wfapp.sh status${NC}"
echo -e "  View logs:      ${GREEN}./wfapp.sh logs${NC}"
echo -e "  Verify health:  ${GREEN}./wfapp.sh verify${NC}"
echo -e "  Restart stack:  ${GREEN}./wfapp.sh restart${NC}"
echo ""

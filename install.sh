#!/bin/bash

# WFAPP Automated Installation Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}======================================================${NC}"
echo -e "${GREEN}      WFAPP (Windows Forensic Artifacts Parser)      ${NC}"
echo -e "${GREEN}            Automated Installation Script            ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo ""

# 1. Check for Docker
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}[!] Docker is not installed.${NC}"
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
    echo -e "${GREEN}[+] .env file already exists. We will update the core parameters.${NC}"
fi

read -p "Enter WAPP API HOST (Default: wapp.localhost): " WAPP_HOST_INPUT
WAPP_HOST=${WAPP_HOST_INPUT:-wapp.localhost}

DEFAULT_SHARED_PATH="$HOME/Documents/shared_results"
read -p "Enter Shared Folder Path for Results (Default: $DEFAULT_SHARED_PATH): " SHARED_PATH_INPUT
SHARED_PATH=${SHARED_PATH_INPUT:-$DEFAULT_SHARED_PATH}

read -p "Enter number of parallel workers (Default: 1): " WORKER_COUNT_INPUT
WORKER_COUNT=${WORKER_COUNT_INPUT:-1}

# Create shared directory if it doesn't exist
mkdir -p "$SHARED_PATH"

# Function to update or append variables in .env
update_env() {
    local key=$1
    local value=$2
    if grep -q "^${key}=" .env; then
        # Use sed to replace existing line (handling paths safely)
        sed -i "s|^${key}=.*|${key}=${value}|" .env
    else
        echo "${key}=${value}" >> .env
    fi
}

update_env "WAPP_API_HOST" "$WAPP_HOST"
update_env "SHARED_FOLDER_PATH" "$SHARED_PATH"
update_env "WORKER_COUNT" "$WORKER_COUNT"

echo -e "${GREEN}[+] Configuration saved to .env${NC}"

# 3. Load Images and Run
if [ -f images.tar ]; then
    echo -e "\n${GREEN}--- Offline Mode Detected (images.tar found) ---${NC}"
    echo -e "[+] Loading Docker images from images.tar..."
    docker load -i images.tar
    echo -e "[+] Starting containers..."
    docker compose up -d
else
    echo -e "\n${GREEN}--- Online Mode: Building and Starting Containers ---${NC}"
    echo -e "Running: docker compose up --build -d"
    docker compose up --build -d
fi

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}      Installation Complete!                         ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "You can access the Web GUI at: ${YELLOW}https://${WAPP_HOST}${NC}"
echo -e "API Endpoint: ${YELLOW}https://${WAPP_HOST}/api/${NC}"
echo -e "Your results will be saved in: ${YELLOW}${SHARED_PATH}${NC}"
echo ""
echo -e "To verify the installation, run:"
echo -e "  curl -k https://${WAPP_HOST}/api/"

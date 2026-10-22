#!/bin/bash

# WFAPP Management & Control CLI
# Handy tool to manage WFAPP services in online and offline environments.

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# Compose binary detection
if docker compose version &>/dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo -e "${RED}[-] Neither 'docker compose' nor 'docker-compose' was found.${NC}"
    exit 1
fi

# Load environment variables if available
if [ -f .env ]; then
    # shellcheck disable=SC1091
    source <(grep -E '^[A-Za-z0-9_]+=' .env | sed 's/\r$//') 2>/dev/null || true
fi

WAPP_HOST="${WAPP_API_HOST:-wapp.localhost}"
SHARED_PATH="${SHARED_FOLDER_PATH:-$HOME/Documents/shared_results}"

show_help() {
    echo -e "${CYAN}======================================================${NC}"
    echo -e "${CYAN}           WFAPP Management Script (CLI)              ${NC}"
    echo -e "${CYAN}======================================================${NC}"
    echo ""
    echo -e "Usage: ${GREEN}./wfapp.sh [COMMAND] [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Commands:${NC}"
    echo -e "  ${GREEN}start${NC}           Start all WFAPP containers in background"
    echo -e "  ${GREEN}stop${NC}            Stop all WFAPP containers"
    echo -e "  ${GREEN}restart${NC}         Restart all WFAPP containers"
    echo -e "  ${GREEN}status | ps${NC}     Display status of all containers"
    echo -e "  ${GREEN}logs [service]${NC}  View live logs (e.g. ./wfapp.sh logs wapp_worker)"
    echo -e "  ${GREEN}verify${NC}          Run end-to-end health check and connectivity test"
    echo -e "  ${GREEN}create-admin${NC}    Add or reset an admin user account"
    echo -e "  ${GREEN}scale <count>${NC}   Scale worker count (e.g. ./wfapp.sh scale 3)"
    echo -e "  ${GREEN}ingest [opts]${NC}   Trigger bulk ingestion scan (e.g. ./wfapp.sh ingest -c MY_CASE)"
    echo -e "  ${GREEN}help${NC}            Show this help message"
    echo ""
}

cmd_start() {
    echo -e "${GREEN}[+] Starting WFAPP services...${NC}"
    # Ensure external network exists if referenced in docker-compose.yml
    if ! docker network inspect shared_sec_net &>/dev/null; then
        echo -e "${YELLOW}[!] Creating shared_sec_net network...${NC}"
        docker network create shared_sec_net >/dev/null || true
    fi
    $COMPOSE_CMD up -d
    echo -e "${GREEN}[+] Services started successfully.${NC}"
    echo -e "Web GUI: ${YELLOW}https://${WAPP_HOST}${NC}"
    echo -e "API:     ${YELLOW}https://${WAPP_HOST}/api/${NC}"
}

cmd_stop() {
    echo -e "${YELLOW}[+] Stopping WFAPP services...${NC}"
    $COMPOSE_CMD down
    echo -e "${GREEN}[+] All services stopped.${NC}"
}

cmd_restart() {
    echo -e "${YELLOW}[+] Restarting WFAPP services...${NC}"
    $COMPOSE_CMD restart
    echo -e "${GREEN}[+] All services restarted.${NC}"
}

cmd_status() {
    echo -e "${CYAN}--- WFAPP Containers Status ---${NC}"
    $COMPOSE_CMD ps
}

cmd_logs() {
    shift || true
    $COMPOSE_CMD logs -f "$@"
}

cmd_scale() {
    local count=${1:-1}
    echo -e "${GREEN}[+] Scaling wapp_worker to ${count} instances...${NC}"
    $COMPOSE_CMD up -d --scale wapp_worker="$count"
    echo -e "${GREEN}[+] Scaled successfully.${NC}"
}

cmd_create_admin() {
    shift || true
    echo -e "${CYAN}--- GUI Admin Account Setup ---${NC}"
    if [ $# -ge 2 ]; then
        $COMPOSE_CMD exec wapp_api flask create-admin "$@"
    else
        read -p "Username: " admin_user
        read -s -p "Password: " admin_pass
        echo ""
        if [ -z "$admin_user" ] || [ -z "$admin_pass" ]; then
            echo -e "${RED}[-] Username and password cannot be empty.${NC}"
            exit 1
        fi
        $COMPOSE_CMD exec wapp_api flask create-admin --username "$admin_user" --password "$admin_pass"
    fi
}

cmd_ingest() {
    shift || true
    echo -e "${CYAN}--- WFAPP Bulk Ingestion ---${NC}"
    local target_svc="wapp_watcher"
    if ! $COMPOSE_CMD ps --status running -q wapp_watcher 2>/dev/null | grep -q .; then
        target_svc="wapp_worker"
    fi
    $COMPOSE_CMD exec "$target_svc" python3 /python-docker/bulk_ingest.py "$@"
}

cmd_verify() {
    echo -e "${CYAN}======================================================${NC}"
    echo -e "${CYAN}          WFAPP System Verification & Health          ${NC}"
    echo -e "${CYAN}======================================================${NC}"
    echo ""

    local all_ok=true

    # 1. Containers state
    echo -e "${YELLOW}[1/4] Checking Docker containers...${NC}"
    local running_containers
    running_containers=$($COMPOSE_CMD ps --status running -q 2>/dev/null | wc -l)
    if [ "$running_containers" -ge 4 ]; then
        echo -e "${GREEN}[✓] Containers running: ${running_containers}${NC}"
    else
        echo -e "${RED}[✗] Expected at least 4 running containers, found: ${running_containers}${NC}"
        $COMPOSE_CMD ps
        all_ok=false
    fi

    # 2. Shared folder check
    echo -e "\n${YELLOW}[2/4] Checking shared directory: ${SHARED_PATH}...${NC}"
    if [ -d "$SHARED_PATH" ]; then
        if [ -w "$SHARED_PATH" ]; then
            echo -e "${GREEN}[✓] Shared folder exists and is writable.${NC}"
        else
            echo -e "${RED}[✗] Shared folder exists but is NOT writable.${NC}"
            all_ok=false
        fi
    else
        echo -e "${RED}[✗] Shared folder does not exist!${NC}"
        all_ok=false
    fi

    # 3. Traefik and API HTTP Endpoint
    echo -e "\n${YELLOW}[3/4] Testing API endpoint (https://127.0.0.1/api/ with Host: ${WAPP_HOST})...${NC}"
    local http_response
    http_response=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Host: ${WAPP_HOST}" https://127.0.0.1/api/ 2>/dev/null || echo "000")
    if [ "$http_response" = "200" ]; then
        echo -e "${GREEN}[✓] API is responding correctly (HTTP 200).${NC}"
    else
        echo -e "${RED}[✗] API check failed with status: ${http_response}${NC}"
        echo -e "    Check container logs with: ./wfapp.sh logs wapp_api"
        all_ok=false
    fi

    # 4. Redis connection
    echo -e "\n${YELLOW}[4/5] Testing Redis broker...${NC}"
    if $COMPOSE_CMD exec -T redis redis-cli ping 2>/dev/null | grep -q "PONG"; then
        echo -e "${GREEN}[✓] Redis broker is healthy (PONG).${NC}"
    else
        echo -e "${RED}[✗] Redis broker check failed.${NC}"
        all_ok=false
    fi

    # 5. Bulk Ingestion Folder
    local bulk_path="${BULK_DEPOT_FOLDER_PATH:-$SHARED_PATH/bulk_ingest}"
    echo -e "\n${YELLOW}[5/5] Checking bulk ingestion folder: ${bulk_path}...${NC}"
    if [ ! -d "$bulk_path" ]; then
        mkdir -p "$bulk_path" 2>/dev/null || true
    fi
    if [ -d "$bulk_path" ] && [ -w "$bulk_path" ]; then
        echo -e "${GREEN}[✓] Bulk ingestion directory is ready and writable.${NC}"
    else
        echo -e "${RED}[✗] Bulk ingestion directory issue (${bulk_path}).${NC}"
        all_ok=false
    fi

    echo ""
    if [ "$all_ok" = true ]; then
        echo -e "${GREEN}======================================================${NC}"
        echo -e "${GREEN}       All checks passed! WFAPP is operational.       ${NC}"
        echo -e "${GREEN}======================================================${NC}"
        echo -e "Web GUI URL: ${YELLOW}https://${WAPP_HOST}${NC}"
        echo -e "Bulk folder: ${YELLOW}${bulk_path}${NC}"
    else
        echo -e "${RED}======================================================${NC}"
        echo -e "${RED}    Some checks failed. Inspect logs for details:    ${NC}"
        echo -e "${RED}    ./wfapp.sh logs                                   ${NC}"
        echo -e "${RED}======================================================${NC}"
    fi
}

# Main Command Dispatcher
COMMAND="${1:-help}"
case "$COMMAND" in
    start)
        cmd_start
        ;;
    stop)
        cmd_stop
        ;;
    restart)
        cmd_restart
        ;;
    status|ps)
        cmd_status
        ;;
    logs)
        cmd_logs "$@"
        ;;
    scale)
        cmd_scale "$2"
        ;;
    ingest)
        cmd_ingest "$@"
        ;;
    create-admin)
        cmd_create_admin "$@"
        ;;
    verify)
        cmd_verify
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}[-] Unknown command: $COMMAND${NC}"
        show_help
        exit 1
        ;;
esac

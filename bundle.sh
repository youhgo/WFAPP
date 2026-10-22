#!/bin/bash

# WFAPP Production Offline Bundling Script
# This script bundles all required Docker images, configs, and application code
# into a verified, standalone archive for air-gapped / offline deployments.

set -e

# ANSI Color Codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Default settings
SKIP_BUILD=false
SKIP_PULL=false
NO_ARCHIVE=false
SPLIT_SIZE=""
OUTPUT_DIR="$SCRIPT_DIR"
DIST_NAME="wfapp_offline_dist"
ARCHIVE_NAME="wfapp_offline.tar.gz"

show_help() {
    echo -e "${CYAN}======================================================${NC}"
    echo -e "${CYAN}      WFAPP Offline Bundling Script - Help            ${NC}"
    echo -e "${CYAN}======================================================${NC}"
    echo ""
    echo -e "Usage: ${GREEN}./bundle.sh [OPTIONS]${NC}"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  ${GREEN}-h, --help${NC}              Show this help message and exit"
    echo -e "  ${GREEN}--skip-build${NC}            Skip building local images ('docker compose build')"
    echo -e "  ${GREEN}--skip-pull${NC}             Skip pulling external images ('docker compose pull')"
    echo -e "  ${GREEN}--no-archive${NC}            Do not tar the distribution; leave the folder uncompressed"
    echo -e "  ${GREEN}--split <SIZE>${NC}          Split final archive into chunks (e.g., 2000M, 2G for FAT32 USB)"
    echo -e "  ${GREEN}--output-dir <DIR>${NC}      Destination directory for output bundle (default: current dir)"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  ./bundle.sh"
    echo -e "  ./bundle.sh --skip-build --skip-pull"
    echo -e "  ./bundle.sh --split 2000M"
    echo -e "  ./bundle.sh --output-dir /media/usb"
    echo ""
}

# Parse CLI options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-pull)
            SKIP_PULL=true
            shift
            ;;
        --no-archive)
            NO_ARCHIVE=true
            shift
            ;;
        --split)
            if [ -z "$2" ] || [[ "$2" == --* ]]; then
                echo -e "${RED}[-] Error: --split requires a size argument (e.g. 2000M, 2G).${NC}"
                exit 1
            fi
            SPLIT_SIZE="$2"
            shift 2
            ;;
        --output-dir)
            if [ -z "$2" ] || [[ "$2" == --* ]]; then
                echo -e "${RED}[-] Error: --output-dir requires a directory path.${NC}"
                exit 1
            fi
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}[-] Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

echo -e "${GREEN}======================================================${NC}"
echo -e "${GREEN}      WFAPP Offline Bundling Pipeline                ${NC}"
echo -e "${GREEN}======================================================${NC}"
echo ""

# -------------------------------------------------------------
# 0. Pre-flight Checks
# -------------------------------------------------------------
echo -e "${CYAN}[Pre-flight] Checking environment & requirements...${NC}"

# Check Docker
if ! command -v docker &>/dev/null; then
    echo -e "${RED}[-] Docker is not installed or not in PATH.${NC}"
    exit 1
fi

if ! docker info &>/dev/null; then
    echo -e "${RED}[-] Docker daemon is not running or current user lacks permission.${NC}"
    exit 1
fi

# Check Docker Compose
if docker compose version &>/dev/null; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    echo -e "${RED}[-] Neither 'docker compose' nor 'docker-compose' was found.${NC}"
    exit 1
fi

# Detect fast compressor (pigz) or standard gzip
if command -v pigz &>/dev/null; then
    COMPRESS_CMD="pigz -c"
    TAR_COMPRESS_OPT="--use-compress-program=pigz"
    echo -e "${GREEN}[✓] Multi-threaded compression tool 'pigz' detected.${NC}"
else
    COMPRESS_CMD="gzip -c"
    TAR_COMPRESS_OPT="-z"
    echo -e "${YELLOW}[!] 'pigz' not found. Falling back to standard 'gzip'.${NC}"
fi

# Destination path
mkdir -p "$OUTPUT_DIR"
DIST_PATH="${OUTPUT_DIR}/${DIST_NAME}"
ARCHIVE_PATH="${OUTPUT_DIR}/${ARCHIVE_NAME}"

# Check available disk space
FREE_KB=$(df -k "$OUTPUT_DIR" | awk 'NR==2 {print $4}')
FREE_GB=$(( FREE_KB / 1024 / 1024 ))
echo -e "Free disk space in target directory: ${YELLOW}${FREE_GB} GB${NC}"
if [ "$FREE_GB" -lt 5 ]; then
    echo -e "${RED}[-] Error: At least 5 GB of free disk space is required to bundle images (found ${FREE_GB} GB).${NC}"
    exit 1
elif [ "$FREE_GB" -lt 10 ]; then
    echo -e "${YELLOW}[!] Warning: Less than 10 GB free space. Proceeding with on-the-fly streaming compression to optimize space.${NC}"
fi

# -------------------------------------------------------------
# 1. Build and Pull Docker Images
# -------------------------------------------------------------
if [ "$SKIP_BUILD" = true ]; then
    echo -e "\n${YELLOW}[1/6] Skipping image build (--skip-build specified).${NC}"
else
    echo -e "\n${GREEN}[1/6] Building local Docker images...${NC}"
    $COMPOSE_CMD build
fi

if [ "$SKIP_PULL" = true ]; then
    echo -e "\n${YELLOW}[2/6] Skipping image pull (--skip-pull specified).${NC}"
else
    echo -e "\n${GREEN}[2/6] Pulling external Docker images...${NC}"
    $COMPOSE_CMD pull
fi

# -------------------------------------------------------------
# 2. Extract and Validate Image List
# -------------------------------------------------------------
echo -e "\n${GREEN}[3/6] Discovering and validating required Docker images...${NC}"

# Extract images dynamically from compose configuration
DYNAMIC_IMAGES=()
while IFS= read -r img; do
    [ -n "$img" ] && DYNAMIC_IMAGES+=("$img")
done < <($COMPOSE_CMD config --images 2>/dev/null | grep -v '^WARN' | sort -u)

# Default fallback list of mandatory images
MANDATORY_IMAGES=(
    "traefik:latest"
    "redis:7-alpine"
    "wapp-api"
    "wapp-frontend"
    "wapp-worker"
    "timberio/vector:latest-alpine"
)

# Merge and deduplicate
ALL_IMAGES=($(printf "%s\n" "${DYNAMIC_IMAGES[@]}" "${MANDATORY_IMAGES[@]}" | sort -u))

echo -e "Target Docker images to bundle:"
MISSING_IMAGES=()
FINAL_IMAGE_LIST=()

for img in "${ALL_IMAGES[@]}"; do
    if docker image inspect "$img" &>/dev/null; then
        echo -e "  ${GREEN}[✓] Found:${NC} $img"
        FINAL_IMAGE_LIST+=("$img")
    else
        # Try appending :latest if no tag was specified
        if [[ "$img" != *":"* ]] && docker image inspect "${img}:latest" &>/dev/null; then
            echo -e "  ${GREEN}[✓] Found:${NC} ${img}:latest"
            FINAL_IMAGE_LIST+=("${img}:latest")
        else
            echo -e "  ${RED}[✗] Missing:${NC} $img"
            MISSING_IMAGES+=("$img")
        fi
    fi
done

if [ ${#MISSING_IMAGES[@]} -gt 0 ]; then
    echo -e "\n${RED}[-] The following required images are missing from local Docker storage:${NC}"
    for m in "${MISSING_IMAGES[@]}"; do
        echo -e "    - $m"
    done
    echo -e "${RED}[-] Please run './bundle.sh' without --skip-build and --skip-pull.${NC}"
    exit 1
fi

# -------------------------------------------------------------
# 3. Prepare Offline Distribution Directory Structure
# -------------------------------------------------------------
echo -e "\n${GREEN}[4/6] Preparing offline directory: ${DIST_PATH}...${NC}"
rm -rf "$DIST_PATH"
mkdir -p "$DIST_PATH"

# Setup automatic cleanup on error
cleanup_on_error() {
    echo -e "\n${RED}[!] Bundling interrupted or failed. Cleaning up temporary files...${NC}"
    rm -rf "$DIST_PATH"
}
trap cleanup_on_error ERR

# -------------------------------------------------------------
# 4. Stream and Save Docker Images (Compressed On-the-Fly)
# -------------------------------------------------------------
IMAGES_TAR_GZ="${DIST_PATH}/images.tar.gz"
echo -e "\n${GREEN}[5/6] Exporting Docker images directly into compressed archive...${NC}"
echo -e "Running: docker save ${FINAL_IMAGE_LIST[*]} | compression..."

START_TIME=$(date +%s)
docker save "${FINAL_IMAGE_LIST[@]}" | $COMPRESS_CMD > "$IMAGES_TAR_GZ"
END_TIME=$(date +%s)
DURATION=$(( END_TIME - START_TIME ))

if [ ! -s "$IMAGES_TAR_GZ" ]; then
    echo -e "${RED}[-] Error: Failed to generate images.tar.gz or file is empty.${NC}"
    exit 1
fi

IMG_SIZE=$(du -h "$IMAGES_TAR_GZ" | cut -f1)
echo -e "${GREEN}[✓] Images exported and compressed in ${DURATION}s (Size: ${IMG_SIZE}).${NC}"

# -------------------------------------------------------------
# 5. Copy Configuration, Code & Support Files
# -------------------------------------------------------------
echo -e "\n${GREEN}[6/6] Packaging project files and dependencies...${NC}"

# Copy core configuration files
cp docker-compose.yml "$DIST_PATH/"
cp .env.exemple "$DIST_PATH/"
cp install.sh "$DIST_PATH/"
cp wfapp.sh "$DIST_PATH/"
chmod +x "$DIST_PATH/install.sh" "$DIST_PATH/wfapp.sh"

# Copy Traefik certificates & Vector configurations
if [ -d dependencies ]; then
    cp -r dependencies "$DIST_PATH/"
fi

# Copy APPEngine/WAPP_MODULE and bulk_ingest.py (excluding bytecode and pycache)
echo -e "  -> Copying core parsing module (APPEngine/WAPP_MODULE & bulk_ingest.py)..."
mkdir -p "$DIST_PATH/APPEngine"
if [ -f APPEngine/bulk_ingest.py ]; then
    cp APPEngine/bulk_ingest.py "$DIST_PATH/APPEngine/"
fi
if command -v rsync &>/dev/null; then
    rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' APPEngine/WAPP_MODULE "$DIST_PATH/APPEngine/"
else
    cp -r APPEngine/WAPP_MODULE "$DIST_PATH/APPEngine/"
    find "$DIST_PATH/APPEngine/WAPP_MODULE" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$DIST_PATH/APPEngine/WAPP_MODULE" -type f -name "*.pyc" -delete 2>/dev/null || true
fi

# Ensure api/db directory exists with placeholder
mkdir -p "$DIST_PATH/api/db"
if [ -f api/db/.gitkeep ]; then
    cp api/db/.gitkeep "$DIST_PATH/api/db/"
else
    touch "$DIST_PATH/api/db/.gitkeep"
fi

# Copy custom SIEM dashboards if present
if [ -d ressources/wazuh_dashboards ]; then
    mkdir -p "$DIST_PATH/ressources"
    cp -r ressources/wazuh_dashboards "$DIST_PATH/ressources/"
fi

# Generate self-contained README_OFFLINE.md
cat << 'EOF' > "$DIST_PATH/README_OFFLINE.md"
# WFAPP - Offline Deployment Package

This standalone package allows deploying WFAPP in air-gapped or network-restricted environments with zero external internet dependencies.

---

## 1. Quick Installation

1. Ensure **Docker** and **Docker Compose** are installed on this offline host.
2. From this folder (`wfapp_offline_dist`), execute the automated installer:
   ```bash
   sudo ./install.sh
   ```
3. The installer will:
   - Detect `images.tar.gz` and load the local Docker images.
   - Automatically initialize the required Docker networks (`shared_sec_net`).
   - Create required data directories with safe permissions.
   - Configure `.env` and set up the GUI admin credentials.
   - Start all containers in offline mode.

---

## 2. Managing the Application (`./wfapp.sh`)

A convenient control CLI (`wfapp.sh`) is provided for operations:

- **Start services:** `./wfapp.sh start`
- **Stop services:** `./wfapp.sh stop`
- **Restart services:** `./wfapp.sh restart`
- **Check container status:** `./wfapp.sh status`
- **View live logs:** `./wfapp.sh logs` or `./wfapp.sh logs wapp_worker`
- **Run health checks:** `./wfapp.sh verify`
- **Add / Reset admin user:** `./wfapp.sh create-admin`

---

## 3. Web Interface & Endpoints

- **Web GUI:** `https://<WAPP_API_HOST>` (Default: `https://wapp.localhost`)
- **API Status:** `curl -k https://<WAPP_API_HOST>/api/`
- **Default shared results folder:** `$HOME/Documents/shared_results`

---

## 4. Integrity Verification

To verify that files in this package were not corrupted during transfer:
```bash
sha256sum -c CHECKSUMS.sha256
```

EOF

# Generate internal checksums
echo -e "  -> Generating SHA-256 checksums inside bundle..."
(cd "$DIST_PATH" && find . -type f ! -name "CHECKSUMS.sha256" -exec sha256sum {} + | sort -k 2 > CHECKSUMS.sha256)

# -------------------------------------------------------------
# 6. Final Compression & Split Packaging
# -------------------------------------------------------------
if [ "$NO_ARCHIVE" = true ]; then
    echo -e "\n${YELLOW}[!] --no-archive specified. Leaving uncompressed folder at: ${DIST_PATH}${NC}"
else
    echo -e "\n${GREEN}Packaging final distribution into ${ARCHIVE_PATH}...${NC}"
    rm -f "${ARCHIVE_PATH}" "${ARCHIVE_PATH}.part_"* "${ARCHIVE_PATH}.sha256"

    # Tar the distribution folder
    tar $TAR_COMPRESS_OPT -cf "$ARCHIVE_PATH" -C "$OUTPUT_DIR" "$DIST_NAME"
    rm -rf "$DIST_PATH"

    # Generate root SHA256
    echo -e "Generating package checksum..."
    (cd "$OUTPUT_DIR" && sha256sum "$ARCHIVE_NAME" > "${ARCHIVE_NAME}.sha256")

    # Handle split option if requested
    if [ -n "$SPLIT_SIZE" ]; then
        echo -e "\n${CYAN}Splitting archive into chunks of ${SPLIT_SIZE}...${NC}"
        split -b "$SPLIT_SIZE" -d -a 2 "$ARCHIVE_PATH" "${ARCHIVE_PATH}.part_"
        (cd "$OUTPUT_DIR" && sha256sum "${ARCHIVE_NAME}.part_"* > "${ARCHIVE_NAME}.parts.sha256")
        echo -e "${GREEN}[✓] Archive split into parts successfully.${NC}"
    fi
fi

# Reset trap
trap - ERR

# -------------------------------------------------------------
# 7. Final Report
# -------------------------------------------------------------
echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}      Bundling Completed Successfully!                ${NC}"
echo -e "${GREEN}======================================================${NC}"

if [ "$NO_ARCHIVE" = true ]; then
    echo -e "Distribution folder: ${YELLOW}${DIST_PATH}${NC}"
else
    FINAL_SIZE=$(du -h "$ARCHIVE_PATH" | cut -f1)
    SHA256_HASH=$(cut -d ' ' -f 1 "${ARCHIVE_PATH}.sha256")
    echo -e "Archive:     ${YELLOW}${ARCHIVE_PATH}${NC} (${FINAL_SIZE})"
    echo -e "SHA256:      ${CYAN}${SHA256_HASH}${NC}"
    echo -e "Checksum file: ${ARCHIVE_PATH}.sha256"

    if [ -n "$SPLIT_SIZE" ]; then
        echo -e "\n${YELLOW}Split Parts Generated:${NC}"
        ls -lh "${ARCHIVE_PATH}.part_"*
        echo -e "\nTo reassemble on the offline host, run:"
        echo -e "  ${GREEN}cat ${ARCHIVE_NAME}.part_* > ${ARCHIVE_NAME}${NC}"
        echo -e "  ${GREEN}sha256sum -c ${ARCHIVE_NAME}.sha256${NC}"
    fi

    echo -e "\n${BLUE}Deployment instructions on the offline server:${NC}"
    echo -e "  1. Copy ${YELLOW}${ARCHIVE_NAME}${NC} (and .sha256) to the server"
    echo -e "  2. Verify:  ${GREEN}sha256sum -c ${ARCHIVE_NAME}.sha256${NC}"
    echo -e "  3. Extract: ${GREEN}tar -xzf ${ARCHIVE_NAME}${NC}"
    echo -e "  4. Install: ${GREEN}cd wfapp_offline_dist && sudo ./install.sh${NC}"
fi

echo ""

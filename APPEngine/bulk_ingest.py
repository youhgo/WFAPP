#!/usr/bin/env python3
"""
WFAPP Bulk Ingestion & Hot-Folder Watcher
Monitors a shared directory for forensic archives (DFIR-ORC, ZIP, 7Z, TAR, GZ),
validates file transfer completion, organizes cases automatically,
and dispatches analysis tasks directly to Celery workers.
"""

import os
import sys
import time
import json
import shutil
import signal
import argparse
from pathlib import Path
from datetime import datetime

# Add current directory to Python path to import Celery tasks
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from tasks import parse_archive, get_machine_name, SHARED_FOLDER_PATH
except ImportError as e:
    # Fallback if imported from outside container
    SHARED_FOLDER_PATH = "/python-docker/shared_files/"
    parse_archive = None
    get_machine_name = lambda ctx, fn: os.path.splitext(fn)[0]


# ANSI Colors for terminal logs
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
RED = "\033[0;31m"
NC = "\033[0m"

SUPPORTED_EXTENSIONS = {".zip", ".7z", ".tar", ".gz", ".tgz"}
IGNORED_DIR_NAMES = {"_processed", "_failed", "_incoming", ".processed", ".failed", "__pycache__"}
INCOMPLETE_EXTENSIONS = {".tmp", ".crdownload", ".part", ".filepart", ".lock", ".uploading"}


def log(msg, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if level == "INFO":
        color = GREEN
    elif level == "WARN":
        color = YELLOW
    elif level == "ERROR":
        color = RED
    else:
        color = CYAN
    print(f"[{timestamp}] {color}[{level}]{NC} {msg}", flush=True)


def resolve_bulk_directory(custom_path=None):
    """
    Resolves the bulk ingest path inside the Docker container.
    Gracefully handles host paths, container paths, and relative paths.
    """
    if custom_path:
        p = Path(custom_path)
        if p.exists():
            return p.resolve()

    raw = os.environ.get("BULK_DEPOT_FOLDER_PATH", "").strip().strip('"').strip("'")
    shared_host = os.environ.get("SHARED_FOLDER_PATH", "").strip().strip('"').strip("'")
    container_shared = Path(SHARED_FOLDER_PATH)

    if not raw:
        return container_shared / "bulk_ingest"

    # If user provided a path inside the container
    if raw.startswith("/python-docker/"):
        return Path(raw)

    # If user provided the host path matching SHARED_FOLDER_PATH
    if shared_host and raw.startswith(shared_host):
        relative_part = raw[len(shared_host):].lstrip("/")
        return container_shared / relative_part

    if "shared_files/" in raw:
        relative_part = raw.split("shared_files/")[-1]
        return container_shared / relative_part

    # Relative directory name or generic subfolder
    return container_shared / raw.lstrip("/")


class BulkIngester:
    def __init__(self, bulk_dir, default_case="Auto_Bulk", default_type="ORC",
                 stability_seconds=5, default_config_path=None, dry_run=False):
        self.bulk_dir = Path(bulk_dir)
        self.default_case = default_case
        self.default_type = default_type
        self.stability_seconds = stability_seconds
        self.default_config_path = default_config_path
        self.dry_run = dry_run
        
        # Track file stability: {str(file_path): (last_size, last_mtime, first_stable_time)}
        self.file_tracker = {}

        # Ensure root bulk directory exists
        self.bulk_dir.mkdir(parents=True, exist_ok=True)

    def load_case_config(self, case_dir):
        """
        Loads configuration for a case.
        Checks for a case-specific config.json first, then falls back to default.
        """
        case_config_file = case_dir / "config.json"
        if case_config_file.is_file():
            try:
                with open(case_config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    log(f"Loaded case-specific config from {case_config_file}", "INFO")
                    return data
            except Exception as e:
                log(f"Failed to parse case config {case_config_file}: {e}", "WARN")

        if self.default_config_path and Path(self.default_config_path).is_file():
            try:
                with open(self.default_config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                log(f"Failed to parse default config {self.default_config_path}: {e}", "WARN")

        return {}

    def is_file_stable(self, file_path):
        """
        Verifies that an archive has finished being written by an external tool
        (SMB, SFTP, rsync, copy) by checking size and mtime stability.
        """
        try:
            stat = file_path.stat()
            current_size = stat.st_size
            current_mtime = stat.st_mtime
        except (FileNotFoundError, PermissionError):
            return False

        if current_size == 0:
            return False  # Empty file or being created

        if self.stability_seconds <= 0:
            return True

        key = str(file_path.resolve())
        now = time.time()

        if key not in self.file_tracker:
            self.file_tracker[key] = (current_size, current_mtime, now)
            return False

        last_size, last_mtime, first_stable_time = self.file_tracker[key]

        if current_size != last_size or current_mtime != last_mtime:
            # File is actively changing! Reset timer
            self.file_tracker[key] = (current_size, current_mtime, now)
            return False

        # File size and mtime have been identical
        elapsed = now - first_stable_time
        if elapsed >= self.stability_seconds:
            # File is stable!
            del self.file_tracker[key]
            return True

        return False

    def scan_and_ingest(self, force_case=None):
        """
        Performs a full scan of the bulk directory and dispatches stable archives.
        Returns the number of archives dispatched.
        """
        if not self.bulk_dir.exists():
            return 0

        dispatched_count = 0

        # Scan all files recursively
        for root, dirs, files in os.walk(self.bulk_dir):
            root_path = Path(root)

            # Skip processed/failed/hidden directories
            dirs[:] = [d for d in dirs if d not in IGNORED_DIR_NAMES and not d.startswith(".")]

            for filename in files:
                file_path = root_path / filename

                # Check extension
                suffix = file_path.suffix.lower()
                if suffix in INCOMPLETE_EXTENSIONS:
                    continue
                if suffix not in SUPPORTED_EXTENSIONS:
                    continue

                # Determine case name and relative folder hierarchy
                relative_to_bulk = file_path.relative_to(self.bulk_dir)
                parts = relative_to_bulk.parts

                if force_case:
                    case_name = force_case
                    case_root = self.bulk_dir / force_case
                elif len(parts) > 1:
                    # File is inside a subfolder, e.g. bulk_ingest/CASE_NAME/host.7z
                    case_name = parts[0]
                    case_root = self.bulk_dir / parts[0]
                else:
                    # File is at the root of bulk_ingest/
                    case_name = self.default_case
                    case_root = self.bulk_dir

                # In watch mode, verify stability before dispatching
                if not self.is_file_stable(file_path):
                    continue

                log(f"Ready for ingestion: {file_path.name} -> Case: '{case_name}'", "INFO")

                if self.dry_run:
                    log(f"[DRY-RUN] Would dispatch {file_path.name} to Celery", "CYAN")
                    dispatched_count += 1
                    continue

                # Prepare destination processed folder inside the case directory
                processed_dir = case_root / "_processed"
                processed_dir.mkdir(parents=True, exist_ok=True)
                dest_file_path = processed_dir / filename

                # Handle duplicate filenames in _processed by appending a timestamp if needed
                if dest_file_path.exists():
                    stem = file_path.stem
                    dest_file_path = processed_dir / f"{stem}_{int(time.time())}{suffix}"

                try:
                    # Move archive to _processed before dispatching
                    shutil.move(str(file_path), str(dest_file_path))
                except Exception as e:
                    log(f"Failed to move {file_path} to {dest_file_path}: {e}", "ERROR")
                    continue

                # Build task payload
                config_data = self.load_case_config(case_root)
                machine_name = get_machine_name({}, dest_file_path.name)
                
                # Detect archive type (ORC vs UAC vs Legacy)
                archive_type = self.default_type
                if "UAC" in dest_file_path.name.upper():
                    archive_type = "UAC"
                elif "ORC" in dest_file_path.name.upper():
                    archive_type = "ORC"

                content = {
                    "caseName": case_name,
                    "machineName": machine_name,
                    "archiveType": archive_type,
                    "parser_config": config_data.get("parser_config", config_data),
                    "artefact_config": config_data.get("artefact_config", {}),
                    "source_folder": str(processed_dir.absolute())
                }

                if parse_archive:
                    try:
                        task = parse_archive.delay(content, dest_file_path.name)
                        log(f"Dispatched Celery task {task.id} for machine '{machine_name}' (Case: {case_name})", "INFO")
                        dispatched_count += 1
                    except Exception as e:
                        log(f"Failed to dispatch Celery task: {e}", "ERROR")
                        # Move to _failed for visibility
                        failed_dir = case_root / "_failed"
                        failed_dir.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(dest_file_path), str(failed_dir / dest_file_path.name))
                else:
                    log(f"parse_archive task not available (outside Celery environment)", "WARN")

        return dispatched_count


def run_watcher(ingester, interval=15):
    """
    Runs the continuous watcher loop until interrupted.
    """
    log("======================================================", "CYAN")
    log("      WFAPP Bulk Ingestion Watcher Started            ", "CYAN")
    log(f"Watching directory: {ingester.bulk_dir}", "CYAN")
    log(f"Scan interval:      {interval}s", "CYAN")
    log(f"Stability check:    {ingester.stability_seconds}s", "CYAN")
    log("======================================================", "CYAN")

    running = True

    def sig_handler(signum, frame):
        nonlocal running
        log("Shutdown signal received. Stopping watcher cleanly...", "WARN")
        running = False

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    while running:
        # Check if enabled via env
        enabled = os.environ.get("BULK_WATCHER_ENABLED", "true").lower() in ("true", "1", "yes")
        if not enabled:
            time.sleep(interval)
            continue

        try:
            count = ingester.scan_and_ingest()
            if count > 0:
                log(f"Batch completed: {count} archive(s) dispatched to Celery.", "INFO")
        except Exception as e:
            log(f"Unexpected error during scan cycle: {e}", "ERROR")

        time.sleep(interval)

    log("WFAPP Bulk Ingestion Watcher stopped.", "CYAN")


def main():
    parser = argparse.ArgumentParser(
        description="WFAPP Bulk Ingestion & Hot-Folder Watcher"
    )
    parser.add_argument(
        "-d", "--directory",
        help="Directory to monitor (defaults to resolved BULK_DEPOT_FOLDER_PATH)."
    )
    parser.add_argument(
        "-c", "--case",
        help="Force a specific Case Name for all discovered files (overrides folder-based auto-detection)."
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Run continuously in background watcher daemon mode."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Execute a single immediate scan and exit."
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(os.environ.get("BULK_SCAN_INTERVAL", "15")),
        help="Scan interval in seconds for watcher mode (default: 15s)."
    )
    parser.add_argument(
        "--stability",
        type=int,
        default=int(os.environ.get("BULK_STABILITY_TIME", "5")),
        help="Time in seconds a file size must remain stable before ingestion (default: 5s)."
    )
    parser.add_argument(
        "-cfg", "--config",
        help="Path to default JSON configuration file."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate scan without moving files or dispatching tasks."
    )

    args = parser.parse_args()

    bulk_dir = resolve_bulk_directory(args.directory)
    default_case = os.environ.get("BULK_DEFAULT_CASE", "Auto_Bulk")
    default_type = os.environ.get("BULK_DEFAULT_TYPE", "ORC")

    # If --once, set stability to 0 to ingest files immediately unless explicitly set
    stability = 0 if args.once and args.stability == 5 else args.stability

    ingester = BulkIngester(
        bulk_dir=bulk_dir,
        default_case=default_case,
        default_type=default_type,
        stability_seconds=stability,
        default_config_path=args.config,
        dry_run=args.dry_run
    )

    if args.watch:
        run_watcher(ingester, interval=args.interval)
    else:
        log(f"Running one-shot bulk scan on: {bulk_dir}", "INFO")
        count = ingester.scan_and_ingest(force_case=args.case)
        log(f"One-shot ingestion finished. Dispatched {count} archive(s).", "INFO")


if __name__ == "__main__":
    main()

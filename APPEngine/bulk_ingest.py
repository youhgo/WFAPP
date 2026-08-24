#!/usr/bin/env python3
import os
import sys
import json
import argparse
from pathlib import Path

# Add APPEngine to sys.path so we can import tasks
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from tasks import parse_archive, get_machine_name, BULK_DEPOT_FOLDER_PATH

def main():
    parser = argparse.ArgumentParser(description="Bulk Ingester for WFAPP - Dispatches archives to Celery workers directly.")
    parser.add_argument("-d", "--directory", required=False, default=BULK_DEPOT_FOLDER_PATH, help="Directory containing the archives (defaults to BULK_DEPOT_FOLDER_PATH).")
    parser.add_argument("-c", "--case", required=True, help="Case name for the analysis.")
    parser.add_argument("-cfg", "--config", required=False, help="Path to the JSON config file to use (e.g., config.json).")
    
    args = parser.parse_args()
    
    config_data = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config_data = json.load(f)
            print(f"[+] Loaded config from {args.config}")
        except Exception as e:
            print(f"[-] Could not load config file {args.config}: {e}")
            sys.exit(1)
    else:
        print("[*] No config provided, using default empty configuration (all plugins enabled).")
        
    directory = Path(args.directory)
    if not directory.exists():
        directory.mkdir(parents=True, exist_ok=True)
        print(f"[+] Created missing bulk directory: {directory}")
        
    print(f"[*] Scanning {directory} for archives...")
    count = 0
    
    for file_path in directory.rglob("*"):
        if file_path.is_file() and file_path.suffix.lower() in [".zip", ".7z", ".tar", ".gz"]:
            file_name = file_path.name
            
            # Try to build content
            content = {
                "caseName": args.case,
                "machineName": get_machine_name({}, file_name),
                "archiveType": "ORC" if "ORC" in file_name.upper() else "UNKNOWN",
                "parser_config": config_data.get("parser_config", config_data),
                "artefact_config": config_data.get("artefact_config", {}),
                "source_folder": str(directory.absolute())
            }
            
            # The Celery worker expects the file to be located in DEPOT_FOLDER_PATH
            # If the user provides a nested directory inside depot, we pass the relative path
            # But the standard is just the file name if it's placed in the root of depot.
            
            print(f"[*] Dispatching task for: {file_name} (Machine: {content['machineName']})")
            
            # Dispatch to Celery queue asynchronously
            parse_archive.delay(content, file_name)
            count += 1
            
    print(f"[+] Bulk ingestion complete. Dispatched {count} tasks to the Celery workers.")

if __name__ == "__main__":
    main()

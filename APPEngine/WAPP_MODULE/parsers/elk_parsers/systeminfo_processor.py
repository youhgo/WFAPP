#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
from datetime import datetime
from .base_processor import BaseFileProcessor


from ...classes.elk_registry import register_elk_processor

@register_elk_processor("system_info")
class SystemInfoProcessor(BaseFileProcessor):
    """Processeur pour les fichiers systeminfo (format CSV)."""
    DEFAULT_PATTERNS = {
        r'^Systeminfo.*\.csv$': "system_info"
    }

    def __init__(self, case_name="unknown", machine_name="unknown"):
        super().__init__(case_name, machine_name)

    def _format_sysinfo_timestamp(self, time_str: str) -> str:
        """
        Convertit les dates type '9/18/2019, 10:07:59 AM' en format ISO 8601.
        """
        if not time_str or time_str == "N/A":
            return None
        try:
            # Adaptation au format CSV Windows (M/D/Y, H:M:S AM/PM)
            dt = datetime.strptime(time_str, "%m/%d/%Y, %I:%M:%S %p")
            return dt.isoformat() + "Z"
        except (ValueError, TypeError):
            try:
                # Fallback si jamais le format change (ex: format FR)
                dt = datetime.strptime(time_str, "%d/%m/%Y, %H:%M:%S")
                return dt.isoformat() + "Z"
            except:
                return None

    def _process_log(self, raw_log: dict) -> dict:
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Mapping des colonnes CSV vers le standard ECS (Elastic Common Schema)
        # Note : On utilise les noms exacts des colonnes de ton CSV
        host_name = raw_log.get("Host Name", "Unknown")
        os_name = raw_log.get("OS Name", "Unknown")
        os_version = raw_log.get("OS Version", "Unknown")

        base_doc = {
            "@timestamp": timestamp,
            "event": {
                "kind": "state",
                "category": "host",
                "dataset": "system_info",
                "original": json.dumps(raw_log)
            },
            "host": {
                "hostname": host_name,
                "name": host_name,
                "domain": raw_log.get("Domain"),
                "os": {
                    "name": os_name,
                    "version": os_version,
                    "full": f"{os_name} {os_version}"
                }
            },
            "system_info": {
                "manufacturer": raw_log.get("System Manufacturer"),
                "model": raw_log.get("System Model"),
                "system_type": raw_log.get("System Type"),
                "bios_version": raw_log.get("BIOS Version"),
                "boot_time": self._format_sysinfo_timestamp(raw_log.get("System Boot Time")),
                "install_date": self._format_sysinfo_timestamp(raw_log.get("Original Install Date")),
                "timezone": raw_log.get("Time Zone"),
                "processors": raw_log.get("Processor(s)"),
                "memory": {
                    "total": raw_log.get("Total Physical Memory"),
                    "available": raw_log.get("Available Physical Memory")
                },
                "network_cards": raw_log.get("Network Card(s)"),
                "hotfixes": raw_log.get("Hotfix(s)")
            }
        }

        if hasattr(self, 'inject_wapp_info'):
            return self.inject_wapp_info(base_doc)
        return base_doc

    def process_file(self, filepath: str, **kwargs):
        print(f"  -> Lecture du fichier SystemInfo (CSV) : {filepath}")

        # Utilisation de cp850 pour gérer d'éventuels encodages Windows FR
        with open(filepath, 'r', encoding='cp850', errors='ignore') as f:
            try:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    try:
                        yield self._process_log(row), "system_info"
                    except Exception as e:
                        print(f"[Attention] Erreur ligne {i + 1} dans {filepath}: {e}")

            except Exception as e:
                print(f"[ERREUR] Impossible de lire le CSV {filepath}. Erreur: {e}")
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from datetime import datetime
from .base_processor import BaseFileProcessor

class LnkJsonProcessor(BaseFileProcessor):
    """Processeur pour les fichiers LNK (format JSON complet)."""
    def _format_lnk_timestamp(self, time_str: str) -> str:
        if not time_str: return None
        try: return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
        except (ValueError, TypeError):
            try: return datetime.fromisoformat(time_str.replace("Z", "+00:00")).isoformat() + "Z"
            except (ValueError, TypeError): return None

    def _get_valid_timestamp(self, raw_log: dict) -> str:
        header = raw_log.get("header", {})
        for key in ["modified_time", "accessed_time", "creation_time"]:
            ts = self._format_lnk_timestamp(header.get(key))
            if ts: return ts
        return datetime.utcnow().isoformat() + "Z"

    def _process_log(self, raw_log: dict) -> dict:
        final_timestamp = self._get_valid_timestamp(raw_log)
        header, data, extra = raw_log.get("header", {}), raw_log.get("data", {}), raw_log.get("extra", {})
        target_path = extra.get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK", {}).get("target_unicode") or extra.get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK", {}).get("target_ansi")
        return {
            "@timestamp": final_timestamp,
                "event": { "kind": "event",
                           "category": "file", "dataset": "lnk",
                           "original": json.dumps(raw_log) },
                "file": { "path": target_path,
                          "size": header.get("file_size"),
                          "directory": data.get("working_directory"),
                          "lnk": {
                              "description": data.get("description"),
                              "icon_location": data.get("icon_location"),
                              "flags": header.get("link_flags"),
                              "creation_time": self._format_lnk_timestamp(header.get("creation_time")),
                              "modified_time": self._format_lnk_timestamp(header.get("modified_time")),
                              "accessed_time": self._format_lnk_timestamp(header.get("accessed_time")) }
                          }
                }

    def process_file(self, filepath: str, **kwargs):
        print(f"  -> Lecture du fichier LNK (JSON complet) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]
                for i, record in enumerate(records):
                    try:
                        if "header" in record and "extra" in record: yield self._process_log(record), "lnk"
                    except Exception as e: print(f"\n[Attention] Impossible de traiter l'enregistrement LNK #{i+1} du fichier {filepath}. Erreur: {e}\n")
            except json.JSONDecodeError as e: print(f"[ERREUR] Le fichier {filepath} n'est pas un JSON valide. Erreur: {e}")

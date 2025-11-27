#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoAppCompatCacheProcessor(BaseEventProcessor):
    """Processeur Plaso pour les événements AppCompatCache (winreg/appcompatcache)."""

    def __init__(self):
        print("  [*] Initialisation du processeur AppCompatCache")

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement AppCompatCache de Plaso."""
        try:
            # 1. Gestion du Timestamp
            # Le 'date_time' (FILETIME) représente le LastWriteTime de la clé,
            # ce qui est le timestamp le plus fiable pour cet artefact.
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                event["estimestamp"] = self._format_dt_to_es(dt_filetime)
            else:
                # Fallback sur le timestamp plaso (moins probable d'être utile ici)
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                event["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 2. Nettoyage
            # Les champs 'path' et 'cached_entry_type' seront conservés.
            self.drop_useless_fields(event)

            # 3. Clé d'index
            return event, "appcompatcache"

        except Exception as e:
            # print(f"[ERREUR] Échec de process_appcompatcache_event: {e}")
            return self.drop_useless_fields(event), "appcompatcache"
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoUserAssistProcessor(BaseEventProcessor):
    """Processeur Plaso pour les événements UserAssist (winreg/userassist)."""

    def __init__(self):
        print("  [*] Initialisation du processeur UserAssist")

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement UserAssist de Plaso."""
        try:
            # 1. Gestion du Timestamp
            # Pour UserAssist, le 'timestamp' (Unix Micro) de Plaso
            # représente le "dernier temps d'exécution", ce qui est le plus pertinent.
            # Nous allons prioriser le FILETIME (LastWriteTime) s'il existe,
            # sinon, utiliser le timestamp de l'événement.

            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))

            if dt_filetime:
                event["estimestamp"] = self._format_dt_to_es(dt_filetime)

            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                event["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 2. Renommer le descripteur de timestamp
            if "timestamp_desc" in event:
                event["userassist_timestamp_type"] = event.pop("timestamp_desc")

            # 3. Nettoyage
            self.drop_useless_fields(event)

            # 4. Clé d'index
            return event, "userassist"

        except Exception as e:
            # print(f"[ERREUR] Échec de process_userassist_event: {e}")
            return self.drop_useless_fields(event), "userassist"
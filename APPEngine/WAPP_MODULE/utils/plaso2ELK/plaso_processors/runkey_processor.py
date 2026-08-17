#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoRunKeyProcessor(BaseEventProcessor):
    """Processeur Plaso pour les clés de persistance Run/RunOnce (winreg/windows_run)."""

    def __init__(self):
        print("  [*] Initialisation du processeur RunKeys")

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement Run Key de Plaso."""
        try:
            # 1. Gestion du Timestamp
            # Le 'date_time' (FILETIME) représente le LastWriteTime de la clé.
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                event["estimestamp"] = self._format_dt_to_es(dt_filetime)
            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                event["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 2. Nettoyage
            # Le champ 'values' (contenant le nom et la data de la clé) sera conservé.
            self.drop_useless_fields(event)

            # 3. Clé d'index
            # Router vers un index dédié pour la persistance.
            return event, "runkey"

        except Exception as e:
            # print(f"[ERREUR] Échec de process_runkey_event: {e}")
            return self.drop_useless_fields(event), "runkey"
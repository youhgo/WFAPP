#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoGenericProcessor(BaseEventProcessor):
    """
    Processeur Plaso générique pour les événements 'other'.
    Regroupe tous les événements non traités dans un index unique "others"
    et stocke l'événement brut en tant que chaîne pour éviter tout conflit de mapping.
    """

    def __init__(self):
        print("  [*] Initialisation du processeur Générique (Mode: Raw String)")

    def process_event(self, event: dict) -> (dict, str):
        """
        Traite un événement générique de Plaso en le stockant comme une chaîne brute.
        """
        try:
            # 1. Créer un nouveau document propre
            processed_doc = {}

            # 2. Gestion du Timestamp (meilleur effort)
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                processed_doc["estimestamp"] = self._format_dt_to_es(dt_filetime)
            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                processed_doc["estimestamp"] = self._format_dt_to_es(dt_plaso)

            processed_doc["data_type"] = event.get("data_type")
            processed_doc["parser"] = event.get("parser")
            # Clé spécifique rétablie
            index_key = "other"

            return processed_doc, index_key

        except Exception as e:
            # print(f"[ERREUR] Échec de process_generic_event: {e}")
            return {"message": f"Generic processing failed: {e}", "raw_event": event.get("event_raw_string")}, "other"
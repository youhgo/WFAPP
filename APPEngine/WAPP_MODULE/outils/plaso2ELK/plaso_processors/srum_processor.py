#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoSrumProcessor(BaseEventProcessor):
    """
    Processeur Plaso pour les événements SRUM (esedb/srum).
    APPROCHE "FORCE STRING" :
    Convertit tous les champs (sauf le timestamp) en string pour
    garantir l'absence de conflits de mapping Elasticsearch.
    """

    def __init__(self):
        print("  [*] Initialisation du processeur SRUM (Mode: Force String)")

    def process_event(self, event: dict) -> (dict, str):
        """
        Traite un événement SRUM de Plaso.
        Convertit tous les champs (sauf timestamp) en string.
        """
        try:
            # 1. Créer un nouveau document propre (approche "whitelist")
            processed_doc = {}

            # 2. Gestion du Timestamp (conserve le type date)
            ole_timestamp = event.get("date_time", {}).get("timestamp")
            dt_ole = self._parse_ole_automation_date_to_dt(ole_timestamp)

            if dt_ole:
                processed_doc["estimestamp"] = self._format_dt_to_es(dt_ole)
            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                processed_doc["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 3. Liste des champs Plaso internes à ignorer (ne pas inclure)
            plaso_fields_to_drop = [
                "__container_type__", "__type__", "date_time",
                "_event_values_hash", "display_name", "inode",
                "pathspec", "strings", "xml_string", "event_version",
                "message_identifier", "offset", "provider_identifier",
                "recovered", "timestamp"
            ]

            # 4. Boucle de conversion en chaîne (le cœur de la solution)
            for key, value in event.items():

                # Ignorer les champs de la liste de suppression
                if key in plaso_fields_to_drop:
                    continue

                # Ignorer le timestamp (déjà traité)
                if key == "estimestamp":
                    continue

                # Ignorer les valeurs nulles
                if value is None:
                    continue

                processed_doc[key] = str(value)

            # 5. Clé d'index - Clé spécifique rétablie
            index_key = 'srum'

            return processed_doc, index_key

        except Exception as e:
            # print(f"[ERREUR] Échec de process_srum_event: {e}")
            return {"message": f"SRUM parsing failed: {e}"}, "srum"
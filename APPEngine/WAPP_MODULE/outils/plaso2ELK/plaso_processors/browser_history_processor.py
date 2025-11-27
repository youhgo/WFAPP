#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta, timezone
from .base_processor import BaseEventProcessor


class PlasoBrowserHistoryProcessor(BaseEventProcessor):
    """
    Processeur Plaso pour les événements d'historique de navigation (Chrome, Firefox, Edge).
    Confine les champs spécifiques dans des sous-objets pour éviter les conflits de mapping.
    """

    def __init__(self):
        print("  [*] Initialisation du processeur Browser History")

    def process_event(self, event: dict) -> (dict, str):
        """
        Traite un événement d'historique de navigation de Plaso.
        """
        try:
            # 1. Créer un nouveau document propre
            processed_doc = {}

            # 2. Gestion du Timestamp
            # Chrome/Edge utilisent WebKitTime (Microsecondes depuis 1601-01-01)
            # La fonction _parse_filetime_to_dt divise par 10 (car FILETIME est en 100ns), ce qui fausse WebKitTime.
            # Nous devons traiter WebKitTime spécifiquement.

            date_time_obj = event.get("date_time", {})
            timestamp_val = date_time_obj.get("timestamp")
            class_name = date_time_obj.get("__class_name__", "")

            dt_obj = None

            if timestamp_val:
                if class_name == "WebKitTime":
                    # WebKitTime: Microsecondes depuis 1601-01-01
                    try:
                        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                        dt_obj = epoch + timedelta(microseconds=timestamp_val)
                    except Exception:
                        dt_obj = None
                else:
                    # Tentative générique (souvent FILETIME ou autre)
                    # Si ce n'est pas WebKitTime, on peut essayer le FILETIME standard
                    # ou se replier sur le timestamp Plaso.
                    dt_obj = self._parse_filetime_to_dt(timestamp_val)

            if dt_obj:
                processed_doc["estimestamp"] = self._format_dt_to_es(dt_obj)
            else:
                # Fallback sur le timestamp normalisé par Plaso (Unix Microseconds)
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                processed_doc["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 3. Analyser le 'data_type' pour le confinement
            # Ex: "chrome:history:file_downloaded"
            data_type = event.get("data_type", "unknown:unknown")
            parts = data_type.split(':')

            browser = "unknown"
            event_type = "unknown"

            if len(parts) >= 2:
                browser = parts[0]
                event_type = ":".join(parts[1:])  # Ex: 'history:file_downloaded'

            processed_doc["browser"] = browser
            processed_doc["event_type"] = event_type

            # 4. Liste des champs Plaso internes à ignorer (whitelist)
            plaso_fields_to_drop = [
                "__container_type__", "__type__", "date_time",
                "_event_values_hash", "display_name", "inode",
                "pathspec", "strings", "xml_string", "event_version",
                "message_identifier", "offset", "provider_identifier",
                "recovered", "timestamp", "estimestamp", "data_type",
                "event_raw_string", "parser", "query"
            ]

            # 5. Créer le sous-objet "confiné"
            # Clé basée sur le type d'événement (ex: 'history:file_downloaded')
            # Remplacer les ':' par '_' pour une clé JSON plus propre
            confined_key = event_type.replace(':', '_')
            processed_doc[confined_key] = {}

            for key, value in event.items():
                if key not in plaso_fields_to_drop:
                    processed_doc[confined_key][key] = value

            # 6. Ajouter la source brute
            processed_doc["event_raw_string"] = event.get("event_raw_string")

            # 7. Clé d'index
            index_key = 'browser_history'

            return processed_doc, index_key

        except Exception as e:
            # print(f"[ERREUR] Échec de process_browser_history_event: {e}")
            return {"message": f"BrowserHistory parsing failed: {e}"}, "browser_history_other"
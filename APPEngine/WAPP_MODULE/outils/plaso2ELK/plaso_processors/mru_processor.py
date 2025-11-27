#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from .base_processor import BaseEventProcessor


class PlasoMruProcessor(BaseEventProcessor):
    """
    Processeur Plaso pour les listes MRU (winreg/bagmru, winreg/mrulistex).
    Dénormalise un événement MRU contenant plusieurs entrées en
    un document Elasticsearch pour CHAQUE entrée.
    """

    def __init__(self):
        print("  [*] Initialisation du processeur MRU")
        # Regex pour extraire les champs clés de l'entrée MRU
        # Exemple d'entrée : "Index: 1 [MRU Value 5]: Path: OUTPUTS, Shell item: [OUTPUTS.lnk]"
        self.entry_regex = re.compile(
            r'Index: (?P<mru_index>\d+)\s+\[MRU Value (?P<mru_value>\d+)\]:\s+'
            r'Path:\s+(?P<mru_path>.*?),\s+'
            r'Shell item:\s+\[(?P<shell_item>.*?)\]'
        )
        self.index_key = "mru"

    def process_event(self, event: dict):
        """
        Traite un événement MRU de Plaso.
        Retourne un générateur de documents (dict, str).
        """
        try:
            # 1. Calcul du Timestamp unique
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                es_timestamp = self._format_dt_to_es(dt_filetime)
            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                es_timestamp = self._format_dt_to_es(dt_plaso)

            # 2. Champs de base à conserver pour chaque entrée
            base_doc = {
                "estimestamp": es_timestamp,
                "key_path": event.get("key_path"),
                "filename": event.get("filename"),
                "parser": event.get("parser"),
                "data_type": event.get("data_type"),
                "timestamp_desc": event.get("timestamp_desc"),
                "event_raw_string": event.get("event_raw_string")  # Conserver la ligne brute si nécessaire
            }

            entries = event.get("entries", [])

            # Si 'entries' n'est pas une liste ou est vide, générer l'événement brut une seule fois
            if not isinstance(entries, list) or not entries:
                self.drop_useless_fields(event)
                yield event, self.index_key
                return

            # 3. Génération des documents individuels
            for entry_line in entries:
                match = self.entry_regex.match(entry_line)

                # Créer un clone du document de base
                processed_doc = base_doc.copy()

                if match:
                    # Extraction des données via regex
                    data = match.groupdict()
                    processed_doc.update({
                        "mru_index": int(data.get("mru_index")),
                        "mru_value_order": int(data.get("mru_value")),  # L'ordre d'utilisation
                        "mru_path": data.get("mru_path"),
                        "mru_shell_item": data.get("shell_item")
                    })
                else:
                    # Fallback si le format n'est pas standard (conserver la ligne brute de l'entrée)
                    processed_doc["mru_raw_entry"] = entry_line

                # Générer le document traité avec la clé spécifique MRU
                yield processed_doc, self.index_key

        except Exception as e:
            # En cas d'échec critique du parsing MRU, renvoyer l'événement brut
            error_doc = {"message": f"MRU denormalization failed: {e}", "raw_event": event.get("event_raw_string")}
            yield error_doc, self.index_key  # Utilise 'mru' comme clé d'artefact pour les erreurs
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoAmcacheProcessor(BaseEventProcessor):
    """
    Processeur Plaso pour les événements Amcache (winreg/amcache).
    """

    def __init__(self):
        print("  [*] Initialisation du processeur Amcache")

    def process_event(self, event: dict) -> (dict, str):
        """
        Traite un événement Amcache de Plaso.
        """
        try:
            # Amcache utilise souvent 'time_elements_tuple' au lieu d'un timestamp Unix standard
            time_tuple = event.get("date_time", {}).get("time_elements_tuple")
            dt = self._parse_time_elements_to_dt(time_tuple)

            # Si le parsing du tuple échoue, on tente le timestamp Unix standard (souvent présent en fallback)
            if not dt:
                dt = self._parse_unix_micro_to_dt(event.get("timestamp"))

            # Si on a toujours pas de date valide, on utilise une date par défaut ou None
            # (Elasticsearch mettra la date d'ingestion ou rejettera selon le mapping,
            # mais _format_dt_to_es gère None en renvoyant None)

            event["estimestamp"] = self._format_dt_to_es(dt)

            self.drop_useless_fields(event)

            # Clé spécifique correcte
            index_key = 'amcache'
            return event, index_key

        except Exception as e:
            # En cas d'erreur, on renvoie un doc d'erreur explicite mais toujours tagué 'amcache'
            # pour qu'il aille dans le bon index (process) et non 'others'
            error_doc = {
                "message": f"Amcache parsing failed: {e}",
                "raw_event_line": event.get("event_raw_string"),
                "parser": "winreg/amcache",
                "artefact_type": "amcache"  # Force le type pour le filtrage
            }
            # On retourne 'amcache' pour qu'il aille dans l'index 'process'
            return error_doc, "amcache"
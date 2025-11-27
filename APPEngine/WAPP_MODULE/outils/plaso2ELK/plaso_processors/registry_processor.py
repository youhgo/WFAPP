#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from .base_processor import BaseEventProcessor


class PlasoRegistryProcessor(BaseEventProcessor):
    """
    Processeur Plaso pour les événements de Registre (winreg).
    MODIFIÉ: Dénormalise les événements winreg_default (qui contiennent la liste 'values')
    ET parse les configurations spécifiques comme TimeZoneInformation.
    """

    def __init__(self):
        print("  [*] Initialisation du processeur Registre")
        self.HIVE_FILE_MAP = {
            r'SOFTWARE': "software",
            r'SYSTEM': "system",
            r'SECURITY': "security",
            r'SAM': "sam",
            r'NTUSER\.DAT': "ntuser",
            r'UsrClass\.dat': "usrclass"
        }
        # Regex pour parser la chaîne de configuration TimeZone (Clé: Valeur)
        self.tz_config_regex = re.compile(r'([a-zA-Z0-9]+):\s*([^:]+)(?=\s+[a-zA-Z0-9]+:|$)')

    def get_specific_hive_type(self, original_filename):
        if not original_filename: return None
        for pattern, log_type in self.HIVE_FILE_MAP.items():
            if re.search(pattern, original_filename, re.IGNORECASE):
                return log_type
        return None

    def process_event(self, event: dict):  # -> (dict, str) ou Generator
        """
        Traite un événement de Registre de Plaso. Retourne un générateur de documents (dict, str).
        """

        # 1. Pré-traitement du Timestamp et de la Hive
        try:
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                es_timestamp = self._format_dt_to_es(dt_filetime)
            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                es_timestamp = self._format_dt_to_es(dt_plaso)

            filename = event.get("filename", "")
            specific_type = self.get_specific_hive_type(filename)

            base_doc = {
                "estimestamp": es_timestamp,
                "key_path": event.get("key_path"),
                "filename": filename,
                "parser": event.get("parser"),
                "data_type": event.get("data_type"),
                "hive_type": specific_type if specific_type else "unknown_hive"
            }

            values = event.get("values")
            configuration = event.get("configuration")

            # 2. Cas de Dénormalisation (Liste de valeurs - winreg_default)
            if isinstance(values, list) and len(values) > 0:
                event.pop("values", None)
                for value_entry in values:
                    if not isinstance(value_entry, dict):
                        continue
                    processed_doc = base_doc.copy()
                    processed_doc["reg_value_name"] = value_entry.get("name")
                    processed_doc["reg_value_data"] = value_entry.get("data")
                    processed_doc["reg_value_type"] = value_entry.get("data_type")
                    # Optionnel : Inclure le message global si nécessaire (sans troncature)
                    # processed_doc["message"] = event.get("message", "")
                    self.drop_useless_fields(processed_doc)
                    yield processed_doc, "hive"
                return

            # 3. Cas de Dénormalisation Spécifique (TimeZone Configuration)
            # Si on a une chaîne 'configuration' mais pas de 'values', on tente de la parser
            if configuration and isinstance(configuration, str) and "TimeZoneKeyName" in configuration:
                matches = self.tz_config_regex.findall(configuration)
                if matches:
                    for key, value in matches:
                        processed_doc = base_doc.copy()
                        processed_doc["reg_value_name"] = key.strip()
                        processed_doc["reg_value_data"] = value.strip()
                        processed_doc["reg_value_type"] = "ConfigString"  # Type artificiel
                        self.drop_useless_fields(processed_doc)
                        yield processed_doc, "hive"
                    return

            # 4. Cas Standard (Clé simple sans liste 'values')
            # Dans ce cas, nous renvoyons simplement l'événement de clé unique
            # mais nous conservons le message/configuration s'il est important

            if configuration:
                base_doc["reg_configuration_raw"] = configuration

            # On garde le message s'il n'est pas vide (SANS TRONCATURE)
            if event.get("message"):
                base_doc["message"] = event.get("message")

            event.pop("value_data", None)
            event.pop("value_type", None)

            event.update(base_doc)
            self.drop_useless_fields(event)

            return event, "hive"

        except Exception as e:
            error_doc = {
                "message": f"Registry key parsing failed: {e}",
                "raw_event_line": event.get("event_raw_string")
            }
            return error_doc, "hive"
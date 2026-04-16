#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
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
            r'UsrClass\.dat': "usrclass",
            r"MuiCache": "muicache"
        }
        # Regex pour parser la chaîne de configuration TimeZone (Clé: Valeur)
        self.tz_config_regex = re.compile(r'([a-zA-Z0-9]+):\s*([^:]+)(?=\s+[a-zA-Z0-9]+:|$)')

    def _get_hive_name_from_path(self, original_filename: str) -> str:
        if not original_filename:
            return "unknown_hive"
        file_name = os.path.basename(original_filename)
        return os.path.splitext(file_name)[0]

    def get_specific_hive_type(self, original_filename: str) -> str:
        if not original_filename:
            return None

        for pattern, log_type in self.HIVE_FILE_MAP.items():
            if re.search(pattern, original_filename, re.IGNORECASE):
                return log_type

        return self._get_hive_name_from_path(original_filename)

    def process_event(self, event: dict):
        """
        Traite un événement de Registre de Plaso.
        Générateur : yield systématiquement un tuple (document, index_key).
        """
        try:
            # 1. Gestion du Timestamp
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                es_timestamp = self._format_dt_to_es(dt_filetime)
            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                es_timestamp = self._format_dt_to_es(dt_plaso)

            # 2. Identification de la ruche (Hive)
            filename = event.get("filename", "")
            key_path = event.get("key_path", "")
            specific_type = None

            if isinstance(key_path, str) and "muicache" in key_path.lower():
                specific_type = "muicache"

            if not specific_type:
                specific_type = self.get_specific_hive_type(filename)

            # 3. Création du document de base
            base_doc = {
                "estimestamp": es_timestamp,
                "key_path": key_path,
                "filename": filename,
                "parser": event.get("parser"),
                "data_type": event.get("data_type"),
                "hive_type": specific_type or "unknown_hive"
            }

            values = event.get("values")
            configuration = event.get("configuration")

            # 4. Scénario A : Dénormalisation d'une liste de valeurs
            if isinstance(values, list) and values:
                for value_entry in values:
                    if not isinstance(value_entry, dict):
                        continue
                    processed_doc = base_doc.copy()
                    processed_doc["reg_value_name"] = value_entry.get("name")
                    processed_doc["reg_value_data"] = value_entry.get("data")
                    processed_doc["reg_value_type"] = value_entry.get("data_type")
                    self.drop_useless_fields(processed_doc)

                    yield processed_doc, "hive"
                return  # On quitte le générateur après avoir traité la liste

            # 5. Scénario B : Parsing de la configuration TimeZone
            if isinstance(configuration, str) and "TimeZoneKeyName" in configuration:
                matches = self.tz_config_regex.findall(configuration)
                if matches:
                    for key, value in matches:
                        processed_doc = base_doc.copy()
                        processed_doc["reg_value_name"] = key.strip()
                        processed_doc["reg_value_data"] = value.strip()
                        processed_doc["reg_value_type"] = "ConfigString"
                        self.drop_useless_fields(processed_doc)

                        yield processed_doc, "hive"
                    return  # On quitte le générateur

            # 6. Scénario par défaut (Événement unique)
            if configuration:
                base_doc["reg_configuration_raw"] = configuration

            if event.get("message"):
                base_doc["message"] = event.get("message")

            # Nettoyage de l'événement original avant fusion
            for key in ["values", "value_data", "value_type"]:
                event.pop(key, None)

            event.update(base_doc)
            self.drop_useless_fields(event)

            yield event, "hive"

        except Exception as e:
            error_doc = {
                "message": f"Registry key parsing failed: {e}",
                "raw_event_line": event.get("event_raw_string")
            }
            yield error_doc, "hive"
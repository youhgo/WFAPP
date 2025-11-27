#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoUsbProcessor(BaseEventProcessor):
    """Processeur Plaso pour les artefacts USB (winreg/windows_usb_devices)."""

    def __init__(self):
        print("  [*] Initialisation du processeur USB Devices")

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement USB de Plaso."""
        try:
            # 1. Gestion du Timestamp
            # Le 'date_time' (FILETIME) est le LastWriteTime de la clé de périphérique.
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                event["estimestamp"] = self._format_dt_to_es(dt_filetime)
            else:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                event["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 2. Nettoyage
            # Les champs 'key_path', 'device_type', 'serial_number' etc. seront conservés.
            self.drop_useless_fields(event)

            # 3. Clé d'index
            return event, "usb"

        except Exception as e:
            # print(f"[ERREUR] Échec de process_usb_event: {e}")
            return self.drop_useless_fields(event), "usb"
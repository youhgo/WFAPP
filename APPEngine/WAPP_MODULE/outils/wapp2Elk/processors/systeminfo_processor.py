#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from datetime import datetime
from .base_processor import BaseFileProcessor


class SystemInfoProcessor(BaseFileProcessor):
    """Processeur pour les fichiers systeminfo (format JSON)."""

    def _format_sysinfo_timestamp(self, time_str: str) -> str:
        """Convertit les dates au format '30/03/2026, 09:33:22' en format ISO 8601."""
        if not time_str or time_str == "N/A":
            return None
        try:
            # Parsing du format français généré par systeminfo
            dt = datetime.strptime(time_str, "%d/%m/%Y, %H:%M:%S")
            return dt.isoformat() + "Z"
        except (ValueError, TypeError):
            return None

    def _process_log(self, raw_log: dict) -> dict:
        # Puisqu'il s'agit d'un instantané de l'état du système (et pas d'un log avec une ligne de temps continue),
        # on utilise le moment de l'ingestion comme timestamp de l'événement.
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Mapping vers le standard ECS (Elastic Common Schema) pour WAZUH
        host_name = raw_log.get("Nom de l'hôte", "Unknown")
        os_name = raw_log.get("Nom du système d'exploitation", "Unknown")
        os_version = raw_log.get("Version du système", "Unknown")

        return {
            "@timestamp": timestamp,
            "event": {
                "kind": "state",
                "category": "host",
                "dataset": "system_info",
                "original": json.dumps(raw_log)
            },
            "host": {
                "hostname": host_name,
                "name": host_name,
                "domain": raw_log.get("Domaine"),
                "os": {
                    "name": os_name,
                    "version": os_version,
                    "full": f"{os_name} {os_version}"
                }
            },
            # Regroupement des données WAPP spécifiques sous une racine system_info
            "system_info": {
                "manufacturer": raw_log.get("Fabricant du système"),
                "model": raw_log.get("Modèle du système"),
                "system_type": raw_log.get("Type du système"),
                "bios_version": raw_log.get("Version du BIOS"),
                "boot_time": self._format_sysinfo_timestamp(raw_log.get("Heure de démarrage du système")),
                "install_date": self._format_sysinfo_timestamp(raw_log.get("Date d'installation originale")),
                "timezone": raw_log.get("Fuseau horaire"),
                "processors": raw_log.get("Processeur(s)"),
                "total_physical_memory": raw_log.get("Mémoire physique totale"),
                "network_cards": raw_log.get("Carte(s) réseau"),
                "hotfixes": raw_log.get("Correctif(s)")
            }
        }

    def process_file(self, filepath: str, **kwargs):
        print(f"  -> Lecture du fichier SystemInfo : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                all_data = json.load(f)
                # S'assurer qu'on itère bien sur une liste (le JSON fourni commence par `[`)
                records = all_data if isinstance(all_data, list) else [all_data]

                for i, record in enumerate(records):
                    try:
                        yield self._process_log(record), "system_info"
                    except Exception as e:
                        print(
                            f"\n[Attention] Impossible de traiter l'enregistrement SystemInfo #{i + 1} du fichier {filepath}. Erreur: {e}\n")

            except json.JSONDecodeError as e:
                print(f"[ERREUR] Le fichier {filepath} n'est pas un JSON valide. Erreur: {e}")
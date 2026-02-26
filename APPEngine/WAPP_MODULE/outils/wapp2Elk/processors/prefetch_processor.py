#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from datetime import datetime
from .base_processor import BaseFileProcessor


class PrefetchJsonProcessor(BaseFileProcessor):
    """Orchestre la lecture et le traitement des fichiers de logs Prefetch (.pf parsés en JSON)."""

    def _parse_run_time(self, timestamp_str: str) -> str:
        """Convertit un timestamp de Prefetch ('YYYY-MM-DD HH:MM:SS') en ISO8601."""
        if not timestamp_str or timestamp_str.upper() == "N/A":
            return None
        try:
            # Le format est standard, on le convertit en ISO8601 UTC
            dt_object = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            return dt_object.isoformat() + "Z"
        except ValueError:
            return None

    def _process_prefetch_record(self, record: dict, dataset: str):
        """
        Traite un enregistrement Prefetch unique et génère un document pour chaque Run Time valide.
        """
        # On travaille sur une copie pour ne pas modifier l'objet original lors de l'itération
        record_copy = record.copy()

        run_times = record_copy.pop("Run Times", {})
        executable_name = record_copy.get("Executable Name")
        original_record = json.dumps(record)

        for run_key, timestamp_str in run_times.items():
            final_timestamp = self._parse_run_time(timestamp_str)

            if final_timestamp:
                # Le nom de l'événement est le nom de l'entrée dans Run Times (ex: Run Time 0)
                event_name = run_key.replace(" ", "_")

                doc = {
                    "@timestamp": final_timestamp,
                    "event": {
                        "kind": "event",
                        "category": "process",
                        "dataset": dataset,
                        "action": "execution",
                        "type": "start",
                        "name": event_name,
                        "original": original_record
                    },
                    "process": {
                        "name": executable_name,
                        "hash": {"prefetch": record_copy.get("Prefetch Hash")},
                        "run_count": record_copy.get("Run Count")
                    },
                    "prefetch": {
                        "hash": record_copy.get("Prefetch Hash"),
                        "run_key": run_key
                    }
                }
                yield doc

    def process_file(self, filepath: str, **kwargs):
        dataset = kwargs.get("dataset")
        print(f"  -> Traitement du fichier Prefetch : {filepath} (dataset: {dataset})")

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]
                for i, record in enumerate(records):
                    if "Executable Name" in record and "Run Times" in record:
                        try:
                            for doc in self._process_prefetch_record(record, dataset):
                                yield doc, "processes"
                        except Exception as e:
                            print(
                                f"\n[Attention] Impossible de traiter l'enregistrement Prefetch #{i + 1} du fichier {filepath}. Erreur: {e}\n")

            except json.JSONDecodeError as e:
                print(f"[ERREUR] Le fichier {filepath} n'est pas un JSON valide. Erreur: {e}")
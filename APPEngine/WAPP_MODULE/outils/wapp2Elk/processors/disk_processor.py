#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import csv
from datetime import datetime, timezone  # Importation de timezone nécessaire pour la gestion de l'overflow
from .base_processor import BaseFileProcessor


class DiskProcessor(BaseFileProcessor):
    """Orchestre la lecture et le traitement des fichiers de logs disque (MFT, USN, Timeline)."""

    def _get_valid_mft_timestamp(self, raw_log: dict) -> str:
        for block, time_type in [('si_times', 'mtime'), ('si_times', 'crtime'), ('fn_times', 'mtime'),
                                 ('fn_times', 'crtime')]:
            timestamp_str = raw_log.get(block, {}).get(time_type)
            if timestamp_str:
                try:
                    datetime.strptime(timestamp_str.split('.')[0], "%Y-%m-%dT%H:%M:%S")
                    return timestamp_str
                except (ValueError, TypeError):
                    continue
        return datetime.utcnow().isoformat() + "Z"

    def _process_mft_log(self, raw_log: dict, dataset) -> dict:
        final_timestamp = self._get_valid_mft_timestamp(raw_log)
        for key in ["raw_record", "data_attribute", "data"]: raw_log.pop(key, None)
        return {"@timestamp": final_timestamp,
                "event": {"kind": "event", "category": "file", "dataset": dataset, "original": json.dumps(raw_log)},
                "file": {"name": raw_log.get("filename"), "size": raw_log.get("filesize"),
                         "record_number": raw_log.get("recordnum"), "parent_reference": raw_log.get("parent_ref"),
                         "timestamps": {"si": raw_log.get("si_times"), "fn": raw_log.get("fn_times")},
                         "flags": raw_log.get("flags")}}

    def _process_mft_file_json(self, filepath: str, dataset):
        print(f"  -> Lecture du fichier MFT (JSON complet) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]
                for i, record in enumerate(records):
                    try:
                        if "recordnum" in record and "si_times" in record:
                            yield self._process_mft_log(record, dataset), "disk"
                    except Exception as e:
                        print(
                            f"\n[Attention] Impossible de traiter l'enregistrement MFT #{i + 1} du fichier {filepath}. Erreur: {e}\n")
            except json.JSONDecodeError as e:
                print(f"[ERREUR] Le fichier {filepath} n'est pas un JSON valide. Erreur: {e}")

    def _parse_usn_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00").replace(" ", "T")).isoformat() + "Z"
        except ValueError:
            try:
                return datetime.strptime(timestamp_str.split('.')[0], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
            except ValueError:
                return datetime.utcnow().isoformat() + "Z"

    def _process_usn_row(self, row: dict, dataset) -> dict:
        original_line = ",".join(str(v) for v in row.values())
        return {"@timestamp": self._parse_usn_timestamp(row.get("TimeStamp")),
                "host": {"name": row.get("ComputerName")},
                "event": {"kind": "event", "category": "file", "dataset": dataset, "action": row.get("Reason"),
                          "original": original_line},
                "file": {"name": row.get("File"), "path": row.get("FullPath"), "attributes": row.get("FileAttributes")},
                "usn": {"usn": row.get("USN"), "frn": row.get("FRN"), "parent_frn": row.get("ParentFRN")},
                "volume": {"id": row.get("VolumeID")}}

    def _process_usn_file(self, filepath: str, dataset):
        print(f"  -> Lecture du fichier USN Journal (CSV) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                try:
                    yield self._process_usn_row(row, dataset), "disk"
                except Exception as e:
                    print(
                        f"\n[Attention] Impossible de traiter la ligne CSV #{i + 2} du fichier {filepath}. Erreur: {e}\n")

    def _parse_timeline_timestamp(self, timestamp_str: str) -> str:
        """Convertit un timestamp Unix epoch (float string) en ISO8601, gère les Overflow."""
        try:
            ts = float(timestamp_str)
            # Tentative de conversion standard (secondes.microsecondes)
            return datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except (ValueError, TypeError):
            # Si le format n'est pas bon, retourne l'heure actuelle
            return datetime.utcnow().isoformat() + "Z"
        except OverflowError:
            # Gestion de l'overflow (probablement des nanosecondes ou centièmes de nanosecondes)
            try:
                ts = float(timestamp_str)
                # Si le nombre est très grand, diviser par 1 milliard pour obtenir les secondes.
                # Ceci gère le cas où le timestamp est en nanosecondes (Plaso) ou en unités similaires.
                if ts > 1_000_000_000:
                    unix_timestamp_seconds = ts / 1_000_000_000
                    return datetime.fromtimestamp(unix_timestamp_seconds, tz=timezone.utc).isoformat().replace('+00:00',
                                                                                                               'Z')
                else:
                    # Si c'est toujours trop grand malgré une tentative de conversion
                    return datetime.utcnow().isoformat() + "Z"
            except Exception:
                # Échec de la deuxième tentative
                return datetime.utcnow().isoformat() + "Z"

    def _process_timeline_row(self, line: str, dataset: str) -> dict:
        """Traite une ligne brute séparée par des pipes (|)."""
        parts = line.strip().split('|')

        if len(parts) < 10:
            return None

        ts_raw = parts[0]
        source_type = parts[1]
        action = parts[2]
        filename = parts[7]
        inode = parts[8]

        return {
            "@timestamp": self._parse_timeline_timestamp(ts_raw),
            "event": {
                "kind": "event",
                "category": "file",
                "dataset": dataset,
                "action": action,
                "module": source_type,
                "original": line.strip()
            },
            "file": {
                "name": filename,
                "inode": inode
            }
        }

    def _process_timeline_file(self, filepath: str, dataset: str):
        print(f"  -> Lecture du fichier Timeline : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if not line.strip(): continue
                try:
                    doc = self._process_timeline_row(line, dataset)
                    if doc:
                        yield doc, "disk"
                except Exception as e:
                    print(f"\n[Attention] Erreur ligne #{i + 1} dans {filepath}: {e}\n")

    def _process_vss_file(self, filepath: str, dataset: str):
        print(f"  -> Lecture du fichier VSS (CSV) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            # DictReader va automatiquement utiliser la première ligne comme en-têtes
            # (SnapshotID, DeviceInstance, VolumeName, CreationTime, Attributes)
            reader = csv.DictReader(f)

            for i, row in enumerate(reader):
                try:
                    # On cible directement 'CreationTime'
                    creation_time_str = row.get("CreationTime")

                    # On réutilise votre parseur USN qui gère bien les formats standards
                    timestamp = self._parse_usn_timestamp(
                        creation_time_str) if creation_time_str else datetime.utcnow().isoformat() + "Z"

                    doc = {
                        "@timestamp": timestamp,
                        "event": {
                            "kind": "state",
                            "category": "host",
                            "dataset": dataset,
                            "original": ",".join(str(v) for v in row.values())
                        },
                        "vss": {
                            "snapshot_id": row.get("SnapshotID"),
                            "device_instance": row.get("DeviceInstance"),
                            "volume_name": row.get("VolumeName"),
                            "attributes": row.get("Attributes")
                        }
                    }
                    yield doc, "disk"
                except Exception as e:
                    print(f"\n[Attention] Impossible de traiter la ligne VSS #{i + 2}. Erreur: {e}\n")

    def process_file(self, filepath: str, **kwargs):
        dataset = kwargs.get("dataset")
        ds_lower = dataset.lower()
        print(f"  -> Traitement du fichier Disque : {filepath} (dataset: {dataset})")

        if ds_lower == "mft_json":
            yield from self._process_mft_file_json(filepath, dataset)
        elif ds_lower == "usnjrnl":
            yield from self._process_usn_file(filepath, dataset)
        elif ds_lower == "mft_timeline":
            yield from self._process_timeline_file(filepath, dataset)
        elif ds_lower == "disk" and "vss_list" in filepath.lower():
            yield from self._process_vss_file(filepath, dataset)
        else:
            print(f"  [Attention] Dataset disque non supporté '{dataset}' pour {filepath}. Ignoré.")
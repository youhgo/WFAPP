#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import traceback
from datetime import datetime
from .base_processor import BaseFileProcessor


class RegistryJsonProcessor(BaseFileProcessor):
    """Processeur pour les fichiers de logs Registre et Amcache générés au format JSON."""

    def _parse_yarp_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str:
            return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f").isoformat() + "Z"
        except (ValueError, TypeError):
            try:
                return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
            except ValueError:
                return datetime.utcnow().isoformat() + "Z"

    def _parse_regipy_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str:
            return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _process_generic_reg_file(self, filepath: str, dataset):
        print(f"  -> Lecture du fichier Registre (Generic) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                clean_line = line.strip()
                if not clean_line: continue
                try:
                    raw_log = json.loads(clean_line)

                    # Récupération adaptative du timestamp
                    raw_ts = raw_log.get("last_written_timestamp") or raw_log.get("last_written")
                    timestamp = self._parse_yarp_timestamp(raw_ts)

                    # 1. Création d'un dictionnaire simplifié (Nom: Data)
                    formatted_values = {}
                    values_data = raw_log.get("values")

                    if values_data:
                        # CAS A : Le bloc 'values' est un dictionnaire (Format Yarp)
                        if isinstance(values_data, dict):
                            for val_name, val_info in values_data.items():
                                if isinstance(val_info, dict):
                                    formatted_values[val_name] = val_info.get("data")
                                else:
                                    formatted_values[val_name] = val_info  # Sécurité si la donnée est déjà brute

                        # CAS B : Le bloc 'values' est une liste (Format standard / autres outils)
                        elif isinstance(values_data, list):
                            for v in values_data:
                                if isinstance(v, dict):
                                    val_name = v.get("name", "Default")
                                    val_data = v.get("data")
                                    formatted_values[val_name] = val_data

                    doc = {
                        "@timestamp": timestamp,
                        "event": {
                            "kind": "state",
                            "category": "registry",
                            "dataset": dataset,
                            "original": clean_line
                        },
                        "registry": {
                            # Récupération adaptative pour le path et ajout du name
                            "path": raw_log.get("path") or raw_log.get("key_path"),
                            "name": raw_log.get("name")
                        }
                    }

                    # Nettoyage si 'name' n'existe pas dans le log source pour ne pas envoyer null
                    if not doc["registry"]["name"]:
                        doc["registry"].pop("name", None)

                    # 2. Protection contre le Mapping Explosion :
                    # On convertit le dictionnaire en une chaîne JSON.
                    if formatted_values:
                        doc["registry"]["values_str"] = json.dumps(formatted_values, ensure_ascii=False)

                    # Renvoyer "registry" pour assurer le bon routage vers l'index ES par l'orchestrateur
                    yield doc, "registry"

                except json.JSONDecodeError:
                    print(f"\n[Attention] Ligne #{i + 1} invalide dans {filepath}\n")
                except Exception as e:
                    # Gestion d'erreur verbeuse
                    print(
                        f"\n[Attention] Impossible de traiter la ligne Registre #{i + 1}. Erreur: {type(e).__name__} - {e}")
                    print(traceback.format_exc())

    def _process_regipy_amcache_file(self, filepath: str):
        print(f"  -> Lecture du fichier Amcache (regipy) : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]

                for i, item in enumerate(records):
                    try:
                        raw_ts = item.get("timestamp") or item.get("last_written_timestamp")
                        timestamp = self._parse_regipy_timestamp(raw_ts)

                        # 1. Simplification
                        formatted_values = {}
                        values_data = item.get("values")

                        if values_data:
                            # Gestion d'Amcache qui peut parfois être sous forme de dict ou de list
                            if isinstance(values_data, dict):
                                for val_name, val_info in values_data.items():
                                    if isinstance(val_info, dict):
                                        formatted_values[val_name] = val_info.get("value")  # regipy utilise 'value'
                                    else:
                                        formatted_values[val_name] = val_info
                            elif isinstance(values_data, list):
                                for v in values_data:
                                    if isinstance(v, dict):
                                        val_name = v.get("name", "Default")
                                        val_data = v.get("value")
                                        formatted_values[val_name] = val_data

                        doc = {
                            "@timestamp": timestamp,
                            "event": {
                                "kind": "state",
                                "category": "registry",
                                "dataset": "amcache_regpy",
                                "original": json.dumps(item)
                            },
                            "registry": {
                                "path": item.get("key_path") or item.get("path"),
                                "name": item.get("name")
                            }
                        }

                        if not doc["registry"]["name"]:
                            doc["registry"].pop("name", None)

                        # 2. Protection contre le Mapping Explosion
                        if formatted_values:
                            doc["registry"]["values_str"] = json.dumps(formatted_values, ensure_ascii=False)

                        yield doc, "registry"

                    except Exception as e:
                        print(
                            f"\n[Attention] Impossible de traiter l'enregistrement Amcache #{i + 1}. Erreur: {type(e).__name__} - {e}\n")
                        print(traceback.format_exc())

            except json.JSONDecodeError as e:
                print(f"[ERREUR] Le fichier {filepath} n'est pas un JSON valide. Erreur: {e}")

    def process_file(self, filepath: str, **kwargs):
        dataset = kwargs.get("dataset")
        if not dataset:
            print(f"  [Attention] Aucun 'dataset' spécifié pour {filepath}. Fichier ignoré.")
            return

        ds_lower = dataset.lower()

        if ds_lower == 'amcache_regpy':
            yield from self._process_regipy_amcache_file(filepath)
        elif ds_lower in [
            'amcache_yarp', 'registry_security', 'registry_software',
            'registry_system', 'registry_ntuser', 'registry_ntuser.dat', 'registry_sam'
        ]:
            # Nettoyer le dataset en interne si c'est un SAM pour respecter l'ancien routage
            internal_ds = 'registry_sam' if 'sam' in ds_lower else dataset
            yield from self._process_generic_reg_file(filepath, internal_ds)
        else:
            print(f"  [Attention] Dataset '{dataset}' non reconnu pour le processeur de registre. Fichier ignoré.")
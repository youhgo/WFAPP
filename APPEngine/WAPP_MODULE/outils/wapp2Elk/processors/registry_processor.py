#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import traceback
from datetime import datetime
from .base_processor import BaseFileProcessor
import sys

from ..elk_registry import register_elk_processor

@register_elk_processor("registry")
class RegistryJsonProcessor(BaseFileProcessor):
    """Processeur pour les fichiers de logs Registre, Amcache et AppCompatCache générés au format JSON."""

    DEFAULT_PATTERNS = {
        r'^Amcache\.hve_regpy\.json$': "amcache_regpy",
        r'^Amcache\.hve_yarp\.jsonl$': "amcache_yarp",
        r'^SECURITY_yarp\.jsonl$': "registry_security",
        r'^SOFTWARE_yarp\.jsonl$': "registry_software",
        r'^SYSTEM_yarp\.jsonl$': "registry_system",
        r'^NTUSER\.DAT_yarp\.jsonl$': "registry_ntuser"
    }

    def __init__(self, case_name="unknown", machine_name="unknown"):
        super().__init__(case_name, machine_name)

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

    def _parse_yarp_appcompatcache_hex(self, hex_data: str) -> list:
        """
        Décodeur binaire pour extraire les chemins d'exécutables et horodatages
        depuis le dump hexadécimal brut (REG_BINARY) généré par YARP pour l'AppCompatCache.
        """
        parsed_entries = []
        try:
            data = bytes.fromhex(hex_data)
        except ValueError:
            return parsed_entries

        # 1. Détection et extraction via la signature Windows 10/11 ('10ts')
        offset = 0
        while offset < len(data):
            idx = data.find(b'10ts', offset)
            if idx == -1:
                break

            try:
                # Structure : 10ts (4) | Inconnu (4) | EntrySize (4) | PathLen (2) | Path (PathLen) | LastMod (8)
                path_length = int.from_bytes(data[idx + 12:idx + 14], 'little')

                # Vérification de sécurité pour éviter des lectures hors-limites
                if 0 < path_length < 2000 and idx + 14 + path_length <= len(data):
                    path_bytes = data[idx + 14:idx + 14 + path_length]
                    path_str = path_bytes.decode('utf-16le', errors='ignore')

                    # Le timestamp de modification du fichier (FILETIME) se trouve juste après le chemin
                    ts_offset = idx + 14 + path_length
                    filetime_val = int.from_bytes(data[ts_offset:ts_offset + 8], 'little')

                    last_mod = None
                    # Vérifie si le FILETIME est valide (> 1 Jan 1601)
                    if filetime_val > 116444736000000000:
                        try:
                            # Conversion FILETIME -> Unix Timestamp -> ISO
                            timestamp_s = (filetime_val - 116444736000000000) / 10000000.0
                            if 0 < timestamp_s < 253402300799:
                                last_mod = datetime.utcfromtimestamp(timestamp_s).isoformat() + "Z"
                        except Exception:
                            pass

                    parsed_entries.append({
                        "file_path": path_str,
                        "last_modified": last_mod
                    })
            except Exception:
                pass

            # On avance toujours de 4 octets pour chercher la signature suivante sereinement
            offset = idx + 4

        # 2. Fallback pour Windows 7/8 (Extraction UTF-16LE simple si on n'a pas vu de '10ts')
        if not parsed_entries:
            # Cherche des chemins du type C:\... ou \\... en UTF-16
            matches = re.finditer(b'(?:[a-zA-Z]\\x00:\\x00\\\\\\x00|\\\\\\x00\\\\\\x00)(?:[^\\x00]\\x00)+', data)
            for m in matches:
                try:
                    path_str = m.group(0).decode('utf-16le', errors='ignore')
                    # On filtre sur les binaires probables
                    if path_str.lower().endswith(('.exe', '.dll', '.bat', '.sys', '.cmd')):
                        parsed_entries.append({
                            "file_path": path_str,
                            "last_modified": None
                        })
                except Exception:
                    continue
        return parsed_entries

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
                    path_val = raw_log.get("path") or raw_log.get("key_path") or ""

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

                    # === NOUVEAU: INTERCEPTION DE L'APPCOMPATCACHE BRUT (YARP) ===
                    if "AppCompatCache" in path_val and formatted_values:
                        yielded_entries = False
                        # On vérifie les deux blocs couramment rencontrés dans ShimCache
                        for val_name in ["AppCompatCache", "CacheMainSdb"]:
                            if val_name in formatted_values and isinstance(formatted_values[val_name], str):
                                hex_data = formatted_values[val_name]
                                # Extraction de tous les chemins d'exécutables depuis l'hexadécimal
                                parsed_entries = self._parse_yarp_appcompatcache_hex(hex_data)

                                for entry in parsed_entries:
                                    doc = {
                                        "@timestamp": entry["last_modified"] or timestamp,
                                        "event": {
                                            "kind": "state",
                                            "category": "registry",
                                            "dataset": f"{dataset}_appcompat",
                                            "original": "Extrait du bloc binaire (AppCompatCache YARP)"
                                        },
                                        "registry": {
                                            "path": path_val,
                                            "name": val_name
                                        },
                                        "file": {
                                            "path": entry["file_path"],
                                            "name": os.path.basename(entry["file_path"].replace('\\', '/'))
                                        },
                                        "process": {
                                            "executable": entry["file_path"]
                                        },
                                        "appcompatcache": {
                                            "executed": None  # Info absente du binaire natif W10/W11
                                        }
                                    }
                                    if hasattr(self, 'inject_wapp_info'):
                                        doc = self.inject_wapp_info(doc)

                                    doc["file"] = {k: v for k, v in doc["file"].items() if v}
                                    yield doc, "registry"
                                    yielded_entries = True

                        # Si on a éclaté la clé en sous-événements, on zappe la génération de la clé générique
                        # Cela évite d'envoyer 100Ko de texte binaire pur dans Elastic
                        if yielded_entries:
                            continue

                            # =============================================================
                    # SUITE POUR LES CLÉS DE REGISTRE STANDARDS
                    # =============================================================
                    doc = {
                        "@timestamp": timestamp,
                        "event": {
                            "kind": "state",
                            "category": "registry",
                            "dataset": dataset,
                            "original": clean_line
                        },
                        "registry": {
                            "path": path_val,
                            "name": raw_log.get("name")
                        }
                    }
                    if hasattr(self, 'inject_wapp_info'):
                        doc = self.inject_wapp_info(doc)

                    if not doc["registry"]["name"]:
                        doc["registry"].pop("name", None)

                    # 2. Protection contre le Mapping Explosion :
                    if formatted_values:
                        doc["registry"]["values_str"] = json.dumps(formatted_values, ensure_ascii=False)

                    yield doc, "registry"

                except json.JSONDecodeError:
                    print(f"\n[Attention] Ligne #{i + 1} invalide dans {filepath}\n")
                except Exception as e:
                    print(
                        f"\n[Attention] Impossible de traiter la ligne Registre #{i + 1}. Erreur: {type(e).__name__} - {e}")

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
                        if hasattr(self, 'inject_wapp_info'):
                            doc = self.inject_wapp_info(doc)
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

    def _process_appcompatcache_file(self, filepath: str, dataset: str):
        """Parseur spécifique pour les entrées AppCompatCache/ShimCache déjà structurées (souvent générées par des plugins regipy)."""
        print(f"  -> Lecture du fichier AppCompatCache : {filepath}")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                # Essayer de lire le fichier comme un JSON complet
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]
            except json.JSONDecodeError:
                # Fallback : si c'est du JSON Lines (NDJSON)
                f.seek(0)
                records = []
                for line in f:
                    clean_line = line.strip()
                    if clean_line:
                        try:
                            records.append(json.loads(clean_line))
                        except Exception:
                            pass

            for i, item in enumerate(records):
                try:
                    # Extraction du timestamp (souvent Last Modified Timestamp de l'exécutable pour ShimCache)
                    raw_ts = item.get("last_modified_timestamp") or item.get("last_modified") or item.get("timestamp")
                    timestamp = self._parse_regipy_timestamp(raw_ts)

                    # Extraction du chemin et déduction du nom de l'exécutable
                    file_path = item.get("file_path") or item.get("path") or item.get("name") or "unknown"

                    doc = {
                        "@timestamp": timestamp,
                        "event": {
                            "kind": "state",
                            "category": "registry",
                            "dataset": dataset,
                            "original": json.dumps(item)
                        },
                        "registry": {
                            "name": "AppCompatCache",
                            "path": item.get(
                                "key_path") or "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache"
                        },
                        "file": {
                            "path": file_path,
                            "name": os.path.basename(file_path.replace('\\', '/')) if file_path != "unknown" else None
                        },
                        "process": {
                            "executable": file_path
                        },
                        "appcompatcache": {
                            "executed": item.get("executed"),
                            "update_timestamp": item.get("update_timestamp")
                        }
                    }

                    # Injection du Case/Machine Name
                    if hasattr(self, 'inject_wapp_info'):
                        doc = self.inject_wapp_info(doc)

                    # Nettoyage des valeurs vides
                    doc["appcompatcache"] = {k: v for k, v in doc["appcompatcache"].items() if v is not None}
                    doc["file"] = {k: v for k, v in doc["file"].items() if v is not None}

                    yield doc, "registry"

                except Exception as e:
                    print(
                        f"\n[Attention] Impossible de traiter l'enregistrement AppCompatCache #{i + 1}. Erreur: {type(e).__name__} - {e}\n")

    def process_file(self, filepath: str, **kwargs):
        dataset = kwargs.get("dataset")
        if not dataset:
            print(f"  [Attention] Aucun 'dataset' spécifié pour {filepath}. Fichier ignoré.")
            return

        ds_lower = dataset.lower()

        if ds_lower == 'amcache_regpy':
            yield from self._process_regipy_amcache_file(filepath)

        elif ds_lower in ['appcompatcache', 'appcompatcache_regpy', 'registry_appcompatcache']:
            yield from self._process_appcompatcache_file(filepath, dataset)

        elif ds_lower in [
            'amcache_yarp', 'registry_security', 'registry_software',
            'registry_system', 'registry_ntuser', 'registry_ntuser.dat', 'registry_sam'
        ]:
            # Nettoyer le dataset en interne si c'est un SAM pour respecter l'ancien routage
            internal_ds = 'registry_sam' if 'sam' in ds_lower else dataset
            yield from self._process_generic_reg_file(filepath, internal_ds)
        else:
            print(f"  [Attention] Dataset '{dataset}' non reconnu pour le processeur de registre. Fichier ignoré.")
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from datetime import datetime
from .base_processor import BaseFileProcessor


class RegistryJsonProcessor(BaseFileProcessor):
    """
    Processeur pour les fichiers de clés de registre (Amcache et génériques).
    Utilise le paramètre 'dataset' pour choisir la bonne logique de parsing.
    """

    def _parse_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).isoformat() + "Z"
        except (ValueError, TypeError):
            print(f"  [Attention] Format de timestamp du registre non reconnu: '{timestamp_str}'.")
            return datetime.utcnow().isoformat() + "Z"

    def _process_generic_reg_log(self, raw_log: dict, dataset: str) -> dict:
        """
        Traite un enregistrement de registre générique (format JSON Lines).
        """
        final_timestamp = self._parse_timestamp(raw_log.get("last_written_timestamp"))
        values_as_json_string = json.dumps(raw_log.get("values", {}))

        return {
            "@timestamp": final_timestamp,
            "event": {"kind": "event", "category": "registry", "dataset": dataset, "original": json.dumps(raw_log)},
            "registry": {"path": raw_log.get("path"), "key": raw_log.get("name"), "values_json": values_as_json_string}
        }

    def _process_regipy_amcache_log(self, raw_log: dict) -> dict:
        """Traite un enregistrement AmCache exporté par Regipy."""
        final_timestamp = self._parse_timestamp(raw_log.get("timestamp"))
        original_log = raw_log.copy()

        doc = {
            "@timestamp": final_timestamp,
            "event": {"kind": "event", "category": "process", "dataset": "amcache.regipy",
                      "original": json.dumps(original_log)},
            "file": {"path": raw_log.get("lower_case_long_path"), "name": raw_log.get("name"),
                     "size": raw_log.get("size")},
            "process": {"executable": raw_log.get("lower_case_long_path"), "name": raw_log.get("name")},
            "pe": {"original_file_name": raw_log.get("original_file_name"), "product": raw_log.get("product_name"),
                   "company": raw_log.get("publisher"), "version": raw_log.get("version")},
            "amcache": {"program_id": raw_log.get("program_id"), "link_date": raw_log.get("link_date"),
                        "language": raw_log.get("language")}
        }
        return doc

    def _process_regipy_amcache_file(self, filepath: str):
        print(f"    -> Fichier traité comme JSON complet (Amcache de Regipy).")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]
                for i, record in enumerate(records):
                    try:
                        if "program_id" in record and "lower_case_long_path" in record:
                            yield self._process_regipy_amcache_log(record), "registry"
                    except Exception as e:
                        print(f"\n[Attention] Impossible de traiter l'enregistrement Amcache #{i + 1}. Erreur: {e}\n")
            except json.JSONDecodeError:
                print(f"[ERREUR] Le fichier {filepath} n'est pas un JSON valide pour un export Amcache.")
            except Exception as e:
                print(f"[ERREUR] Erreur inattendue lors de la lecture de {filepath}: {e}")

    def _process_generic_reg_file_legacy(self, filepath: str, dataset: str):
        print(f"    -> Fichier traité comme JSON Lines (dataset: {dataset}).")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:

            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip()
                if not stripped_line: continue
                try:
                    raw_log_data = json.loads(stripped_line)
                    if "path" in raw_log_data and "last_written_timestamp" in raw_log_data:
                        yield self._process_generic_reg_log(raw_log_data, dataset), "registry"
                except Exception as e:
                    print(f"\n[Attention] Impossible de traiter la ligne de registre #{line_num}. Erreur: {e}\n")

    def _process_generic_reg_file(self, filepath: str, dataset: str):
        print(f"    -> Fichier traité comme JSON Lines (dataset: {dataset}).")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:

            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip()
                if not stripped_line: continue
                try:
                    raw_log_data = json.loads(stripped_line)
                    if "path" in raw_log_data and "last_written_timestamp" in raw_log_data:
                        # Routage spécifique pour la base SAM
                        if dataset == 'registry_sam':
                            yield self._process_sam_log(raw_log_data, dataset), "registry"
                        else:
                            yield self._process_generic_reg_log(raw_log_data, dataset), "registry"
                except Exception as e:
                    print(f"\n[Attention] Impossible de traiter la ligne de registre #{line_num}. Erreur: {e}\n")

    def process_file(self, filepath: str, **kwargs):
        dataset = kwargs.get("dataset")
        if not dataset:
            print(f"  [Attention] Aucun 'dataset' spécifié pour {filepath}. Fichier ignoré.")
            return

        print(f"  -> Traitement du fichier de registre : {filepath}")

        # 1. Normalisation en minuscules pour gérer 'registry_SAM', 'registry_NTUSER.DAT', etc.
        ds_lower = dataset.lower()

        if ds_lower == 'amcache_regpy':
            yield from self._process_regipy_amcache_file(filepath)
        elif ds_lower in [
            'amcache_yarp', 'registry_security', 'registry_software',
            'registry_system', 'registry_ntuser', 'registry_ntuser.dat', 'registry_sam'
        ]:
            # Conserver la logique de routage spécifique pour SAM
            internal_ds = 'registry_sam' if 'sam' in ds_lower else dataset
            yield from self._process_generic_reg_file(filepath, internal_ds)
        else:
            print(f"  [Attention] Dataset '{dataset}' non reconnu pour le processeur de registre. Fichier ignoré.")

    def _process_sam_log(self, raw_log: dict, dataset: str) -> dict:
        """
        Traite un enregistrement de la base SAM en enrichissant les données
        (extraction des RIDs, noms d'utilisateurs et groupes).
        """
        final_timestamp = self._parse_timestamp(raw_log.get("last_written_timestamp"))
        values_as_json_string = json.dumps(raw_log.get("values", {}))

        # Document de base ECS
        doc = {
            "@timestamp": final_timestamp,
            "event": {"kind": "event", "category": "iam", "dataset": dataset, "original": json.dumps(raw_log)},
            "registry": {"path": raw_log.get("path"), "key": raw_log.get("name"), "values_json": values_as_json_string}
        }

        path_parts = raw_log.get("path", "").split("\\")
        name = raw_log.get("name", "")
        values = raw_log.get("values", {})

        # -- 1. Utilisateurs (Mappage Nom -> RID) --
        # Exemple : ROOT\SAM\Domains\Account\Users\Names\Administrator
        if len(path_parts) >= 7 and path_parts[4] == "Users" and path_parts[5] == "Names":
            username = name
            # Le RID est stocké dans le champ 'type' de la valeur par défaut dans cet export
            rid_hex = values.get("", {}).get("type", "")

            doc["user"] = {"name": username, "id": rid_hex}
            doc["event"]["action"] = "sam_user_mapping"

        # -- 2. Utilisateurs (Données brutes par RID) --
        # Exemple : ROOT\SAM\Domains\Account\Users\000001F4
        elif len(path_parts) == 6 and path_parts[4] == "Users" and name != "Users":
            rid = name.lstrip("0")  # Convertit "000001F4" en "1F4"
            if not rid: rid = "0"

            doc["user"] = {"id": f"0x{rid.lower()}"}
            doc["event"]["action"] = "sam_user_properties"

        # -- 3. Groupes/Alias locaux (Mappage Nom -> RID) --
        # Exemple : ROOT\SAM\Domains\Builtin\Aliases\Names\Administrators
        elif len(path_parts) >= 7 and path_parts[4] == "Aliases" and path_parts[5] == "Names":
            group_name = name
            rid_hex = values.get("", {}).get("type", "")

            doc["group"] = {"name": group_name, "id": rid_hex}
            doc["event"]["action"] = "sam_group_mapping"

        return doc

    def process_file_legacy(self, filepath: str, **kwargs):
        dataset = kwargs.get("dataset")
        if not dataset:
            print(f"  [Attention] Aucun 'dataset' spécifié pour {filepath}. Fichier ignoré.")
            return

        print(f"  -> Traitement du fichier de registre : {filepath}")
        if dataset == 'amcache_regpy':
            yield from self._process_regipy_amcache_file(filepath)
        elif dataset in ['amcache_yarp', 'registry_security', 'registry_software', 'registry_system',
                         'registry_ntuser']:
            yield from self._process_generic_reg_file(filepath, dataset)
        else:
            print(f"  [Attention] Dataset '{dataset}' non reconnu pour le processeur de registre. Fichier ignoré.")


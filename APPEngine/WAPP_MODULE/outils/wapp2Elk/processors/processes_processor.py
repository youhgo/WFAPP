#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import os
import xmltodict
import json
import re
from datetime import datetime
from .base_processor import BaseFileProcessor


class ProcessesProcessor(BaseFileProcessor):
    """Processeur pour divers formats de listes de processus et d'autoruns (CSV et XML)."""

    def _parse_wmi_timestamp(self, ts: str) -> str:
        if not ts or '.' not in ts: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.strptime(ts.split('.')[0], "%Y%m%d%H%M%S").isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _parse_ps_timestamp(self, ts: str) -> str:
        if not ts: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p").isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _parse_timeline_timestamp(self, ts: str) -> str:
        if not ts or ts.startswith("1601-01-01"): return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.strptime(ts.split('.')[0], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _parse_autoruns_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str: return datetime.utcnow().isoformat() + "Z"
        try:
            return datetime.strptime(timestamp_str, "%Y%m%d-%H%M%S").isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _process_win32_process_row(self, row: dict, dataset) -> dict:
        return {"@timestamp": self._parse_wmi_timestamp(row.get("CreationDate")),
                "host": {"name": row.get("PSComputerName")},
                "event": {"kind": "event", "category": "process", "dataset": dataset,
                          "original": ",".join(str(v) for v in row.values())},
                "process": {"name": row.get("ProcessName"), "executable": row.get("ExecutablePath"),
                            "pid": row.get("ProcessId"), "parent": {"pid": row.get("ParentProcessId")},
                            "command_line": row.get("CommandLine")}}

    def _process_get_process_row(self, row: dict, dataset) -> dict:
        return {"@timestamp": self._parse_ps_timestamp(row.get("StartTime")), "host": {"name": row.get("MachineName")},
                "event": {"kind": "event", "category": "process", "dataset": dataset,
                          "original": ",".join(str(v) for v in row.values())},
                "process": {"name": row.get("ProcessName"), "executable": row.get("Path"), "pid": row.get("Id"),
                            "session_id": row.get("SI")}}

    def _process_sampleinfo_row(self, row: dict, dataset) -> dict:
        return {"@timestamp": datetime.utcnow().isoformat() + "Z", "host": {"name": row.get("ComputerName")},
                "event": {"kind": "event", "category": "process", "dataset": dataset,
                          "original": ",".join(str(v) for v in row.values())},
                "file": {"path": row.get("FullPath"), "name": row.get("FileName")},
                "process": {"code_signature": {"status": row.get("Authenticode")}}, "status": row.get("Running")}

    def _process_timeline_row(self, row: dict, dataset) -> dict:
        return {"@timestamp": self._parse_timeline_timestamp(row.get("Time")),
                "host": {"name": row.get("ComputerName")},
                "event": {"kind": "event", "category": "process", "dataset": dataset,
                          "action": row.get("Type"), "original": ",".join(str(v) for v in row.values())},
                "process": {"pid": row.get("ProcessID"), "parent": {"pid": row.get("ParentID")}},
                "dll": {"path": row.get("FullPath")}}

    def _process_autoruns_csv_row(self, row: dict, dataset) -> dict:
        # Renommer les clés pour éviter les espaces, au cas où.
        processed_row = {k.replace(' ', ''): v for k, v in row.items() if k}
        return {
            "@timestamp": self._parse_autoruns_timestamp(processed_row.get("Time")),
            "event": {"kind": "event", "category": "process", "dataset": dataset,
                      "original": ",".join(str(v) for v in row.values())},
            "rule": {"name": processed_row.get("Entry"), "category": processed_row.get("Category")},
            "registry": {"path": processed_row.get("EntryLocation")},
            "process": {"executable": processed_row.get("ImagePath"),
                        "name": os.path.basename(processed_row.get("ImagePath")) if processed_row.get(
                            "ImagePath") else None, "version": processed_row.get("Version"),
                        "hash": {"md5": processed_row.get("MD5"), "sha1": processed_row.get("SHA-1"),
                                 "sha256": processed_row.get("SHA-256")},
                        "code_signature": {"subject_name": processed_row.get("Signer"),
                                           "publisher": processed_row.get("Company")}},
            "service": {"description": processed_row.get("Description")},
            "user": {"name": processed_row.get("Profile")},
            "status": processed_row.get("Enabled")
        }

    def _process_autoruns_xml_item(self, item: dict, dataset) -> dict:
        return {
            "@timestamp": self._parse_autoruns_timestamp(item.get("time")),
            "event": {"kind": "event", "category": "process", "dataset": dataset, "original": json.dumps(item)},
            "rule": {"name": item.get("itemname"), "category": item.get("category")},
            "registry": {"path": item.get("location")},
            "process": {"executable": item.get("imagepath"),
                        "name": os.path.basename(item.get("imagepath")) if item.get("imagepath") else None,
                        "version": item.get("version"),
                        "hash": {"md5": item.get("md5hash"), "sha1": item.get("sha1hash"),
                                 "sha256": item.get("sha256hash")},
                        "code_signature": {"subject_name": item.get("signer"), "publisher": item.get("company")}},
            "service": {"description": item.get("description")},
            "user": {"name": item.get("profile")},
            "status": item.get("enabled")
        }

    def _process_csv_file(self, filepath: str, dataset: str):
        print(f"  -> Lecture du fichier de Processus (CSV) : {filepath}")
        file_encoding = 'utf-8'
        file_encoding2 =  'utf-8-sig'
        with open(filepath, 'rb') as raw_file:
            if b'\x00' in raw_file.read(100):
                file_encoding = 'utf-16'

        with open(filepath, 'r', encoding=file_encoding, errors='replace') as f:
            lines = f.readlines()

        header_fields, header_index = None, -1
        for i, line in enumerate(lines):
            clean_line = line.strip()

            if not clean_line or "Sysinternals" in clean_line or "Copyright" in clean_line:
                continue
            if "," in clean_line:
                try:
                    header_fields = next(csv.reader([clean_line]))
                    print(header_fields)
                    header_index = i
                    break
                except StopIteration:
                    continue

        if not header_fields:
            print(f"  [Attention] En-tête CSV non reconnu pour {filepath}. Fichier ignoré.")
            return

            # Remplacer l'ancien parser_map par celui-ci :
        parser_map = {
            "processes_win32": (self._process_win32_process_row, "Win32_Process"),
            "process_processes1": (self._process_win32_process_row, "Win32_Process"),

            "processes_get_proc": (self._process_get_process_row, "Get-Process *"),
            "process_processes2": (self._process_get_process_row, "Get-Process *"),

            "processes_sampleinfo": (self._process_sampleinfo_row, "SampleInfo"),
            "process_process_sampleinfo": (self._process_sampleinfo_row, "SampleInfo"),

            "processes_timeline": (self._process_timeline_row, "Timeline"),
            "process_process_timeline": (self._process_timeline_row, "Timeline"),

            "autoruns_sysinternals": (self._process_autoruns_csv_row, "Autoruns CSV"),
            "process_autoruns": (self._process_autoruns_csv_row, "Autoruns CSV")
        }

        # Modifier cette ligne pour gérer la casse de manière robuste :
        parser_func, fmt = parser_map.get(dataset.lower(), (None, None))

        if not parser_func:
            print(f"  [Attention] Format de CSV de processus non reconnu pour dataset '{dataset}'. Fichier ignoré.")
            return

        print(f"    -> Format détecté : {fmt}")
        reader = csv.DictReader(lines[header_index + 1:], fieldnames=header_fields)
        for i, row in enumerate(reader):
            try:
                if not any(row.values()): continue
                yield parser_func(row, dataset), "processes"
            except Exception as e:
                print(
                    f"\n[Attention] Impossible de traiter la ligne de processus #{i + header_index + 2}. Erreur: {e}\n")

    def _process_xml_file(self, filepath: str, dataset):
        print("    -> Format détecté : Autoruns XML")
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                xml_content = f.read()
                xml_content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', xml_content)
                data = xmltodict.parse(xml_content)
                items = data.get('autoruns', {}).get('item', [])
                if not isinstance(items, list): items = [items]
                for i, item in enumerate(items):
                    try:
                        yield self._process_autoruns_xml_item(item, dataset), "processes"
                    except Exception as e:
                        print(f"\n[Attention] Impossible de traiter l'item XML #{i + 1}. Erreur: {e}\n")
            except Exception as e:
                print(f"[ERREUR] Impossible de parser le fichier XML {filepath}. Erreur: {e}")

    def _process_listdlls_file(self, filepath: str, dataset: str):
        print(f"  -> Lecture du fichier Listdlls : {filepath}")
        current_process = None
        current_pid = None
        current_cmdline = None

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()

                # 1. Ignorer les lignes inutiles (En-têtes, erreurs, séparateurs)
                if (not clean_line or
                        clean_line.startswith("---") or
                        clean_line.startswith("Base ") or
                        "Listdlls" in clean_line or
                        "Sysinternals" in clean_line or
                        "Copyright" in clean_line or
                        "Error opening" in clean_line or
                        "Acc" in clean_line):  # Capture "Accès refusé" même avec des caractères corrompus
                    continue

                # 2. Détection d'un nouveau processus (ex: "winlogon.exe pid: 640")
                if " pid: " in clean_line:
                    parts = clean_line.split(" pid: ")
                    current_process = parts[0].strip()
                    current_pid = parts[1].strip()
                    current_cmdline = None  # Réinitialisation pour le nouveau processus
                    continue

                # 3. Détection de la ligne de commande
                if clean_line.startswith("Command line:"):
                    current_cmdline = clean_line.replace("Command line:", "").strip()
                    continue

                # 4. Extraction des informations de la DLL
                if clean_line.startswith("0x"):
                    parts = clean_line.split()
                    # Il faut au moins 3 éléments : Base, Size, et le début du Path
                    if len(parts) >= 3:
                        try:
                            base = parts[0]
                            size = parts[1]
                            # On rejoint le reste au cas où le chemin contiendrait des espaces
                            dll_path = " ".join(parts[2:])
                            dll_name = os.path.basename(dll_path.replace('\\', '/'))

                            doc = {
                                "@timestamp": datetime.utcnow().isoformat() + "Z",
                                "event": {
                                    "kind": "state",
                                    "category": "process",
                                    "dataset": dataset,
                                    "original": clean_line
                                },
                                "process": {
                                    "name": current_process,
                                    "pid": current_pid,
                                    "command_line": current_cmdline
                                },
                                "dll": {
                                    "name": dll_name,
                                    "path": dll_path,
                                    "base_address": base,
                                    "size": size
                                }
                            }
                            yield doc, "processes"
                        except Exception as e:
                            print(f"\n[Attention] Impossible de traiter la ligne Listdlls #{line_num}. Erreur: {e}\n")

    def _process_psservice_file(self, filepath: str, dataset: str):
        print(f"  -> Lecture du fichier psService : {filepath}")

        current_service = {}
        description_lines = []
        is_parsing_description = False

        def yield_service(svc):
            # Formate et envoie le service accumulé
            if "service_name" in svc:
                if description_lines:
                    svc["description"] = " ".join(description_lines).strip()

                doc = {
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                    "event": {
                        "kind": "state",
                        "category": "host",
                        "dataset": dataset,
                        # On pourrait stocker la concaténation de toutes les lignes, mais on garde simple ici
                        "original": f"SERVICE_NAME: {svc.get('service_name')} | STATE: {svc.get('state_desc')}"
                    },
                    "service": {
                        "name": svc.get("service_name"),
                        "display_name": svc.get("display_name"),
                        "description": svc.get("description"),
                        "state": svc.get("state_desc", "").strip().lower(),
                        "type": svc.get("type", "").strip()
                    },
                    "psservice": {
                        "group": svc.get("group"),
                        "win32_exit_code": svc.get("win32_exit_code"),
                        "service_exit_code": svc.get("service_exit_code"),
                        "state_code": svc.get("state_code"),
                        "state_flags": svc.get("state_flags")
                    }
                }
                # Nettoyage des valeurs vides
                doc["psservice"] = {k: v for k, v in doc["psservice"].items() if v}
                return doc
            return None

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                clean_line = line.strip()

                # Ignorer l'en-tête
                if "PsService" in clean_line or "Copyright" in clean_line or "Sysinternals" in clean_line:
                    continue

                # Un nouveau bloc de service commence
                if line.startswith("SERVICE_NAME:"):
                    # Si on a un service en cours, on l'envoie
                    if current_service:
                        doc = yield_service(current_service)
                        if doc: yield doc, "processes"

                    # On réinitialise pour le nouveau service
                    current_service = {"service_name": clean_line.replace("SERVICE_NAME:", "").strip()}
                    description_lines = []
                    is_parsing_description = False
                    continue

                if not current_service:
                    continue

                # Ligne vide : fin du bloc (normalement géré par le prochain SERVICE_NAME, mais sécurité)
                if not clean_line:
                    continue

                if line.startswith("DISPLAY_NAME:"):
                    current_service["display_name"] = clean_line.replace("DISPLAY_NAME:", "").strip()
                    is_parsing_description = True  # La description suit immédiatement
                    continue

                # Clés standard indentées
                if ":" in clean_line and (clean_line.startswith("TYPE") or clean_line.startswith("STATE") or
                                          clean_line.startswith("WIN32_EXIT_CODE") or clean_line.startswith(
                            "SERVICE_EXIT_CODE") or
                                          clean_line.startswith("CHECKPOINT") or clean_line.startswith("WAIT_HINT") or
                                          clean_line.startswith("GROUP")):
                    is_parsing_description = False  # On est sorti de la description

                    parts = clean_line.split(":", 1)
                    key = parts[0].strip()
                    val = parts[1].strip() if len(parts) > 1 else ""

                    if key == "TYPE":
                        current_service["type"] = val
                    elif key == "GROUP":
                        current_service["group"] = val
                    elif key == "STATE":
                        # ex: "1  STOPPED"
                        state_parts = val.split(maxsplit=1)
                        current_service["state_code"] = state_parts[0] if len(state_parts) > 0 else ""
                        current_service["state_desc"] = state_parts[1] if len(state_parts) > 1 else ""
                    elif key == "WIN32_EXIT_CODE":
                        current_service["win32_exit_code"] = val
                    elif key == "SERVICE_EXIT_CODE":
                        current_service["service_exit_code"] = val

                    continue

                # Flags de state (ex: "(NOT_STOPPABLE,NOT_PAUSABLE,IGNORES_SHUTDOWN)")
                if clean_line.startswith("(") and clean_line.endswith(")"):
                    current_service["state_flags"] = clean_line.strip("()")
                    continue

                # Si on est ici et que is_parsing_description est vrai, c'est une ligne de description
                if is_parsing_description:
                    description_lines.append(clean_line)

            # Ne pas oublier le dernier service du fichier !
            if current_service:
                doc = yield_service(current_service)
                if doc: yield doc, "processes"

    def _process_enumlocs_file(self, filepath: str, dataset: str):
        print(f"  -> Lecture du fichier Enumlocs : {filepath} (Agrégation en 1 document)")

        doc_data = {
            "parameters": {},
            "volumes": [],
            "statistics": {}
        }

        current_section = None
        current_volume = None
        start_time = None
        host_name = None

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                clean_line = line.strip()

                # Ignorer l'en-tête de l'outil
                if not clean_line or clean_line.startswith("NTFSUtil") or clean_line.startswith("Various"):
                    continue

                # --- Détection des sections ---
                if clean_line == "Parameters":
                    current_section = "parameters"
                    continue
                elif clean_line.startswith("Available locations:") or clean_line.startswith("Volume:"):
                    current_section = "volumes"

                    # Si on avait déjà un volume en cours de lecture, on le sauvegarde
                    if current_volume:
                        doc_data["volumes"].append(current_volume)

                    # Nettoyage de la ligne pour extraire les infos du volume
                    vol_str = clean_line.replace("Available locations:", "").strip()
                    if vol_str.startswith("Volume:"):
                        vol_str = vol_str.replace("Volume:", "").strip()

                    vol_parts = [p.strip() for p in vol_str.split(",")]
                    current_volume = {
                        "id": vol_parts[0] if len(vol_parts) > 0 else "",
                        "status": vol_parts[1] if len(vol_parts) > 1 else "",
                        "fs_type": vol_parts[2] if len(vol_parts) > 2 else "",
                        "mounted_volumes": [],
                        "disk_interfaces": [],
                        "physical_drives": []
                    }
                    continue
                elif clean_line == "Statistics":
                    if current_volume:
                        doc_data["volumes"].append(current_volume)
                        current_volume = None
                    current_section = "statistics"
                    continue

                # --- Lecture du contenu selon la section ---
                if ":" in clean_line:
                    parts = clean_line.split(":", 1)
                    key = parts[0].strip()
                    val = parts[1].strip()

                    if current_section == "parameters":
                        # Formatage des clés (ex: "Computer name" -> "computer_name")
                        safe_key = key.lower().replace(" ", "_").replace("-", "_")
                        doc_data["parameters"][safe_key] = val

                        if safe_key == "start_time":
                            start_time = val
                        elif safe_key == "computer_name":
                            host_name = val

                    elif current_section == "volumes" and current_volume is not None:
                        if key == "MountedVolume":
                            current_volume["mounted_volumes"].append(val)
                        elif key == "DiskInterfaceVolume":
                            current_volume["disk_interfaces"].append(val)
                        elif key == "PhysicalDriveVolume":
                            current_volume["physical_drives"].append(val)
                        else:
                            current_volume[key.lower().replace(" ", "_")] = val

                    elif current_section == "statistics":
                        safe_key = key.lower().replace(" ", "_").replace("(", "").replace(")", "")
                        doc_data["statistics"][safe_key] = val

            # N'oublions pas de sauvegarder le tout dernier volume du fichier !
            if current_volume:
                doc_data["volumes"].append(current_volume)

        # Génération du document final unique
        # On utilise le 'Start time' du fichier si présent, sinon l'heure actuelle
        timestamp = start_time if start_time else datetime.utcnow().isoformat() + "Z"

        doc = {
            "@timestamp": timestamp,
            "event": {
                "kind": "state",
                "category": "host",
                "dataset": dataset
            },
            "enumlocs": doc_data
        }

        if host_name:
            doc["host"] = {"name": host_name}

        yield doc, "processes"

    def _process_ps_history_file(self, filepath: str, dataset: str):
        print(f"  -> Lecture du fichier PowerShell History : {filepath}")

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()

                # Ignorer les lignes vides
                if not clean_line:
                    continue

                # Extraction basique du programme appelé (le premier mot)
                parts = clean_line.split(maxsplit=1)
                cmd_name = parts[0] if parts else "unknown"

                doc = {
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                    "event": {
                        "kind": "event",
                        "category": "process",
                        "dataset": dataset,
                        "action": "executed_command",
                        "original": clean_line
                    },
                    "process": {
                        "name": cmd_name,
                        "command_line": clean_line
                    }
                }

                try:
                    yield doc, "processes"
                except Exception as e:
                    print(f"\n[Attention] Impossible de traiter la commande PS #{line_num}. Erreur: {e}\n")

    def process_file(self, filepath: str, **kwargs):
        dataset = kwargs.get("dataset")
        if not dataset:
            print(f"  [Attention] Aucun 'dataset' spécifié pour {filepath}. Fichier ignoré.")
            return

        ds_lower = dataset.lower()

        if ds_lower in ["processes_autorun", "process_process_autoruns"]:
            yield from self._process_xml_file(filepath, dataset)

        elif ds_lower in [
            "processes_win32", "process_processes1",
            "processes_get_proc", "process_processes2",
            "processes_sampleinfo", "process_process_sampleinfo",
            "processes_timeline", "process_process_timeline",
            "autoruns_sysinternals", "process_autoruns"
        ]:
            yield from self._process_csv_file(filepath, dataset)

        elif ds_lower in ["listdlls", "process_listdlls"]:
            yield from self._process_listdlls_file(filepath, dataset)

        elif ds_lower in ["psservice", "process_psservice"]:
            yield from self._process_psservice_file(filepath, dataset)

        elif ds_lower in ["enumlocs", "process_enumlocs"]:
            yield from self._process_enumlocs_file(filepath, dataset)

        # NOUVEAU: Ajout du routage pour PowerShell History
        elif ds_lower in ["consolehost_history", "process_consolehost_history",
                          "ps_history"] or "consolehost_history" in ds_lower:
            yield from self._process_ps_history_file(filepath, dataset)

        # Datasets restants à développer
        elif ds_lower in ["process_handle"]:
            print(f"  [Info] Un parseur spécifique doit être développé pour : {dataset}")

        else:
            print(f"  [Attention] Dataset de processus non supporté '{dataset}'. Fichier ignoré.")


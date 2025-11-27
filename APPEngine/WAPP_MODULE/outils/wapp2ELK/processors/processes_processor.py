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
        with open(filepath, 'r', encoding='utf-8-sig', errors='ignore') as f:
            lines = f.readlines()

        header_fields, header_index = None, -1
        for i, line in enumerate(lines):
            clean_line = line.strip()
            if not clean_line or "Sysinternals" in clean_line or "Copyright" in clean_line:
                continue
            if "," in clean_line:
                try:
                    header_fields = next(csv.reader([clean_line]))
                    header_index = i
                    break
                except StopIteration:
                    continue

        if not header_fields:
            print(f"  [Attention] En-tête CSV non reconnu pour {filepath}. Fichier ignoré.")
            return

        parser_map = {
            "processes_win32": (self._process_win32_process_row, "Win32_Process"),
            "processes_get_proc": (self._process_get_process_row, "Get-Process *"),
            "processes_sampleinfo": (self._process_sampleinfo_row, "SampleInfo"),
            "processes_timeline": (self._process_timeline_row, "Timeline"),
            "autoruns_sysinternals": (self._process_autoruns_csv_row, "Autoruns CSV")
        }

        parser_func, fmt = parser_map.get(dataset, (None, None))

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

    def process_file(self, filepath: str, **kwargs):
        dataset = kwargs.get("dataset")
        if dataset == "processes_autorun":
            yield from self._process_xml_file(filepath, dataset)
        elif dataset in ["processes_win32", "processes_get_proc", "processes_sampleinfo", "processes_timeline",
                         "autoruns_sysinternals"]:
            yield from self._process_csv_file(filepath, dataset)
        else:
            print(f"  [Attention] Dataset de processus non supporté '{dataset}'. Fichier ignoré.")


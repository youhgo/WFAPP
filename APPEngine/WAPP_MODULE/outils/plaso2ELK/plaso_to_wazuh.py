#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import re
import os
import traceback
import time
from datetime import timedelta
from types import GeneratorType

# Import the adapted uploader
from wazuh_uploader import WazuhUploader

# --- PROCESSOR IMPORTS KEEP SAME ---
# Assumes these files exist in your "plaso_processors" folder
from plaso_processors.evtx_processor import PlasoEvtxProcessor
from plaso_processors.registry_processor import PlasoRegistryProcessor
from plaso_processors.mft_processor import PlasoMftProcessor
from plaso_processors.lnk_processor import PlasoLnkProcessor
from plaso_processors.prefetch_processor import PlasoPrefetchProcessor
from plaso_processors.srum_processor import PlasoSrumProcessor
from plaso_processors.browser_history_processor import PlasoBrowserHistoryProcessor
from plaso_processors.amcache_processor import PlasoAmcacheProcessor
from plaso_processors.generic_processor import PlasoGenericProcessor
from plaso_processors.appcompatcache_processor import PlasoAppCompatCacheProcessor
from plaso_processors.userassist_processor import PlasoUserAssistProcessor
from plaso_processors.runkey_processor import PlasoRunKeyProcessor
from plaso_processors.usb_processor import PlasoUsbProcessor
from plaso_processors.mru_processor import PlasoMruProcessor


class PlasoPipeline:
    def __init__(self, case_name, machine_name, timeline_path, es_hosts, es_user, es_pass, chunk_size, verify_ssl,
                 es_timeout, thread_count, mode):
        self.case_name = self._sanitize_for_index(case_name)
        self.machine_name = machine_name.lower().replace(" ", "_")
        self.timeline_path = timeline_path
        self.chunk_size = chunk_size

        # Wazuh index pattern convention (optional, but helps organization)
        self.index_prefix = f"forensic_{self.case_name}_{self.machine_name}"

        # Initialize WazuhUploader instead of ElasticUploader
        self.uploader = WazuhUploader(es_hosts, es_user, es_pass, verify_ssl, es_timeout, thread_count, mode)

        self.parser_regex_map = {
            "amcache": re.compile(r'winreg/amcache'),
            "userassist": re.compile(r'userassist'),
            "appcompatcache": re.compile(r'appcompatcache'),
            "srum": re.compile(r'esedb/srum'),
            "prefetch": re.compile(r'prefetch'),
            "runkey": re.compile(r'winreg/windows_run'),
            "usb": re.compile(r'winreg/windows_usb_devices'),
            "mru": re.compile(r'winreg/(bagmru|mrulistex)'),
            "hive": re.compile(r'winreg'),
            "evtx": re.compile(r'winevtx'),
            "browser_history": re.compile(r'(sqlite/((chrome|firefox|edge).*history))'),
            "lnk": re.compile(r'lnk'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)'),
            "other": re.compile(r'.*')
        }

        self.index_category_map = {
            "evtx": "evtx",
            "runkey": "hive",
            "usb": "hive",
            "mru": "hive",
            "hive": "hive",
            "srum": "process",
            "amcache": "process",
            "appcompatcache": "process",
            "prefetch": "process",
            "userassist": "process",
            "browser_history": "browser_artefacts",
            "lnk": "files",
            "mft": "files",
            "other": "others"
        }

        self.processors = {
            "srum": PlasoSrumProcessor(),
            "amcache": PlasoAmcacheProcessor(),
            "appcompatcache": PlasoAppCompatCacheProcessor(),
            "runkey": PlasoRunKeyProcessor(),
            "usb": PlasoUsbProcessor(),
            "mru": PlasoMruProcessor(),
            "userassist": PlasoUserAssistProcessor(),
            "browser_history": PlasoBrowserHistoryProcessor(),
            "evtx": PlasoEvtxProcessor(),
            "hive": PlasoRegistryProcessor(),
            "mft": PlasoMftProcessor(),
            "lnk": PlasoLnkProcessor(),
            "prefetch": PlasoPrefetchProcessor(),
            "other": PlasoGenericProcessor()
        }
        print("[*] Processeurs initialisés.")

    def _sanitize_for_index(self, name: str) -> str:
        return ''.join(c if c.isalnum() or c in '-_' else '_' for c in name).lower()

    def identify_artefact_type(self, event: dict) -> str:
        parser = event.get("parser", "")
        for key, value_regex in self.parser_regex_map.items():
            if re.search(value_regex, parser):
                return key
        return "other"

    def run(self):
        print("\n--- CONFIGURATION WAZUH ---")
        print(f"  Fichier Timeline : {self.timeline_path}")
        print(f"  Index Prefix     : {self.index_prefix}")
        print(f"  Taille des Lots  : {self.chunk_size}")
        print("---------------------------\n")

        actions_generator = self._process_timeline_file()

        # Creates Index Templates in Wazuh
        self.uploader.setup_templates(
            priority=400,
            evtx=f"{self.index_prefix}_evtx*",
            hive=f"{self.index_prefix}_hive*",
            process=f"{self.index_prefix}_process*",
            files=f"{self.index_prefix}_files*",
            browser_artefacts=f"{self.index_prefix}_browser_artefacts*",
            others=f"{self.index_prefix}_others*"
        )

        self.uploader.bulk_upload(actions_generator, self.chunk_size)

    def _process_timeline_file(self):
        # ... [Keep exact same logic as original script] ...
        print(f"[*] Début de la lecture du fichier timeline : {self.timeline_path}")
        it = 0
        try:
            with open(self.timeline_path, 'r', encoding='utf-8') as f:
                for line in f:
                    it += 1
                    if it % (self.chunk_size * 10) == 0:
                        print(f"    ... Ligne {it} atteinte")
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue
                    try:
                        event = json.loads(stripped_line)
                        event["event_raw_string"] = stripped_line

                        artefact_type_key = self.identify_artefact_type(event)
                        processor = self.processors.get(artefact_type_key, self.processors["other"])
                        processor_result = processor.process_event(event)

                        if isinstance(processor_result, GeneratorType):
                            events_to_yield = processor_result
                        elif isinstance(processor_result, tuple) and len(processor_result) == 2:
                            events_to_yield = [processor_result]
                        else:
                            processed_doc = {"message": f"Processor error", "raw": event.get("event_raw_string")}
                            events_to_yield = [(processed_doc, "other")]

                        for item in events_to_yield:
                            try:
                                processed_doc, specific_index_key = item
                            except Exception:
                                processed_doc = {"error": "unpacking"}
                                specific_index_key = "other"

                            processed_doc["artefact_type"] = specific_index_key
                            index_category_key = self.index_category_map.get(specific_index_key, "others")
                            index_name = f"{self.index_prefix}_{index_category_key}"

                            yield {
                                "_index": index_name,
                                "_source": processed_doc
                            }
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        traceback.print_exc()
        except Exception as e:
            print(f"[ERREUR FATALE] {e}")
            exit(1)
        print(f"[*] Lecture terminée. {it} lignes.")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Injecteur Plaso vers Wazuh Indexer.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-t", "--timeline", required=True,
                        help="Chemin vers le fichier timeline Plaso (jsonl).")
    parser.add_argument("-c", "--case-name", required=True, help="Nom du dossier.")
    parser.add_argument("-m", "--machine-name", required=True, help="Nom de la machine.")

    # Wazuh Default Settings
    parser.add_argument("--es-hosts", default="https://localhost:9200",
                        help="URL du Wazuh Indexer (ex: https://192.168.1.50:9200).")
    parser.add_argument("--es-user", default="admin", help="Utilisateur Wazuh Indexer.")
    parser.add_argument("--es-pass", default="SecretPassword", help="Mot de passe Wazuh Indexer.")

    parser.add_argument("--chunk-size", type=int, default=500, help="Taille des lots.")
    parser.add_argument("--verify-ssl", action="store_true", default=False,
                        help="Vérifier le certificat SSL (Généralement False pour Wazuh self-signed).")
    parser.add_argument("--es-timeout", type=int, default=60, help="Timeout.")
    parser.add_argument("--thread-count", type=int, default=4, help="Threads.")
    parser.add_argument("--mode", choices=['streaming', 'parallel'], default='parallel',
                        help="Mode d'envoi.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    start_time = time.time()

    try:
        pipeline = PlasoPipeline(
            case_name=args.case_name,
            machine_name=args.machine_name,
            timeline_path=args.timeline,
            es_hosts=args.es_hosts.split(','),
            es_user=args.es_user,
            es_pass=args.es_pass,
            chunk_size=args.chunk_size,
            verify_ssl=args.verify_ssl,
            es_timeout=args.es_timeout,
            thread_count=args.thread_count,
            mode=args.mode
        )
        pipeline.run()
    except Exception as e:
        print(f"\n[ERREUR] {e}")
        traceback.print_exc()
    finally:
        print(f"\n[*] Durée : {str(timedelta(seconds=int(time.time() - start_time)))}")
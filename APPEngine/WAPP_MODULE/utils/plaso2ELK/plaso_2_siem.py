#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import re
import os
import traceback
import time
from datetime import timedelta
from .elastic_uploader import ElasticUploader
from types import GeneratorType

from .plaso_processors.base_processor import BaseEventProcessor
from .plaso_processors.evtx_processor import PlasoEvtxProcessor
from .plaso_processors.registry_processor import PlasoRegistryProcessor
from .plaso_processors.mft_processor import PlasoMftProcessor
from .plaso_processors.lnk_processor import PlasoLnkProcessor
from .plaso_processors.prefetch_processor import PlasoPrefetchProcessor
from .plaso_processors.srum_processor import PlasoSrumProcessor
from .plaso_processors.browser_history_processor import PlasoBrowserHistoryProcessor
from .plaso_processors.amcache_processor import PlasoAmcacheProcessor
from .plaso_processors.generic_processor import PlasoGenericProcessor
from .plaso_processors.appcompatcache_processor import PlasoAppCompatCacheProcessor
from .plaso_processors.userassist_processor import PlasoUserAssistProcessor
from .plaso_processors.runkey_processor import PlasoRunKeyProcessor
from .plaso_processors.usb_processor import PlasoUsbProcessor
from .plaso_processors.mru_processor import PlasoMruProcessor


class PlasoPipeline:
    """
    Orchestre la lecture d'une timeline Plaso (jsonl) et l'envoi des événements
    parsés à Elasticsearch via des processeurs dédiés.
    """

    def __init__(self, case_name, machine_name, timeline_path, es_hosts, es_user, es_pass, chunk_size, verify_ssl,
                 es_timeout, thread_count, mode):
        self.case_name = self._sanitize_for_index(case_name)
        self.machine_name = machine_name.lower().replace(" ", "_")
        self.timeline_path = timeline_path
        self.chunk_size = chunk_size

        self.index_prefix = f"plaso_{self.case_name}_{self.machine_name}"

        self.uploader = ElasticUploader(es_hosts, es_user, es_pass, verify_ssl, es_timeout, thread_count, mode)

        # MAPPING VERS LES NOUVEAUX INDEX PLUS LARGES
        # IMPORTANT : L'ordre est crucial. Les regex les plus spécifiques doivent être testées AVANT les regex génériques.
        self.parser_regex_map = {
            # --- PROCESS (Artefacts d'exécution - Prioritaires car souvent 'winreg') ---
            "amcache": re.compile(r'winreg/amcache'),  # Spécifique (winreg)
            "userassist": re.compile(r'userassist'),  # Spécifique (winreg)
            "appcompatcache": re.compile(r'appcompatcache'),
            "srum": re.compile(r'esedb/srum'),
            "prefetch": re.compile(r'prefetch'),

            # --- HIVE SPÉCIFIQUES (Registre Windows) ---
            "runkey": re.compile(r'winreg/windows_run'),  # Spécifique
            "usb": re.compile(r'winreg/windows_usb_devices'),  # Spécifique
            "mru": re.compile(r'winreg/(bagmru|mrulistex)'),  # Spécifique

            # --- HIVE GÉNÉRIQUE (Registre Windows - Doit être après les spécifiques) ---
            "hive": re.compile(r'winreg'),  # Générique (attrape tout le reste de winreg)

            # --- EVTX ---
            "evtx": re.compile(r'winevtx'),

            # --- BROWSER ---
            "browser_history": re.compile(r'(sqlite/((chrome|firefox|edge).*history))'),

            # --- FILES ---
            "lnk": re.compile(r'lnk'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)'),

            # --- OTHER / FALLBACK ---
            "other": re.compile(r'.*')  # Prend tout le reste
        }

        # Dictionnaire pour mapper le type d'artefact (clé du processeur) au nom de l'INDEX CONSOLIDÉ
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
        # La boucle respecte l'ordre d'insertion du dictionnaire (Python 3.7+)
        for key, value_regex in self.parser_regex_map.items():
            if re.search(value_regex, parser):
                return key
        return "other"

    def run(self):
        print("\n--- CONFIGURATION ---")
        print(f"  Fichier Timeline : {self.timeline_path}")
        print(f"  Index Prefix     : {self.index_prefix}")
        print(f"  Taille des Lots  : {self.chunk_size}")
        print(f"  Mode d'envoi     : {self.uploader.mode}")
        print(f"  Timeout (s)      : {self.uploader.es_timeout}")
        print("---------------------\n")

        # Générer et envoyer les actions
        actions_generator = self._process_timeline_file()

        # Mettre en place les templates ES pour les nouvelles catégories (Priorité 400)
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
        print(f"[*] Début de la lecture du fichier timeline : {self.timeline_path}")
        it = 0
        try:
            with open(self.timeline_path, 'r', encoding='utf-8') as f:
                for line in f:
                    it += 1

                    if it % (self.chunk_size * 10) == 0:  # Log de progression
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
                            print(
                                f"[Attention] Le processeur '{artefact_type_key}' a retourné un résultat inattendu: {type(processor_result)}. Traitement générique de l'erreur.")
                            processed_doc = {"message": f"Processor '{artefact_type_key}' returned malformed result.",
                                             "raw_event": event.get("event_raw_string")}
                            specific_index_key = "other"
                            events_to_yield = [(processed_doc, specific_index_key)]

                        for item in events_to_yield:
                            try:
                                processed_doc, specific_index_key = item
                            except ValueError as ve:
                                print(f"[ERREUR D'UNPACKING] Échec à la ligne {it} ({artefact_type_key}). Erreur: {ve}")
                                error_doc = {
                                    "message": f"Unpacking error: {ve}. Original item: {item}",
                                    "raw_event_line": stripped_line,
                                    "artefact_type": "error_data"
                                }
                                specific_index_key = "other"
                                processed_doc = error_doc
                            except Exception as e:
                                print(f"[ERREUR CRITIQUE] Échec à la ligne {it} ({artefact_type_key}). Erreur: {e}")
                                error_doc = {
                                    "message": f"Critical iteration error: {e}",
                                    "raw_event_line": stripped_line,
                                    "artefact_type": "critical_error"
                                }
                                specific_index_key = "other"
                                processed_doc = error_doc

                            # CONSERVATION DE LA CLÉ SPÉCIFIQUE DANS LE DOCUMENT
                            processed_doc["artefact_type"] = specific_index_key

                            # DÉTERMINATION DE L'INDEX CONSOLIDÉ
                            index_category_key = self.index_category_map.get(specific_index_key, "others")

                            index_name = f"{self.index_prefix}_{index_category_key}"

                            yield {
                                "_index": index_name,
                                "_source": processed_doc
                            }

                    except json.JSONDecodeError:
                        print(f"[Attention] Ligne JSON invalide ignorée (ligne {it})")
                        continue
                    except Exception as e:
                        print(f"[ERREUR] Échec du traitement de la ligne {it}. Erreur: {e}")
                        print(f"  Ligne: {stripped_line[:200]}...")
                        traceback.print_exc()

        except FileNotFoundError:
            print(f"[ERREUR FATALE] Le fichier timeline '{self.timeline_path}' n'a pas été trouvé.")
            exit(1)
        except Exception as e:
            print(f"[ERREUR FATALE] Échec de la lecture du fichier. Erreur: {e}")
            traceback.print_exc()
            exit(1)

        print(f"[*] Lecture du fichier terminée. Total de {it} lignes traitées.")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Processeur de timeline Plaso (jsonl) pour envoi vers Elasticsearch.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-t", "--timeline", required=True,
                        help="Chemin vers le fichier timeline Plaso au format JSON Lines (jsonl).")
    parser.add_argument("-c", "--case-name", required=True, help="Nom du cas (utilisé dans le nom de l'index).")
    parser.add_argument("-m", "--machine-name", required=True,
                        help="Nom de la machine (utilisé dans le nom de l'index).")
    parser.add_argument("--es-hosts", default="https://localhost:9200",
                        help="Hôte(s) Elasticsearch, séparés par des virgules.")
    parser.add_argument("--es-user", default="elastic", help="Nom d'utilisateur pour Elasticsearch.")
    parser.add_argument("--es-pass", default="changeme", help="Mot de passe pour Elasticsearch.")
    parser.add_argument("--chunk-size", type=int, default=250, help="Nombre de documents à envoyer par lot.")
    parser.add_argument("--verify-ssl", action="store_true", dest="verify_ssl", default=False,
                        help="Active la vérification du certificat SSL (désactivée par défaut).")
    parser.add_argument("--es-timeout", type=int, default=60,
                        help="Délai d'attente pour les requêtes Elasticsearch (en secondes).")
    parser.add_argument("--thread-count", type=int, default=4, help="Nombre de threads à utiliser pour parallel_bulk.")
    parser.add_argument("--mode", choices=['streaming', 'parallel'], default='parallel',
                        help="Mode d'envoi vers Elasticsearch.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    # Démarrage du chronomètre
    start_time = time.time()
    print(f"[*] Démarrage du script à {time.strftime('%H:%M:%S', time.localtime(start_time))}")

    try:
        pipeline = PlasoPipeline(
            case_name=args.case_name,
            machine_name=args.machine_name,
            timeline_path=args.timeline,
            es_hosts=args.es_hosts.split(','),  # Convertir en liste
            es_user=args.es_user,
            es_pass=args.es_pass,
            chunk_size=args.chunk_size,
            verify_ssl=args.verify_ssl,
            es_timeout=args.es_timeout,
            thread_count=args.thread_count,
            mode=args.mode
        )
        pipeline.run()
    except (ConnectionError) as e:
        print(f"\n[ERREUR DE CONNEXION] {e}")
    except Exception as e:
        print(f"\n[ERREUR INATTENDUE] Une erreur est survenue : {e}")
        traceback.print_exc()
    finally:
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"\n[*] Fin du traitement.")
        print(f"[*] Temps d'exécution total : {str(timedelta(seconds=int(elapsed_time)))}")
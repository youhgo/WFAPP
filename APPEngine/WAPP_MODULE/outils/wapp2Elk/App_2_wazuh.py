#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os
import argparse
import traceback
import json

from .wazuh_uploader import WazuhUploader
from .processors.evtx_processor import EvtxJsonProcessor
from .processors.disk_processor import DiskProcessor
from .processors.lnk_processor import LnkJsonProcessor
from .processors.registry_processor import RegistryJsonProcessor
from .processors.network_processor import NetworkProcessor
from .processors.processes_processor import ProcessesProcessor
from .processors.prefetch_processor import PrefetchJsonProcessor
from .processors.systeminfo_processor import SystemInfoProcessor

class ForensicPipeline:
    """
    Classe principale pour orchestrer le parsing d'artefacts forensiques et leur envoi à Wazuh Indexer.
    """

    def __init__(self, case_name, machine_name, es_hosts, es_user, es_pass, chunk_size, verify_ssl,
                 artifact_types, es_timeout, thread_count, mode, source_dir=None, config_file=None):
        self.case_name = self._sanitize_for_index(case_name)
        self.machine_name = self._sanitize_for_index(machine_name)
        self.index_prefix = self._sanitize_for_index("wapp")
        self.source_dir = source_dir
        self.config_file = config_file
        self.chunk_size = chunk_size

        self.allowed_types = self._normalize_artifact_types(artifact_types)

        self.target_indices = {
            "evtx": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_evtx",
            "disk": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_disk",
            "lnk": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_lnk",
            "registry": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_registry",
            "network": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_network",
            "processes": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_process",
            "prefetch": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_prefetch",
            "system_info": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_systeminfo"
        }

        self.ARTEFACT_PATTERNS = {
            r'^.*Amcache\.hve_regpy\.json$': "amcache_regpy",
            r'^.*Amcache\.hve_yarp\.jsonl$': "amcache_yarp",
            r'^.*SECURITY_yarp\.jsonl$': "registry_security",
            r'^.*SOFTWARE_yarp\.jsonl$': "registry_software",
            r'^.*SYSTEM_yarp\.jsonl$': "registry_system",
            r'^.*NTUSER\.DAT_yarp\.jsonl$': "registry_ntuser",
            r'^.*SAM_yarp.jsonl$': "registry_sam",
            r'.*\.evtx\.json$': "evtx",
            r'^mft\.json$': "mft",
            r'^mft\.timeline$': "mft_timeline",
            r'^USNINFO.*\.csv$': "usnjrnl",
            r'^.*\.lnk\.json$': "lnk",
            r'^netstat\.txt$': "netstat",
            r'^tcpvcon\.txt$': "tcpvcon",
            r'^arp_cache\.txt$': "arp",
            r'^DNS_records\.txt$': "dns",
            r'^autoruns\.csv$': "autoruns_sysinternals",
            r'^processes1\.csv$': "processes_win32",
            r'^processes2\.csv$': "processes_get_proc",
            r'^Process_sampleinfo\.csv$': "processes_sampleinfo",
            r'^Process_timeline\.csv$': "processes_timeline",
            r'^Process_Autoruns\.xml$': "processes_autorun",
            r'^.*\.pf\.json$': "prefetch"
        }

        self.uploader = WazuhUploader(
            es_hosts=es_hosts.split(','),
            es_user=es_user,
            es_pass=es_pass,
            verify_ssl=verify_ssl,
            es_timeout=es_timeout,
            thread_count=thread_count,
            mode=mode
        )

        self.processors = {
            "evtx": EvtxJsonProcessor(), "disk": DiskProcessor(), "lnk": LnkJsonProcessor(),
            "registry": RegistryJsonProcessor(), "network": NetworkProcessor(), "processes": ProcessesProcessor(),
            "prefetch": PrefetchJsonProcessor(), "system_info": SystemInfoProcessor()
        }

    def _sanitize_for_index(self, name: str) -> str:
        return ''.join(c if c.isalnum() or c in '-_' else '_' for c in name).lower()

    def _normalize_artifact_types(self, types_str: str) -> set:
        if not types_str or "all" in types_str.lower():
            return {"all"}

        mapping = {
            "process": "processes", "processes": "processes",
            "pf": "prefetch", "prefetch": "prefetch",
            "hive": "registry", "registry": "registry", "reg": "registry",
            "network": "network", "net": "network",
            "disk": "disk", "fs": "disk", "mft": "disk",
            "evtx": "evtx", "event": "evtx", "logs": "evtx",
            "lnk": "lnk", "shortcut": "lnk"
        }

        normalized = set()
        for t in types_str.split(','):
            t_clean = t.strip().lower()
            if t_clean in mapping:
                normalized.add(mapping[t_clean])
            else:
                print(f"[Attention] Type d'artefact inconnu ignoré : '{t_clean}'")

        return normalized

    def validate_patterns(self):
        print("[*] Validation des patterns d'artefacts...")
        for pattern in self.ARTEFACT_PATTERNS.keys():
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                print(f"\n[ERREUR DE CONFIGURATION] Expression régulière invalide : '{pattern}'")
                exit(1)
        print("[+] Patterns validés avec succès.")

    def run(self):
        self.validate_patterns()

        print("\n--- CONFIGURATION WAZUH INDEXER ---")
        print(f"Types demandés : {', '.join(self.allowed_types)}")
        for doc_type, index_name in self.target_indices.items():
            if "all" in self.allowed_types or doc_type in self.allowed_types:
                print(f"Index {doc_type.upper():<10}: {index_name}")
        print("-----------------------------------\n")

        template_patterns = {}
        for name in self.target_indices.keys():
            if "all" in self.allowed_types or name in self.allowed_types:
                template_patterns[name] = f"*_{self.machine_name}_{name}"

        self.uploader.setup_templates(priority=400, **template_patterns)

        if self.config_file:
            actions_generator = self._process_from_config()
        elif self.source_dir:
            actions_generator = self._find_and_process_files()
        else:
            print("[ERREUR] Aucun répertoire source ni fichier de configuration spécifié.")
            return

        self.uploader.bulk_upload(actions_generator, self.chunk_size)

    def _process_single_file(self, filepath, dataset, filename):
        processor_key, processor_method = self._get_processor_for_dataset(dataset)

        if "all" not in self.allowed_types and processor_key not in self.allowed_types:
            return

        print(f"  -> Traitement : {filepath} (dataset: {dataset})")

        if processor_method:
            kwargs = {"machine_name": self.machine_name} if processor_key == "network" else {}
            try:
                for doc, doc_type in processor_method.process_file(filepath, dataset=dataset,
                                                                   filename=filename, **kwargs):

                    # SÉCURITÉ : Vérifie si le processeur a renvoyé un type d'index valide
                    if doc_type not in self.target_indices:
                        print(
                            f"  [ERREUR CRITIQUE] Le processeur a renvoyé '{doc_type}', mais l'orchestrateur ne connaît que : {list(self.target_indices.keys())}")
                        continue

                    yield {"_index": self.target_indices[doc_type], "_source": doc}

            except Exception as e:
                # GESTION D'ERREUR VERBEUSE : Affiche le type d'erreur et la trace complète
                print(
                    f"  [ERREUR CRITIQUE] Echec lors du traitement du fichier {filename}: {type(e).__name__} - {str(e)}")
                print(traceback.format_exc())
        else:
            print(f"  [Attention] Aucun processeur trouvé pour le dataset '{dataset}'. Fichier ignoré.")

    def _process_from_config(self):
        # Pour éviter d'afficher un dictionnaire géant dans les logs, on adapte le message
        source_name = "un dictionnaire en mémoire" if isinstance(self.config_file, dict) else self.config_file
        print(f"[*] Lecture de la configuration depuis : {source_name}")

        try:
            # 1. Vérifie si on a déjà un dictionnaire (cas du WAPP Worker)
            if isinstance(self.config_file, dict):
                config = self.config_file

            # 2. Sinon, on considère que c'est un chemin de fichier (cas de la Ligne de Commande)
            elif isinstance(self.config_file, (str, bytes, os.PathLike)):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            else:
                print(f"[ERREUR] Format de configuration non supporté : {type(self.config_file)}")
                return

            # La suite du code reste identique
            for item in config.get("files", []):
                filepath = item.get("path")
                dataset = item.get("type")

                if not filepath or not dataset:
                    print(f"  [Attention] Entrée invalide dans la configuration : {item}")
                    continue

                if not os.path.exists(filepath):
                    print(f"  [Attention] Fichier introuvable : {filepath}")
                    continue

                filename = os.path.basename(filepath)
                yield from self._process_single_file(filepath, dataset, filename)

        except Exception as e:
            print(f"[ERREUR] Impossible de lire ou analyser le fichier de configuration : {e}")
            traceback.print_exc()

    def _find_and_process_files(self):
        print(f"[*] Recherche récursive des artefacts dans : {self.source_dir}")

        IGNORED_DIRS = {'timeline'}
        IGNORED_FILES = ["USN.CSV"]

        for root, dirs, files in os.walk(self.source_dir):
            dirs[:] = [d for d in dirs if d.lower() not in IGNORED_DIRS]

            for filename in files:
                dataset = None
                if any(ignored in filename.lower() for ignored in IGNORED_FILES):
                    print(f"  [Ignoré] {filename} correspond à la liste d'exclusion.")
                    continue

                for pattern, ds in self.ARTEFACT_PATTERNS.items():
                    if re.match(pattern, filename, re.IGNORECASE):
                        dataset = ds
                        break

                if dataset:
                    filepath = os.path.join(root, filename)
                    yield from self._process_single_file(filepath, dataset, filename)

    def _get_processor_for_dataset(self, dataset):
        """
        CORRECTION: Logique assouplie via `startswith` et conversion en minuscules pour attraper
        les catégories WAPP (ex: 'network_netstat', 'process_autoruns', 'registry_SAM').
        """
        ds_lower = dataset.lower()

        if ds_lower.startswith("registry") or ds_lower.startswith("amcache"):
            return "registry", self.processors["registry"]

        elif ds_lower.startswith("disk") or ds_lower in ["mft", "usnjrnl", "mft_timeline"]:
            return "disk", self.processors["disk"]

        elif ds_lower.startswith("network") or ds_lower in ["netstat", "tcpvcon", "arp", "dns"]:
            return "network", self.processors["network"]

        elif ds_lower.startswith("process") or ds_lower.startswith("autorun"):
            return "processes", self.processors["processes"]

        elif ds_lower.startswith("evtx"):
            return "evtx", self.processors["evtx"]

        elif ds_lower.startswith("lnk"):
            return "lnk", self.processors["lnk"]

        elif ds_lower.startswith("prefetch"):
            return "prefetch", self.processors["prefetch"]

        elif ds_lower == "systeminfo":
            return "system_info", self.processors["system_info"]

        # Si un type est inconnu (ex: systemInfo sans processeur dédié), on retourne None
        return None, None


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Processeur de logs forensiques pour envoi vers Wazuh Indexer.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-c", "--case-name", required=True, help="Nom du cas.")
    parser.add_argument("-m", "--machine-name", required=True, help="Nom de la machine analysée.")
    parser.add_argument("-s", "--source-dir",
                        help="Répertoire source à scanner (utilisé si --config n'est pas fourni).")
    parser.add_argument("--config",
                        help="Chemin vers le fichier de configuration JSON contenant les fichiers à traiter.")
    parser.add_argument("-t", "--type", default="all",
                        help="Types d'artefacts à traiter, séparés par virgules. Options: process, hive, network, disk, evtx, lnk, prefetch.")
    parser.add_argument("--es-hosts", default="https://localhost:9200", help="Hôte(s) Wazuh Indexer.")
    parser.add_argument("--es-user", default="admin", help="Nom d'utilisateur Wazuh Indexer.")
    parser.add_argument("--es-pass", default="SecretPassword", help="Mot de passe Wazuh Indexer.")
    parser.add_argument("--chunk-size", type=int, default=5000, help="Nombre de documents à envoyer par lot.")
    parser.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl",
                        help="Désactive la vérification SSL.")
    parser.add_argument("--es-timeout", type=int, default=60, help="Timeout de la connexion.")
    parser.add_argument("--thread-count", type=int, default=4, help="Nombre de threads (mode parallel).")
    parser.add_argument("--mode", choices=['streaming', 'parallel'], default='parallel',
                        help="Mode d'envoi vers Wazuh.")

    args = parser.parse_args()

    if not args.source_dir and not args.config:
        parser.error(
            "Vous devez spécifier soit un répertoire source (-s/--source-dir), soit un fichier de configuration (--config).")

    return args


if __name__ == "__main__":
    args = parse_arguments()

    try:
        pipeline = ForensicPipeline(
            case_name=args.case_name,
            machine_name=args.machine_name,
            source_dir=args.source_dir,
            config_file=args.config,
            es_hosts=args.es_hosts,
            es_user=args.es_user,
            es_pass=args.es_pass,
            chunk_size=args.chunk_size,
            verify_ssl=args.verify_ssl,
            artifact_types=args.type,
            es_timeout=args.es_timeout,
            thread_count=args.thread_count,
            mode=args.mode
        )
        pipeline.run()
    except (FileNotFoundError, ConnectionError) as e:
        print(f"\n[ERREUR] {e}")
    except Exception as e:
        print(f"\n[ERREUR INATTENDUE] Une erreur est survenue : {e}")
        traceback.print_exc()
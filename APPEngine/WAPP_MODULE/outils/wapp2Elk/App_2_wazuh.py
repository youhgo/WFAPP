#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os
import argparse
import traceback

from wazuh_uploader import WazuhUploader
from processors.evtx_processor import EvtxJsonProcessor
from processors.disk_processor import DiskProcessor
from processors.lnk_processor import LnkJsonProcessor
from processors.registry_processor import RegistryJsonProcessor
from processors.network_processor import NetworkProcessor
from processors.processes_processor import ProcessesProcessor
from processors.prefetch_processor import PrefetchJsonProcessor


class ForensicPipeline:
    """
    Classe principale pour orchestrer le parsing d'artefacts forensiques et leur envoi à Wazuh Indexer.
    """

    def __init__(self, case_name, machine_name, source_dir, es_hosts, es_user, es_pass, chunk_size, verify_ssl,
                 artifact_types, es_timeout, thread_count, mode):
        self.case_name = self._sanitize_for_index(case_name)
        self.machine_name = self._sanitize_for_index(machine_name)
        self.index_prefix = self._sanitize_for_index("wapp")
        self.source_dir = source_dir
        self.chunk_size = chunk_size

        self.allowed_types = self._normalize_artifact_types(artifact_types)

        self.target_indices = {
            "evtx": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_evtx",
            "disk": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_disk",
            "lnk": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_lnk",
            "registry": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_registry",
            "network": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_network",
            "processes": f"{self.index_prefix}_{self.case_name}_{self.machine_name}_process"
        }

        self.ARTEFACT_PATTERNS = {
            r'^Amcache\.hve_regpy\.json$': "amcache_regpy",
            r'^Amcache\.hve_yarp\.jsonl$': "amcache_yarp",
            r'^SECURITY_yarp\.jsonl$': "registry_security",
            r'^SOFTWARE_yarp\.jsonl$': "registry_software",
            r'^SYSTEM_yarp\.jsonl$': "registry_system",
            r'^NTUSER\.DAT_yarp\.jsonl$': "registry_ntuser",
            r'^SAM_yarp.jsonl$': "registry_sam",
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

        # Initialisation du nouvel uploader Wazuh
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
            "prefetch": PrefetchJsonProcessor()
        }

    def _sanitize_for_index(self, name: str) -> str:
        return ''.join(c if c.isalnum() or c in '-_' else '_' for c in name).lower()

    def _normalize_artifact_types(self, types_str: str) -> set:
        """Convertit l'entrée utilisateur en catégories internes."""
        if not types_str or "all" in types_str.lower():
            return {"all"}

        mapping = {
            "process": "processes", "processes": "processes", "pf": "processes", "prefetch": "processes",
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
        """Vérifie la validité de toutes les expressions régulières au démarrage."""
        print("[*] Validation des patterns d'artefacts...")
        for pattern in self.ARTEFACT_PATTERNS.keys():
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                print(f"\n[ERREUR DE CONFIGURATION] L'expression régulière suivante est invalide : '{pattern}'")
                exit(1)
        print("[+] Patterns validés avec succès.")

    def run(self):
        """Lance l'ensemble du processus de traitement et d'envoi."""
        self.validate_patterns()

        print("\n--- CONFIGURATION WAZUH INDEXER ---")
        print(f"Types demandés : {', '.join(self.allowed_types)}")
        for doc_type, index_name in self.target_indices.items():
            if "all" in self.allowed_types or doc_type in self.allowed_types:
                print(f"Index {doc_type.upper():<10}: {index_name}")
        print("-----------------------------------\n")

        # Configuration des templates
        template_patterns = {}
        for name in self.target_indices.keys():
            if "all" in self.allowed_types or name in self.allowed_types:
                template_patterns[name] = f"*_{self.machine_name}_{name}"

        # Utilisation de la méthode adaptée pour Wazuh
        self.uploader.setup_templates(priority=400, **template_patterns)

        actions_generator = self._find_and_process_files()

        # Envoi des données (streaming ou parallel)
        self.uploader.bulk_upload(actions_generator, self.chunk_size)

    def _find_and_process_files(self):
        """Parcourt le répertoire source, identifie les fichiers et délègue le parsing."""
        print(f"[*] Recherche récursive des artefacts dans : {self.source_dir}")

        IGNORED_DIRS = {'timeline'}
        IGNORED_FILES = ["USN.CSV"]

        for root, dirs, files in os.walk(self.source_dir):
            dirs[:] = [d for d in dirs if d.lower() not in IGNORED_DIRS]

            for filename in files:
                dataset = None
                # --- VÉRIFICATION DE LA LISTE D'EXCLUSION ---
                if any(ignored in filename.lower() for ignored in IGNORED_FILES):
                    print(f"  [Ignoré] {filename} correspond à la liste d'exclusion.")
                    continue
                for pattern, ds in self.ARTEFACT_PATTERNS.items():
                    if re.match(pattern, filename, re.IGNORECASE):
                        dataset = ds
                        break

                if dataset:
                    processor_key, processor_method = self._get_processor_for_dataset(dataset)

                    if "all" not in self.allowed_types and processor_key not in self.allowed_types:
                        continue

                    filepath = os.path.join(root, filename)
                    print(f"  -> Fichier trouvé : {filepath} (dataset: {dataset})")

                    if processor_method:
                        kwargs = {"machine_name": self.machine_name} if processor_key == "network" else {}
                        try:
                            for doc, doc_type in processor_method.process_file(filepath, dataset=dataset,
                                                                               filename=filename, **kwargs):
                                yield {"_index": self.target_indices[doc_type], "_source": doc}
                        except Exception as e:
                            print(f"  [ERREUR] Echec traitement fichier {filename}: {e}")
                    else:
                        print(f"  [Attention] Aucun processeur trouvé pour le dataset '{dataset}'. Fichier ignoré.")

    def _get_processor_for_dataset(self, dataset):
        if dataset.startswith("registry") or dataset.startswith("amcache"):
            return "registry", self.processors["registry"]
        elif dataset in ["mft", "usnjrnl", "mft_timeline"]:
            return "disk", self.processors["disk"]
        elif dataset in ["netstat", "tcpvcon", "arp", "dns"]:
            return "network", self.processors["network"]
        elif dataset.startswith("processes") or dataset.startswith("autoruns"):
            return "processes", self.processors["processes"]
        elif dataset == "evtx":
            return "evtx", self.processors["evtx"]
        elif dataset == "lnk":
            return "lnk", self.processors["lnk"]
        elif dataset == "prefetch":
            return "processes", self.processors["prefetch"]
        return None, None


def parse_arguments():
    """Définit et parse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Processeur de logs forensiques pour envoi vers Wazuh Indexer.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-c", "--case-name", required=True, help="Nom du cas.")
    parser.add_argument("-m", "--machine-name", required=True, help="Nom de la machine analysée.")
    parser.add_argument("-s", "--source-dir", required=True,
                        help="Répertoire source à scanner récursivement.")
    parser.add_argument("-t", "--type", default="all",
                        help="Types d'artefacts à traiter, séparés par virgules. "
                             "Options: process, hive, network, disk, evtx, lnk.")

    # Arguments pour la connexion Wazuh Indexer (par défaut Wazuh credentials)
    parser.add_argument("--es-hosts", default="https://localhost:9200",
                        help="Hôte(s) Wazuh Indexer, séparés par des virgules.")
    parser.add_argument("--es-user", default="admin", help="Nom d'utilisateur Wazuh Indexer.")
    parser.add_argument("--es-pass", default="SecretPassword", help="Mot de passe Wazuh Indexer.")

    # Arguments de performance et upload
    parser.add_argument("--chunk-size", type=int, default=5000, help="Nombre de documents à envoyer par lot.")
    parser.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl",
                        help="Désactive la vérification du certificat SSL.")
    parser.add_argument("--es-timeout", type=int, default=60, help="Timeout de la connexion.")
    parser.add_argument("--thread-count", type=int, default=4, help="Nombre de threads (mode parallel).")
    parser.add_argument("--mode", choices=['streaming', 'parallel'], default='parallel',
                        help="Mode d'envoi vers Wazuh Indexer.")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    try:
        pipeline = ForensicPipeline(
            case_name=args.case_name,
            machine_name=args.machine_name,
            source_dir=args.source_dir,
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
        import traceback

        print(f"\n[ERREUR INATTENDUE] Une erreur est survenue : {e}")
        traceback.print_exc()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os
import argparse
import traceback
from .elastic_uploader import ElasticUploader
from .processors.evtx_processor import EvtxJsonProcessor
from .processors.disk_processor import DiskProcessor
from .processors.lnk_processor import LnkJsonProcessor
from .processors.registry_processor import RegistryJsonProcessor
from .processors.network_processor import NetworkProcessor
from .processors.processes_processor import ProcessesProcessor


class ForensicPipeline:
    """
    Classe principale pour orchestrer le parsing d'artefacts forensiques et leur envoi à Elasticsearch.
    """

    def __init__(self, case_name, machine_name, source_dir, es_hosts, es_user, es_pass, chunk_size, verify_ssl):
        self.case_name = self._sanitize_for_index(case_name)
        self.machine_name = self._sanitize_for_index(machine_name)
        self.source_dir = source_dir
        self.chunk_size = chunk_size

        self.target_indices = {
            "evtx": f"{self.case_name}_{self.machine_name}_evtx",
            "disk": f"{self.case_name}_{self.machine_name}_disk",
            "lnk": f"{self.case_name}_{self.machine_name}_lnk",
            "registry": f"{self.case_name}_{self.machine_name}_registry",
            "network": f"{self.case_name}_{self.machine_name}_network",
            "processes": f"{self.case_name}_{self.machine_name}_processes"
        }

        self.ARTEFACT_PATTERNS = {
            r'^Amcache\.hve_regpy\.json$': "amcache_regpy",
            r'^Amcache\.hve_yarp\.jsonl$': "amcache_yarp",
            r'^SECURITY_yarp\.jsonl$': "registry_security",
            r'^SOFTWARE_yarp\.jsonl$': "registry_software",
            r'^SYSTEM_yarp\.jsonl$': "registry_system",
            r'^NTUSER\.DAT_yarp\.jsonl$': "registry_ntuser",
            r'.*\.evtx\.json$': "evtx",
            r'^mft\.json$': "mft",
            r'^USN.*\.csv$': "usnjrnl",
            r'^.*\.lnk(\.|\_\{.*\})\.json$': "lnk",
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
            r'^Process_Autoruns\.xml$': "processes_autorun"
        }

        self.uploader = ElasticUploader(es_hosts.split(','), es_user, es_pass, verify_ssl)
        self.processors = {
            "evtx": EvtxJsonProcessor(), "disk": DiskProcessor(), "lnk": LnkJsonProcessor(),
            "registry": RegistryJsonProcessor(), "network": NetworkProcessor(), "processes": ProcessesProcessor()
        }

    def _sanitize_for_index(self, name: str) -> str:
        return ''.join(c if c.isalnum() or c in '-_' else '_' for c in name).lower()

    def validate_patterns(self):
        """Vérifie la validité de toutes les expressions régulières au démarrage."""
        print("[*] Validation des patterns d'artefacts...")
        for pattern in self.ARTEFACT_PATTERNS.keys():
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                print(f"\n[ERREUR DE CONFIGURATION] L'expression régulière suivante est invalide : '{pattern}'")
                print(f"Détails de l'erreur: {e}")
                print("Veuillez corriger le dictionnaire ARTEFACT_PATTERNS dans le script.")
                exit(1)
        print("[+] Patterns validés avec succès.")

    def run(self):
        """Lance l'ensemble du processus de traitement et d'envoi."""
        self.validate_patterns()

        print("\n--- CONFIGURATION ---")
        for doc_type, index_name in self.target_indices.items():
            print(f"Index {doc_type.upper():<10}: {index_name}")
        print("---------------------\n")

        template_patterns = {name: f"*_{self.machine_name}_{name}" for name in self.target_indices.keys()}
        self.uploader.setup_templates(**template_patterns)

        actions_generator = self._find_and_process_files()
        self.uploader.streaming_bulk_upload(actions_generator, self.chunk_size)

    def _find_and_process_files(self):
        """Parcourt le répertoire source, identifie les fichiers et délègue le parsing."""
        print(f"[*] Recherche récursive des artefacts dans : {self.source_dir}")
        for root, _, files in os.walk(self.source_dir):
            for filename in files:
                dataset = None
                for pattern, ds in self.ARTEFACT_PATTERNS.items():
                    if re.match(pattern, filename, re.IGNORECASE):
                        dataset = ds
                        break

                if dataset:
                    filepath = os.path.join(root, filename)
                    print(f"  -> Fichier trouvé : {filepath} (dataset: {dataset})")

                    processor_key, processor_method = self._get_processor_for_dataset(dataset)
                    if processor_method:
                        kwargs = {"machine_name": self.machine_name} if processor_key == "network" else {}
                        for doc, doc_type in processor_method.process_file(filepath, dataset=dataset, filename=filename,
                                                                           **kwargs):
                            yield {"_index": self.target_indices[doc_type], "_source": doc}
                    else:
                        print(f"  [Attention] Aucun processeur trouvé pour le dataset '{dataset}'. Fichier ignoré.")

    def _get_processor_for_dataset(self, dataset):
        if dataset.startswith("registry") or dataset.startswith("amcache"):
            return "registry", self.processors["registry"]
        elif dataset in ["mft", "usnjrnl"]:
            return "disk", self.processors["disk"]
        elif dataset in ["netstat", "tcpvcon", "arp", "dns"]:
            return "network", self.processors["network"]
        elif dataset.startswith("processes") or dataset.startswith("autoruns"):
            return "processes", self.processors["processes"]
        elif dataset == "evtx":
            return "evtx", self.processors["evtx"]
        elif dataset == "lnk":
            return "lnk", self.processors["lnk"]
        return None, None


def parse_arguments():
    """Définit et parse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Processeur de logs forensiques pour envoi vers Elasticsearch.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-c", "--case-name", required=True, help="Nom du cas.")
    parser.add_argument("-m", "--machine-name", required=True, help="Nom de la machine analysée.")
    parser.add_argument("-s", "--source-dir", required=True,
                        help="Répertoire source à scanner récursivement pour trouver les artefacts.")

    # Arguments pour la connexion Elasticsearch
    parser.add_argument("--es-hosts", default="https://localhost:9200",
                        help="Hôte(s) Elasticsearch, séparés par des virgules.")
    parser.add_argument("--es-user", default="elastic", help="Nom d'utilisateur pour Elasticsearch.")
    parser.add_argument("--es-pass", default="changeme", help="Mot de passe pour Elasticsearch.")
    parser.add_argument("--chunk-size", type=int, default=15000, help="Nombre de documents à envoyer par lot.")
    parser.add_argument("--no-verify-ssl", action="store_false", dest="verify_ssl",
                        help="Désactive la vérification du certificat SSL.")
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
            verify_ssl=args.verify_ssl
        )
        pipeline.run()
    except (FileNotFoundError, ConnectionError) as e:
        print(f"\n[ERREUR] {e}")
    except Exception as e:
        import traceback

        print(f"\n[ERREUR INATTENDUE] Une erreur est survenue : {e}")
        traceback.print_exc()


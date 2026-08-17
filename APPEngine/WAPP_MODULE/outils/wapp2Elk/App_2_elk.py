#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os
import argparse
import traceback
from .elastic_uploader import ElasticUploader
from .elk_registry import ELK_PROCESSORS_REGISTRY
import pkgutil
import importlib
from . import processors

# Charger tous les modules du dossier processors pour déclencher l'enregistrement @register_elk_processor
for _, module_name, _ in pkgutil.iter_modules(processors.__path__):
    importlib.import_module(f".processors.{module_name}", package=__package__)



class ElkForensicPipeline:
    """
    Classe principale pour orchestrer le parsing d'artefacts forensiques et leur envoi à Elasticsearch.
    """

    def __init__(self, case_name, machine_name, source_dir, es_hosts, es_user, es_pass, chunk_size, verify_ssl,
                 artifact_types):
        self.case_name = self._sanitize_for_index(case_name)
        self.machine_name = self._sanitize_for_index(machine_name)
        self.index_prefix = self._sanitize_for_index("wapp")
        self.source_dir = source_dir
        self.chunk_size = chunk_size

        self.allowed_types = self._normalize_artifact_types(artifact_types)

        self.target_indices = {}
        self.processor_instances = {}
        
        for category, cls_list in ELK_PROCESSORS_REGISTRY.items():
            self.target_indices[category] = f"{self.index_prefix}_{self.case_name}_{self.machine_name}_{category}"
            for cls in cls_list:
                self.processor_instances[cls] = cls(case_name=self.case_name, machine_name=self.machine_name)


    def _sanitize_for_index(self, name: str) -> str:
        return ''.join(c if c.isalnum() or c in '-_' else '_' for c in name).lower()

    def _normalize_artifact_types(self, types_str: str) -> set:
        """Convertit l'entrée utilisateur en catégories internes."""
        if not types_str or "all" in types_str.lower():
            return {"all"}

        # Mapping des alias utilisateur vers les clés internes (clés de target_indices)
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
        for cls in self.processor_instances.keys():
            for pattern in cls.DEFAULT_PATTERNS.keys():
                try:
                    re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    print(f"\n[ERREUR DE CONFIGURATION] L'expression régulière suivante est invalide : '{pattern}' (dans {cls.__name__})")
                    exit(1)
        print("[+] Patterns validés avec succès.")

    def run(self):
        """Lance l'ensemble du processus de traitement et d'envoi."""
        self.validate_patterns()

        print("\n--- CONFIGURATION ---")
        print(f"Types demandés : {', '.join(self.allowed_types)}")
        for doc_type, index_name in self.target_indices.items():
            # On affiche uniquement les index qui seront utilisés
            if "all" in self.allowed_types or doc_type in self.allowed_types:
                print(f"Index {doc_type.upper():<10}: {index_name}")
        print("---------------------\n")

        # Setup templates uniquement pour les types concernés
        template_patterns = {}
        for name in self.target_indices.keys():
            if "all" in self.allowed_types or name in self.allowed_types:
                template_patterns[name] = f"*_{self.machine_name}_{name}"

        self.uploader.setup_templates(**template_patterns)

        actions_generator = self._find_and_process_files()
        self.uploader.streaming_bulk_upload(actions_generator, self.chunk_size)

    def _find_and_process_files(self):
        """Parcourt le répertoire source, identifie les fichiers et délègue le parsing."""
        print(f"[*] Recherche récursive des artefacts dans : {self.source_dir}")

        IGNORED_DIRS = {'timeline'}

        for root, dirs, files in os.walk(self.source_dir):
            dirs[:] = [d for d in dirs if d.lower() not in IGNORED_DIRS]

            for filename in files:
                dataset = None
                category = None
                processor_instance = None
                
                # Cherche le bon processeur
                for cls, instance in self.processor_instances.items():
                    for pattern, ds in cls.DEFAULT_PATTERNS.items():
                        if re.match(pattern, filename, re.IGNORECASE):
                            dataset = ds
                            category = cls.__processor_name__
                            processor_instance = instance
                            break
                    if dataset:
                        break

                if dataset and processor_instance:
                    # --- FILTRAGE PAR TYPE (--type) ---
                    if "all" not in self.allowed_types and category not in self.allowed_types:
                        continue

                    filepath = os.path.join(root, filename)
                    print(f"  -> Fichier trouvé : {filepath} (dataset: {dataset})")

                    kwargs = {"machine_name": self.machine_name} if category == "network" else {}
                    try:
                        for doc, doc_type in processor_instance.process_file(filepath, dataset=dataset, filename=filename, **kwargs):
                            yield {"_index": self.target_indices.get(doc_type, self.target_indices[category]), "_source": doc}
                    except Exception as e:
                        print(f"  [ERREUR] Echec traitement fichier {filename}: {e}")



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

    # Nouvel argument --type
    parser.add_argument("-t", "--type", default="all",
                        help="Types d'artefacts à traiter, séparés par virgules. "
                             "Options: process, hive (ou registry), network, disk, evtx, lnk. "
                             "Par défaut: all")

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
        pipeline = ElkForensicPipeline(
            case_name=args.case_name,
            machine_name=args.machine_name,
            source_dir=args.source_dir,
            es_hosts=args.es_hosts,
            es_user=args.es_user,
            es_pass=args.es_pass,
            chunk_size=args.chunk_size,
            verify_ssl=args.verify_ssl,
            artifact_types=args.type  # On passe l'argument type ici
        )
        pipeline.run()
    except (FileNotFoundError, ConnectionError) as e:
        print(f"\n[ERREUR] {e}")
    except Exception as e:
        import traceback

        print(f"\n[ERREUR INATTENDUE] Une erreur est survenue : {e}")
        traceback.print_exc()
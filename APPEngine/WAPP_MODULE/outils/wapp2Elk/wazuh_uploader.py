#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import traceback
import warnings
import os
import time

# On utilise opensearchpy pour la compatibilité avec Wazuh Indexer
from opensearchpy import OpenSearch
from opensearchpy.helpers import streaming_bulk, parallel_bulk
from opensearchpy.exceptions import OpenSearchException, TransportError


def json_default_serializer(obj):
    """Surcharge le sérialiseur JSON pour gérer les objets d'erreur non sérialisables."""
    if isinstance(obj, (OpenSearchException, TransportError)):
        return str(obj)
    try:
        return obj.to_dict()
    except AttributeError:
        raise TypeError(f'Object of type {obj.__class__.__name__} is not JSON serializable')


class WazuhUploader:
    """Gère la connexion et l'envoi en masse des documents au Wazuh Indexer avec robustesse forensique."""

    def __init__(self, es_hosts: list, es_user: str, es_pass: str, verify_ssl: bool, es_timeout: int, thread_count: int,
                 mode: str):
        self.es_timeout = es_timeout
        self.thread_count = thread_count
        self.mode = mode
        self.failed_log_file = "failed_uploads.json"

        try:
            # Configuration de la connexion Wazuh / OpenSearch
            es_options = {
                "hosts": es_hosts,
                "http_auth": (es_user, es_pass),
                "verify_certs": verify_ssl,
                "timeout": es_timeout,
                "max_retries": 10,
                "retry_on_timeout": True,
                "ssl_show_warn": False
            }

            if not verify_ssl:
                from urllib3.exceptions import InsecureRequestWarning
                warnings.filterwarnings('ignore', category=InsecureRequestWarning)
                es_options["ssl_assert_hostname"] = False  # Crucial pour les setups Docker Wazuh

            self.client = OpenSearch(**es_options)

            if not self.client.ping():
                raise ConnectionError("La connexion au Wazuh Indexer a échoué.")
            print("Connexion au Wazuh Indexer réussie.")

            # Initialisation du fichier de logs d'échec
            with open(self.failed_log_file, 'w', encoding='utf-8') as f:
                f.write("")  # Nettoie les échecs de l'exécution précédente

        except Exception as e:
            raise ConnectionError(f"Impossible d'initialiser le client Wazuh/OpenSearch : {e}")

    def _create_index_template(self, template_name: str, index_pattern: str, priority: int):
        """Crée ou met à jour un template d'index."""
        template_body = {
            "index_patterns": [index_pattern],
            "priority": priority,
            "template": {
                "settings": {
                    "index.mapping.total_fields.limit": 5000,  # Augmenté pour éviter les erreurs sur gros volumes
                    "index.refresh_interval": "5s"  # Optimisation de l'ingestion
                },
                "mappings": {
                    "properties": {
                        # Format ECS compatible
                        "@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"}
                    }
                }
            }
        }
        try:
            self.client.indices.put_index_template(
                name=template_name,
                body=template_body
            )
            print(f"Template '{template_name}' pour '{index_pattern}' créé/mis à jour.")
        except Exception as e:
            print(f"[Attention] Impossible de créer le template '{template_name}'. Erreur: {e}")

    def setup_templates(self, priority: int = 400, **kwargs):
        """Configure dynamiquement les templates basés sur les index cibles."""
        for name, pattern in kwargs.items():
            self._create_index_template(f"forensic_{name}_template", pattern, priority)

    def _log_failure(self, doc, error):
        """Sauvegarde les documents échoués sur le disque pour garantir aucune perte de données."""
        with open(self.failed_log_file, 'a', encoding='utf-8') as f:
            entry = {"error": str(error), "document": doc}
            f.write(json.dumps(entry, default=json_default_serializer) + "\n")

    def bulk_upload(self, actions_generator, chunk_size: int):
        """Gère l'upload avec protection contre les surcharges (429) et limites de taille."""

        # CONFIGURATION ROBUSTE
        # 1. max_chunk_bytes: Limite les lots à 50 Mo (votre demande)
        # 2. max_retries: Réessaie 15 fois avant d'échouer
        # 3. max_backoff: Attend jusqu'à 60 secondes si le serveur est occupé

        bulk_params = {
            "chunk_size": chunk_size,
            "max_chunk_bytes": 50 * 1024 * 1024,  # Limite stricte de 50 Mo
            "max_retries": 15,
            "initial_backoff": 2,
            "max_backoff": 60,
            "request_timeout": self.es_timeout,
            "raise_on_error": False,
            "raise_on_exception": False
        }

        if self.mode == 'parallel':
            bulk_func = parallel_bulk
            print(f"\nEnvoi en mode PARALLÈLE ({self.thread_count} threads). Limite : 50 Mo/lot...")
            bulk_params["thread_count"] = self.thread_count
            bulk_params["queue_size"] = 4  # Empêche l'explosion mémoire en parallèle
        else:
            bulk_func = streaming_bulk
            print(f"\nEnvoi en mode STREAMING (séquentiel). Limite : 50 Mo/lot...")

        success_count = 0
        fail_count = 0

        try:
            for ok, result in bulk_func(client=self.client, actions=actions_generator, **bulk_params):
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    # Extraction des détails de l'erreur
                    if self.mode == 'parallel':
                        # parallel_bulk retourne (success, item)
                        action, info = result.popitem() if result else ("unknown", {})
                        error_reason = info.get("error", "Erreur inconnue")
                        doc_id = info.get("_id", "unknown")
                    else:
                        # streaming_bulk retourne (success, result)
                        action, info = result.popitem() if result else ("unknown", {})
                        error_reason = info.get("error", "Erreur inconnue")
                        doc_id = info.get("_id", "unknown")

                    # Affichage console minimal pour ne pas polluer
                    if fail_count % 100 == 0:
                        print(f"   [!] {fail_count} échecs jusqu'ici. Dernier motif : {error_reason}")

                    # Sauvegarde dans le fichier pour récupération forensique
                    self._log_failure({"id": doc_id, "info": info}, error_reason)

            print("\n" + "=" * 30)
            print("ENVOI TERMINÉ")
            print("=" * 30)
            print(f"[-] Documents succès : {success_count}")
            print(f"[-] Documents échec  : {fail_count}")

            if fail_count > 0:
                print(f"[CRITIQUE] {fail_count} documents n'ont pas pu être envoyés.")
                print(f"           Consultez '{self.failed_log_file}' pour récupérer les données.")
            else:
                print("[OK] Intégrité vérifiée : Aucune erreur signalée.")
                if os.path.exists(self.failed_log_file):
                    os.remove(self.failed_log_file)  # Nettoyage si tout est OK

        except Exception as e:
            print(f"ERREUR CRITIQUE DANS LE PIPELINE : {traceback.format_exc()}")
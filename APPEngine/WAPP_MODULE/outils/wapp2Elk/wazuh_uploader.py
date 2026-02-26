#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import traceback
import warnings

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
    """Gère la connexion et l'envoi en masse des documents au Wazuh Indexer."""

    def __init__(self, es_hosts: list, es_user: str, es_pass: str, verify_ssl: bool, es_timeout: int, thread_count: int,
                 mode: str):
        self.es_timeout = es_timeout
        self.thread_count = thread_count
        self.mode = mode

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

        except Exception as e:
            raise ConnectionError(f"Impossible d'initialiser le client Wazuh/OpenSearch : {e}")

    def _create_index_template(self, template_name: str, index_pattern: str, priority: int):
        """Crée ou met à jour un template d'index."""
        template_body = {
            "index_patterns": [index_pattern],
            "priority": priority,
            "template": {
                "settings": {
                    "index.mapping.total_fields.limit": 5000  # Augmenté pour éviter les erreurs sur gros volumes
                },
                "mappings": {
                    "properties": {
                        # CORRECTION : Remplacé 'estimestamp' par '@timestamp' pour compatibilité avec
                        # la plupart des processeurs forensiques générant du format ECS
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

    def bulk_upload(self, actions_generator, chunk_size: int):
        """Gère l'upload selon le mode choisi (parallèle ou streaming/séquentiel)."""
        if self.mode == 'parallel':
            bulk_func = parallel_bulk
            print(f"\nEnvoi en mode PARALLÈLE ({self.thread_count} threads) par lots de {chunk_size}...")
            kwargs = {"thread_count": self.thread_count}
        else:
            bulk_func = streaming_bulk
            print(f"\nEnvoi en mode STREAMING (séquentiel) par lots de {chunk_size}...")
            kwargs = {}

        success_count, fail_count = 0, 0
        try:
            for ok, result in bulk_func(
                    client=self.client,
                    actions=actions_generator,
                    chunk_size=chunk_size,
                    request_timeout=self.es_timeout,
                    raise_on_error=False,
                    raise_on_exception=False,
                    **kwargs
            ):
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    # Affiche l'erreur complète uniquement sur le premier échec ou un échantillon pour éviter de spammer la console
                    if fail_count <= 5:
                        print(f"\n[ERREUR D'ENVOI] Document échoué : {json.dumps(result, indent=2, default=json_default_serializer)}")

            print("\nEnvoi terminé.")
            print(f"Documents envoyés avec succès : {success_count}")
            if fail_count > 0:
                print(f"Documents en échec : {fail_count} (voir les logs plus haut)")
        except Exception as e:
            print(f"Une erreur critique est survenue durant l'upload : {traceback.format_exc()}")
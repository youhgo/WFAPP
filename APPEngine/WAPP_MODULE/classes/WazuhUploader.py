#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import traceback
import warnings

# We use opensearchpy for Wazuh Indexer compatibility
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


def inject_wapp_metadata(actions_generator, case_name, machine_name):
    """
    Générateur qui intercepte le flux de documents destiné à Wazuh/OpenSearch
    pour y injecter le case_name et le machine_name.
    """
    for action in actions_generator:
        if "_source" in action:
            # Création d'un sous-objet pour garder les logs propres et filtrables
            action["_source"]["wapp_info"] = {
                "case_name": case_name,
                "machine_name": machine_name
            }
        yield action


class WazuhUploader:
    """Gère la connexion et l'envoi en masse des documents au Wazuh Indexer."""

    def __init__(self, es_hosts: list, es_user: str, es_pass: str, verify_ssl: bool, es_timeout: int, thread_count: int,
                 mode: str, case_name: str = "unknown", machine_name: str = "unknown"):
        self.es_timeout = es_timeout
        self.thread_count = thread_count
        self.mode = mode
        self.case_name = case_name
        self.machine_name = machine_name

        try:
            # Configuration de la connexion Wazuh / OpenSearch
            es_options = {
                "hosts": es_hosts,
                "http_auth": (es_user, es_pass),  # Wazuh uses http_auth tuple
                "verify_certs": verify_ssl,
                "timeout": es_timeout,
                "max_retries": 10,
                "retry_on_timeout": True,
                "ssl_show_warn": False
            }

            if not verify_ssl:
                from urllib3.exceptions import InsecureRequestWarning
                warnings.filterwarnings('ignore', category=InsecureRequestWarning)
                es_options["ssl_assert_hostname"] = False  # Crucial for Wazuh docker setups

            self.client = OpenSearch(**es_options)

            if not self.client.ping():
                raise ConnectionError("La connexion au Wazuh Indexer a échoué.")
            print("Connexion au Wazuh Indexer réussie.")

        except Exception as e:
            raise ConnectionError(f"Impossible d'initialiser le client Wazuh/OpenSearch : {e}")

    def _create_index_template(self, template_name: str, index_pattern: str, priority: int):
        """Crée ou met à jour un template d'index."""
        # Note: OpenSearch syntax is slightly different for templates in some versions,
        # but modern Wazuh supports composable templates similar to ES.
        template_body = {
            "index_patterns": [index_pattern],
            "priority": priority,
            "template": {
                "settings": {
                    "index.mapping.total_fields.limit": 5000  # Increased for Plaso
                },
                "mappings": {
                    "dynamic_templates": [
                        {
                            "ip_fields": {
                                "match_pattern": "regex",
                                "match": "^(.*_ip|ip)$",
                                "mapping": {"type": "ip"}
                            }
                        },
                        {
                            "port_fields": {
                                "match_pattern": "regex",
                                "match": "^(.*_port|port)$",
                                "mapping": {"type": "integer"}
                            }
                        }
                    ],
                    "properties": {
                        "estimestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
                        "@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"}
                    }
                }
            }
        }
        try:
            self.client.indices.put_index_template(
                name=template_name,
                body=template_body  # OpenSearch often expects 'body' arg
            )
            print(f"Template '{template_name}' pour '{index_pattern}' créé/mis à jour.")
        except Exception as e:
            print(f"[Attention] Impossible de créer le template '{template_name}'. Erreur: {e}")

    def setup_templates(self, priority: int = 400, **kwargs):
        for name, pattern in kwargs.items():
            self._create_index_template(f"forensic_{name}_template", pattern, priority)

    def bulk_upload(self, actions_generator, chunk_size: int, dlq_path: str = None):

        # ---> INJECTION À LA VOLÉE DES MÉTADONNÉES <---
        modified_actions_generator = inject_wapp_metadata(actions_generator, self.case_name, self.machine_name)

        if self.mode == 'parallel':
            bulk_func = parallel_bulk
            print(f"\nEnvoi en mode PARALLÈLE ({self.thread_count} threads) par lots de {chunk_size}...")
            kwargs = {"thread_count": self.thread_count}
        else:
            bulk_func = streaming_bulk
            print(f"\nEnvoi en mode STREAMING (séquentiel) par lots de {chunk_size}...")
            kwargs = {}

        success_count, fail_count = 0, 0
        failed_docs = []
        try:
            for ok, result in bulk_func(
                    client=self.client,
                    actions=modified_actions_generator,  # Utilisation du générateur modifié
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
                    failed_docs.append(result)
                    print(
                        f"\\n[ERREUR D'ENVOI] Document échoué : {json.dumps(result, indent=2, default=json_default_serializer)}")

            print("\\nEnvoi terminé.")
            print(f"Documents envoyés avec succès : {success_count}")
            if fail_count > 0:
                print(f"Documents en échec : {fail_count}")
                if not dlq_path:
                    dlq_path = "/python-docker/shared_files/failed_uploads_wazuh.json"
                try:
                    with open(dlq_path, 'w', encoding='utf-8') as f:
                        json.dump(failed_docs, f, indent=2, ensure_ascii=False, default=json_default_serializer)
                    print(f"Les documents échoués ont été sauvegardés dans : {dlq_path}")
                except Exception as e:
                    print(f"Erreur lors de la sauvegarde de la DLQ : {e}")
        except Exception as e:
            print(f"Une erreur critique est survenue : {traceback.format_exc()}")
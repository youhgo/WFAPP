#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import traceback

from elasticsearch import Elasticsearch
from elasticsearch.helpers import streaming_bulk, parallel_bulk


class ElasticUploader:
    """Gère la connexion et l'envoi en masse des documents à Elasticsearch."""

    def __init__(self, es_hosts: list, es_user: str, es_pass: str, verify_ssl: bool = True):
        try:
            es_options = {"basic_auth": (es_user, es_pass), "verify_certs": verify_ssl, "request_timeout": 60, "max_retries": 10, "retry_on_timeout": True}
            if not verify_ssl:
                import warnings
                from urllib3.exceptions import InsecureRequestWarning
                warnings.filterwarnings('ignore', category=InsecureRequestWarning)
                es_options["ca_certs"] = False
            self.client = Elasticsearch(es_hosts, **es_options)
            if not self.client.ping(): raise ConnectionError("La connexion à Elasticsearch a échoué.")
            print("Connexion à Elasticsearch réussie.")
        except Exception as e:
            raise ConnectionError(f"Impossible d'initialiser le client Elasticsearch : {e}")

    def _create_index_template(self, template_name: str, index_pattern: str):
        """Crée ou met à jour un template d'index pour forcer le mapping de @timestamp et des types avancés ECS."""
        template_body = {
            "index_patterns": [index_pattern],
            "priority": 300,
            "template": {
                "settings": {"index.mapping.total_fields.limit": 2000},
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
                        "@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"}
                    }
                }
            }
        }
        try:
            self.client.indices.put_index_template(name=template_name, index_patterns=template_body["index_patterns"],
                                                   priority=template_body["priority"],
                                                   template=template_body["template"])
            print(f"Template d'index '{template_name}' pour le pattern '{index_pattern}' créé/mis à jour.")
        except Exception as e:
            print(f"[Attention] Impossible de créer le template d'index '{template_name}'. Erreur: {e}")

    def setup_templates(self, **kwargs):
        """Configure les templates pour les différents types de logs."""
        for name, pattern in kwargs.items():
            self._create_index_template(f"forensic_{name}_template", pattern)

    def bulk_upload(self, actions_generator, chunk_size: int, thread_count: int = 4, mode: str = 'wapp', dlq_path: str = "/python-docker/shared_files/failed_uploads.json"):
        if mode == 'parallel':
            bulk_func = parallel_bulk
            print(f"\\nEnvoi en mode PARALLÈLE ({thread_count} threads) par lots de {chunk_size}...")
            kwargs = {"thread_count": thread_count}
        else:
            bulk_func = streaming_bulk
            print(f"\\nEnvoi en mode STREAMING (séquentiel) par lots de {chunk_size}...")
            kwargs = {}

        success_count, fail_count = 0, 0
        failed_docs = []
        try:
            for ok, result in bulk_func(
                    client=self.client, actions=actions_generator, chunk_size=chunk_size,
                    raise_on_error=False, raise_on_exception=False, **kwargs
            ):
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    failed_docs.append(result)
                    print(f"\\n[ERREUR D'ENVOI] Document échoué : {json.dumps(result, indent=2)}")
                    
            print("\\nEnvoi terminé.")
            print(f"Documents envoyés avec succès : {success_count}")
            if fail_count > 0:
                print(f"Documents en échec : {fail_count}")
                try:
                    with open(dlq_path, 'w', encoding='utf-8') as f:
                        json.dump(failed_docs, f, indent=2, ensure_ascii=False)
                    print(f"Les documents échoués ont été sauvegardés dans : {dlq_path}")
                except Exception as e:
                    print(f"Erreur lors de la sauvegarde de la DLQ : {e}")

        except Exception as e:
            print(f"Une erreur critique est survenue durant l'envoi en streaming : {traceback.format_exc()}")

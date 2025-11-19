#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import traceback

from elasticsearch import Elasticsearch
from elasticsearch.helpers import streaming_bulk


class ElasticUploader:
    """Gère la connexion et l'envoi en masse des documents à Elasticsearch."""

    def __init__(self, es_hosts: list, es_user: str, es_pass: str, verify_ssl: bool = True):
        try:
            es_options = {"basic_auth": (es_user, es_pass), "verify_certs": verify_ssl}
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
        """Crée ou met à jour un template d'index pour forcer le mapping de @timestamp."""
        template_body = {
            "index_patterns": [index_pattern],
            "priority": 300,
            "template": {
                "settings": {"index.mapping.total_fields.limit": 2000},
                "mappings": {
                    "properties": {"@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"}}}
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

    def streaming_bulk_upload(self, actions_generator, chunk_size: int):
        """Envoie des documents depuis un générateur en utilisant streaming_bulk pour optimiser la mémoire."""
        print(f"\nEnvoi des documents en streaming par lots de {chunk_size}...")
        success_count, fail_count = 0, 0
        try:
            for ok, result in streaming_bulk(
                    client=self.client, actions=actions_generator, chunk_size=chunk_size,
                    raise_on_error=False, raise_on_exception=False,
            ):
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    print(f"\n[ERREUR D'ENVOI] Document échoué : {json.dumps(result, indent=2)}")
            print("\nEnvoi terminé.")
            print(f"Documents envoyés avec succès : {success_count}")
            if fail_count > 0:
                print(f"Documents en échec : {fail_count}")
        except Exception as e:
            print(f"Une erreur critique est survenue durant l'envoi en streaming : {traceback.format_exc()}")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import traceback

from elasticsearch import Elasticsearch
from elasticsearch.helpers import streaming_bulk, parallel_bulk
from elasticsearch.exceptions import ApiError
import sys

def json_default_serializer(obj):
    """Surcharge le sérialiseur JSON pour gérer les objets d'erreur non sérialisables."""
    if isinstance(obj, ApiError):
        return str(obj)
    try:
        return obj.to_dict()
    except AttributeError:
        # Reviens à la méthode par défaut (généralement raise TypeError)
        raise TypeError(f'Object of type {obj.__class__.__name__} is not JSON serializable')


class ElasticUploader:
    """Gère la connexion et l'envoi en masse des documents à Elasticsearch."""

    def __init__(self, es_hosts: list, es_user: str, es_pass: str, verify_ssl: bool, es_timeout: int, thread_count: int,
                 mode: str):
        self.es_timeout = es_timeout
        self.thread_count = thread_count
        self.mode = mode
        if isinstance(verify_ssl, str):
            verify_ssl = verify_ssl.lower() in ('true', '1', 'yes', 'on')
        try:
            es_options = {
                "basic_auth": (es_user, es_pass),
                "verify_certs": verify_ssl,
                "request_timeout": int(es_timeout),  # Timeout général de la requête
                "max_retries": 10,
                "retry_on_timeout": True,
                "maxsize": 200
            }
            if not verify_ssl:
                import warnings
                from urllib3.exceptions import InsecureRequestWarning
                warnings.filterwarnings('ignore', category=InsecureRequestWarning)
                es_options["ca_certs"] = False

            self.client = Elasticsearch(es_hosts, **es_options)
            if not self.client.ping():
                sys.stderr.write("La connexion à Elasticsearch a échoué.")
                raise ConnectionError("La connexion à Elasticsearch a échoué.")
            sys.stderr.write("Connexion à Elasticsearch réussie.")
        except Exception as e:
            raise ConnectionError(f"Impossible d'initialiser le client Elasticsearch : {e}")

    def close(self):
        """Ferme proprement la connexion client."""
        if self.client:
            self.client.close()

    def _create_index_template(self, template_name: str, index_pattern: str, priority: int):
        """Crée ou met à jour un template d'index pour forcer le mapping de @timestamp."""
        template_body = {
            "index_patterns": [index_pattern],
            "priority": priority,  # Priorité 400 pour éviter les conflits avec les anciens templates
            "template": {
                "settings": {"index.mapping.total_fields.limit": 2000},
                "mappings": {
                    "properties": {
                        "estimestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"}}}
            }
        }
        try:

            self.client.indices.put_index_template(name=template_name, index_patterns=template_body["index_patterns"],
                                                   priority=template_body["priority"],
                                                   template=template_body["template"])
            print(
                f"Template d'index '{template_name}' pour le pattern '{index_pattern}' créé/mis à jour (Prio: {priority}).")
        except Exception as e:
            print(f"[Attention] Impossible de créer le template d'index '{template_name}'. Erreur: {e}")

    def setup_templates(self, priority: int = 400, **kwargs):
        """Configure les templates pour les différents types de logs. kwargs = {name: pattern}"""
        for name, pattern in kwargs.items():
            self._create_index_template(f"forensic_{name}_template", pattern, priority)

    def bulk_upload(self, actions_generator, chunk_size: int):
        """Envoie des documents en utilisant streaming_bulk ou parallel_bulk."""


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
                    print(
                        f"\n[ERREUR D'ENVOI] Document échoué : {json.dumps(result, indent=2, default=json_default_serializer)}")

            print("\nEnvoi terminé.")
            print(f"Documents envoyés avec succès : {success_count}")
            if fail_count > 0:
                print(f"Documents en échec : {fail_count}")
        except Exception as e:
            print(f"Une erreur critique est survenue durant l'envoi en streaming : {traceback.format_exc()}")
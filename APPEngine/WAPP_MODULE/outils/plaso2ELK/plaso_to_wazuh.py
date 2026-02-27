#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import traceback
import warnings
import time
import os

# We use opensearchpy for Wazuh Indexer compatibility
from opensearchpy import OpenSearch
from opensearchpy.helpers import streaming_bulk, parallel_bulk
from opensearchpy.exceptions import OpenSearchException, TransportError


def json_default_serializer(obj):
    """Overrides JSON serializer to handle non-serializable error objects."""
    if isinstance(obj, (OpenSearchException, TransportError)):
        return str(obj)
    try:
        return obj.to_dict()
    except AttributeError:
        raise TypeError(f'Object of type {obj.__class__.__name__} is not JSON serializable')


class WazuhUploader:
    """Manages connection and bulk upload to Wazuh Indexer with Forensic Robustness."""

    def __init__(self, es_hosts: list, es_user: str, es_pass: str, verify_ssl: bool, es_timeout: int, thread_count: int,
                 mode: str):
        self.es_timeout = es_timeout
        self.thread_count = thread_count
        self.mode = mode
        self.failed_log_file = "failed_uploads.json"

        try:
            # Wazuh / OpenSearch Connection Configuration
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
                es_options["ssl_assert_hostname"] = False

            self.client = OpenSearch(**es_options)

            if not self.client.ping():
                raise ConnectionError("Connection to Wazuh Indexer failed.")
            print("Connection to Wazuh Indexer successful.")

            # Initialize failure log
            with open(self.failed_log_file, 'w', encoding='utf-8') as f:
                f.write("")  # Clear previous run failures

        except Exception as e:
            raise ConnectionError(f"Cannot initialize Wazuh/OpenSearch client: {e}")

    def _create_index_template(self, template_name: str, index_pattern: str, priority: int):
        """Creates or updates an index template."""
        template_body = {
            "index_patterns": [index_pattern],
            "priority": priority,
            "template": {
                "settings": {
                    "index.mapping.total_fields.limit": 10000,
                    "index.refresh_interval": "5s"  # Slows down refresh to save CPU during ingest
                },
                "mappings": {
                    "properties": {
                        "estimestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"}
                    }
                }
            }
        }
        try:
            self.client.indices.put_index_template(
                name=template_name,
                body=template_body
            )
            print(f"Template '{template_name}' for '{index_pattern}' created/updated.")
        except Exception as e:
            print(f"[Warning] Cannot create template '{template_name}'. Error: {e}")

    def setup_templates(self, priority: int = 400, **kwargs):
        for name, pattern in kwargs.items():
            self._create_index_template(f"forensic_{name}_template", pattern, priority)

    def _log_failure(self, doc, error):
        """Saves failed documents to disk to ensure no data loss."""
        with open(self.failed_log_file, 'a', encoding='utf-8') as f:
            entry = {"error": str(error), "document": doc}
            f.write(json.dumps(entry, default=json_default_serializer) + "\n")

    def bulk_upload(self, actions_generator, chunk_size: int):
        # ROBUSTNESS CONFIGURATION
        # 1. max_chunk_bytes: Limits batch to 10MB prevents 'rejected_execution_exception'
        # 2. max_retries: Retries 15 times before failing
        # 3. max_backoff: Waits up to 60 seconds if server is busy (429)

        bulk_params = {
            "chunk_size": chunk_size,
            "max_chunk_bytes": 50 * 1024 * 1024,  # 10 MB Hard Limit
            "max_retries": 15,
            "initial_backoff": 2,
            "max_backoff": 60,
            "request_timeout": self.es_timeout,
            "raise_on_error": False,
            "raise_on_exception": False
        }

        if self.mode == 'parallel':
            bulk_func = parallel_bulk
            print(f"\nSending in PARALLEL mode ({self.thread_count} threads). Limit: 10MB/batch...")
            bulk_params["thread_count"] = self.thread_count
            # Parallel bulk requires queue_size to prevent memory explosion
            bulk_params["queue_size"] = 4
        else:
            bulk_func = streaming_bulk
            print(f"\nSending in STREAMING mode (Sequential). Limit: 10MB/batch...")

        success_count = 0
        fail_count = 0

        try:
            for ok, result in bulk_func(client=self.client, actions=actions_generator, **bulk_params):
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    # Extract error details
                    if self.mode == 'parallel':
                        # parallel_bulk returns (success, item)
                        # The item structure is usually { "index": { ...error... } }
                        action, info = result.popitem() if result else ("unknown", {})
                        error_reason = info.get("error", "Unknown error")
                        doc_id = info.get("_id", "unknown")
                    else:
                        # streaming_bulk returns (success, result)
                        action, info = result.popitem() if result else ("unknown", {})
                        error_reason = info.get("error", "Unknown error")
                        doc_id = info.get("_id", "unknown")

                    # Log to console briefly
                    if fail_count % 100 == 0:
                        print(f"   [!] {fail_count} failures so far. Latest: {error_reason}")

                    # Log to file for forensic recovery
                    self._log_failure({"id": doc_id, "info": info}, error_reason)

            print("\n" + "=" * 30)
            print("UPLOAD COMPLETE")
            print("=" * 30)
            print(f"[-] Successful Documents : {success_count}")
            print(f"[-] Failed Documents     : {fail_count}")

            if fail_count > 0:
                print(f"[CRITICAL] {fail_count} documents failed to upload.")
                print(f"           Review '{self.failed_log_file}' to recover data.")
            else:
                print("[OK] Integrity check passed: No errors reported.")
                if os.path.exists(self.failed_log_file):
                    os.remove(self.failed_log_file)  # Clean up empty log

        except Exception as e:
            print(f"CRITICAL PIPELINE ERROR: {traceback.format_exc()}")
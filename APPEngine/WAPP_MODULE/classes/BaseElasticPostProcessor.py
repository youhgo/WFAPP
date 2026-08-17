import os
import re
from abc import ABC
from .BasePostProcessor import BasePostProcessor

class BaseElasticPostProcessor(BasePostProcessor, ABC):
    """
    Base class for Elasticsearch and Wazuh post processors.
    Mutualizes the orchestration logic for finding and parsing JSONL files.
    """
    
    def _sanitize_for_index(self, name: str) -> str:
        return ''.join(c if c.isalnum() or c in '-_' else '_' for c in name).lower()

    def _find_and_process_files(self, processor_instances, target_indices):
        for filepath in self.context.siem_ingestion_files:
            if not os.path.exists(filepath):
                continue
            filename = os.path.basename(filepath)
            dataset = None
            category = None
            processor_instance = None
            
            for cls, instance in processor_instances.items():
                for pattern, ds in cls.DEFAULT_PATTERNS.items():
                    if re.match(pattern, filename, re.IGNORECASE):
                        dataset = ds
                        category = cls.__processor_name__
                        processor_instance = instance
                        break
                if dataset:
                    break

            if dataset and processor_instance:
                kwargs = {"machine_name": self.context.machine_name} if category == "network" else {}
                try:
                    for doc, doc_type in processor_instance.process_file(filepath, dataset=dataset, filename=filename, **kwargs):
                        yield {"_index": target_indices.get(doc_type, target_indices[category]), "_source": doc}
                    except Exception as e:
                        self.logger.error(f"[WAPP][ELASTIC] Error processing file {filename}: {e}", indentation=2)

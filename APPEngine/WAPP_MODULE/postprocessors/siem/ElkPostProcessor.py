import os
import json
import traceback
from ...classes.BaseElasticPostProcessor import BaseElasticPostProcessor
from ...classes.Registry import register_postprocessor
from ...classes.ElasticUploader import ElasticUploader
from ...classes.elk_registry import ELK_PROCESSORS_REGISTRY
from ...parsers import elk_parsers

@register_postprocessor('elk')
class ElkPostProcessor(BaseElasticPostProcessor):
    """
    Generates JSON files for ElasticSearch/Kibana natively.
    """
    recommended = True
    importance = "Optional"
    speed = "Slow"
    priority = 5
    requires = []

    def run(self) -> None:
        try:
            es_host = f"{os.getenv('ELK_HOST', 'localhost')}:{os.getenv('ELK_PORT', '9200')}"
            verify_ssl = str(os.getenv('ES_VERIFYSSL', '0')).lower() in ['1', 'true', 'yes']
            chunk_size = int(os.getenv('ES_CHUNKSIZE', '500'))
            es_user = os.getenv('ELK_USER', '')
            es_pass = os.getenv('ELK_PASSWD', '')

            self.logger.info("[WAPP][ELK] Sending WAPP data to Elasticsearch natively", header="START", indentation=1)

            case_name_sanitized = self._sanitize_for_index(self.context.case_name)
            machine_name_sanitized = self._sanitize_for_index(self.context.machine_name)
            index_prefix = "wapp"

            target_indices = {}
            processor_instances = {}
            for category, cls_list in ELK_PROCESSORS_REGISTRY.items():
                target_indices[category] = f"{index_prefix}_{case_name_sanitized}_{machine_name_sanitized}_{category}"
                for cls in cls_list:
                    processor_instances[cls] = cls(case_name=self.context.case_name, machine_name=self.context.machine_name)

            actions_generator = self._find_and_process_files(processor_instances, target_indices)
            
            vector_export_path = self.context.siem_ingestion_dir / "vector_export_elk.jsonl"
            os.makedirs(os.path.dirname(vector_export_path), exist_ok=True)
            
            # Dump to JSONL for Vector to pick up
            count = 0
            with open(vector_export_path, 'a', encoding='utf-8') as f:
                for action in actions_generator:
                    doc = action["_source"]
                    doc["_target_index"] = action["_index"]
                    f.write(json.dumps(doc) + "\n")
                    count += 1
            
            self.logger.info(f"[WAPP][ELK] Success: Wrote {count} documents to {vector_export_path} for Vector ingestion", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[WAPP][ELK] aborting, ERROR: {traceback.format_exc()}", header="ERROR", indentation=1)

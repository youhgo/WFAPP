import os
import traceback
from ..classes.BaseElasticPostProcessor import BaseElasticPostProcessor
from ..classes.Registry import register_postprocessor
from ..classes.ElasticUploader import ElasticUploader
from ..classes.elk_registry import ELK_PROCESSORS_REGISTRY
from ..parsers import elk_parsers

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

            uploader = ElasticUploader(es_hosts=[es_host], es_user=es_user, es_pass=es_pass, verify_ssl=verify_ssl)

            case_name_sanitized = self._sanitize_for_index(self.context.case_name)
            machine_name_sanitized = self._sanitize_for_index(self.context.machine_name)
            index_prefix = "wapp"

            target_indices = {}
            processor_instances = {}
            for category, cls_list in ELK_PROCESSORS_REGISTRY.items():
                target_indices[category] = f"{index_prefix}_{case_name_sanitized}_{machine_name_sanitized}_{category}"
                for cls in cls_list:
                    processor_instances[cls] = cls(case_name=self.context.case_name, machine_name=self.context.machine_name)

            template_patterns = {name: f"*_{machine_name_sanitized}_{name}" for name in target_indices.keys()}
            uploader.setup_templates(**template_patterns)

            actions_generator = self._find_and_process_files(processor_instances, target_indices)
            dlq_path = self.context.result_parsed_dir / "orcLogs" / "failed_uploads_elk.json"
            uploader.streaming_bulk_upload(actions_generator, chunk_size, dlq_path=str(dlq_path))

            self.logger.info("[WAPP][ELK] Success", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[WAPP][ELK] aborting, ERROR: {traceback.format_exc()}", header="ERROR", indentation=1)

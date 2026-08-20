import os
import traceback
from ..classes.BaseElasticPostProcessor import BaseElasticPostProcessor
from ..classes.Registry import register_postprocessor
from ..classes.WazuhUploader import WazuhUploader, inject_wapp_metadata
from ..classes.elk_registry import ELK_PROCESSORS_REGISTRY
from ..parsers import elk_parsers

@register_postprocessor('wazuh')
class WazuhPostProcessor(BaseElasticPostProcessor):
    """
    Generates JSON files ready to be ingested by Wazuh natively.
    """
    recommended = True
    importance = "Optional"
    speed = "Slow"
    priority = 6
    requires = []

    def run(self) -> None:
        try:
            es_host = f"{os.getenv('WAZUH_HOST')}:{os.getenv('WAZUH_PORT')}"
            verify_ssl = os.getenv('WAZUH_VERIFYSSL', '0').lower() in ['1', 'true', 'yes']
            chunk_size = int(os.getenv('WAZUH_CHUNKSIZE', '500'))
            es_user = os.getenv('WAZUH_USER', '')
            es_pass = os.getenv('WAZUH_PASSWD', '')
            es_timeout = int(os.getenv('WAZUH_TIMEOUT', '60'))
            thread_count = int(os.getenv('WAZUH_NBTHREAD', '4'))
            mode = os.getenv('WAZUH_MODE', 'wapp')

            self.logger.info("[WAPP][WAZUH] Sending WAPP data to Wazuh natively", header="START", indentation=1)

            uploader = WazuhUploader(
                es_hosts=[es_host], es_user=es_user, es_pass=es_pass, verify_ssl=verify_ssl,
                es_timeout=es_timeout, thread_count=thread_count, mode=mode,
                case_name=self.context.case_name, machine_name=self.context.machine_name
            )

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

            dlq_path = str(self.context.parsed_dir / "orcLogs" / "failed_uploads_wazuh.json")
            actions_generator = self._find_and_process_files(processor_instances, target_indices)
            uploader.bulk_upload(actions_generator, chunk_size, dlq_path=dlq_path)

            self.logger.info("[WAPP][WAZUH] Success", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[WAPP][WAZUH] aborting, ERROR: {traceback.format_exc()}", header="ERROR", indentation=1)

import os
import traceback
from ...classes.BasePostProcessor import BasePostProcessor
from ...classes.Registry import register_postprocessor
from ...utils.plaso2ELK import plaso_to_wazuh

@register_postprocessor('plaso2wazuh')
class Plaso2WazuhPostProcessor(BasePostProcessor):
    """
    Generates JSON files ready to be ingested by Wazuh from Plaso.
    """
    recommended = True
    importance = "Optional"
    speed = "Slow"

    priority = 45
    requires = ['plaso']

    def run(self) -> None:
        timeline_json_path = self.context.timeline_dir / "timeline.json"
        try:
            wazuh_host = f"{os.getenv('WAZUH_HOST', 'localhost')}:{os.getenv('WAZUH_PORT', '9200')}"
            verify_ssl = str(os.getenv('WAZUH_VERIFYSSL', '0')).lower() in ['1', 'true', 'yes']

            self.logger.info("[PLASO][WAZUH]", header="START", indentation=1)

            p_agent = plaso_to_wazuh.PlasoPipeline(
                case_name=self.context.case_name,
                machine_name=self.context.machine_name,
                timeline_path=str(timeline_json_path),
                es_hosts=wazuh_host,
                es_user=os.getenv('WAZUH_USER', ''),
                es_pass=os.getenv('WAZUH_PASSWD', ''),
                chunk_size=int(os.getenv('WAZUH_CHUNKSIZE', '500')),
                verify_ssl=verify_ssl,
                es_timeout=int(os.getenv('WAZUH_TIMEOUT', '60')),
                thread_count=int(os.getenv('WAZUH_NBTHREAD', '4')),
                mode=os.getenv('WAZUH_MODE', 'wapp')
            )
            p_agent.run()
            self.logger.info("[PLASO][WAZUH]", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PLASO][WAZUH] aborting, ERROR: {traceback.format_exc()}", header="ERROR", indentation=1)

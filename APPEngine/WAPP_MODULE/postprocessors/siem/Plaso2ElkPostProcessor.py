import os
import traceback
from ...classes.BasePostProcessor import BasePostProcessor
from ...classes.Registry import register_postprocessor
from ...utils.plaso2ELK import plaso_2_siem

@register_postprocessor('plaso2elk')
class Plaso2ElkPostProcessor(BasePostProcessor):
    """
    Generates JSON files for ElasticSearch/Kibana from Plaso.
    """
    recommended = True
    importance = "Optional"
    speed = "Slow"

    priority = 40
    requires = ['plaso']

    def run(self) -> None:
        timeline_json_path = self.context.timeline_dir / "timeline.json"
        try:
            es_host = f"{os.getenv('ELK_HOST', 'localhost')}:{os.getenv('ELK_PORT', '9200')}"
            verify_ssl = str(os.getenv('ES_VERIFYSSL', '0')).lower() in ['1', 'true', 'yes']

            self.logger.info("[PLASO][ELK]", header="START", indentation=1)
            self.logger.info(
                f"[PLASO][ELK] param are: {self.context.case_name}|{self.context.machine_name}|{timeline_json_path}|{es_host}|{os.getenv('ELK_USER')}|xxxxxx|{os.getenv('ES_CHUNKSIZE')}|{verify_ssl}|{os.getenv('ES_TIMEOUT')}|{os.getenv('ES_NBTHREAD')}|{os.getenv('ES_MODE')}",
                header="START", indentation=1)

            p_agent = plaso_2_siem.PlasoPipeline(
                case_name=self.context.case_name,
                machine_name=self.context.machine_name,
                timeline_path=str(timeline_json_path),
                es_hosts=es_host,
                es_user=os.getenv('ELK_USER', ''),
                es_pass=os.getenv('ELK_PASSWD', ''),
                chunk_size=int(os.getenv('ES_CHUNKSIZE', '500')),
                verify_ssl=verify_ssl,
                es_timeout=int(os.getenv('ES_TIMEOUT', '60')),
                thread_count=int(os.getenv('ES_NBTHREAD', '4')),
                mode=os.getenv('ES_MODE', 'wapp')
            )
            p_agent.run()
            self.logger.info("[PLASO][ELK]", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PLASO][ELK] aborting, ERROR: {traceback.format_exc()}", header="ERROR", indentation=1)

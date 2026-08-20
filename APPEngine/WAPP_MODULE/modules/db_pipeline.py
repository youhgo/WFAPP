import re
import traceback
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import DualOutputSink
from ..parsers.ActivitiesCacheParser import ActivitiesCacheParser

@register_pipeline(name="database")
class DbPipeline(BaseArtefactPipeline):
    """
    Parses common SQLite databases.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
    DEFAULT_PATTERNS = {"Activity_cache": [r"ActivitiesCache(?:_\d+)?\.db"], "sdb": [r".*(?:_\d+)?\.sdb"], "SRUM": [r"SRUDB(?:_\d+)?\.dat", r"SRU.*(?:_\d+)?\.log"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_other_dir = self.context.parsed_dir / "database"
        self.out_dir = self.context.result_parsed_dir
        self.out_other_dir.mkdir(exist_ok=True)
        self.parser = ActivitiesCacheParser(self.logger, separator=self.context.separator)
        self.sinks = {}

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][DATABASE] Processing {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return

            if self._matches_category(file_path.name, "Activity_cache"):
                for artifact_type, record in self.parser.parse(file_path):
                    if artifact_type not in self.sinks:
                        out_path = self.out_other_dir / f"{artifact_type}.csv"
                        self.sinks[artifact_type] = DualOutputSink(out_path, separator=self.context.separator, jsonl_dir=self.context.siem_ingestion_dir, context=self.context)
                        self.context.wazuh_importer_file_config["files"].append({"path": str(out_path), "type": artifact_type})
                        
                    self.sinks[artifact_type].write_record(record)
                    
            elif self._matches_category(file_path.name, "sdb"):
                self.copy_raw_artefact(file_path, self.out_other_dir)
            elif self._matches_category(file_path.name, "SRUM"):
                self.copy_raw_artefact(file_path, self.out_other_dir)
                
            self.logger.info(f"[PIPELINE][DATABASE] Success", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][DATABASE] Error on {file_path.name}: {traceback.format_exc()}", header="ERROR", indentation=1)

    def finalize(self):
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()
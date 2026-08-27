from pathlib import Path
from typing import Dict

from ...classes.BaseArtefactPipelines import BaseArtefactPipeline
from ...classes.WappContext import WappContext
from ...classes.Registry import register_pipeline
from ...classes.BaseParser import CsvOutputSink
from ...parsers.ogre.OgreParser import OgreParser

@register_pipeline(name="ogre_systeminfo")
class OgreSystemInfoPipeline(BaseArtefactPipeline):
    """
    Parses DFIR-Ogre system info output files.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
    DEFAULT_PATTERNS = {
        "ogre_systeminfo": [
            r".*\.systeminfo\.jsonl$",
            r".*\.reg_systeminfo\.jsonl$"
        ]
    }

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = OgreParser(separator=self.context.separator)
        self.sinks: Dict[str, CsvOutputSink] = {}
        

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][OGRE_SYSTEMINFO] Processing {file_path.name}", header="START", indentation=1)
        try:
            
            self.context.siem_ingestion_files.append(str(file_path))
            self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": "system_info"})

            for artifact_type, record in self.parser.parse(file_path):
                if artifact_type not in self.sinks:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.sinks[artifact_type] = CsvOutputSink(csv_path, separator=self.context.separator)
                
                self.sinks[artifact_type].write_record(record)
                
            self.logger.info(f"[PIPELINE][OGRE_SYSTEMINFO] Success for {file_path.name}", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][OGRE_SYSTEMINFO] Error on {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()

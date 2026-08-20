import re
import json
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import DualOutputSink
from ..parsers.SystemInfoParser import SystemInfoParser

@register_pipeline(name="system_info")
class SystemInfoPipeline(BaseArtefactPipeline):
    """
    Parses general system information.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
    DEFAULT_PATTERNS = {"system_info": [r"Systeminfo(?:_\d+)?\.csv"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = SystemInfoParser(self.logger, separator=self.context.separator)
        self.csv_sink = None
        self.all_data = []

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][SYSINFO] Processing {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return
            
            self.context.siem_ingestion_files.append(str(file_path))
                
            has_data = False
            for artifact_type, record in self.parser.parse(file_path):
                has_data = True
                
                # CSV writing
                if not self.csv_sink:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.csv_sink = DualOutputSink(csv_path, separator=self.context.separator, jsonl_dir=self.context.siem_ingestion_dir, context=self.context)
                self.csv_sink.write_record(record)
                
                # Keep in memory to generate the final txt/json (small volume of data)
                self.all_data.append(record)

            if has_data:
                # Creation of JSON/TXT versions 
                out_txt = self.context.result_parsed_dir / "systeminfo.txt"
                out_json = self.context.result_parsed_dir / "systeminfo.json"
                
                with open(out_json, 'w', encoding='utf-8') as f:
                    json.dump(self.all_data, f, indent=4)
                    
                with open(out_txt, 'w', encoding='utf-8') as f:
                    for entry in self.all_data:
                        for k, v in entry.items():
                            f.write(f"{k}:{v}\n")
                        f.write("\n")
                
                self.context.wazuh_importer_file_config["files"].append({"path": str(out_json), "type": "systemInfo"})
                self.logger.info(f"[PIPELINE][SYSINFO] Processing {file_path.name}", header="SUCCESS", indentation=2)

        except Exception as e:
            self.logger.error(f"[PIPELINE][SYSINFO] Error: {e}", header="ERROR", indentation=2)

        self.logger.info(f"[PIPELINE][SYSINFO] Processing {file_path.name}", header="FINISHED", indentation=1)
        
    def finalize(self):
        if self.csv_sink:
            self.csv_sink.close()
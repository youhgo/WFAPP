import json
from pathlib import Path
import re

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import DualOutputSink
from ..parsers.Linkparser import LinkParser

@register_pipeline(name="lnk")
class LnkPipeline(BaseArtefactPipeline):
    """
    Parses LNK shortcut files.
    """
    recommended = True
    DEFAULT_PATTERNS = {"lnk": [".*.lnk"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.lnk_dir = self.context.parsed_dir / "lnk"
        self.lnk_dir.mkdir(exist_ok=True)
        self.parser = LinkParser(self.logger, separator=self.context.separator)
        self.csv_sink = None

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][LNK] Processing {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return
                
            if self._matches_category(file_path.name, "lnk"):
                for artifact_type, record in self.parser.parse(file_path):
                    raw_json = record.pop("_raw_json", None)
                    
                    if not self.csv_sink:
                        csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                        self.csv_sink = DualOutputSink(csv_path, separator=self.context.separator, jsonl_dir=self.context.siem_ingestion_dir, context=self.context)
                    
                    self.csv_sink.write_record(record)
                    
                    if raw_json:
                        json_path = self.lnk_dir / f"{file_path.stem}.lnk.json"
                        with open(json_path, "w", encoding="utf-8") as outfile:
                            json.dump(raw_json, outfile, indent=4, default=str)
                        self.context.wazuh_importer_file_config["files"].append({"path": str(json_path), "type": "lnk"})
                        
        except Exception as e:
            self.logger.error(f"[PIPELINE][LNK] Error: {e}", header="ERROR", indentation=1)

    def finalize(self):
        if self.csv_sink:
            self.csv_sink.close()
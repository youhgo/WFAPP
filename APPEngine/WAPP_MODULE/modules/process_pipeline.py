import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import DualOutputSink, TextOutputSink
from ..parsers.ProcessParser import ProcessParser

@register_pipeline(name="process")
class ProcessPipeline(BaseArtefactPipeline):
    """
    Parses process execution histories.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
    DEFAULT_PATTERNS = {"process1": [r"processes?_?1(?:_\d+)?\.csv"], "process2": [r"processes?_?2(?:_\d+)?\.csv"], "autoruns": [r"autoruns(?:_\d+)?\.csv"], "sample_autoruns": [r"GetSamples_autoruns(?:_\d+)?\.xml", r"Process_Autoruns(?:_\d+)?\.xml"], "sample_timeline": [r"GetSamples_timeline(?:_\d+)?\.csv", r"Process_timeline(?:_\d+)?\.csv"], "sample_info": [r"GetSamples_sampleinfo(?:_\d+)?\.csv", r"Process_sampleinfo(?:_\d+)?\.csv"], "handle": [r"handle(?:_\d+)?\.txt"], "enum_lock": [r"Enumlocs(?:_\d+)?\.txt"], "list_dll": [r"Listdlls(?:_\d+)?\.txt"], "ps_services": [r"psService(?:_\d+)?\.txt"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_process_dir = self.context.parsed_dir / "process"
        self.out_dir = self.context.result_parsed_dir
        self.out_process_dir.mkdir(exist_ok=True)
        self.parser = ProcessParser(self.logger, separator=self.context.separator)
        self.sinks = {}

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][PROCESS] Processing {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return
                
            for reg_pattern in self.get_regex_patterns():
                if re.search(reg_pattern, file_path.name, re.IGNORECASE):
                    self.copy_raw_artefact(file_path, self.out_process_dir)
                    self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": f"process_{file_path.stem}"})
                    self.context.siem_ingestion_files.append(str(file_path))
                    break

            category = None
            kwargs = {}
            if self._matches_category(file_path.name, "autoruns"):
                category = "autoruns"
            elif self._matches_category(file_path.name, "process1"):
                category = "process1"
            elif self._matches_category(file_path.name, "process2"):
                category = "process2"
            elif self._matches_category(file_path.name, "sample_autoruns"):
                category = "sample_autoruns"
            elif self._matches_category(file_path.name, "sample_timeline"):
                category = "sample_timeline"
            elif self._matches_category(file_path.name, "sample_info"):
                category = "sample_info"

            if category:
                if category == "process1":
                    # Parse normal version
                    for artifact_type, record in self.parser.parse(file_path, category=category, is_simplified=False):
                        if artifact_type not in self.sinks:
                            out_path = self.out_dir / artifact_type
                            self.sinks[artifact_type] = TextOutputSink(out_path)
                        self.sinks[artifact_type].write_record(record)
                    # Parse simplified version
                    for artifact_type, record in self.parser.parse(file_path, category=category, is_simplified=True):
                        if artifact_type not in self.sinks:
                            out_path = self.out_dir / artifact_type
                            self.sinks[artifact_type] = TextOutputSink(out_path)
                        self.sinks[artifact_type].write_record(record)
                else:
                    for artifact_type, record in self.parser.parse(file_path, category=category, **kwargs):
                        if artifact_type not in self.sinks:
                            if isinstance(record, dict):
                                out_path = self.out_dir / f"{artifact_type}.csv"
                                self.sinks[artifact_type] = DualOutputSink(out_path, separator=self.context.separator, jsonl_dir=self.context.siem_ingestion_dir, context=self.context)
                            else:
                                out_path = self.out_dir / artifact_type
                                self.sinks[artifact_type] = TextOutputSink(out_path)
                                
                        self.sinks[artifact_type].write_record(record)
                    
        except Exception as e:
            self.logger.error(f"[PIPELINE][PROCESS] Error on {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()
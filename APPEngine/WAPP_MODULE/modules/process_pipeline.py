import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink, TextOutputSink
from ..parsers.ProcessParser import ProcessParser

@register_pipeline(name="process")
class ProcessPipeline(BaseArtefactPipeline):
    DEFAULT_PATTERNS = {"process1": ["process1.csv", "processes1.csv"], "process2": ["process2.csv", "processes2.csv"], "autoruns": ["autoruns.csv"], "sample_autoruns": ["GetSamples_autoruns.xml", "Process_Autoruns.xml"], "sample_timeline": ["GetSamples_timeline.csv", "Process_timeline.csv"], "sample_info": ["GetSamples_sampleinfo.csv", "Process_sampleinfo.csv"], "handle": ["handle.txt"], "enum_lock": ["Enumlocs.txt"], "list_dll": ["Listdlls.txt"], "ps_services": ["psService.txt"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_process_dir = self.context.parsed_dir / "process"
        self.out_dir = self.context.result_parsed_dir
        self.out_process_dir.mkdir(exist_ok=True)
        self.parser = ProcessParser(self.logger, separator=self.context.separator)
        self.sinks = {}


        patterns = []
        for v in self.config_process.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns


        patterns = self.config_process.get(category_key, [])
        for p in patterns:
            if re.search(p, file_name, re.IGNORECASE):
                return True
        return False

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][PROCESS] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return
                
            for reg_pattern in self.get_regex_patterns():
                if re.search(reg_pattern, file_path.name, re.IGNORECASE):
                    self.copy_raw_artefact(file_path, self.out_process_dir)
                    self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": f"process_{file_path.stem}"})
                    break

            category = None
            kwargs = {}
            if self._matches_category(file_path.name, "autoruns"):
                category = "autoruns"
            elif self._matches_category(file_path.name, "process1"):
                category = "process1"
                kwargs = {"is_simplified": True}
            elif self._matches_category(file_path.name, "process2"):
                category = "process2"
            elif self._matches_category(file_path.name, "sample_autoruns"):
                category = "sample_autoruns"
            elif self._matches_category(file_path.name, "sample_timeline"):
                category = "sample_timeline"
            elif self._matches_category(file_path.name, "sample_info"):
                category = "sample_info"

            if category:
                for artifact_type, record in self.parser.parse(file_path, category=category, **kwargs):
                    if artifact_type not in self.sinks:
                        if isinstance(record, dict):
                            out_path = self.out_dir / f"{artifact_type}.csv"
                            self.sinks[artifact_type] = CsvOutputSink(out_path, separator=self.context.separator)
                        else:
                            # It's a text line (e.g. process1)
                            # process1 is historically a file named 'process1' or 'process1_s' without extension
                            out_path = self.out_dir / artifact_type
                            self.sinks[artifact_type] = TextOutputSink(out_path)
                            
                    self.sinks[artifact_type].write_record(record)
                    
        except Exception as e:
            self.logger.error(f"[PIPELINE][PROCESS] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()
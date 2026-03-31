import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers.ProcessParser import ProcessParser

class ProcessPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_process_dir = self.context.parsed_dir / "process"
        self.out_dir = self.context.result_parsed_dir
        self.out_process_dir.mkdir(exist_ok=True)
        self.parser = ProcessParser(self.logger, separator=self.context.separator)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("process", {})

    def get_regex_patterns(self):
        patterns = []
        for v in self.config_process.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns

    def _matches_category(self, file_name, category_key):
        patterns = self.config_process.get(category_key, [])
        for p in patterns:
            if re.search(p, file_name, re.IGNORECASE):
                return True
        return False

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][PROCESS] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            for reg_pattern in self.get_regex_patterns():
                if re.search(reg_pattern, file_path.name, re.IGNORECASE):
                    self.copy_raw_artefact(file_path, self.out_process_dir)
                    self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": f"process_{file_path.stem}"})

            if self._matches_category(file_path.name, "autoruns"):
                self.parser.parse_autoruns_sysinternals(str(file_path), str(self.out_dir))
            elif self._matches_category(file_path.name, "process1"):
                self.parser.parse_process1(str(file_path), str(self.out_dir), is_simplified=True)
            elif self._matches_category(file_path.name, "process2"):
                self.parser.parse_process2(str(file_path), str(self.out_dir), output_delimiter=self.context.separator)
            elif self._matches_category(file_path.name, "sample_autoruns"):
                self.parser.parse_process_autoruns(str(file_path), str(self.out_dir))
            elif self._matches_category(file_path.name, "sample_timeline"):
                self.parser.parse_process_timeline(str(file_path), str(self.out_dir), output_delimiter=self.context.separator)
            elif self._matches_category(file_path.name, "sample_info"):
                self.parser.parse_process_infos(str(file_path), str(self.out_dir), output_delimiter=self.context.separator)
        except Exception as e:
            self.logger.error(f"[PIPELINE][PROCESS] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)
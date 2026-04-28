from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers import SystemInfoParser
import re

class SystemInfoPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = SystemInfoParser.SystemInfoParser(self.logger, separator=self.context.separator)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("system", {})

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
        self.logger.info(f"[PIPELINE][SYSINFO] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            res_file = self.parser.parse_system_info(str(file_path), str(self.context.result_parsed_dir))
            if res_file:
                self.context.wazuh_importer_file_config["files"].append( {"path": str(file_path), "type": f"systemInfo"})
                self.logger.info(f"[PIPELINE][SYSINFO] Traitement de {file_path.name}", header="SUCCESS",
                                 indentation=2)

        except Exception as e:
            self.logger.error(f"[PIPELINE][SYSINFO] Erreur: {e}", header="ERROR", indentation=2)

        self.logger.info(f"[PIPELINE][SYSINFO] Traitement de {file_path.name}", header="FINISHED", indentation=1)
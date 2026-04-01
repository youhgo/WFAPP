from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers import RegistryParser
import re


class HivePipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = RegistryParser.RegistryParser(self.logger)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("hives", {})

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
        self.logger.info(f"[PIPELINE][HIVE] Traitement de {file_path.name}", header="START", indentation=1)
        try:

            if self._matches_category(file_path.name, "AMCACHE"):
                res_file = self.parser.export_amcache_to_jsonl(str(file_path), str(self.context.result_parsed_dir))
                if res_file:
                    self.context.wazuh_importer_file_config["files"].append({"path": str(res_file), "type": "amcache_yarp"})
                res_file1 = self.parser.parse_amcache_regpy(str(file_path), str(self.context.result_parsed_dir))
                if res_file1:
                    self.context.wazuh_importer_file_config["files"].append(
                            {"path": str(res_file1), "type": "amcache_regpy"})
            else:
                res_file, hv_name = self.parser.export_hive_to_jsonl(str(file_path), str(self.context.result_parsed_dir))
                if res_file:
                    self.context.wazuh_importer_file_config["files"].append({"path": str(res_file), "type": f"registry_{hv_name}"})
            self.logger.info(f"[PIPELINE][HIVE] Succès", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][HIVE] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)
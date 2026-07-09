from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers import DiskParser
import re

class DiskPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = DiskParser.DiskParser(self.logger, separator=self.context.separator)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("disk", {})
        self.out_disk_dir = self.context.parsed_dir / "disk"
        self.out_dir = self.context.result_parsed_dir
        self.out_disk_dir.mkdir(parents=True, exist_ok=True)

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
        self.logger.info(f"[PIPELINE][DISK] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            if self._matches_category(file_path.name, "VSS_List"):
                self.copy_raw_artefact(file_path, self.out_disk_dir)
                self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": "disk"})

            elif self._matches_category(file_path.name, "usn_journal"):
                res_file = self.parser.parse_usnjrnl(str(file_path), str(self.context.result_parsed_dir))
                self.copy_raw_artefact(file_path, self.out_disk_dir)
                self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": "usnjrnl"})

        except Exception as e:
            self.logger.error(f"[PIPELINE][DISK] Erreur: {e}", header="ERROR", indentation=1)
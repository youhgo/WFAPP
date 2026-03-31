from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers import Linkparser
import re

class LnkPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.lnk_dir = self.context.parsed_dir / "lnk"
        self.lnk_dir.mkdir(exist_ok=True)
        self.parser = Linkparser.LinkParser(self.logger, str(self.lnk_dir), str(self.context.result_parsed_dir), self.context.separator)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("lnk", {})

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
        self.logger.info(f"[PIPELINE][LNK] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            if self._matches_category(file_path.name, "lnk"):
                res_file = self.parser.parse_lnk_to_json(str(file_path))
                if res_file:
                    self.context.wazuh_importer_file_config["files"].append({"path": str(res_file), "type": "lnk"})
        except Exception as e:
            self.logger.error(f"[PIPELINE][LNK] Erreur: {e}", header="ERROR", indentation=1)
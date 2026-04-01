import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext

class ScriptPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_script_dir = self.context.parsed_dir / "script"
        self.out_dir = self.context.result_parsed_dir
        self.out_script_dir.mkdir(parents=True, exist_ok=True)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("scripts", {})

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
        self.logger.info(f"[PIPELINE][SCRIPT] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            out_bat_dir = self.out_script_dir / "bat"
            out_bat_dir.mkdir(parents=True, exist_ok=True)
            if self._matches_category(file_path.name, "bat"):
                self.copy_raw_artefact(file_path, out_bat_dir)
        except Exception as e:
            self.logger.error(f"[PIPELINE][SCRIPT] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)
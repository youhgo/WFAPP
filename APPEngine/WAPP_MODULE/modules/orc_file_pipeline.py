import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext


class OrcLogPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_log_dir = self.context.parsed_dir / "orcLogs"
        self.out_dir = self.context.result_parsed_dir
        self.out_log_dir.mkdir(exist_ok=True)
        # "orc" est un dictionnaire dans le JSON, donc .values() fonctionne ici
        self.config_process = self.context.artefact_config.get("orc", {})

    def get_regex_patterns(self):
        """Récupère les patterns en gérant les dictionnaires ou les listes."""
        if isinstance(self.config_process, list):
            return self.config_process

        patterns = []
        for v in self.config_process.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns

    def _matches_category(self, file_name, category_key):
        patterns = self.config_process.get(category_key, [])
        if not isinstance(patterns, list):
            patterns = [patterns]

        for p in patterns:
            if re.search(p, file_name, re.IGNORECASE):
                return True
        return False

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][ORCLOGS] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            matched = False
            for reg_pattern in self.get_regex_patterns():
                if re.search(reg_pattern, file_path.name, re.IGNORECASE):
                    self.copy_raw_artefact(file_path, self.out_log_dir)
                    matched = True
                    break  # Évite de copier plusieurs fois si plusieurs regex matchent
        except Exception as e:
            self.logger.error(f"[PIPELINE][ORCLOGS] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)
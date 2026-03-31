import re
from pathlib import Path
import traceback

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers import ActivitiesCacheParser

class DbPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_other_dir = self.context.parsed_dir / "database"
        self.out_dir = self.context.result_parsed_dir
        self.out_other_dir.mkdir(exist_ok=True)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("database", {})

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
        self.logger.info(f"[PIPELINE][DATABASE] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            if self._matches_category(file_path.name, "Activity_cache"):
                parser = ActivitiesCacheParser.ActivitiesCacheParser(self.logger, separator=self.context.separator)
                parser.parse_activities_cache(file_path, self.out_other_dir)
            elif self._matches_category(file_path.name, "sdb"):
                pass
            elif self._matches_category(file_path.name, "SRUM"):
                pass
        except Exception as e:
            self.logger.error(f"[PIPELINE][DATABASE] Erreur sur {file_path.name}: {traceback.format_exc()}",
                              header="ERROR", indentation=1)
import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext

from ..classes.Registry import register_pipeline

@register_pipeline('legacy')
class OtherPipeline(BaseArtefactPipeline):
    """
    Process legacy ORC artefacts not explicitly parsed by other pipelines.
    """
    recommended = False
    importance = "Optional"
    speed = "Fast"
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_other_dir = self.context.parsed_dir / "other"
        self.out_dir = self.context.result_parsed_dir
        self.out_other_dir.mkdir(exist_ok=True)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("other", {})

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
        self.logger.info(f"[PIPELINE][OTHER] Processing {file_path.name}", header="START", indentation=1)
        try:
            if self._matches_category(file_path.name, "event_consumer"):
                self.copy_raw_artefact(file_path, self.out_other_dir)
            elif self._matches_category(file_path.name, "ad_computer"):
                self.copy_raw_artefact(file_path, self.out_other_dir)
        except Exception as e:
            self.logger.error(f"[PIPELINE][OTHER] Error on {file_path.name}: {e}", header="ERROR", indentation=1)
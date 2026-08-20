import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline

@register_pipeline(name="scripts")
class ScriptPipeline(BaseArtefactPipeline):
    """
    Parses scripts and associated executions.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
    DEFAULT_PATTERNS = {"bat": [".*.bat"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_script_dir = self.context.parsed_dir / "script"
        self.out_dir = self.context.result_parsed_dir
        self.out_script_dir.mkdir(parents=True, exist_ok=True)

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][SCRIPT] Processing {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return
                
            out_bat_dir = self.out_script_dir / "bat"
            out_bat_dir.mkdir(parents=True, exist_ok=True)
            if self._matches_category(file_path.name, "bat"):
                self.copy_raw_artefact(file_path, out_bat_dir)
                
            self.logger.info(f"[PIPELINE][SCRIPT] Success", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][SCRIPT] Error on {file_path.name}: {e}", header="ERROR", indentation=1)
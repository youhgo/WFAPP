import re
import shutil
from pathlib import Path
import traceback
from typing import List, Tuple

# Importe le contexte depuis le même dossier pour le typage
from .WappContext import WappContext


class BaseArtefactPipeline:
    """Base class for all artifact pipelines."""
    
    # List of tuples (regex, boolean_recurse) for the inventory
    # EX: [(r'System32/config/SYSTEM$', False)]
    file_match_patterns: List[Tuple[str, bool]] = []
    
    # Defines if the plugin is recommended for general use.
    recommended: bool = True

    DEFAULT_PATTERNS = {}

    def __init__(self, context: WappContext):
        self.context = context
        self.logger = context.logger
        self.pipeline_name = getattr(self.__class__, '__pipeline_name__', 'unknown')

    def get_regex_patterns(self) -> list:
        custom_config = self.context.config.get("pipelines", {}).get(self.pipeline_name, {})
        patterns_dict = custom_config.get("patterns", self.DEFAULT_PATTERNS)
        
        patterns = []
        if isinstance(patterns_dict, dict):
            for v in patterns_dict.values():
                patterns.extend(v if isinstance(v, list) else [v])
        elif isinstance(patterns_dict, list):
            patterns.extend(patterns_dict)
        return patterns

    def _matches_category(self, file_name, category_key):
        custom_config = self.context.config.get("pipelines", {}).get(self.pipeline_name, {})
        patterns_dict = custom_config.get("patterns", self.DEFAULT_PATTERNS)
        
        patterns = patterns_dict.get(category_key, [])
        if not isinstance(patterns, list):
            patterns = [patterns]
            
        for p in patterns:
            if re.search(p, file_name, re.IGNORECASE):
                return True
        return False

    def can_process(self, file_path: Path) -> bool:
        patterns = self.get_regex_patterns()
        for pattern in patterns:
            if re.search(pattern, file_path.name, re.IGNORECASE):
                return True
        return False

    def process(self, file_path: Path):
        raise NotImplementedError

    def copy_raw_artefact(self, file_path: Path, out_dir):
        """
        Utility function to copy the raw artifact to a centralized folder.
        All pipelines can call it to save the source file.
        """
        #out_dir = self.context.parsed_dir  / end_folder
        out_dir.mkdir(parents=True, exist_ok=True)

        dest_file = out_dir / file_path.name

        # Collision management (multiple files with the same final name)
        counter = 1
        while dest_file.exists():
            if dest_file.stat().st_size == file_path.stat().st_size:
                return  # Identical file (perfect duplicate) already present
            dest_file = out_dir / f"{file_path.stem}_{counter}{file_path.suffix}"
            counter += 1

        try:
            shutil.copy2(file_path, dest_file)
            self.logger.info(f"[PIPELINE][COPY] {file_path.name} copied.", header="INFO",
                             indentation=2)
        except Exception as e:
            self.logger.error(f"[PIPELINE][COPY] Error copying {file_path.name}: {traceback.format_exc()}", header="ERROR", indentation=1)

    def finalize(self):
        """Called once all files have been traversed."""
        pass
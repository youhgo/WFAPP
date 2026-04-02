import subprocess
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers import DiskParser
import re

class MftPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.mft_dir = self.context.parsed_dir / "disk"
        self.mft_dir.mkdir(parents=True, exist_ok=True)
        self.parser = DiskParser.DiskParser(self.logger, separator=self.context.separator)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("master_file_table", {})

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
        self.logger.info(f"[PIPELINE][MFT] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            clean_mft_name = file_path.name.replace("$", "")
            mft_result_file = self.mft_dir / f"{clean_mft_name}.timeline"
            self.context.wazuh_importer_file_config["files"].append({"path": str(mft_result_file), "type": "mft_timeline"})

            # Utilisation de l'outil externe analyzeMFT
            my_cmd = ["python3", str(self.context.analyze_mft_tool_path), "-f", str(file_path), "-o",
                      str(mft_result_file), "--timeline"]
            subprocess.run(my_cmd, stderr=subprocess.DEVNULL)

            # Parsing final en CSV
            res_file = self.parser.parse_plaso_csv(str(mft_result_file), str(self.context.result_parsed_dir))
            self.logger.info(f"[PIPELINE][MFT] Succès", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][MFT] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)
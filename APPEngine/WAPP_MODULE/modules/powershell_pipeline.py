from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
import re

class PowerShellPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_powershell_script_dir = self.context.parsed_dir / "script" / "powershell"
        self.out_powershell_script_dir.mkdir(parents=True, exist_ok=True)

        self.out_powershell_dir = self.context.parsed_dir / "powershell"
        self.out_powershell_dir.mkdir(parents=True, exist_ok=True)

        self.config_process = self.context.artefact_config.get("artefacts", {}).get("powershell", {})

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
        self.logger.info(f"[PIPELINE][POWERSHELL] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            if self._matches_category(file_path.name, "consol_history"):
                self.copy_raw_artefact(file_path, self.context.result_parsed_dir)
                self.context.wazuh_importer_file_config["files"].append({"path": str(file_path),
                                                                         "type": f"process_consolehost_history"})

            if self._matches_category(file_path.name, "scripts"):
                self.copy_raw_artefact(file_path, self.out_powershell_script_dir)

            if self._matches_category(file_path.name, "powerview"):
                self.copy_raw_artefact(file_path, self.out_powershell_dir)

            if self._matches_category(file_path.name, "Module_Analysis_Cache"):
                self.copy_raw_artefact(file_path, self.out_powershell_dir)


        except Exception as e:
            self.logger.error(f"[PIPELINE][POWERSHELL] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)
import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline

@register_pipeline(name="powershell")
class PowerShellPipeline(BaseArtefactPipeline):
    """
    Parses PowerShell execution logs.
    """
    recommended = True
    DEFAULT_PATTERNS = {"consol_history": [r"ConsoleHost_history(?:_\d+)?\.txt"], "Module_Analysis_Cache": [r"ModuleAnalysisCache(?:_\d+)?"], "powerview": [r"PowerView(?:_\d+)?"], "scripts": [r".*(?:_\d+)?\.ps1"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_powershell_script_dir = self.context.parsed_dir / "script" / "powershell"
        self.out_powershell_script_dir.mkdir(parents=True, exist_ok=True)

        self.out_powershell_dir = self.context.parsed_dir / "powershell"
        self.out_powershell_dir.mkdir(parents=True, exist_ok=True)


    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][POWERSHELL] Processing {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return
                
            if self._matches_category(file_path.name, "consol_history"):
                self.copy_raw_artefact(file_path, self.context.result_parsed_dir)
                self.context.wazuh_importer_file_config["files"].append({
                    "path": str(file_path),
                    "type": f"process_consolehost_history"
                })

            if self._matches_category(file_path.name, "scripts"):
                self.copy_raw_artefact(file_path, self.out_powershell_script_dir)

            if self._matches_category(file_path.name, "powerview"):
                self.copy_raw_artefact(file_path, self.out_powershell_dir)

            if self._matches_category(file_path.name, "Module_Analysis_Cache"):
                self.copy_raw_artefact(file_path, self.out_powershell_dir)

            self.logger.info(f"[PIPELINE][POWERSHELL] Success", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][POWERSHELL] Error on {file_path.name}: {e}", header="ERROR", indentation=1)
import re
from pathlib import Path

from ...classes.BaseArtefactPipelines import BaseArtefactPipeline
from ...classes.WappContext import WappContext
from ...classes.Registry import register_pipeline

@register_pipeline(name="scripts")
class ScriptPipeline(BaseArtefactPipeline):
    """
    Parses scripts and associated executions.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
    DEFAULT_PATTERNS = {
        "batch": [
            r"\.bat(?:\.\d+|_\d+)?$",
            r"\.cmd(?:\.\d+|_\d+)?$"
        ],
        "powershell": [
            r"\.ps1(?:\.\d+|_\d+)?$",
            r"\.psm1(?:\.\d+|_\d+)?$",
            r"\.psd1(?:\.\d+|_\d+)?$",
            r"\.ps1xml(?:\.\d+|_\d+)?$",
            r"\.psc1(?:\.\d+|_\d+)?$"
        ],
        "vbscript": [
            r"\.vbs(?:\.\d+|_\d+)?$",
            r"\.vbe(?:\.\d+|_\d+)?$"
        ],
        "jscript": [
            r"\.js(?:\.\d+|_\d+)?$",
            r"\.jse(?:\.\d+|_\d+)?$"
        ],
        "wsh": [
            r"\.wsf(?:\.\d+|_\d+)?$",
            r"\.wsh(?:\.\d+|_\d+)?$"
        ],
        "hta": [
            r"\.hta(?:\.\d+|_\d+)?$"
        ],
        "wsc": [
            r"\.sct(?:\.\d+|_\d+)?$"
        ],
        "shortcut_ms": [
            r"\.settingcontent-ms(?:\.\d+|_\d+)?$"
        ],
        "scf": [
            r"\.scf(?:\.\d+|_\d+)?$"
        ],
        "webshell": [
            r"\.php(?:\.\d+|_\d+)?$",
            r"\.asp(?:\.\d+|_\d+)?$",
            r"\.aspx(?:\.\d+|_\d+)?$",
            r"\.jsp(?:\.\d+|_\d+)?$",
            r"\.cfm(?:\.\d+|_\d+)?$",
            r"\.ashx(?:\.\d+|_\d+)?$",
            r"\.asmx(?:\.\d+|_\d+)?$"
        ],
        "python": [
            r"\.py(?:\.\d+|_\d+)?$",
            r"\.pyw(?:\.\d+|_\d+)?$"
        ],
        "perl": [
            r"\.pl(?:\.\d+|_\d+)?$"
        ],
        "ruby": [
            r"\.rb(?:\.\d+|_\d+)?$"
        ],
        "shell": [
            r"\.sh(?:\.\d+|_\d+)?$",
            r"\.bash(?:\.\d+|_\d+)?$",
            r"\.zsh(?:\.\d+|_\d+)?$",
            r"\.ksh(?:\.\d+|_\d+)?$",
            r"\.csh(?:\.\d+|_\d+)?$"
        ],
        "installer_config": [
            r"\.inf(?:\.\d+|_\d+)?$",
            r"\.reg(?:\.\d+|_\d+)?$"
        ],
        "office_macro": [
            r"\.docm(?:\.\d+|_\d+)?$",
            r"\.xlsm(?:\.\d+|_\d+)?$",
            r"\.pptm(?:\.\d+|_\d+)?$",
            r"\.docb(?:\.\d+|_\d+)?$"
        ],
        "chm": [
            r"\.chm(?:\.\d+|_\d+)?$"
        ],
        "jar": [
            r"\.jar(?:\.\d+|_\d+)?$"
        ]
    }

    CATEGORY_TO_FOLDER = {
        "batch": "bat",
        "powershell": "powershell",
        "vbscript": "vbs",
        "jscript": "jscript",
        "wsh": "wsh",
        "hta": "hta",
        "wsc": "wsc",
        "shortcut_ms": "shortcut_ms",
        "scf": "scf",
        "webshell": "webshell",
        "python": "python",
        "perl": "perl",
        "ruby": "ruby",
        "shell": "shell",
        "installer_config": "installer_config",
        "office_macro": "office_macro",
        "chm": "chm",
        "jar": "jar"
    }

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_script_dir = self.context.parsed_dir / "scripts"
        self.out_dir = self.context.result_parsed_dir
        self.out_script_dir.mkdir(parents=True, exist_ok=True)

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][SCRIPT] Processing {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return
                
            for category, folder in self.CATEGORY_TO_FOLDER.items():
                if self._matches_category(file_path.name, category):
                    dest_dir = self.out_script_dir / folder
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    self.copy_raw_artefact(file_path, dest_dir)
                    break
                
            self.logger.info(f"[PIPELINE][SCRIPT] Success", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][SCRIPT] Error on {file_path.name}: {e}", header="ERROR", indentation=1)

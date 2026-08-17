import json
import os
from datetime import datetime
from pathlib import Path

# Import direct de la classe LoggerManager depuis le même dossier
from .LoggerManager import LoggerManager


class WappContext:
    """Stocke la configuration globale, le logger et les chemins d'exécution."""

    def __init__(self, path_to_archive, output_directory, case_name, machine_name, separator, main_id, artefact_config,
                 main_config):
        self.path_to_archive = Path(path_to_archive)
        self.output_directory = Path(output_directory)
        self.case_name = case_name
        self.machine_name = machine_name or "no_name"
        self.separator = separator
        self.main_id = main_id or self.machine_name

        # Outils
        self.tool_path = os.environ.get("TOOL_PATH", "/python-docker/WAPP_MODULE/outils")
        self.evtx_dump_path = os.path.join(self.tool_path, "evtx_dump")
        self.analyze_mft_tool_path = "/python-docker/analyzeMFT/analyzeMFT.py"

        # Dates & Dossiers de base
        self.current_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        self.machine_working_folder_name = f"{self.machine_name}_{self.current_date}"
        self.case_work_dir = self.output_directory / self.case_name
        self.machine_working_folder_path = self.case_work_dir / self.machine_working_folder_name

        # Logs
        self.log_dir = self.output_directory / "execution_logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.running_log_file_path = self.log_dir / f"{self.main_id}_running.log"
        self.logger = LoggerManager("running", str(self.running_log_file_path), "INFO")

        # Dossiers d'extraction
        self.extracted_main_dir = self.machine_working_folder_path / "extracted"
        self.extracted_dir = self.extracted_main_dir / "extracted_raw"
        self.restored_path = self.extracted_main_dir / "restaured"

        # Dossiers de parsing
        self.parsed_dir = self.machine_working_folder_path / "parsed"
        self.result_parsed_dir = self.parsed_dir / "parsed_for_human"
        self.timeline_dir = self.parsed_dir / "timeline"

        # Création de l'arborescence
        self._init_directories()

        # Configurations
        self.config = self._load_config(main_config, "/python-docker/WAPP_MODULE/config/wfapp_config.json", {}, "[CONFIG]")

        # Wazuh & SystemInfo
        self.wazuh_importer_file_config = {"files": []}
        self.system_info = {}

    def _init_directories(self):
        dirs_to_create = [
            self.case_work_dir, self.machine_working_folder_path, self.extracted_main_dir,
            self.extracted_dir, self.restored_path, self.parsed_dir, self.result_parsed_dir,
            self.timeline_dir
        ]
        for d in dirs_to_create:
            d.mkdir(parents=True, exist_ok=True)

    def _load_config(self, custom_config, file_path, default_config, log_header):
        if custom_config and isinstance(custom_config, dict):
            self.logger.info(f"{log_header} Custom config loaded", header="INFO")
            return custom_config
        try:
            with open(file_path, "r") as f:
                self.logger.info(f"{log_header} Loading config from {file_path}", header="INFO")
                return json.load(f)
        except Exception:
            self.logger.info(f"{log_header} No config file found at {file_path}, using defaults.", header="INFO")
            return default_config
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
        self.artefact_config = self._load_config(artefact_config,
                                                 "/python-docker/WAPP_MODULE/config/artefact_name_config.json",
                                                 self._get_default_artefact_config(), "[ARTEFACT][CONFIG]")
        self.main_config = self._load_config(main_config, "/python-docker/WAPP_MODULE/config/parser_config.json",
                                             self._get_default_main_config(), "[PARSER][CONFIG]")

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
            self.logger.error(f"{log_header} Error loading config, using embedded fallback", header="ERROR")
            return default_config

    def _get_default_artefact_config(self):
        return {
            "artefacts": {
                "system": {
                    "system_info": ["Systeminfo.csv"]
                },
                "network": {
                    "tcpvcon": ["Tcpvcon.txt"],
                    "arp_cache": ["arp_cache.txt"],
                    "dns_cache": ["dns_cache.txt"],
                    "netstat": ["netstat.txt"],
                    "routes": ["routes.txt"],
                    "hosts": ["hosts$"],
                    "lmhosts": ["lmhosts.sam"],
                    "protocol": ["protocol$"],
                    "services": ["services$"],
                    "network": ["networks$"],
                    "bits": ["BITS_jobs.txt"],
                    "dns_records": ["DNS_records.txt"]
                },
                "hives": {
                    "NTUSER": ["NTUSER.DAT$"],
                    "AMCACHE": ["Amcache.hve$"],
                    "SOFTWARE": ["SOFTWARE$"],
                    "SYSTEM": ["SYSTEM$"],
                    "SECURITY": ["SECURITY$"],
                    "SAM": ["SAM$"]
                },
                "process": {
                    "process1": ["process1.csv", "processes1.csv"],
                    "process2": ["process2.csv", "processes2.csv"],
                    "autoruns": ["autoruns.csv"],
                    "sample_autoruns": ["GetSamples_autoruns.xml", "Process_Autoruns.xml"],
                    "sample_timeline": ["GetSamples_timeline.csv", "Process_timeline.csv"],
                    "sample_info": ["GetSamples_sampleinfo.csv", "Process_sampleinfo.csv"],
                    "handle": ["handle.txt"],
                    "enum_lock": ["Enumlocs.txt"],
                    "list_dll": ["Listdlls.txt"],
                    "ps_services": ["psService.txt"]
                },
                "event_logs": {
                    "evtx": [".*.evtx"]
                },
                "powershell": {
                    "consol_history": ["ConsoleHost_history.txt"],
                    "Module_Analysis_Cache": ["ModuleAnalysisCache"],
                    "powerview": ["PowerView"],
                    "scripts": [".*.ps1"]
                },
                "master_file_table": {
                    "MFT": ["MFT$"]
                },
                "disk": {
                    "usn_journal": ["USNInfo.*.csv"],
                    "VSS_List": ["VSS_list.csv"]
                },
                "lnk": {
                    "lnk": [".*.lnk"]
                },
                "files": {
                    "Wmi": ["OBJECTS.DATA", "INDEX.BTR", "MAPPING*.MAP"],
                    "recent_file": [".*-ms"]
                },
                "prefetch": {
                    "super_fetch": ["ag.*.db"],
                    "prefetch": [".*.pf"]
                },
                "database": {
                    "Activity_cache": ["ActivitiesCache.db"],
                    "sdb": [".*.sdb"],
                    "SRUM": ["SRUDB.dat", "SRU.*.log"]
                },
                "browsers": {
                    "browser_history": [".*.sqlite"]
                },
                "others": {
                    "event_consumer": ["EventConsumer.txt"],
                    "ad_computer": ["AD_computers.csv"],
                    "setup_api": ["setupapi"],
                    "mrt": ["mrt"]
                },
                "scripts": {
                    "bat": [
                        ".*.bat"
                    ]
                }
            }
        }

    def _get_default_main_config(self):
        return {"restore": 0, "rename_from_orc": 0, "disk": 1, "elk": 0, "plaso2elk": 0, "wazuh": 0, "plaso2wazuh": 0,
                "evtx": 1, "hive": 1, "mft": 1, "mpp": 1, "network": 1, "lnk": 1, "plaso": 1, "prefetch": 1,
                "process": 1, "system_info": 1, "webHistory": 1}
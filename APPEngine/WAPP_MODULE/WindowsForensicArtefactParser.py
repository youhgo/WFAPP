#!/usr/bin/python3
import argparse
import csv
from datetime import datetime, timedelta
import json
import os
import re
import subprocess
import sys
import time
import traceback

from .classes import DiskParser, EventParser, FileManager, Linkparser, LoggerManager, MaximumPlasoParserJson, \
    NetWorkParser, OrcExtractor, plaso2Elk, PrefetchParser, ProcessParser, RegistryParser, SystemInfoParser, WebHistoryParser


# Try importing pyscca; fail if it doesn't import
try:
    import pyscca #Import pyscca, necessary from libscca
except ImportError:
    print("Please install libscca with Python bindings")


# TODO : Parsing
# TODO : Parse Log erasure
# TODO : Export pre plaso as JSON for SIEM

class WindowsForensicArtefactParser:
    """
       Class WindowsForensicArtefactParser
       MPP or WindowsForensicArtefactParser is a python script that will parse a plaso - Log2Timeline json timeline file.
       The goal is to provide easily readable and straight forward files for the Forensic analyst.
       MPP will create a file for each artefact.
       Attributes :
       None
    """

    def __init__(self, path_to_archive, output_directory, case_name, is_orc=True, machine_name="", separator='|', main_id="",
                 artefact_config=None, main_config=None) -> None:
        """
        Constructor for the WindowsForensicArtefactParser Class

        :param output_directory: (str) directory where the results file will be written
        :param separator: (str) separator for csv output file
        :param case_name:  (str) name that will be set into json result files (for practical purpose with elk)
        :param main_config: (dict) json str containing the main configuration
        :param artefact_config: (dict) json str containing the configuration for the artefacts names
        """

        self.ascii_art_wapp = r"""
        ███████╗    ██████═╗ ██████╗ ██████╗ 
        ██╔════██╗██╔═════██╗██╔══██╗██╔══██
        ██║    ██║██║     ██║██║███ ║██║███
        ██║    ██║██║     ██║██║    ║██║
        ███████╔╝╚║═╝██████╔████╗══╗████║
        ╚══════╝  ╚═════╝  ╚════╝  ╚════╝ 
        
        Windows Forensic Artefect Parser Project
        Made by Hugo ROLLAND
        """
        print(self.ascii_art_wapp)
        self.path_to_archive = path_to_archive
        self.dir_out = output_directory
        self.case_name = case_name
        self.separator = separator
        self.is_orc = is_orc

        if machine_name:
            self.machine_name = machine_name
        else:
            self.machine_name = "no_name"

        if main_id:
            self.main_id = main_id
        else:
            self.main_id = self.machine_name


        self.tool_path = os.environ.get("TOOL_PATH", "/python-docker/WAPP_MODULE/outils")
        self.evtx_dump_path = os.path.join(self.tool_path, "evtx_dump")
        self.analyze_mft_tool_path = "/python-docker/analyzeMFT/analyzeMFT.py"

        self.current_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        self.machine_working_folder_name = self.machine_name + "_" + self.current_date
        self.system_info = {}
        self.case_work_dir = os.path.join(self.dir_out, self.case_name)
        self.log_dir = os.path.join(self.dir_out, "execution_logs")

        self.machine_working_folder_path = os.path.join(self.case_work_dir, self.machine_working_folder_name)
        self.extracted_main_dir = os.path.join(self.machine_working_folder_path, "extracted")
        self.extracted_dir = os.path.join(self.extracted_main_dir, "extracted_raw")
        self.restored_path = os.path.join(self.extracted_main_dir, "restaured")
        self.parsed_dir = os.path.join(self.machine_working_folder_path, "parsed")
        self.orc_log_dir = os.path.join(self.parsed_dir, "orc_log")
        self.process_dir = os.path.join(self.parsed_dir, "process")
        self.network_dir = os.path.join(self.parsed_dir, "network")
        self.powershell_dir = os.path.join(self.parsed_dir, "powershell")
        self.hive_dir = os.path.join(self.parsed_dir, "hives")
        self.lnk_dir = os.path.join(self.parsed_dir, "lnk")
        self.prefetch_dir = os.path.join(self.parsed_dir, "prefetch")
        self.timeline_dir = os.path.join(self.parsed_dir, "timeline")
        self.txt_log_dir = os.path.join(self.parsed_dir, "textLogs")
        self.disk_dir = os.path.join(self.parsed_dir, "disks_info")
        self.result_parsed_dir = os.path.join(self.parsed_dir, "parsed_for_human")
        self.evt_dir = os.path.join(self.parsed_dir, "event")
        self.mft_dir = os.path.join(self.disk_dir, "mft")
        self.other_dir = os.path.join(self.parsed_dir, "others")
        self.scripts_dir = os.path.join(self.parsed_dir, "scripts")
        self.initialise_working_directories()

        self.running_log_file_path = os.path.join(self.log_dir, "{}_running.log".format(self.main_id))

        self.logger_run = LoggerManager.LoggerManager("running", self.running_log_file_path, "INFO")

        if artefact_config:
            if isinstance(artefact_config, dict):
                self.artefact_config = artefact_config
                self.logger_run.info(
                    "[ARTEFACT][CONFIG] loading custom config  {}".format(json.dumps(self.artefact_config, indent=4)),
                    header="INFO", indentation=0)
            else :
                self.logger_run.error(
                    "[ARTEFACT][CONFIG] Incorrect config provided: {}, using default".format(
                        json.dumps(artefact_config)), header="ERROR", indentation=0)
        else:
            artefact_config_path = "/python-docker/WAPP_MODULE/config/artefact_name_config.json"
            try:
                self.logger_run.info("[ARTEFACT][CONFIG] Loading default config file {}".format(artefact_config_path),
                                     header="INFO", indentation=0)
                with open(artefact_config_path, "r") as config_file_stream:
                    self.artefact_config = json.load(config_file_stream)
            except:
                self.artefact_config = {

                    "orc": {
                        "orc_run_logs": [
                            "Statistics.json",
                            "config.xml",
                            "Config.xml",
                            "FastFind_result.xml",
                            "Statistics_*.json",
                            "_config.xml",
                            "Artefacts.log",
                            "VSS_list.log",
                            "Browsers_artefacts.log",
                            "UserHives.log",
                            "autoruns.log",
                            "MFT.log",
                            "SystemHives.log",
                            "Event.log",
                            "processes2.log",
                            "TextLogs.log",
                            "AD_computers.log",
                            "SAM.log",
                            "DNS_records.log",
                            "TextLogs",
                            "Browsers_history.log",
                            "EventConsumer.log",
                            "USNInfo.log",
                            "processes1.log"
                        ]
                    },
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
                            "scripts" : [".*.ps1"]
                        },
                        "master_file_table": {
                            "MFT": ["MFT$"]
                        },
                        "disk": {
                            "usn_journal": ["USNInfo.*.csv"],
                            "VSS_List": ["VSS_list.csv"]
                        },
                        "files": {
                            "Activity_cache": ["ActivitiesCache.db"],
                            "sdb": [".*.sdb"],
                            "SRUM": ["SRUDB.dat", "SRU.*.log"],
                            "super_fetch": ["ag.*.db"],
                            "Wmi": ["OBJECTS.DATA", "INDEX.BTR", "MAPPING*.MAP"],
                            "prefetch": [".*.pf"],
                            "lnk": [".*.lnk"],
                            "recent_file": [".*-ms"]
                        },
                        "browsers": {
                            "browser_history": [".*.sqlite"]
                        },
                        "others_text": {
                            "event_consumer": ["EventConsumer.txt"],
                            "ad_computer": ["AD_computers.csv"]
                        },
                        "others_bin": {
                            "setup_api": ["setupapi"],
                            "mrt": ["mrt"]
                        },
                        "scripts": {
                            "bat": [".*.bat"]
                        }
                    }
                }

                self.logger_run.info(
                    "[ARTEFACT][CONFIG] Error loading default config file, loading embedded config {}".format(
                        json.dumps(self.artefact_config, indent=4)),
                    header="INFO", indentation=0)

        if main_config:
            if isinstance(main_config, dict):
                self.main_config = main_config
                self.logger_run.info("[PARSER][CONFIG] Loading Custom config provided: {}".format(json.dumps(self.main_config, indent=4)),
                                      header="INFO",indentation=0)
            else :
                self.logger_run.error(
                    "[PARSER][CONFIG] Incorrect config provided: {}, using default".format(
                        json.dumps(artefact_config)), header="ERROR", indentation=0)
        else:
            parser_config = "/python-docker/WAPP_MODULE/config/parser_config.json"
            try:
                self.logger_run.info("[ARTEFACT][CONFIG] No config provided, loading default config file {}".format(parser_config), header="INFO", indentation=0)
                with open(parser_config, "r") as config_file_stream:
                    self.main_config = json.load(config_file_stream)
            except:

                self.logger_run.error("[PARSER][CONFIG] Error loading config : {}".format(traceback.format_exc()),
                                     header="ERROR", indentation=0)
                self.main_config = {
                    "restore": 0,
                    "rename_from_orc": 0,
                    "disk": 1,
                    "elk": 0,
                    "evtx": 1,
                    "hive": 1,
                    "mft": 1,
                    "mpp": 1,
                    "network": 1,
                    "lnk": 1,
                    "plaso": 1,
                    "prefetch": 1,
                    "process": 1,
                    "system_info": 1,
                    "webHistory": 1
                }
                self.logger_run.info("[PARSER][CONFIG] No config provided using embedded {}".format(json.dumps(self.main_config, indent=4)),
                                     header="INFO", indentation=0)

        self.plaso_storage_file = os.path.join(self.timeline_dir, "timeline.plaso")
        self.l2t_log_file = os.path.join(self.timeline_dir, "l2t.log.gz")
        self.psort_log_file = os.path.join(self.timeline_dir, "l2t.log.gz")
        self.timeline_json_path = os.path.join(self.timeline_dir, "timeline.json")
        self.timeline_csv_path = os.path.join(self.timeline_dir, "timeline.csv")

    def initialise_working_directories(self):
        """
            To create directories where the results will be written
        """
        try:
            os.makedirs(self.case_work_dir, exist_ok=True)
            os.makedirs(self.machine_working_folder_path, exist_ok=True)
            os.makedirs(self.extracted_main_dir, exist_ok=True)
            print("[CREATING FOLDER] {}".format(self.extracted_main_dir))
            os.makedirs(self.extracted_dir, exist_ok=True)
            os.makedirs(self.restored_path, exist_ok=True)
            print("[CREATING FOLDER] {}".format(self.parsed_dir))
            os.makedirs(self.parsed_dir, exist_ok=True)
            print("[CREATING FOLDER] {}".format(self.log_dir))
            os.makedirs(self.log_dir, exist_ok=True)

            os.makedirs(self.mft_dir, exist_ok=True)
            os.makedirs(self.evt_dir, exist_ok=True)
            os.makedirs(self.process_dir, exist_ok=True)
            os.makedirs(self.network_dir, exist_ok=True)
            os.makedirs(self.powershell_dir, exist_ok=True)
            os.makedirs(self.hive_dir, exist_ok=True)
            os.makedirs(self.timeline_dir, exist_ok=True)
            os.makedirs(self.txt_log_dir, exist_ok=True)
            os.makedirs(self.disk_dir, exist_ok=True)
            os.makedirs(self.result_parsed_dir, exist_ok=True)
            os.makedirs(self.lnk_dir, exist_ok=True)
            os.makedirs(self.orc_log_dir, exist_ok=True)
            os.makedirs(self.prefetch_dir, exist_ok=True)
            os.makedirs(self.other_dir, exist_ok=True)
            os.makedirs(self.scripts_dir, exist_ok=True)

        except:
            sys.stderr.write("\nfailed to initialises directories {}\n".format(traceback.format_exc()))

    def extract(self):
        """
         to extract orc archives
        :return:
        """
        extraction_successful = False
        try:
            extractor = OrcExtractor.OrcExtractor(self.logger_run, "infected")

            self.logger_run.info("[EXTRACTING] archives", header="START", indentation=0)

            cleaned_name_archive = self.clean_archive_name(r'__\d+$', self.path_to_archive)
            root, filename = os.path.split(cleaned_name_archive)  # /blabla/ - orc1.7z
            filename_wo_ext, file_ext = os.path.splitext(filename)  # /blabla/orc1

            if file_ext in [".7z", ".zip"]:
                self.logger_run.info("[EXTRACTING] {}".format(self.path_to_archive), header="START", indentation=1)
                extraction_successful = extractor.extract_recursively(file_ext, self.path_to_archive, self.extracted_dir)
            self.logger_run.info("[EXTRACTING] archives", header="FINISHED", indentation=0)
        except:
            self.logger_run.error("[EXTRACTING] archives {}".format(traceback.format_exc()), header="ERROR", indentation=0)

        if extraction_successful and self.is_orc:
            try:
                if self.main_config.get("restore", False):
                    restorer = OrcExtractor.ArtefactRestorer(self.extracted_dir, self.restored_path, self.logger_run)
                    restorer.run()
                else:
                    if self.main_config.get("rename_from_orc"):
                        renamer = OrcExtractor.ArtefactRenamer(self.extracted_dir, self.logger_run)
                        renamer.run()
                    else:
                        f_manager = FileManager.FileManager()
                        f_manager.rename_nested_folder(self.extracted_dir)
            except Exception as e:
                self.logger_run.error(f"Critical error while restoring : {e}\n{traceback.format_exc()}",
                             header="CRITICAL")
        else:
            self.logger_run.error("Restoration process failed.", header="ABORT")

    def clean_archive_name(self, pattern, og_name):
        new_name = re.sub(pattern, '', og_name)
        return new_name

    def search_and_mv_artefacts(self, l_file_to_search, out_dir):
        mngr = FileManager.FileManager()
        for f_patern in l_file_to_search:
            l_file = mngr.recursive_file_search(self.extracted_main_dir, f_patern)
            if l_file:
                for file in l_file:
                    mngr.move_file_to_dest(file, out_dir)

    def move_artefact_no_parsing(self):

        for artefact, list_pattern in self.artefact_config.get("orc",{}).items():
            self.search_and_mv_artefacts(list_pattern, self.orc_log_dir)

        for artefact, list_pattern in self.artefact_config.get("artefacts", {}).get("powershell", {}).items():
            self.search_and_mv_artefacts(list_pattern, self.powershell_dir)

        for artefact, list_pattern in self.artefact_config.get("artefacts", {}).get("system", {}).items():
            self.search_and_mv_artefacts(list_pattern, self.parsed_dir)

        all_file_to_search = []
        for k, v in self.artefact_config.get("artefacts", {}).get("network", {}).items():
            if type(v) == list:
                all_file_to_search.extend(v)
            elif type(v) == str:
                all_file_to_search.append(v)
        self.search_and_mv_artefacts(all_file_to_search, self.network_dir)

        all_file_to_search = []
        for k, v in self.artefact_config.get("artefacts", {}).get("process", {}).items():
            if type(v) == list:
                all_file_to_search.extend(v)
            elif type(v) == str:
                all_file_to_search.append(v)
        self.search_and_mv_artefacts(all_file_to_search, self.process_dir)

        all_file_to_search = []
        for k, v in self.artefact_config.get("artefacts", {}).get("disk", {}).items():
            if type(v) == list:
                all_file_to_search.extend(v)
            elif type(v) == str:
                all_file_to_search.append(v)
        self.search_and_mv_artefacts(all_file_to_search, self.disk_dir)

        all_file_to_search = []
        for k, v in self.artefact_config.get("artefacts", {}).get("others_text", {}).items():
            if type(v) == list:
                all_file_to_search.extend(v)
            elif type(v) == str:
                all_file_to_search.append(v)
        self.search_and_mv_artefacts(all_file_to_search, self.result_parsed_dir)

        all_file_to_search = []
        for k, v in self.artefact_config.get("artefacts", {}).get("scripts", {}).items():
            if type(v) == list:
                all_file_to_search.extend(v)
            elif type(v) == str:
                all_file_to_search.append(v)
        self.search_and_mv_artefacts(all_file_to_search, self.scripts_dir)

    def l2t(self):
        """
        To create a Timeline of all the files with Log2Timeline
        :return:
        """
        try:

            self.logger_run.info("[CREATING][LOG2TIMELINE]", header="START", indentation=2)
            tool_path = "log2timeline.py"
            my_cmd = ["{}".format(tool_path),
                      "--logfile", "{}".format(self.l2t_log_file),
                      "--storage-file", "{}".format(self.plaso_storage_file),
                      "{}".format(self.extracted_main_dir)]

            subprocess.run(my_cmd)
            self.logger_run.info("[CREATING][LOG2TIMELINE]", header="FINISHED", indentation=2)
        except:
            self.logger_run.error("[CREATING][LOG2TIMELINE] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=0)

    def psort(self):
        """
        To sort Log2timeline result file with plaso psort
        :return:
        """
        try:
            #  psort.py -w test.json -o json_line test_to_plaso.plaso
            self.logger_run.info("[PARSING][PSORT]", header="START", indentation=2)
            tool_path = "psort.py"
            my_cmd = ["{}".format(tool_path),
                      "-o", "json_line",
                      "--logfile", "{}".format(self.psort_log_file),
                      "-w",  "{}".format(self.timeline_json_path),
                      "{}".format(self.plaso_storage_file)
                      ]
            subprocess.run(my_cmd)
            self.logger_run.info("[PARSING][PSORT]", header="FINISHED", indentation=2)

            self.logger_run.info("[PARSING][PSORT] Sorting to CSV", header="START", indentation=2)
            my_cmd = ["{}".format(tool_path),
                      "-o", "l2tcsv",
                      "--logfile", "{}".format(self.psort_log_file),
                      "-w",  "{}".format(self.timeline_csv_path),
                      "{}".format(self.plaso_storage_file)
                      ]
            subprocess.run(my_cmd)
            self.logger_run.info("[PARSING][PSORT] Sorting to CSV", header="FINISHED", indentation=2)
        except:
            self.logger_run.error("[PARSING][PSORT] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=2)

    def convert_evtx_to_json(self):
        """
        to Launch evtdump for converting evtx file to json files
        :return:
        """
        try:
            self.logger_run.info("[TOOLING][EVTXDUMP]", header="START", indentation=2)
            evtx_f_pattern = self.artefact_config.get("artefacts", {}).get("event_logs", {}).get("evtx", [])
            if evtx_f_pattern and isinstance(evtx_f_pattern, list):
                mngr = FileManager.FileManager()
                for pattern in evtx_f_pattern:
                    all_evt = mngr.recursive_file_search(self.extracted_main_dir, pattern)
                    if all_evt:
                        for evt in all_evt:
                            try:
                                evt_name = os.path.basename(evt)
                                evt_name_wo_ext = os.path.splitext(evt_name)[0]
                                evt_json_name = evt_name_wo_ext + ".evtx.json"
                                self.logger_run.info("[TOOLING][EVTXDUMP] Converting {} to json".format(evt_name_wo_ext),
                                                     header="START", indentation=3)

                                out_file = os.path.join(self.evt_dir, evt_json_name)
                                my_cmd = ["{}".format(self.evtx_dump_path), "{}".format(evt)]
                                with open(out_file, "w") as outfile:
                                    subprocess.run(my_cmd, stdout=outfile)

                                self.logger_run.info("[TOOLING][EVTXDUMP] Converting {} to json".format(evt_name_wo_ext),
                                                     header="FINISHED", indentation=3)

                            except:
                                self.logger_run.error("[TOOLING][EVTXDUMP] Converting {} to json: {}"
                                                      .format(evt_name_wo_ext, traceback.format_exc()),
                                                     header="FAILED", indentation=3)

            self.logger_run.info("[TOOLING][EVTXDUMP]", header="FINISHED", indentation=2)
        except:
            self.logger_run.error(
                "[TOOLING][EVTXDUMP] {}".format( traceback.format_exc()), header="ERROR", indentation=2)

    def convert_mft_to_json(self):
        """
        To parse mft file with analyse mft and parse it to human readble format (|DATE|TIME|ETC|ETC)
        :return:
        """
        try:
            self.logger_run.info("[TOOLING][ANALYZEMFT]", header="START", indentation=2)
            mft_result_file = os.path.join(self.mft_dir, "mft.json")
            mngr = FileManager.FileManager()

            mft_patterns = self.artefact_config.get("artefacts", {}).get("master_file_table", {}).get("MFT", [])
            if mft_patterns and isinstance(mft_patterns, list):
                for mft_pattern in mft_patterns:
                    mft_files = mngr.recursive_file_search(self.extracted_main_dir, mft_pattern)
                    if mft_files:
                        for mft_file in mft_files:
                            my_cmd = ["python3", "{}".format(self.analyze_mft_tool_path),
                                      "-f", "{}".format(mft_file),
                                      "-o", "{}".format(mft_result_file),
                                      "--json",
                                      "--verbose",
                                      "--debug"]
                            subprocess.run(my_cmd)

                        self.logger_run.info("[TOOLING][ANALYZEMFT]", header="FINISHED", indentation=2)
                        return mft_result_file
            else:
                self.logger_run.info("[TOOLING][ANALYZEMFT] No MFT File found", header="FAILED", indentation=2)
                return None
        except:
            self.logger_run.error(
                "[TOOLING][ANALYZEMFT] {}".format( traceback.format_exc()), header="ERROR", indentation=3)
            return None

    def convert_mft_to_csv(self):
        """
        To parse mft file with analyse mft and parse it to human readble format (|DATE|TIME|ETC|ETC)
        :return:
        """
        try:
            self.logger_run.info("[TOOLING][ANALYZEMFT]", header="START", indentation=2)
            mft_result_file = os.path.join(self.mft_dir, "mft.timeline")
            mngr = FileManager.FileManager()

            mft_patterns = self.artefact_config.get("artefacts", {}).get("master_file_table", {}).get("MFT", [])
            if mft_patterns and isinstance(mft_patterns, list):
                for mft_pattern in mft_patterns:
                    mft_files = mngr.recursive_file_search(self.extracted_main_dir, mft_pattern)
                    if mft_files:
                        for mft_file in mft_files:
                            my_cmd = ["python3", "{}".format(self.analyze_mft_tool_path),
                                      "-f", "{}".format(mft_file),
                                      "-o", "{}".format(mft_result_file),
                                      "--timeline",
                                      "--verbose",
                                      "--debug"]
                            subprocess.run(my_cmd)

                        self.logger_run.info("[TOOLING][ANALYZEMFT]", header="FINISHED", indentation=2)
                        return mft_result_file
            else:
                self.logger_run.info("[TOOLING][ANALYZEMFT] No MFT File found", header="FAILED", indentation=2)
                return None
        except:
            self.logger_run.error(
                "[TOOLING][ANALYZEMFT] {}".format( traceback.format_exc()), header="ERROR", indentation=3)
            return None

    def clean_duplicate_in_file(self, file):
        """
        Remove duplicated line in file
        Args:
        file (str): path to file to be cleaned
        """
        seen_lines = set()
        l_temp = []
        with open(file, 'r') as f:
            for line in f:
                if line not in seen_lines:
                    seen_lines.add(line)
                    l_temp.append(line)

        with open(file, 'w') as f:
            f.writelines(l_temp)

    def clean_duplicates(self, dir_to_clean):

        """
        To clean duplicates line in file
        :return:
        """
        try:
            self.logger_run.info("[CLEAN DUPLICATE]", header="START", indentation=1)
            mngr = FileManager.FileManager()
            l_file = mngr.list_files_recursive(dir_to_clean, "*")
            for file in l_file:
                self.logger_run.info(f"[CLEAN DUPLICATE] Cleaning {file}", header="FINISH", indentation=1)
                self.clean_duplicate_in_file(file)
            self.logger_run.info("[CLEAN DUPLICATE]", header="FINISH", indentation=1)
        except:
            self.logger_run.error("[CLEAN DUPLICATE] {}".format(traceback.format_exc()), header="ERROR", indentation=1)

    def create_timeline(self):
        """
        Gathers data from all parsed CSVs, adds the source filename, sorts them by
        the first column (timestamp), and writes to a single timeline.csv file.
        """
        timeline_entries = []
        mngr = FileManager.FileManager()

        SOURCE_FILE_COLUMN_INDEX = 2
        final_header = None

        source_files = mngr.list_files_recursive(self.result_parsed_dir, "*.csv")
        for file_path in source_files:
            if file_path.name == "small_timeline.csv":
                continue

            try:
                with file_path.open('r', newline='', encoding='utf-8') as f:
                    reader = csv.reader(f, delimiter='|')
                    try:
                        header = next(reader)
                        if final_header is None:
                            final_header = header[:]  # Make a copy
                            final_header.insert(SOURCE_FILE_COLUMN_INDEX, 'SourceFile')
                    except StopIteration:
                        self.logger_run.info(f"[CREATING][TIMELINE] Skipping empty file {file_path}", header="INFO", indentation=3)
                        continue

                    for row in reader:
                        if not row:
                            continue

                        row.insert(SOURCE_FILE_COLUMN_INDEX, file_path.stem)
                        timeline_entries.append(row)

            except csv.Error as e:
                self.logger_run.error("[CREATING][TIMELINE] Bad CSV", header="FAILED", indentation=3)
            except IOError as e:
                self.logger_run.error(f"[CREATING][TIMELINE] Could not read file {file_path}: {e}", header="FAILED", indentation=3)
            except Exception:
                self.logger_run.error(f"[CREATING][TIMELINE] An unexpected error occurred with file {file_path}: {traceback.format_exc()}", header="FAILED", indentation=3)

        if not timeline_entries:
            self.logger_run.info("[CREATING][TIMELINE] Not CSV entry found, skipping", header="INFO", indentation=3)
            return

        try:
            sorted_timeline = sorted(timeline_entries, key=lambda x: x[0])
        except IndexError:
            sorted_timeline = sorted(timeline_entries)  # Fallback to a simple sort

        timeline_path = os.path.join(self.result_parsed_dir, "small_timeline.csv")

        try:
            with open(timeline_path,'w', newline='', encoding='utf-8') as tl:
                writer = csv.writer(tl, delimiter='|')
                if final_header:
                    writer.writerow(final_header)
                writer.writerows(sorted_timeline)

        except IOError as e:
            self.logger_run.error(f"[CREATING][TIMELINE] Could not write file {timeline_path}: {e}", header="FAILED",
                                  indentation=3)

    def do_system_info(self):
        try:
            self.logger_run.info("[PARSING][SYSTEMINFO]", header="START", indentation=1)
            s_parser = SystemInfoParser.SystemInfoParser(self.logger_run)
            self.system_info = s_parser.parse_all(self.extracted_main_dir, self.result_parsed_dir)
            self.logger_run.info("[PARSING][SYSTEMINFO]", header="FINISHED", indentation=1)

            if self.system_info and self.system_info[0].get("Nom d'hôte", ""):
                self.machine_name = self.system_info[0].get("Nom d'hôte", "")
                self.logger_run.info("Machine Name found : {}".format(self.machine_name), header="INFO", indentation=0)
        except Exception as ex:
            self.logger_run.error("[PARSING][SYSTEMINFO] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=0)

    def do_network(self):
        self.logger_run.info("[PARSING][NETWORK]", header="START", indentation=1)
        n_parser = NetWorkParser.NetWorkParser(self.logger_run)
        n_parser.parse_all(self.network_dir, self.result_parsed_dir )
        self.logger_run.info("[PARSING][NETWORK]", header="FINISHED", indentation=1)

    def do_process(self):
        self.logger_run.info("[PARSING][PROCESS]", header="START", indentation=1)
        p_parser = ProcessParser.ProcessParser(self.logger_run)
        p_parser.parse_all(self.process_dir, self.result_parsed_dir)
        self.logger_run.info("[PARSING][PROCESS]", header="FINISHED", indentation=1)

    def do_disk(self):
        """
        To parse USN journal to human readble format (|DATE|TIME|ETC|ETC)
        :return:
        """
        try:
            self.logger_run.info("[PARSING][USNJRNL]", header="START", indentation=1)

            mngr = FileManager.FileManager()
            d_parser = DiskParser.DiskParser(self.logger_run)
            usn_paterns = self.artefact_config.get("artefacts", {}).get("disk", {}).get("usn_journal")

            for usn_patern in usn_paterns:
                usn_files = mngr.recursive_file_search(self.parsed_dir, usn_patern)
                for usn_file in usn_files:
                    d_parser.parse_usnjrnl(usn_file, self.result_parsed_dir)

            self.logger_run.info("[PARSING][USNJRNL]", header="FINISHED", indentation=1)

        except:
            self.logger_run.error("[CREATING][USNJRNL] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=1)

    def do_hive(self):

        self.logger_run.info("[PARSING][HIVES]", header="START", indentation=1)
        h_parser = RegistryParser.RegistryParser(self.logger_run)
        h_parser.parse_amcache_regpy(self.extracted_main_dir, self.result_parsed_dir)
        h_parser.parse_all_hives_yarp(self.extracted_main_dir, self.result_parsed_dir)
        self.logger_run.info("[PARSING][HIVES]", header="FINISHED", indentation=1)

    def do_lnk(self):
        """
        To convert all LNK file to json and parse them to a human friendly format : DATE|TIME|ETC|ETC
        :return:
        """
        try:

            self.logger_run.info("[PARSING][LNK]", header="START", indentation=1)
            lnk_parser = Linkparser.LinkParser(self.logger_run, self.lnk_dir, self.result_parsed_dir)
            mngr = FileManager.FileManager()

            lnk_paterns = self.artefact_config.get("artefacts", {}).get("files", {}).get("lnk", "")
            for lnk_patern in lnk_paterns:
                lnk_files = mngr.recursive_file_search(self.extracted_main_dir, lnk_patern)
                for lnk_file in lnk_files:
                    try:
                        lnk_name = os.path.basename(lnk_file)
                        lnk_name_wo_ext = os.path.splitext(lnk_name)[0]
                        lnk_parser.parse_lnk_to_json(lnk_file)
                    except:
                        self.logger_run.error("[PARSING][LNK] {} {}".format(lnk_name, traceback.format_exc()),
                                              header="ERROR",
                                              indentation=2)

            self.logger_run.info("[PARSING][LNK]", header="FINISHED", indentation=1)

        except:
            self.logger_run.error("[PARSING][LNK] {}".format(traceback.format_exc()),  header="ERROR",
                                  indentation=1)

    def do_prefetch(self, is_volume=False, is_json=True):
        """
        To parse pf files to the human readable format Date|Time|ID|ETC
        :return:
        """
        try:
            output = {}
            pf_re = re.compile(r'.*.pf$')
            self.logger_run.info("[PARSING][PREFETCH]", header="START", indentation=1)
            mngr = FileManager.FileManager()
            pf_parser = PrefetchParser.PrefetchParser(self.logger_run)
            prefetch_final_file = os.path.join(self.result_parsed_dir, "prefetchs.csv")

            l_pf_files = mngr.recursive_file_search(self.extracted_main_dir, pf_re)
            if l_pf_files:
                for pf_file in l_pf_files:
                    root, pf_file_name = os.path.split(pf_file)
                    output = pf_parser.parse_file(pf_file, is_volume)
                    if output:
                        pf_out_file_json = os.path.join(self.prefetch_dir, "{}.json".format(pf_file_name))
                        pf_parser.outputResults(output, prefetch_final_file)
                        pf_parser.outputResults(output, pf_out_file_json, True)
            else:
                self.logger_run.info("[NO][PREFECTH]", header="FOUND", indentation=1)

            self.logger_run.info("[PARSING][PREFECTH]", header="FINISHED", indentation=2)
        except:
            self.logger_run.error("[PARSING][PREFECTH] {}".format(traceback.format_exc()),
                                  header="PREFECTH", indentation=1)

    def do_plaso(self):
        self.logger_run.info("[TOOLING][PLASO]", header="START", indentation=1)
        self.l2t()
        self.psort()
        self.logger_run.info("[TOOLING][PLASO]", header="FINISHED", indentation=1)

    def do_maximum_plaso_parser(self):
        """
        Launch Maximum plaso parser, a parser for json plaso timeline that convert a timeline to lot of differents
        artefacts files formated in human friendly format : DATE|TIME|ETC|ETC
        :return:
        """
        try:
            self.logger_run.info("[MAXIMUMPLASOPARSER]", header="START", indentation=1)
            mp = MaximumPlasoParserJson.MaximumPlasoParser(path_to_timeline=self.timeline_json_path,
                                                           output_directory=self.parsed_dir,
                                                           output_type="csv",
                                                           separator=self.separator,
                                                           case_name=self.case_name,
                                                           config_file=None,
                                                           machine_name=self.machine_name)

            mp.parse_timeline()
            self.logger_run.info("[MAXIMUMPLASOPARSER]", header="FINISHED", indentation=1)
        except:
            self.logger_run.error("[MAXIMUMPLASOPARSER] {}".format(traceback.format_exc()), header="ERROR", indentation=1)

    def do_mft_json(self):
        """
        Launch the converting and parsing of mft
        :return:
        """
        try:
            self.logger_run.info("[PARSING][MFT]", header="START", indentation=1)
            mft_result_file = self.convert_mft_to_json()
            if mft_result_file:
                d_parser = DiskParser.DiskParser(self.logger_run)
                d_parser.parse_mft_json(mft_result_file, self.result_parsed_dir)
            self.logger_run.info("[PARSING][MFT]", header="FINISHED", indentation=1)
        except:
            self.logger_run.error("[PARSING][MFT] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=1)

    def do_mft_csv(self):
        """
        Launch the converting and parsing of mft
        :return:
        """
        try:
            self.logger_run.info("[PARSING][MFT]", header="START", indentation=1)
            mft_result_file = self.convert_mft_to_csv()

            if mft_result_file:
                d_parser = DiskParser.DiskParser(self.logger_run)
                d_parser.parse_plaso_csv(mft_result_file, self.result_parsed_dir)
            self.logger_run.info("[PARSING][MFT]", header="FINISHED", indentation=1)
        except:
            self.logger_run.error("[PARSING][MFT] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=1)

    def do_evtx(self):
        """
        Launch the converting and parsing of evtx
        :return:
        """
        try:
            self.logger_run.info("[PARSING][EVTX]", header="START", indentation=1)
            self.convert_evtx_to_json()
            e_parser = EventParser.EventParser(self.evt_dir, self.result_parsed_dir)
            e_parser.parse_all()
            self.logger_run.info("[PARSING][EVTX]", header="FINISHED", indentation=1)
        except:
            self.logger_run.error("[PARSING][EVTX] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=1)

    def do_elk(self):
        p_agent = plaso2Elk.PlasoToELK(self.logger_run, self.timeline_json_path, self.case_name, self.machine_name)
        if p_agent.test_connection():
            p_agent.send_to_elk_in_bulk()
        else:
            self.logger_run.error("[CONNECTING][ELK] aboarding", header="ERROR", indentation=1)

    def do_web_history(self):
        w_parser = WebHistoryParser.HistoryExporter(self.logger_run, self.extracted_main_dir,
                                                    os.path.join(self.result_parsed_dir, "web_history.csv"))
        w_parser.run()

    def do(self):
        self.extract()

        self.move_artefact_no_parsing()
        self.logger_run.info("[PARSING][ARTEFACTS]", header="START", indentation=0)

        if self.main_config.get("system_info", False):
            self.do_system_info()
        if self.main_config.get("evtx", False):
            self.do_evtx()
        if self.main_config.get("network", False):
            self.do_network()
        if self.main_config.get("process", False):
            self.do_process()
        if self.main_config.get("webHistory", False):
            self.do_web_history()
        if self.main_config.get("lnk", False):
            self.do_lnk()
        if self.main_config.get("prefetch", False):
            self.do_prefetch()
        if self.main_config.get("hive", False):
            self.do_hive()
        if self.main_config.get("mft", False):
            self.do_mft_json() # not using csv cause analysemft fail inside docker...
        if self.main_config.get("disk", False):
            self.do_disk()

        self.clean_duplicates(self.result_parsed_dir)
        self.create_timeline()

        if self.main_config.get("plaso", False):
            self.do_plaso()
            if self.main_config.get("mpp", False):
                self.do_maximum_plaso_parser()
            if self.main_config.get("elk", False):
                self.do_elk()

        self.logger_run.info("[PARSING][ARTEFACTS]", header="FINISHED", indentation=0)

def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Solution to parse DFIR-Orc archives'))


    argument_parser.add_argument('-a', '--archive', action="store",
                                 required=False, dest="archive", default=False,
                                 help="path to the orc archive")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")

    argument_parser.add_argument("-c", "--casename", action="store",
                                 required=True, dest="case_name", default=None,
                                 help="name of the case u working on")

    argument_parser.add_argument("-s", "--separator", action="store",
                                 required=False, dest="separator", default="|",
                                 help="separator that will be used on csv files")

    argument_parser.add_argument("-m", "--machine_name", action="store",
                                 required=False, dest="machine_name",
                                 metavar="name of the machine",
                                 help="name of the machine")


    return argument_parser

if __name__ == '__main__':

    parser = parse_args()
    args = parser.parse_args()

    start_time = time.time()
    now = datetime.now()  # current date and time
    date_time = now.strftime("%m/%d/%Y, %H:%M:%S")

    print("Started at {}:".format(date_time))

    if args.archive:
        mp = WindowsForensicArtefactParser(args.archive, args.output_dir, args.case_name, args.machine_name)
        WindowsForensicArtefactParser(path_to_archive=args.archive,
                                      output_directory=args.output_dir,
                                      case_name=args.case_name,
                                      machine_name=args.machine_name,
                                      separator="|",
                                      main_id=None,
                                      artefact_config=None,
                                      main_config=None)
        mp.do()

    else:
        print(parser.print_help())
        exit(1)

    time_in_sec = time.time() - start_time
    print("Finished in {} ".format(timedelta(seconds=time_in_sec)))



"""
Info for further parsing
location": "Microsoft-Windows-Windows Defender%4WHC.evtx
event id 1116 1117 1015 1013 1014 1012 1011 1010 1009 1008 1007 1006 1005 1004 1003 1002   
4614 This event is generated when a user attempts to change their password. It is logged on domain controllers 
and member computers. 
"""

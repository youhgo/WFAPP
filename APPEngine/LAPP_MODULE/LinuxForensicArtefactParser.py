#!/usr/bin/python3
import argparse
from datetime import datetime
import os
import sys
import traceback
from .classes import LoggerManager, Extractor

class LinuxForensicArtefactParser:
    """
       Class WindowsForensicArtefactParser
       MPP or WindowsForensicArtefactParser is a python script that will parse a plaso - Log2Timeline json timeline file.
       The goal is to provide easily readable and straight forward files for the Forensic analyst.
       MPP will create a file for each artefact.
       Attributes :
       None
    """

    def __init__(self, path_to_archive, output_directory, case_name, machine_name="", separator='|',
                 main_id="") -> None:
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

        if machine_name:
            self.machine_name = machine_name
        else:
            self.machine_name = "no_name"

        if main_id:
            self.main_id = main_id
        else:
            self.main_id = self.machine_name


        self.current_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        self.machine_working_folder_name = self.machine_name + "_" + self.current_date
        self.case_work_dir = os.path.join(self.dir_out, self.case_name)
        self.log_dir = os.path.join(self.dir_out, "execution_logs")
        self.machine_working_folder_path = os.path.join(self.case_work_dir, self.machine_working_folder_name)
        self.extracted_main_dir = os.path.join(self.machine_working_folder_path, "extracted")
        self.parsed_dir = os.path.join(self.machine_working_folder_path, "parsed")
        self.timeline_dir = os.path.join(self.parsed_dir, "timeline")
        self.initialise_working_directories()

        self.running_log_file_path = os.path.join(self.log_dir, "{}_running.log".format(self.main_id))
        self.logger_run = LoggerManager.LoggerManager("running", self.running_log_file_path, "INFO")

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
            os.makedirs(self.parsed_dir, exist_ok=True)
            os.makedirs(self.log_dir, exist_ok=True)
            os.makedirs(self.timeline_dir, exist_ok=True)

        except:
            sys.stderr.write("\nfailed to initialises directories {}\n".format(traceback.format_exc()))

    def extract(self):
        """
         to extract orc archives
        :return:
        """
        extraction_successful = False
        try:
            extractor = Extractor.ArchiveExtractor(self.path_to_archive)

            self.logger_run.info("[EXTRACTING] archives", header="START", indentation=0)

            root, filename = os.path.split(self.extracted_main_dir)  # /blabla/ - orc1.7z
            filename_wo_ext, file_ext = os.path.splitext(filename)  # /blabla/orc1

            if file_ext in ["tar.gz"]:
                self.logger_run.info("[EXTRACTING] {}".format(self.path_to_archive), header="START", indentation=1)
                extraction_successful = extractor.run(self.path_to_archive)
            self.logger_run.info("[EXTRACTING] archives", header="FINISHED", indentation=0)
        except:
            self.logger_run.error("[EXTRACTING] archives {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=0)


    def do(self):
        self.extract()

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



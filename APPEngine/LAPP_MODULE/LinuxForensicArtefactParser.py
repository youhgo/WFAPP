#!/usr/bin/python3
import argparse
import time
from datetime import datetime, timedelta
import os
import sys
import traceback

# Imports des classes métiers
from .classes.LappContext import LappContext
from .classes.Extractor import ArchiveExtractor
from .modules.dispatcher import ArtefactDispatcher

class LinuxForensicArtefactParser:
    """Orchestrateur Principal de LAPP."""

    def __init__(self, path_to_archive, output_directory, case_name, is_uac=True, machine_name="", separator='|',
                 main_id="", artefact_config=None, main_config=None) -> None:

        self.ascii_art_lapp = r"""
            ██╗       █████╗  ██████╗ ██████╗ 
            ██║      ██╔══██╗ ██╔══██╗██╔══██╗
            ██║      ███████║ ██████╔╝██████╔╝
            ██║      ██╔══██║ ██╔═══╝ ██╔═══╝ 
            ███████╗ ██║  ██║ ██║     ██║     
            ╚══════╝   ╚═╝  ╚═╝ ╚═╝     ╚═╝     
    
            Linux Forensic Artefact Parser Project
            """

        print(self.ascii_art_lapp)
        self.is_uac = is_uac

            # Initialisation du contexte global (qui gère l'arborescence et les configs)
        self.ctx = LappContext(path_to_archive, output_directory, case_name, machine_name, separator, main_id,
                                   artefact_config, main_config)
        self.logger = self.ctx.logger


    def extract(self):
        extraction_successful = False
        try:
            # Utilisation de l'extracteur générique
            extractor = ArchiveExtractor(str(self.ctx.extracted_main_dir), self.logger)
            self.logger.info("[EXTRACTING] archives", header="START")

            archive_path = str(self.ctx.path_to_archive)
            self.logger.info("[EXTRACTING] Got Archive {}".format(archive_path), header="INFO")

            # La méthode run() de l'extracteur se charge du nettoyage de nom et de la récursivité
            self.logger.info("[EXTRACTING] {}".format(archive_path), header="START")
            extractor.run(archive_path)
            
            extraction_successful = True
            self.logger.info("[EXTRACTING] archives", header="FINISHED")
        except Exception as e:
            self.logger.error("[EXTRACTING] Error: {}".format(e), header="ERROR")

        if not extraction_successful:
            exit(1)


    def do_wazuh(self):
        self.logger.info("[LAPP][WAZUH]", header="START", indentation=1)
        # TODO: Pipeline Wazuh
        self.logger.info("[LAPP][WAZUH] Pipeline à développer...", header="INFO", indentation=1)
        self.logger.info("[LAPP][WAZUH]", header="FINISHED", indentation=1)

    def do(self):
        """Le Chef d'Orchestre principal."""
        
        # 1. Extraction de l'archive
        self.extract()

        dispatcher = ArtefactDispatcher(self.ctx)
        dispatcher.run_discovery(self.ctx.extracted_main_dir)

        if self.ctx.main_config.get("wazuh", False):
            self.do_wazuh()
            
        self.logger.info("[LAPP] Fin de l'exécution.", header="FINISHED")


def parse_args():
    argument_parser = argparse.ArgumentParser(description='Solution to parse UAC/Linux archives')
    argument_parser.add_argument('-a', '--archive', action="store", required=False, dest="archive", default=False,
                                 help="path to the linux archive")
    argument_parser.add_argument("-o", "--output", action="store", required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")
    argument_parser.add_argument("-c", "--casename", action="store", required=True, dest="case_name", default=None,
                                 help="name of the case u working on")
    argument_parser.add_argument("-s", "--separator", action="store", required=False, dest="separator", default="|",
                                 help="separator that will be used on csv files")
    argument_parser.add_argument("-m", "--machine_name", action="store", required=False, dest="machine_name",
                                 metavar="name of the machine", help="name of the machine")
    return argument_parser


if __name__ == '__main__':
    parser = parse_args()
    args = parser.parse_args()

    start_time = time.time()
    now = datetime.now()
    print("Started at {}:".format(now.strftime('%m/%d/%Y, %H:%M:%S')))

    if args.archive:
        app = LinuxForensicArtefactParser(
            path_to_archive=args.archive,
            output_directory=args.output_dir,
            case_name=args.case_name,
            machine_name=args.machine_name,
            separator=args.separator
        )
        app.do()
    else:
        print(parser.print_help())
        exit(1)

    time_in_sec = time.time() - start_time
    print("Finished in {} ".format(timedelta(seconds=time_in_sec)))
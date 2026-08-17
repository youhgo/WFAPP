#!/usr/bin/python3
import argparse
import csv
from datetime import datetime, timedelta
import os
import re
import subprocess
import sys
import time
import traceback
from pathlib import Path
import json

# Imports des classes métiers

from .classes.WappContext import WappContext

# Import du dispatcher dynamique
from .classes.dispatcher import ArtefactDispatcher
from .classes.PreProcessorDispatcher import PreProcessorDispatcher
from .classes.PostProcessorDispatcher import PostProcessorDispatcher

# Imports des parsers et outils externes
from .parsers import MaximumPlasoParserJson
from .utils.plaso2ELK import plaso_2_siem, plaso_to_wazuh


try:
    import pyscca  # Import pyscca, necessary from libscca
except ImportError:
    print("Please install libscca with Python bindings")


class WindowsForensicArtefactParser:
    """Orchestrateur Principal de WAPP."""

    def __init__(self, path_to_archive, output_directory, case_name, is_orc=True, machine_name="", separator='|',
                 main_id="", artefact_config=None, main_config=None) -> None:
        self.ascii_art_dopp = r"""
        ███████╗    ██████═╗ ██████╗ ██████╗ 
        ██╔════██╗██╔═════██╗██╔══██╗██╔══██
        ██║    ██║██║     ██║██║███ ║██║███
        ██║    ██║██║     ██║██║    ║██║
        ███████╔╝╚║═╝██████╔████╗══╗████║
        ╚══════╝  ╚═════╝  ╚════╝  ╚════╝ 

        DFIR ORC Parser Project
        """
        self.ascii_art_wapp = r"""
        ██╗    ██╗  █████╗  ██████╗ ██████╗ 
        ██║    ██║ ██╔══██╗ ██╔══██╗██╔══██╗
        ██║ █╗ ██║ ███████║ ██████╔╝██████╔╝
        ██║███╗██║ ██╔══██║ ██╔═══╝ ██╔═══╝ 
        ╚███╔███╔╝ ██║  ██║ ██║     ██║     
         ╚══╝╚══╝  ╚═╝  ╚═╝ ╚═╝     ╚═╝     

        Windows Forensic Artefact Parser Project
        """

        print(self.ascii_art_wapp)
        self.is_orc = is_orc

        # Initialisation du contexte global
        self.ctx = WappContext(path_to_archive, output_directory, case_name, machine_name, separator, main_id,
                               artefact_config, main_config)
        self.logger = self.ctx.logger

        # Fichiers Plaso (post-processing)
        self.plaso_storage_file = self.ctx.timeline_dir / "timeline.plaso"
        self.l2t_log_file = self.ctx.timeline_dir / "l2t.log.gz"
        self.psort_log_file = self.ctx.timeline_dir / "psort.log.gz"
        self.timeline_json_path = self.ctx.timeline_dir / "timeline.json"
        self.timeline_csv_path = self.ctx.timeline_dir / "timeline.csv"




    def do(self):
        """Le Chef d'Orchestre principal."""
        
        # 1. Exécution des plugins de Pré-Traitement (Extraction, Restauration, Renommage, etc.)
        pre_dispatcher = PreProcessorDispatcher(self.ctx)
        pre_dispatcher.run()

        # 2. Lancement du Dispatcher (Inventaire et parsing dynamique O(N))
        dispatcher = ArtefactDispatcher(self.ctx)
        dispatcher.run_discovery(self.ctx.extracted_main_dir)

        # 3. Exécution des plugins de Post-Traitement (Nettoyage, Timeline, Plaso, ELK, Wazuh, etc.)
        post_dispatcher = PostProcessorDispatcher(self.ctx)
        post_dispatcher.run()

        self.logger.info("[WAPP] Fin de l'exécution.", header="FINISHED")


def parse_args():
    argument_parser = argparse.ArgumentParser(description='Solution to parse DFIR-Orc archives')
    argument_parser.add_argument('-a', '--archive', action="store", required=False, dest="archive", default=False,
                                 help="path to the orc archive")
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
    print(f"Started at {now.strftime('%m/%d/%Y, %H:%M:%S')}:")

    if args.archive:
        app = WindowsForensicArtefactParser(
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
    print(f"Finished in {timedelta(seconds=time_in_sec)} ")
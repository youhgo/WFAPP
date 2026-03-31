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
from .classes.OrcExtractor import OrcExtractor, ArtefactRestorer
from .classes.OrcRenamer import OrcRenamer
from .classes.WappContext import WappContext

# Import du dispatcher dynamique
from .modules.dispatcher import ArtefactDispatcher

# Imports des parsers et outils externes
from .parsers import MaximumPlasoParserJson
from .outils.plaso2ELK import plaso_2_siem, plaso_to_wazuh
from .outils.wapp2Elk import App_2_wazuh, App_2_elk


try:
    import pyscca  # Import pyscca, necessary from libscca
except ImportError:
    print("Please install libscca with Python bindings")


class WindowsForensicArtefactParser:
    """Orchestrateur Principal de WAPP."""

    def __init__(self, path_to_archive, output_directory, case_name, is_orc=True, machine_name="", separator='|',
                 main_id="", artefact_config=None, main_config=None) -> None:
        self.ascii_art_wapp = r"""
        ███████╗    ██████═╗ ██████╗ ██████╗ 
        ██╔════██╗██╔═════██╗██╔══██╗██╔══██
        ██║    ██║██║     ██║██║███ ║██║███
        ██║    ██║██║     ██║██║    ║██║
        ███████╔╝╚║═╝██████╔████╗══╗████║
        ╚══════╝  ╚═════╝  ╚════╝  ╚════╝ 

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

    def extract(self):
        extraction_successful = False
        try:
            extractor = OrcExtractor(self.logger, "avproof")
            self.logger.info("[EXTRACTING] archives", header="START")
            cleaned_name_archive = re.sub(r'__\d+$', '', str(self.ctx.path_to_archive))
            file_ext = os.path.splitext(cleaned_name_archive)[1]

            if file_ext in [".7z", ".zip"]:
                extraction_successful = extractor.extract_recursively(file_ext, str(self.ctx.path_to_archive),
                                                                      str(self.ctx.extracted_dir))
            self.logger.info("[EXTRACTING] archives", header="FINISHED")
        except Exception as e:
            self.logger.error(f"[EXTRACTING] Error: {e}", header="ERROR")

        if extraction_successful and self.is_orc:
            try:
                # Si restauration de l'arborescence (Virtual FileSystem) demandée
                if self.ctx.main_config.get("restore", False):
                    restorer = ArtefactRestorer(str(self.ctx.extracted_dir), str(self.ctx.restored_path), self.logger)
                    restorer.run()
                else:
                    # NOUVELLE LOGIQUE : Renommage intelligent via GetThis.csv
                    renamer = OrcRenamer(self.ctx)
                    renamer.rename_files(self.ctx.extracted_dir)
            except Exception as e:
                self.logger.error(f"Critical error while post-processing extraction : {e}", header="CRITICAL")

    def clean_duplicates(self, dir_to_clean):
        self.logger.info("[CLEAN DUPLICATE] Démarrage", header="START")
        try:
            for file in Path(dir_to_clean).rglob("*"):
                if file.is_file():
                    seen_lines = set()
                    l_temp = []
                    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if line not in seen_lines:
                                seen_lines.add(line)
                                l_temp.append(line)
                    with open(file, 'w', encoding='utf-8') as f:
                        f.writelines(l_temp)
            self.logger.info("[CLEAN DUPLICATE] Terminé", header="FINISHED")
        except Exception as e:
            self.logger.error(f"[CLEAN DUPLICATE] Erreur: {e}", header="ERROR")

    def create_timeline(self):
        self.logger.info("[CREATING][TIMELINE]", header="START")
        timeline_entries = []
        final_header = None
        SOURCE_FILE_COLUMN_INDEX = 2

        for file_path in self.ctx.result_parsed_dir.rglob("*.csv"):
            if file_path.name == "small_timeline.csv": continue
            try:
                with file_path.open('r', newline='', encoding='utf-8') as f:
                    reader = csv.reader(f, delimiter='|')
                    try:
                        header = next(reader)
                        if final_header is None:
                            final_header = header[:]
                            final_header.insert(SOURCE_FILE_COLUMN_INDEX, 'SourceFile')
                    except StopIteration:
                        continue
                    for row in reader:
                        if not row: continue
                        row.insert(SOURCE_FILE_COLUMN_INDEX, file_path.stem)
                        timeline_entries.append(row)
            except Exception:
                pass

        if timeline_entries:
            try:
                sorted_timeline = sorted(timeline_entries, key=lambda x: x[0])
            except IndexError:
                sorted_timeline = sorted(timeline_entries)

            timeline_path = self.ctx.result_parsed_dir / "small_timeline.csv"
            with open(timeline_path, 'w', newline='', encoding='utf-8') as tl:
                writer = csv.writer(tl, delimiter='|')
                if final_header: writer.writerow(final_header)
                writer.writerows(sorted_timeline)
        self.logger.info("[CREATING][TIMELINE]", header="FINISHED")

    # --- Plaso, ELK, Wazuh ---
    def do_plaso(self):
        self.logger.info("[TOOLING][PLASO] Log2Timeline", header="START")
        try:
            subprocess.run(
                ["log2timeline.py", "--logfile", str(self.l2t_log_file), "--storage-file", str(self.plaso_storage_file),
                 str(self.ctx.extracted_main_dir)])
            self.logger.info("[PARSING][PSORT] to JSON", header="START")
            subprocess.run(["psort.py", "-o", "json_line", "--logfile", str(self.psort_log_file), "-w",
                            str(self.timeline_json_path), str(self.plaso_storage_file)])
            subprocess.run(
                ["psort.py", "-o", "l2tcsv", "--logfile", str(self.psort_log_file), "-w", str(self.timeline_csv_path),
                 str(self.plaso_storage_file)])
        except Exception as e:
            self.logger.error(f"[TOOLING][PLASO] Erreur: {e}", header="ERROR")

    def do_maximum_plaso_parser(self):
        """
        Launch Maximum plaso parser, a parser for json plaso timeline that convert a timeline to lot of differents
        artefacts files formated in human friendly format : DATE|TIME|ETC|ETC
        """
        try:
            self.logger.info("[MAXIMUMPLASOPARSER]", header="START", indentation=1)
            # Correction: Retrait du mp.parse_timeline(), on instancie et on appelle proprement
            parser = MaximumPlasoParserJson.MaximumPlasoParser(
                path_to_timeline=str(self.ctx.timeline_json_path),
                output_directory=str(self.ctx.parsed_dir),
                separator=self.ctx.separator,
                machine_name=self.ctx.machine_name
            )
            parser.parse_timeline()
            self.logger.info("[MAXIMUMPLASOPARSER]", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error("[MAXIMUMPLASOPARSER] {}".format(traceback.format_exc()), header="ERROR", indentation=1)

    def do_plaso2elk(self):
        try:
            es_host = f"{os.getenv('ELK_HOST', 'localhost')}:{os.getenv('ELK_PORT', '9200')}"
            verify_ssl = str(os.getenv('ES_VERIFYSSL', '0')).lower() in ['1', 'true', 'yes']

            self.logger.info("[PLASO][ELK]", header="START", indentation=1)
            self.logger.info(
                f"[PLASO][ELK] param are: {self.ctx.case_name}|{self.ctx.machine_name}|{self.ctx.timeline_json_path}|{es_host}|{os.getenv('ELK_USER')}|xxxxxx|{os.getenv('ES_CHUNKSIZE')}|{verify_ssl}|{os.getenv('ES_TIMEOUT')}|{os.getenv('ES_NBTHREAD')}|{os.getenv('ES_MODE')}",
                header="START", indentation=1)

            # Correction: Ajout de .ctx pour les variables globales et valeurs par défaut pour les getenv()
            p_agent = plaso_2_siem.PlasoPipeline(
                case_name=self.ctx.case_name,
                machine_name=self.ctx.machine_name,
                timeline_path=str(self.ctx.timeline_json_path),
                es_hosts=es_host,
                es_user=os.getenv('ELK_USER', ''),
                es_pass=os.getenv('ELK_PASSWD', ''),
                chunk_size=int(os.getenv('ES_CHUNKSIZE', '500')),
                verify_ssl=verify_ssl,
                es_timeout=int(os.getenv('ES_TIMEOUT', '60')),
                thread_count=int(os.getenv('ES_NBTHREAD', '4')),
                mode=os.getenv('ES_MODE', 'wapp')
            )
            p_agent.run()
            self.logger.info("[PLASO][ELK]", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PLASO][ELK] aborting, ERROR: {traceback.format_exc()}", header="ERROR", indentation=1)

    def do_elk(self, artifact_types="all"):
        try:
            es_host = f"{os.getenv('ELK_HOST', 'localhost')}:{os.getenv('ELK_PORT', '9200')}"
            verify_ssl = str(os.getenv('ES_VERIFYSSL', '0')).lower() in ['1', 'true', 'yes']

            self.logger.info("[WAPP][ELK]", header="START", indentation=1)

            # Correction: Ajout de .ctx et cast de l'output en chaine de caractère
            pipeline = App_2_elk.ElkForensicPipeline(
                case_name=self.ctx.case_name,
                machine_name=self.ctx.machine_name,
                source_dir=str(self.ctx.result_parsed_dir),
                es_hosts=es_host,
                es_user=os.getenv('ELK_USER', ''),
                es_pass=os.getenv('ELK_PASSWD', ''),
                chunk_size=int(os.getenv('ES_CHUNKSIZE', '500')),
                verify_ssl=verify_ssl,
                artifact_types=artifact_types
            )
            pipeline.run()
            self.logger.info("[WAPP][ELK]", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[WAPP][ELK] aborting, ERROR: {traceback.format_exc()}", header="ERROR", indentation=1)

    def do_plaso2wazuh(self):
        try:
            wazuh_host = f"{os.getenv('WAZUH_HOST', 'localhost')}:{os.getenv('WAZUH_PORT', '9200')}"
            verify_ssl = str(os.getenv('WAZUH_VERIFYSSL', '0')).lower() in ['1', 'true', 'yes']

            self.logger.info("[PLASO][WAZUH]", header="START", indentation=1)

            # Ajout de valeurs par défaut sur les int() pour éviter les erreurs NoneType
            p_agent = plaso_to_wazuh.PlasoPipeline(
                case_name=self.ctx.case_name,
                machine_name=self.ctx.machine_name,
                timeline_path=str(self.ctx.timeline_json_path),
                es_hosts=wazuh_host,
                es_user=os.getenv('WAZUH_USER', ''),
                es_pass=os.getenv('WAZUH_PASSWD', ''),
                chunk_size=int(os.getenv('WAZUH_CHUNKSIZE', '500')),
                verify_ssl=verify_ssl,
                es_timeout=int(os.getenv('WAZUH_TIMEOUT', '60')),
                thread_count=int(os.getenv('WAZUH_NBTHREAD', '4')),
                mode=os.getenv('WAZUH_MODE', 'wapp')
            )
            p_agent.run()
            self.logger.info("[PLASO][WAZUH]", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PLASO][WAZUH] aborting, ERROR: {traceback.format_exc()}", header="ERROR",
                              indentation=1)

    def do_wazuh(self):
        try:
            es_host = f"{os.getenv('WAZUH_HOST')}:{os.getenv('WAZUH_PORT')}"
            verify_ssl = os.getenv('WAZUH_VERIFYSSL', '0').lower() in ['1', 'true', 'yes']
            self.logger.info("[WAPP][WAZUH] Envoi des données WAPP vers Wazuh", header="START", indentation=1)
            pipeline = App_2_wazuh.ForensicPipeline(
                case_name = self.ctx.case_name,
                machine_name = self.ctx.machine_name,
                es_hosts = es_host,
                es_user = os.getenv('WAZUH_USER', ''),
                es_pass = os.getenv('WAZUH_PASSWD', ''),
                chunk_size = int(os.getenv('WAZUH_CHUNKSIZE')),
                verify_ssl = verify_ssl,
                artifact_types =  "all",
                es_timeout = int(os.getenv('WAZUH_TIMEOUT')),
                thread_count = int(os.getenv('WAZUH_NBTHREAD')),
                mode = os.getenv('WAZUH_MODE'),
                source_dir = str(self.ctx.result_parsed_dir),
                config_file = self.ctx.wazuh_importer_file_config
            )

            pipeline.run()

            self.logger.info("[WAPP][WAZUH] Succès", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[WAPP][WAZUH] Erreur: {e}", header="ERROR", indentation=1)


    def do(self):
        """Le Chef d'Orchestre principal."""
        # 1. Extraction de l'archive et Pré-Processing (Renommage ou Restauration)
        self.extract()

        # 2. Lancement du Dispatcher (Inventaire et parsing dynamique O(N))
        dispatcher = ArtefactDispatcher(self.ctx)
        dispatcher.run_discovery(self.ctx.extracted_main_dir)

        # 3. Post-Processing de l'environnement WAPP (Nettoyage & Timeline globale)
        self.clean_duplicates(
            self.ctx.result_parsed_dir)
        self.create_timeline()

        if self.ctx.main_config.get("elk", False):
            self.do_elk("all")
        if self.ctx.main_config.get("wazuh", False):
            self.do_wazuh()
        if self.ctx.main_config.get("plaso", False):
            self.do_plaso()
            if self.ctx.main_config.get("mpp", False):
                self.do_maximum_plaso_parser()
            if self.ctx.main_config.get("plaso2elk", False):
                self.do_plaso2elk()
            if self.ctx.main_config.get("plaso2wazuh", False):
                self.do_plaso2wazuh()

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
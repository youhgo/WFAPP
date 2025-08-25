#!/usr/bin/python3
import argparse
import csv
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk  # Added import for the bulk helper
import json
import logging
import LnkParse3
import os
import pathlib
from pathlib import Path
import py7zr
import re
from regipy.registry import RegistryHive
from regipy.plugins.utils import run_relevant_plugins
import shutil
import subprocess
import sys
import time
import traceback
from typing import Dict, List, Any
import xmltodict
from yarp import * # must be install from github : https://github.com/msuhanov/yarp/releases
import zipfile
# Try importing pyscca; fail if it doesn't import
try:
    import pyscca #Import pyscca, necessary from libscca
except ImportError:
    print("Please install libscca with Python bindings")


# TODO : Parsing
# TODO : Parse Log erasure
# TODO : Add proper config manegment
# TODO : General
# TODO : Parse Task Scheduler event 4698 + 4702
# TODO : Config to choose what parser to use


class LoggerManager:
    """
    Class to manage logging, based on Python's `logging` module.
    """

    # Using an internal class to group headers
    class Headers:
        START = "[START]"
        STOP = "[STOP]"
        FINISHED = "[FINISHED]"
        SUCCESS = "[SUCCESS]"
        FAILED = "[FAILED]"
        INFO = "[INFO]"
        PARSING = "[PARSING]"
        WARNING = "[WARNING]"
        ERROR = "[ERROR]"

        @staticmethod
        def get(name):
            return getattr(LoggerManager.Headers, name.upper(), "")

    def __init__(self, logger_name: str, log_file_path: str, level: str = "INFO"):
        """
        Constructor for the LoggerManager class.

        Args:
            logger_name (str): Name of the logger.
            log_file_path (str): Path to the log file.
            level (str, optional): Logging level. Defaults to "INFO".
        """
        self.logLevel = getattr(logging, level.upper(), logging.INFO)
        self.logger_name = logger_name
        self.log_file_path = pathlib.Path(log_file_path)  # Convert to a Path object
        self.my_logger = self._initialise_logging()

        # Add a method to handle all message types
        self.log = self._generic_log

    def _initialise_logging(self) -> logging.Logger:
        """
        Function to initialize the logger object.
        This is an internal method (convention _), as it should not be called directly.
        """
        logger = logging.getLogger(self.logger_name)

        try:
            logger.setLevel(self.logLevel)
            formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')

            # Handler for the console
            stdout_handler = logging.StreamHandler(sys.stderr)
            stdout_handler.setFormatter(formatter)
            stdout_handler.setLevel(self.logLevel)
            logger.addHandler(stdout_handler)

            # --- FIX: Create a stream handler using an explicitly opened file ---
            try:
                # Ensure the parent directory exists
                self.log_file_path.parent.mkdir(parents=True, exist_ok=True)

                file_handler = logging.FileHandler(self.log_file_path)
                file_handler.setFormatter(formatter)
                file_handler.setLevel(self.logLevel)
                logger.addHandler(file_handler)

            except Exception as e:
                # If there's an issue with the file, log a clear error to the console
                # but don't stop the application
                sys.stderr.write(f"\n[ERROR] Failed to set up file logging: {e}\n")

            return logger
        except Exception:
            sys.stderr.write(f"\nErreur lors de l'initialisation du logger:\n{traceback.format_exc()}\n")
            raise

    def get_logger(self) -> logging.Logger:
        """
        Returns the logger object.
        """
        return self.my_logger

    def _generic_log(self, msg: str, level: str = "info", header_type: str = "INFO", indentation: int = 0):
        """
        Generic method to log messages uniformly.
        """
        header = self.Headers.get(header_type)
        indent = "-" * (indentation * 2) if indentation > 0 else ""
        formatted_message = "{}>{} {}".format(indent, header, msg)

        log_method = getattr(self.my_logger, level.lower(), self.my_logger.info)
        log_method(formatted_message)

    def info(self, msg: str, header: str = "INFO", indentation: int = 0):
        self._generic_log(msg, level="info", header_type=header, indentation=indentation)

    def warning(self, msg: str, header: str = "WARNING", indentation: int = 0):
        self._generic_log(msg, level="warning", header_type=header, indentation=indentation)

    def error(self, msg: str, header: str = "FAILED", indentation: int = 0):
        self._generic_log(msg, level="error", header_type=header, indentation=indentation)

    def debug(self, msg: str, header: str = "DEBUG", indentation: int = 0):
        self._generic_log(msg, level="debug", header_type=header, indentation=indentation)

class OrcExtractor:
    """
       Class to Extract archives
    """

    def __init__(self, logger) -> None:
        """
        The constructor for OrcExtractor class.
        """
        self.logger_run = logger

    def extract_7z(self, zipped_file, to_folder, password='infected'):
        try:
            self.logger_run.info("[EXTRACTING] {}".format(zipped_file), header="START", indentation=2)
            with py7zr.SevenZipFile(zipped_file, mode='r', password=password) as z:
                z.extractall(path=to_folder)

            self.logger_run.info("[EXTRACTING] {}".format(zipped_file), header="FINISHED", indentation=2)

        except py7zr.Bad7zFile:
            self.logger_run.error(
                "[EXTRACTING] '{}' is not a valid 7z archive or is corrupted.".format(zipped_file),
                header="ERROR",
                indentation=2)

        except FileNotFoundError:
            pass
        except OSError as e:
            if e.errno == 36:  # Errno 36 corresponds to 'File name too long'
                self.logger_run.error(
                    "[EXTRACTING] Error: File name too long. {} could not be extracted.".format(
                        str(e).split(':', 1)[-1][-100:]),
                    header="ERROR",
                    indentation=2)

            else:
                self.logger_run.error(
                    "[EXTRACTING] Unexpectd ERROR '{}' ".format(traceback.format_exc()),
                    header="ERROR",
                    indentation=2)

        except:
            self.logger_run.error(
                "[EXTRACTING] Unexpectd ERROR '{}' ".format(traceback.format_exc()),
                header="ERROR",
                indentation=2)

    def extract_zip(self, zipped_file, to_folder, password='infected'):
        """Extrait tous les fichiers d'une archive ZIP dans un répertoire spécifié.

        Args:
          zipped_file: Chemin vers le fichier ZIP.
          to_folder: Chemin du répertoire de destination.
        """
        try:
            with zipfile.ZipFile(zipped_file, 'r') as zip_ref:
                zip_ref.extractall(to_folder)
        except FileNotFoundError:
            pass
            ''' Ignore for now
            self.logger_run.error(
                "[EXTRACTING] '{}' Wasnt found".format(zipped_file),
                header="ERROR",
                indentation=2)
            '''


    def extract_and_create_dir_name(self, zipped_file):
        """ Unzip a zip file
        """
        try:
            root, filename = os.path.split(zipped_file)  # /blabla/ - orc1.7z
            filename_wo_ext, file_ext = os.path.splitext(filename)  # /blabla/orc1
            new_path_out = os.path.join(root, filename_wo_ext)  # /blabla/orc1
            os.makedirs(new_path_out, exist_ok=True)
            if file_ext == ".7z":
                self.extract_7z(zipped_file, new_path_out)
            if file_ext == ".zip":
                self.extract_zip(zipped_file, new_path_out)

        except FileNotFoundError:
            pass
        except:
            self.logger_run.error(
                "[EXTRACTING] Unexpectd ERROR '{}' ".format(traceback.format_exc()),
                header="ERROR",
                indentation=2)

    def extract_nested_7zip(self, zipped_file, to_folder):
        """ Unzip a zip file and its contents, including nested zip files
            Delete the zip file(s) after extraction
        """
        try:
            self.extract_and_create_dir_name(zipped_file)
            os.remove(zipped_file)
            for root, dirs, files in os.walk(to_folder):
                for filename in files:
                    if re.search(r'\.7z$', filename):
                        file_spec = os.path.join(root, filename)
                        self.extract_nested_7zip(file_spec, root)
        except FileNotFoundError:
            pass
        except:
            self.logger_run.error(
                "[EXTRACTING] Unexpectd ERROR '{}' ".format(traceback.format_exc()),
                header="ERROR",
                indentation=2)

    def extract_nested_zip(self, zipped_file, to_folder):
        """ Unzip a zip file and its contents, including nested zip files
            Delete the zip file(s) after extraction
        """
        try:
            self.extract_and_create_dir_name(zipped_file)
            os.remove(zipped_file)
            for root, dirs, files in os.walk(to_folder):
                for filename in files:
                    if re.search(r'\.zip$', filename):
                        file_spec = os.path.join(root, filename)
                        self.extract_nested_zip(file_spec, root)
        except FileNotFoundError:
            pass
        except:
            self.logger_run.error(
                "[EXTRACTING] Unexpectd ERROR '{}' ".format(traceback.format_exc()),
                header="ERROR",
                indentation=2)

    def extract_7z_archive(self, zipped_file, to_folder):
        """ Extract a zip file including nested zip files
            Delete the zip file(s) after extraction
        """
        try:
            self.extract_7z(zipped_file, to_folder)
            for root, dirs, files in os.walk(to_folder):
                for filename in files:
                    if re.search(r'\.7z$', filename):
                        file_spec = os.path.join(root, filename)
                        self.extract_nested_7zip(file_spec, root)
        except Exception as ex:
            self.logger_run.error(
                "[EXTRACTING] Unexpectd ERROR '{}' ".format(traceback.format_exc()),
                header="ERROR",
                indentation=2)

    def extract_zip_archive(self, zipped_file, to_folder):
        """ Extract a zip file including nested zip files
            Delete the zip file(s) after extraction
        """
        try:
            self.extract_zip(zipped_file, to_folder)
            for root, dirs, files in os.walk(to_folder):
                for filename in files:
                    if re.search(r'\.zip$', filename):
                        file_spec = os.path.join(root, filename)
                        self.extract_nested_zip(file_spec, root)
        except Exception as ex:
            self.logger_run.error(
                "[EXTRACTING] Unexpectd ERROR '{}' ".format(traceback.format_exc()),
                header="ERROR",
                indentation=2)

class FileManager:
    """
       Class to manage files
       Attributes :
       """

    def __init__(self, config="") -> None:
        """
        The constructor for FileManager class.
        Parameters:
        """
        if config:
            self.config = config

    def clean_filename(self, path_to_file):
        try:
            l_file_to_preserve = ["USNInfo", "NTFSInfo"]
            if os.path.exists(path_to_file):
                root, filename = os.path.split(path_to_file)
                if ".data" in filename or "_data" in filename:
                    for f in l_file_to_preserve:
                        if f in filename:
                            return
                    filename_wo_tail1 = re.sub(r'_\{.*\}.data$', '', filename)
                    filename_wo_tail2 = re.sub(r'\_data$', '', filename_wo_tail1)
                    filename_wo_head = re.sub(r'^(([a-zA-Z]|\d){0,30}_){0,3}', '', filename_wo_tail2)
                    final_name = os.path.join(root, filename_wo_head)
                    os.rename(path_to_file, final_name)
        except:
            print(traceback.format_exc())

    def rename_nested_folder(self, base_dir):
        try:
            for roots, dirs, files in os.walk(base_dir):
                for fileName in files:
                    file = os.path.join(roots, fileName)
                    self.clean_filename(file)
        except:
            print(traceback.format_exc())

    def find_files_n_recursive(self, path_in, ext):
        p = Path(path_in).glob(ext)
        return p

    def find_files_n_recursive_regex(self, path_in, regu_exp):
        res = []
        for f in os.listdir(path_in):
            if re.search(regu_exp, f):
                res.append(os.path.join(path_in, f))
        return res

    def find_files_recursive(self, path_in, ext):
        def_file_lift = []
        p = Path(path_in).rglob(ext)
        for item in p:
            if item.is_file():
                def_file_lift.append(item)
        return def_file_lift

    def list_files_recursive(self, folder_path):
        l_file = []
        path_folder = Path(folder_path)
        for item in path_folder.rglob('*'):
            if item.is_file():
                l_file.append(item)
        return l_file

    def delet_specific_files(self, file_name, folder_name):
        pass

    def move_file_to_dest(self, file, new_dest):
        if os.path.isfile(file):
            end_path = os.path.join(new_dest, os.path.basename(file))
            shutil.move(file, end_path)

    def copy_file_to_dest(self, file, new_dest):
        if os.path.isfile(file):
            end_path = os.path.join(new_dest, os.path.basename(file))
            shutil.copy(file, end_path)

    def copy_folder_to_dest(self, folder, new_dest):
        if os.path.isdir(folder):
            end_path = os.path.join(new_dest, os.path.basename(folder))
            shutil.copytree(folder, end_path)

    def search_and_move_multiple_file_to_dest_recurs(self, dir_to_search, pattern, new_dest):
        for file in self.find_files_recursive(dir_to_search, pattern):
            self.move_file_to_dest(file, new_dest)

    def search_and_move_multiple_file_to_dest_n_recurs(self, dir_to_search, pattern, new_dest):
        for file in self.find_files_n_recursive(dir_to_search, pattern):
            self.move_file_to_dest(file, new_dest)

    def search_and_copy_multiple_file_to_dest_recurs(self, dir_to_search, pattern, new_dest):
        for file in self.find_files_recursive(dir_to_search, pattern):
            self.copy_file_to_dest(file, new_dest)

    def search_and_copy_multiple_file_to_dest_n_recurs(self, dir_to_search, pattern, new_dest):

        for file in self.find_files_n_recursive(dir_to_search, pattern):
            self.copy_file_to_dest(file, new_dest)

    def recursive_file_search(self, dir, reg_ex):
        files = []
        for element in os.listdir(dir):
            full_path = os.path.join(dir, element)
            if os.path.isfile(full_path):
                if re.search(reg_ex, element):  # ,  re.IGNORECASE):
                    if full_path not in files:
                        files.append(full_path)
            elif os.path.isdir(full_path):
                files.extend(self.recursive_file_search(full_path, reg_ex))
        return files

    def search_and_copy_recurs(self, dir_to_search, destination, reg_ex):
        l_file = self.recursive_file_search(dir_to_search, reg_ex)
        for file in l_file:
            self.copy_file_to_dest(file, destination)

class NetWorkParser:
    """
       Class parse network files to human-readable csv DATE|TIME|ETC|ETC
    """

    def __init__(self, logger, artefact_config=None, separator="|") -> None:
        """
        The constructor for NetWorkParser class
        :param separator: str: csv separator default is pipe
        """
        self.logger_run = logger
        self.separator = separator
        if not artefact_config:
            self.artefact_config = {
                "netstat": r'netstat\.txt$',
                "tcpvcon": r'Tcpvcon\.txt$'
                }
        else:
            self.artefact_config = artefact_config

    def parse_tcpvcon(self, input_filepath, output_filepath):
        """
        Parses a classic CSV file, removes specified header/footer lines,
        removes duplicate lines, and rewrites unique entries to an output file
        with a specified output separator.

        :param input_filepath: str : Path to the input CSV file.
        :param output_filepath: str : Path to the desired output file.
        :return: None
        """
        unique_processed_lines = set()
        exclusion_strings = [
            "Sysinternals - www.sysinternals.com",
            "Copyright (C) 1996-2023 Mark Russinovich & Bryce Cogswell"
        ]

        header_list = ["Protocol", "Process", "PID", "State", "Local Addr", "Distant Addr"]
        try:
            with open(input_filepath, 'r', encoding='utf-8') as file_in:
                for line in file_in:
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue  # Skip entirely empty lines

                    should_exclude = False
                    for exclusion_str in exclusion_strings:
                        if exclusion_str in stripped_line:
                            should_exclude = True
                            break  # Found an exclusion string, no need to check others

                    if should_exclude:
                        continue

                    fields = [field.strip() for field in stripped_line.split(',')]
                    processed_line = self.separator.join(fields)
                    unique_processed_lines.add(processed_line)

            sorted_unique_lines = sorted(list(unique_processed_lines))

            with open(output_filepath, 'w', encoding='utf-8') as out_file:
                out_file.write("{}\n".format(self.separator.join(header_list)))
                for entry in sorted_unique_lines:
                    out_file.write("{}\n".format(entry))
            self.logger_run.info("[PARSING][TCPVCON]", header="FINISHED", indentation=2)


        except FileNotFoundError:
            self.logger_run.error(
                "[PARSING][TCPVCON]: File not found {}".format(input_filepath), header="ERROR",
                indentation=2)

        except UnicodeDecodeError as e:
            self.logger_run.error(
                "[PARSING][TCPVCON]: UnicodeDecodeError {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)
        except Exception as e:
            self.logger_run.error(
                "[PARSING][TCPVCON]:  {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

    def parse_netstat(self, input_filepath, output_filepath):
        """
        Reads network data from an input file, formats it into a CSV-like format
        with '|' as a separator, removing extra whitespace and duplicate lines,
        and writes to an output file.

        Args:
            input_filepath (str|path): The path to the input file containing netstat data.
            output_filepath (str): The path to the output file to write the formatted data.
        """
        try:
            unique_processed_lines = set()  # Use a set to automatically handle duplicates

            with open(input_filepath, 'r', encoding='utf-8', errors='ignore') as infile:
                for line in infile:
                    # Strip leading/trailing whitespace from the entire line
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue  # Skip empty lines

                    # Split the line by any whitespace and filter out empty strings
                    fields = [field.strip() for field in stripped_line.split()]

                    # Join the cleaned fields with the pipe separator
                    processed_line = "|".join(fields)
                    unique_processed_lines.add(processed_line)  # Add to the set

            # Convert the set back to a list and sort it for consistent output order
            sorted_output_lines = sorted(list(unique_processed_lines))

            with open(output_filepath, 'w', encoding='utf-8') as outfile:
                outfile.write("\n".join(sorted_output_lines))
            self.logger_run.info("[PARSING][NETSTAT]", header="FINISHED", indentation=2)

        except FileNotFoundError:
            self.logger_run.error(
                "[PARSING][NETSTAT]: File not found {}".format(input_filepath), header="ERROR",
                indentation=2)
        except Exception as e:
            self.logger_run.error(
                "[PARSING][NETSTAT]:  {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

    def parse_all(self, input_dir, output_dir):
        """
        Main function to parse networks files
        :param input_dir: str : dir where files to be parsed are located
        :param output_dir: str : dir where results files will be written
        :return:
        """

        netstats_files = self.recursive_file_search(input_dir, self.artefact_config.get("netstat", ""))
        if netstats_files:
            for netstat_file in netstats_files:
                self.logger_run.info("[PARSING][NETSTAT]", header="START", indentation=2)
                self.parse_netstat(netstat_file, os.path.join(output_dir, "netstat_parsed.csv"))

        tcpvcon_files = self.recursive_file_search(input_dir, self.artefact_config.get("tcpvcon", ""))
        if tcpvcon_files:
            for tcpvcon_file in tcpvcon_files:
                self.logger_run.info("[PARSING][TCPVCON]", header="START", indentation=2)
                self.parse_tcpvcon(tcpvcon_file, os.path.join(output_dir, "tcpvcon_parsed.csv"))

    def recursive_file_search(self, input_dir, reg_ex):
        files = []
        for element in os.listdir(input_dir):
            full_path = os.path.join(input_dir, element)
            if os.path.isfile(full_path):
                if re.search(reg_ex, element):  # ,  re.IGNORECASE):
                    if full_path not in files:
                        files.append(full_path)
            elif os.path.isdir(full_path):
                files.extend(self.recursive_file_search(full_path, reg_ex))
        return files

class ProcessParser:
    """
    Class to parsed various tool results files into straight forward human readble csv.
    (sysinternals Autoruns, DFIR-ORC PROCESS1, DFIR-ORC PROCESS2, DFIR-ORC PROCESS INFO, DFIR-ORC PROCESS_TIMELINE
    DFIR-ORC PROCESS_AUTORUNS)
    """

    def __init__(self, logger, artefact_config=None, separator="|") -> None:
        """
        The constructor for ProcessParser class
        :param separator: str: csv separator default is pipe
        :param artefact_config: dict: artefact config
        """
        self.logger_run = logger
        self.separator = separator
        if not artefact_config:
            self.artefact_config = {
                "process1": "processes1.csv",
                "process2": "processes2.csv",
                "autoruns": "autoruns.csv",
                "sample_autoruns": ["GetSamples_autoruns.xml", "Process_Autoruns.xml"],
                "sample_timeline": ["GetSamples_timeline.csv", "Process_timeline.csv"],
                "sample_info": ["GetSamples_sampleinfo.csv", "Process_sampleinfo.csv"]
                }
        else:
            self.artefact_config = artefact_config

    def parse_autoruns_sysinternals(self, input_filepath, output_dir):
        """
        Parses a UTF-16 encoded Autoruns CSV file.
        - Skips initial metadata/header lines.
        - Splits the 'Time' column (YYYYMMDD-HHmmSS) into 'YYYY-MM-DD' and 'HH-mm-SS'.
        - Extracts only 'Entry', 'Image Path', 'Launch String', and 'MD5' columns.
        - Removes duplicate rows.
        - Outputs to a new CSV with '|' as a separator and a custom header.

        :param input_filepath: str : Path to the input UTF-16 CSV file.
        :param output_dir: str : Path to the desired output file.
        :return: None
        """
        output_filepath  = os.path.join(output_dir, "autoruns_sysinternals_parsed.csv")
        # Lines to exclude at the very beginning of the file (metadata/headers)
        initial_exclusion_patterns = [
            r"Sysinternals",  # Catches "Sysinternals Autoruns v14.11 - Autostart program viewer"
            r"Copyright"  # Catches "Copyright (C) 2002-2024 Mark Russinovich"
        ]

        # Full header of the actual CSV data (for mapping column names to indices)
        full_input_header = [
            "Time", "Entry Location", "Entry", "Enabled", "Category", "Profile",
            "Description", "Signer", "Company", "Image Path", "Version",
            "Launch String", "MD5", "SHA-1", "PESHA-1", "PESHA-256", "SHA-256", "IMP"
        ]

        # Desired output header for the selected columns, with new 'Date' and 'Time'
        output_header = ["Date", "Time", "Entry", "Image Path", "Launch String", "MD5"]

        # Map column names to their indices based on the full_input_header
        column_indices = {name: full_input_header.index(name) for name in full_input_header}
        unique_processed_rows = set()

        try:
            with open(input_filepath, 'r', encoding='utf-16', newline='') as infile:
                for line in infile.readlines():
                    for exclude_pattern in initial_exclusion_patterns:
                        if re.match(exclude_pattern, line, re.IGNORECASE):
                            continue
                        else:
                            if line.strip():
                                l_line = line.split(",")
                                if len(l_line) < 14: #indice of md5
                                    # Log a warning or skip, depending on desired strictness
                                    self.logger_run.warning(
                                        "[PARSING] [AUTORUNS] : skipping malformed row due to insufficient fields, field = '{}'".format(
                                            line), header="WARNING", indentation=2)

                                    continue
                                else:
                                    raw_timestamp = l_line[column_indices["Time"]].strip()
                                    entry_val = l_line[column_indices["Entry"]].strip()
                                    imgpath_val = l_line[column_indices["Image Path"]].strip()
                                    launchstring_val = l_line[column_indices["Launch String"]].strip()
                                    md5_val = l_line[column_indices["MD5"]].strip()
                                    formatted_date = ""
                                    formatted_time = ""

                                    if len(raw_timestamp) == 15 and raw_timestamp[8] == '-':  # YYYYMMDD-HHmmSS
                                        formatted_date = "{}-{}-{}".format(raw_timestamp[0:4], raw_timestamp[4:6],
                                                                           raw_timestamp[6:8])
                                        formatted_time = "{}:{}:{}".format(raw_timestamp[9:11], raw_timestamp[11:13],
                                                                           raw_timestamp[13:15])
                                    else:
                                        self.logger_run.warning(
                                            "[PARSING] [AUTORUNS]:Timestamp format unexpected for '{}'. Using raw value.".format(
                                            raw_timestamp), header="WARNING", indentation=2)

                                        # Handle cases where timestamp might not match expected format
                                        formatted_date = raw_timestamp  # Fallback to original
                                        formatted_time = ""  # No time if cannot parse

                                    unique_processed_rows.add(
                                        "{}|{}|{}|{}|{}|{}".format(formatted_date, formatted_time, entry_val,
                                                                   imgpath_val, launchstring_val, md5_val))

            # Sort unique rows for consistent output
            sorted_unique_lines = sorted(list(unique_processed_rows))

            # Write to output file
            with open(output_filepath, 'w', encoding='utf-8', newline='') as outfile:
                outfile.write("{}\n".format(self.separator.join(output_header)))
                for entry in sorted_unique_lines:
                    outfile.write("{}\n".format(entry))
            self.logger_run.info("[PARSING][AUTORUNS]", header="FINISHED", indentation=2)

        except FileNotFoundError:
            self.logger_run.error(
                "[PARSING][AUTORUNS]: File not found {}".format(input_filepath), header="ERROR",
                indentation=2)
        except UnicodeDecodeError as e:
            self.logger_run.error(
                "[PARSING][AUTORUNS]: UnicodeDecodeError {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

        except Exception as e:
            self.logger_run.error(
                "[PARSING][AUTORUNS]: Unexpected error {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

    def parse_process1(self, input_file, output_dir, is_simplified=False):
        full_input_header = ["PSComputerName","ProcessName","Handles","VM","WS","Path","__GENUS","__CLASS",
                             "__SUPERCLASS","__DYNASTY","__RELPATH","__PROPERTY_COUNT","__DERIVATION","__SERVER",
                             "__NAMESPACE","__PATH","Caption","CommandLine","CreationClassName","CreationDate",
                             "CSCreationClassName","CSName","Description","ExecutablePath","ExecutionState",
                             "Handle","HandleCount","InstallDate","KernelModeTime","MaximumWorkingSetSize",
                             "MinimumWorkingSetSize","Name","OSCreationClassName","OSName","OtherOperationCount",
                             "OtherTransferCount","PageFaults","PageFileUsage","ParentProcessId","PeakPageFileUsage",
                             "PeakVirtualSize","PeakWorkingSetSize","Priority","PrivatePageCount","ProcessId",
                             "QuotaNonPagedPoolUsage","QuotaPagedPoolUsage","QuotaPeakNonPagedPoolUsage",
                             "QuotaPeakPagedPoolUsage","ReadOperationCount","ReadTransferCount","SessionId","Status",
                             "TerminationDate","ThreadCount","UserModeTime","VirtualSize","WindowsVersion",
                             "WorkingSetSize","WriteOperationCount","WriteTransferCount"]

        tree = self.extract_tree_from_process(input_file, full_input_header)
        out_file = os.path.join(output_dir, "process1_parsed.csv")
        out_file_simple = os.path.join(output_dir, "process1_simplified.csv")
        try:
            if is_simplified:
                with open(out_file_simple, 'w', encoding='utf-8') as outfile:
                    self.print_process_tree(tree, is_simplified=True, output_stream=outfile)

            with open(out_file, 'w', encoding='utf-8') as outfile:
                self.print_process_tree(tree, is_simplified=False, output_stream=outfile)

            self.logger_run.info("[PARSING][PROCESS1]", header="FINISHED", indentation=2)

        except Exception as e:
            self.logger_run.error(
                "[PARSING][PROCESS1]: unexpected Error {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

    def extract_tree_from_process(self, file_path, full_input_header):
        """
        Parse the output of DFIR-ORC process1 cmd  to a straight forward human readable csv file
        :param file_path: path of the process result file
        :param full_input_header: csv header from process result file
        :return:
        """


        # Desired output header for the selected columns, with new 'Date' and 'Time'
        output_header = ["ProcessId", "ParentProcessId", "ProcessName","ExecutablePath", "CommandLine", "CreationDate",
                         "InstallDate"]

        # Map column names to their indices based on the full_input_header
        column_indices = {name: full_input_header.index(name) for name in full_input_header}

        processes = {}

        with open(file_path, "r") as process:
            csv_reader = csv.reader(process, delimiter=",")
            next(csv_reader)
            for line in csv_reader:
                if line:
                    ProcessId = line[column_indices["ProcessId"]].strip()
                    ParentProcessId = line[column_indices["ParentProcessId"]].strip()
                    ProcessName = line[column_indices["ProcessName"]].strip()
                    if not ProcessName:
                        ProcessName = line[column_indices["Name"]].strip()
                    ExecutablePath = line[column_indices["ExecutablePath"]].strip()
                    if not ExecutablePath:
                        ExecutablePath = line[column_indices["Path"]].strip()
                    CommandLine = line[column_indices["CommandLine"]].strip()
                    CreationDate = self.format_wmi_timestamp(line[column_indices["CreationDate"]].strip())
                    InstallDate = self.format_wmi_timestamp(line[column_indices["InstallDate"]].strip())

                    res = {
                        "ProcessId": ProcessId,
                        "ParentProcessId": ParentProcessId,
                        "ProcessName": ProcessName,
                        "ExecutablePath": ExecutablePath,
                        "CreationDate": CreationDate,
                        "InstallDate": InstallDate,
                        "CommandLine": CommandLine,
                        "Children" : []
                    }
                    if not processes.get(ProcessId):
                        processes[ProcessId] = res
                    else:
                        self.logger_run.print_warning_failed_sub_2("[PARSING] Process1 PID {} already exist".format(ProcessId))

        # --- Build the tree structure ---
        # Identify processes that are children and link them to their parents
        # Identify root processes (those whose parent is 0 or not found in data)
        root_pids = []

        for pid, process_info in processes.items():
            parent_pid = process_info["ParentProcessId"]

            # If parent_pid is 0 (often system root) or parent not found in our data
            if parent_pid == 0 or parent_pid not in processes:
                root_pids.append(pid)
            else:
                # Link current process to its parent's children list
                processes[parent_pid]["Children"].append(pid)

        for pid in processes:
            processes[pid]["Children"].sort()

        return {
            "processes": processes,
            "roots": sorted(root_pids)  # Sort root PIDs for consistent output
        }

    def print_process_tree(self, tree_data: dict, is_simplified=False, output_stream=None, indent_char="----",
                           indent_char_pid="════",
                           current_pid=None, level=0):
        """
        Recursively prints the process tree in a human-readable indented format.

        Args:
            tree_data: The dictionary returned by build_process_tree.
            output_stream: Where to print (default is sys.stdout). Can be a file object.
            indent_char: Character(s) to use for indentation.
            indent_char_pid: Character(s) to use for Pip indentation.
            current_pid: Internal: The PID of the current node being printed (for recursion).
            level: Internal: Current indentation level.
            is_simplified: Bool: set to True to remove cmd from output
        """
        if not output_stream:
            import sys
            output_stream = sys.stdout

        processes = tree_data.get("processes", {})
        roots = tree_data.get("roots", [])

        if not processes:
            output_stream.write("No process data to display.\n")
            return

        if current_pid is None:  # Start recursion from root processes
            for root_pid in roots:
                if is_simplified:
                    self._print_process_node_simplified(processes, output_stream, indent_char, indent_char_pid,
                                                        root_pid, level)
                else:
                    self._print_process_node(processes, output_stream, indent_char, indent_char_pid, root_pid, level)
        else:  # Recursive call for children
            if is_simplified:
                self._print_process_node_simplified(processes, output_stream, indent_char, indent_char_pid, current_pid,
                                                    level)
            else:
                self._print_process_node(processes, output_stream, indent_char, indent_char_pid, current_pid, level)

    def _print_process_node(self, processes, output_stream, indent_char, indent_char_pid, pid, level):
        """Helper to print a single process node and its children."""
        if pid not in processes:
            return

        process = processes[pid]
        indent = indent_char * level
        indent_pid = indent_char_pid * level

        output_stream.write("{}>({}) {} (Parent: {})\n".format(indent_pid, process['ProcessId'],process['ProcessName'], process['ParentProcessId']))
        output_stream.write("{}{}>[CREATED]: {}\n".format(indent, indent_char, process['CreationDate']))
        output_stream.write("{}{}>[PATH]: {}\n".format(indent, indent_char, process['ExecutablePath']))

        if process['CommandLine']:

            output_stream.write("{}{}>[CMD]: {}\n".format(indent, indent_char, process['CommandLine']))

        # Recursively print children
        for child_pid in process['Children']:
            self._print_process_node(processes, output_stream, indent_char, indent_char_pid, child_pid, level + 1)

    def _print_process_node_simplified(self, processes, output_stream, indent_char, indent_char_pid, pid, level):
        """Helper to print a single process node and its children."""
        if pid not in processes:
            return

        process = processes[pid]
        indent_pid = indent_char_pid * level
        output_stream.write("{}>({}) {} (Parent: {}) | [CREATED]: {} | [PATH]: {}\n".format(indent_pid,
                                                                                           process['ProcessId'],
                                                                                           process['ProcessName'],
                                                                                           process['ParentProcessId'],
                                                                                           process['CreationDate'],
                                                                                           process['ExecutablePath']))

        # Recursively print children
        for child_pid in process['Children']:
            self._print_process_node_simplified(processes, output_stream, indent_char, indent_char_pid, child_pid,
                                                level + 1)

    def format_wmi_timestamp(self, wmi_timestamp_str: str) -> str:
        """
        Formats a WMI timestamp string (YYYYMMDDHHmmSS.ffffff+UUU or YYYYMMDD-HHmmSS.ffffff+UUU)
        into a YYYY-MM-DD-HH:mm:SS format.

        Args:
            wmi_timestamp_str: The input WMI timestamp string.

        Returns:
            The formatted timestamp string, or the original string if parsing fails
            or if the input is too short.
        """
        # Check if the string is empty or too short to contain the core datetime part
        if not wmi_timestamp_str or len(wmi_timestamp_str) < 14:
            return wmi_timestamp_str

        # Define the desired output format
        output_format = "%Y-%m-%d|%H:%M:%S"

        # Define the possible input formats for datetime.strptime, ordered by preference or likelihood
        possible_input_formats = [
            "%Y%m%d%H%M%S",  # Standard format YYYYMMDDHHmmSS
            "%Y%m%d-%H%M%S"  # Format with hyphen YYYYMMDD-HHmmSS
        ]

        for input_format in possible_input_formats:
            # Determine the length of the part to extract based on the current format
            # YYYYMMDDHHmmSS is 14 chars, YYYYMMDD-HHmmSS is 15 chars
            if input_format == "%Y%m%d%H%M%S":
                datetime_part_len = 14
            elif input_format == "%Y%m%d-%H%M%S":
                datetime_part_len = 15
            else:
                continue # Should not happen with the defined formats

            if len(wmi_timestamp_str) < datetime_part_len:
                continue # Skip if string is too short for this specific format

            datetime_part = wmi_timestamp_str[:datetime_part_len]

            try:
                # Parse the string into a datetime object
                dt_object = datetime.strptime(datetime_part, input_format)
                # If parsing is successful, format and return immediately
                return dt_object.strftime(output_format)
            except ValueError:
                # If parsing fails for this format, try the next one
                continue # Go to the next format in the loop

        # If none of the formats worked, log a warning and return the original string
        self.logger_run.warning(
            "[PARSING][TIMESTAMP]: Could not parse timestamp '{}' with any known format. Returning original string.".format(
                wmi_timestamp_str), header="WARNING", indentation=3)

        return wmi_timestamp_str

    def parse_process_infos(self, file_path, output_dir, output_delimiter='|'):
        """
        Parse the output of DFIR-ORC GetSample_info  to a straight forward human readable csv file
        :param file_path: path of the GetSample__info result file
        :return:
        """
        out_file = os.path.join(output_dir, "process_sampleinfo_parsed.csv")
        self.convert_csv_separator(file_path, out_file, output_delimiter)
        self.logger_run.info("[PARSING][PROCESS_INFO]", header="FINISHED", indentation=2)

    def parse_process_timeline(self, file_path, output_dir, output_delimiter='|'):
        """
        Parse the output of DFIR-ORC GetSample_info  to a straight forward human readable csv file
        :param file_path: path of the GetSample__info result file
        :return:
        """
        out_file = os.path.join(output_dir, "process_timeline_parsed.csv")
        self.convert_csv_separator(file_path, out_file, output_delimiter)
        self.logger_run.info("[PARSING][PROCESS_TIMELINE]", header="FINISHED", indentation=2)

    def parse_process2(self, file_path, output_dir, output_delimiter='|'):
        """
        Parse the output of DFIR-ORC GetSample_info  to a straight forward human readable csv file
        :param file_path: path of the GetSample__info result file
        :return:
        """
        out_file = os.path.join(output_dir, "process2_parsed.csv")
        self.convert_csv_separator(file_path, out_file, output_delimiter)
        self.logger_run.info("[PARSING][PROCESS2]", header="FINISHED", indentation=2)

    def convert_csv_separator(self, in_file, out_file, output_delimiter):
        with open(in_file, "r") as process:
            reader = csv.reader(process, delimiter=",")
            header = next(reader)
            with open(out_file, 'w', encoding='utf-8', newline='') as outfile:
                writer = csv.writer(outfile, delimiter=output_delimiter, quoting=csv.QUOTE_MINIMAL)
                writer.writerow(header)
                for row in reader:
                    writer.writerow(row)

    def parse_process_autoruns(self, file_path, output_dir):
        """
        Parse the output of DFIR-ORC GetSample_autoruns  to a straight forward human readable csv file
        :param file_path: path of the GetSample_autoruns result file
        :param output_dir: path of the output directory for results
        :return:
        """

        res = set()
        with open(file_path, 'r') as autorun_file:
            file_as_json = xmltodict.parse(autorun_file.read())
            for key, values in file_as_json.items():
                for key1, values1 in values.items():  # value 1 is list
                    for item in values1:
                        date_time = self.format_wmi_timestamp(item.get("time", "-"))
                        launchstr = item.get("launchstring", "-")
                        path = item.get("imagepath", "-")
                        hash = item.get("md5hash", "-")

                        res.add("{}{}{}{}{}{}{}".format(date_time,
                                                        self.separator, path,
                                                        self.separator, launchstr,
                                                        self.separator, hash))
        sorted_unique_lines = sorted(list(res))
        out_file = os.path.join(output_dir, "process_autoruns_parsed.csv")

        try:
            with open(out_file, 'w', encoding='utf-8') as outfile:
                for raw in sorted_unique_lines:
                    outfile.write(raw)
                    outfile.write("\n")
            self.logger_run.info("[PARSING][PROCESS_AUTORUNS]", header="FINISHED", indentation=2)
        except Exception as e:
            self.logger_run.error(
                "[PARSING][PROCESS_AUTORUNS]: unexpected Error {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)


    def recursive_file_search(self, input_dir, reg_ex):
        files = []
        for element in os.listdir(input_dir):
            full_path = os.path.join(input_dir, element)
            if os.path.isfile(full_path):
                if re.search(reg_ex, element):  # ,  re.IGNORECASE):
                    if full_path not in files:
                        files.append(full_path)
            elif os.path.isdir(full_path):
                files.extend(self.recursive_file_search(full_path, reg_ex))
        return files

    def parse_all(self, input_dir, output_dir):
        autoruns_sysinternals_files = self.recursive_file_search(input_dir, self.artefact_config.get("autoruns", ""))
        if autoruns_sysinternals_files:
            self.logger_run.info("[PARSING][AUTORUNS]", header="START", indentation=2)
            for autorun_file in autoruns_sysinternals_files:
                self.parse_autoruns_sysinternals(autorun_file, output_dir)

        process1_files = self.recursive_file_search(input_dir, self.artefact_config.get("process1", ""))
        if process1_files:
            self.logger_run.info("[PARSING][PROCESS1]", header="START", indentation=2)
            for process1_file in process1_files:
                self.parse_process1(process1_file, output_dir, is_simplified=True)

        process2_files = self.recursive_file_search(input_dir, self.artefact_config.get("process2", ""))
        if process2_files:
            self.logger_run.info("[PARSING][PROCESS2]", header="START", indentation=2)
            for process2_file in process2_files:
                self.parse_process2(process2_file, output_dir)

        self.logger_run.info("[PARSING][PROCESS_AUTORUNS]", header="START", indentation=2)
        for pattern in self.artefact_config.get("sample_autoruns", ""):
            for process_autoruns_file in self.recursive_file_search(input_dir, pattern):
                self.parse_process_autoruns(process_autoruns_file, output_dir)
        self.logger_run.info("[PARSING][PROCESS_TIMELINE]", header="START", indentation=2)
        for pattern in self.artefact_config.get("sample_timeline", ""):
            for process_timeline_file in self.recursive_file_search(input_dir, pattern):
                self.parse_process_timeline(process_timeline_file, output_dir)
        self.logger_run.info("[PARSING][PROCESS_INFO]", header="START", indentation=2)
        for pattern in self.artefact_config.get("sample_info", ""):
            for process_info_file in self.recursive_file_search(input_dir, pattern):
                self.parse_process_infos(process_info_file, output_dir)

class SystemInfoParser:
    """
    Class to parsed various tool results files into straight forward human readble csv.
    (sysinternals Autoruns, DFIR-ORC PROCESS1, DFIR-ORC PROCESS2, DFIR-ORC PROCESS INFO, DFIR-ORC PROCESS_TIMELINE
    DFIR-ORC PROCESS_AUTORUNS)
    """

    def __init__(self, logger, artefact_config=None, separator="|") -> None:
        """
        The constructor for ProcessParser class
        :param separator: str: csv separator default is pipe
        :param artefact_config: dict: artefact config
        """
        self.logger_run = logger
        self.separator = separator
        if not artefact_config:
            self.artefact_config = {
                "artefacts": {
                    "system": {
                        "system_info": ["Systeminfo.csv"]
                    }
                }
            }
        else:
            self.artefact_config = artefact_config

    def parse_system_info(self, file_path, output_dir):
        """
        Parses systeminfo CSV files, formats the data, and saves it to both
        a text file and a JSON file.
        """
        self.logger_run.info("[PARSING][SYSTEMINFO]", header="START", indentation=2)
        all_system_info_data = []
        try:
            with open(file_path, 'r', encoding='cp850', errors='ignore') as system_info_file:
                reader = csv.reader(system_info_file)
                header = next(reader)

                for line in reader:
                    if not line or len(line) != len(header):
                        self.logger_run.error(
                            "[PARSING][SYSTEMINFO]: Skipping malformed line in {}: {}".format(file_path, line), header="ERROR",
                            indentation=2)

                        continue

                    line_dict = dict(zip(header, line))
                    all_system_info_data.append(line_dict)

        except Exception as e:
            self.logger_run.error(
                "[PARSING][SYSTEMINFO]: unexpected Error {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

        if all_system_info_data:
            out_txt_file_path = os.path.join(output_dir, "systeminfo.txt")
            out_json_file_path = os.path.join(output_dir, "systeminfo.json")

            with open(out_json_file_path, 'w') as out_json_file_stream:
                json.dump(all_system_info_data, out_json_file_stream, indent=4)

            with open(out_txt_file_path, 'w') as out_txt_file_stream:
                for entry in all_system_info_data:
                    for key, value in entry.items():
                        out_txt_file_stream.write("{}:{}\n".format(key, value))
                    out_txt_file_stream.write("\n")  # Add a blank line between entries

            self.logger_run.info("[PARSING][SYSTEMINFO]", header="FINISHED", indentation=2)
            return all_system_info_data

        else:
            self.logger_run.info("[PARSING][SYSTEMINFO] no data was found or parsed ", header="FAILED", indentation=2)
            return all_system_info_data

    def parse_all(self, input_dir, output_dir):
        system_info = {}
        try:
            mngr = FileManager()
            file_patterns = self.artefact_config.get("artefacts", {}).get("system", {}).get("system_info", [])
            if not file_patterns:
                self.logger_run.info("[PARSING][SYSTEMINFO] No file patterns configured for systeminfo.", header="FAILED",
                                     indentation=2)
                return system_info

            for file_pattern in file_patterns:
                l_file = mngr.recursive_file_search(input_dir, file_pattern)
                if not l_file:
                    self.logger_run.info("[PARSING][SYSTEMINFO] No file matching pattern'{}' found.".format(file_pattern), header="FAILED",
                                         indentation=2)
                    continue  # Continue to the next pattern if a file is not found

                for file_path in l_file:
                    self.logger_run.info("[PARSING][SYSTEMINFO]", header="START", indentation=2)
                    system_info = self.parse_system_info(file_path, output_dir)

            return system_info

        except Exception as e:
            self.logger_run.error(
                "[PARSING][SYSTEMINFO]: unexpected Error {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)
            return system_info

class DiskParser:
    """
    Class to parse disk info related artefacts, such as USN Journal logs.
    """

    def __init__(self,  logger_run, separator: str = "|") -> None:
        """
        The constructor for DiskParser class.

        Args:
            separator: The separator to use for the output CSV file.
            logger_run: The logger for normal runtime information.
        """
        self.separator = separator
        self.logger_run = logger_run

    def parse_usnjrnl(self, input_file_path: str, output_path: str):
        """
        Parses a USN Journal CSV file, reformats the data, and saves it
        to a new CSV file.

        Args:
            input_file_path: Full path of the USN CSV file to parse.
            output_path: Full path where the reformatted CSV results will be written.
        """

        output_file_path = os.path.join(output_path, "USN_parsed.csv")
        try:
            with open(input_file_path, 'r', newline='', encoding='utf-8') as infile, \
                    open(output_file_path, 'w', newline='', encoding='utf-8') as outfile:
                reader = csv.reader(infile)
                header = [h.strip() for h in next(reader)]
                try:
                    date_time_col_idx = header.index("TimeStamp")
                    file_name_col_idx = header.index("File")
                    file_path_col_idx = header.index("FullPath")
                    reason_col_idx = header.index("Reason")
                except ValueError as e:
                    self.logger_run.error(
                        "[PARSING][USNJOURNAL]: ad header column: {}".format(traceback.format_exc()), header="ERROR",
                        indentation=2)
                    return

                output_header = ["Date", "Time", "FileName", "Reason", "FilePath"]
                writer = csv.writer(outfile, delimiter=self.separator)
                writer.writerow(output_header)

                for row_num, line in enumerate(reader, 2):
                    if not line:
                        continue
                    try:
                        date_time_str = line[date_time_col_idx]
                        file_name = line[file_name_col_idx]
                        file_path = line[file_path_col_idx]
                        reason = line[reason_col_idx]
                        date, time = date_time_str.split(" ", 1)
                        writer.writerow([date, time, file_name, reason, file_path])

                    except IndexError:
                        # Handle cases where a row might have fewer columns than expected
                        pass
                    except ValueError:
                        pass

                self.logger_run.info("[PARSING][USNJOURNAL]", header="FINISHED", indentation=2)

        except FileNotFoundError:
            self.logger_run.error(
                "[PARSING][USNJOURNAL]: Input file not found at '{}'.".format(input_file_path), header="ERROR",
                indentation=2)

        except Exception:
            self.logger_run.error(
                "[PARSING][USNJOURNAL]: Unexpected Error: {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

    def parse_mft(self, json_file_path, output_path):
        """
        Converts a JSON-formatted MFT bodyfile into a pipe-separated CSV timeline.

        This function reads a JSON file and extracts key forensic data points. It
        creates a new entry for each timestamp (creation, access, modification),
        effectively "flattening" the data into a chronological timeline format.

        :param json_file_path: The path to the input MFT JSON file.
        :type json_file_path: str
        :param output_path: The path for the output pipe-separated CSV file.
        :type output_path: str
        :return: None
        """

        csv_file_path =  os.path.join(output_path, "mft_as_timeline.csv")
        try:
            # Step 1: Open the input JSON file and load the data.
            with open(json_file_path, 'r', encoding='utf-8') as json_file:
                json_records = json.load(json_file)

            # Step 2: Flatten the data into a list of timeline events.
            timeline_events = []
            for record in json_records:
                try:
                    fn_times = record.get('fn_times', {})

                    # Check for the presence of each timestamp and add a new event to the list.
                    # 'crtime' (Creation Time)
                    if 'crtime' in fn_times and fn_times['crtime']:
                        timeline_events.append({
                            "timestamp": fn_times['crtime'],
                            "event_type": "crtime",
                            "filename": record.get('filename', ''),
                            "filesize": record.get('filesize', ''),
                            "recordnum": record.get('recordnum', '')
                        })

                    # 'atime' (Access Time)
                    if 'atime' in fn_times and fn_times['atime']:
                        timeline_events.append({
                            "timestamp": fn_times['atime'],
                            "event_type": "atime",
                            "filename": record.get('filename', ''),
                            "filesize": record.get('filesize', ''),
                            "recordnum": record.get('recordnum', '')
                        })

                    # 'mtime' (Modification Time)
                    if 'mtime' in fn_times and fn_times['mtime']:
                        timeline_events.append({
                            "timestamp": fn_times['mtime'],
                            "event_type": "mtime",
                            "filename": record.get('filename', ''),
                            "filesize": record.get('filesize', ''),
                            "recordnum": record.get('recordnum', '')
                        })

                    # 'fn_times' is a special case for MFT body files, representing an entry.
                    # We can also include this for a complete timeline.
                    if 'fn_times' in record and record['fn_times'] and 'btime' in record['fn_times'] and \
                            record['fn_times']['btime']:
                        timeline_events.append({
                            "timestamp": record['fn_times']['btime'],
                            "event_type": "btime",
                            "filename": record.get('filename', ''),
                            "filesize": record.get('filesize', ''),
                            "recordnum": record.get('recordnum', '')
                        })

                except (ValueError, TypeError) as e:
                    print(f"Skipping malformed record during flattening: {record}. Error: {e}")
                    continue

            # Step 3: Sort the flattened events chronologically.
            timeline_events.sort(key=lambda event: event.get('timestamp', '0'))

            # Step 4: Open the output CSV file and write the sorted data.
            with open(csv_file_path, 'w', encoding='utf-8', newline='') as csv_file:
                # Create the csv writer with the pipe delimiter.
                writer = csv.writer(csv_file, delimiter='|', quoting=csv.QUOTE_NONE, escapechar='\\')

                # Write the header row.
                header = ["timestamp", "event_type", "filename", "filesize", "recordnum"]
                writer.writerow(header)

                # Write the new rows to the CSV file.
                for event in timeline_events:
                    row_data = [
                        event['timestamp'],
                        event['event_type'],
                        event['filename'],
                        event['filesize'],
                        event['recordnum']
                    ]
                    writer.writerow(row_data)
            self.logger_run.info("[PARSING][MFT]", header="FINISHED", indentation=2)

        except json.JSONDecodeError as e:
            self.logger_run.error(
                "[PARSING][MFT]: Input file not a valid json '{} error: {}'.".format(json_file_path, e), header="ERROR",
                indentation=2)

        except FileNotFoundError:
            self.logger_run.error(
                "[PARSING][MFT]: Input file not found at '{}'.".format(json_file_path), header="ERROR",
                indentation=2)

        except Exception:
            self.logger_run.error(
                "[PARSING][MFT]: Unexpected Error: {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

class EventParser:
    """
       Class to parse event json files to human-readable format |DATE|TIME|ETC|ETC
       Attributes :
    """

    def __init__(self, events_json_directory, output_directory) -> None:
        """
        The constructor for EventParser class.
        Parameters:
        """
        self.separator = "|"
        self.work_dir = events_json_directory
        self.output_directory = output_directory

        self.l_csv_header_4624 = ["Date", "Time", "event_code", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port", "logon_type"]
        self.l_csv_header_4625 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port"]
        self.l_csv_header_4672 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port"]
        self.l_csv_header_4648 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port"]
        self.l_csv_header_4688 = ["Date", "Time", "event_code", "subject_user_name", "target_user_name",
                                  "parent_process_name", "new_process_name", "command_line"]
        self.l_csv_header_tscheduler = ["Date", "Time", "event_code", "name", "task_name", "instance_id",
                                        "action_name", "result_code", "user_name", "user_context"]
        self.l_csv_header_remot_rdp = ["Date", "Time", "event_code", "user_name", "ip_addr"]
        self.l_csv_header_local_rdp = ["Date", "Time", "event_code", "user_name", "ip_addr", "session_id",
                                       "source", "target_session", "reason_n", "reason"]
        self.l_csv_header_bits = ["Date", "Time", "event_code", "id", "job_id", "job_title", "job_owner",
                                  "user", "bytes_total", "bytes_transferred", "file_count", "file_length", "file_Time",
                                  "name", "url", "process_path"]
        self.l_csv_header_7045 = ["Date", "Time", "event_code", "account_name", "img_path", "service_name",
                                  "start_type"]
        self.l_csv_header_powershell = ["Date", "Time", "event_code", "path_to_script", "script_block_text"]
        self.l_csv_header_script_powershell = ["Date", "Time", "event_code", "cmd"]
        self.l_csv_header_wmi = ["Date", "Time", "user", "nameSpace", "Query"]
        self.l_csv_header_app_exp = ["Date", "Time", "ExePath", "FixName", "Query"]
        self.l_csv_header_windefender = ["Date", "Time", "Event", "ThreatName", "Severity", "User", "ProcessName",
                                         "Path", "Action"]
        self.l_csv_header_start_stop = ["Date", "Time", "message"]

        self.logon_res_file_csv = ""
        self.logon_failed_file_csv = ""
        self.logon_spe_file_csv = ""
        self.logon_exp_file_csv = ""
        self.new_proc_file_csv = ""
        self.task_scheduler_file_csv = ""
        self.remote_rdp_file_csv = ""
        self.local_rdp_file_csv = ""
        self.bits_file_csv = ""
        self.service_file_csv = ""
        self.powershell_file_csv = ""
        self.powershell_script_file_csv = ""
        self.wmi_file_csv = ""

        self.windefender_res_file_csv = ""

        self.windows_start_stop_res_file_csv = ""

        self.initialise_results_files_csv()

    def initialise_result_file_csv(self, header, file_name, extension="csv"):
        """
        initialise a result file, write the header into it and return a stream to this file
        :param header: (list[str]) list containing all column name
        :param file_name: (str) the name of the file containing
        :param extension: (str) the name of the extension of the file
        :return: stream to a file
        """
        result_file_stream = open(os.path.join(self.output_directory, "{}.{}".format(file_name, extension)), 'a')
        result_file_stream.write(self.separator.join(header))
        result_file_stream.write("\n")
        return result_file_stream

    def initialise_results_files_csv(self):
        """
        Function that will initialise all csv result file.
        It will open a stream to all results file and write header into it.
        Stream are keeped open to avoid opening and closing multiple file every new line of the timeline
        :return: None
        """

        self.logon_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_4624, "user_logon_id4624")
        self.logon_failed_file_csv = self.initialise_result_file_csv(self.l_csv_header_4625,
                                                                     "user_failed_logon_id4625")
        self.logon_spe_file_csv = self.initialise_result_file_csv(self.l_csv_header_4672,
                                                                  "user_special_logon_id4672")
        self.logon_exp_file_csv = self.initialise_result_file_csv(self.l_csv_header_4648,
                                                                  "user_explicit_logon_id4648")
        self.new_proc_file_csv = self.initialise_result_file_csv(self.l_csv_header_4688,
                                                                 "new_proc_file_id4688")
        self.windows_start_stop_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_start_stop,
                                                                               "windows_start_stop")
        self.task_scheduler_file_csv = self.initialise_result_file_csv(self.l_csv_header_tscheduler,
                                                                       "task_scheduler")
        self.remote_rdp_file_csv = self.initialise_result_file_csv(self.l_csv_header_remot_rdp,
                                                                   "remote_rdp")
        self.local_rdp_file_csv = self.initialise_result_file_csv(self.l_csv_header_local_rdp,
                                                                  "local_rdp")
        self.bits_file_csv = self.initialise_result_file_csv(self.l_csv_header_bits, "bits")
        self.service_file_csv = self.initialise_result_file_csv(self.l_csv_header_7045, "new_service_id7045")
        self.powershell_file_csv = self.initialise_result_file_csv(self.l_csv_header_powershell,
                                                                   "powershell")
        self.powershell_script_file_csv = self.initialise_result_file_csv(self.l_csv_header_script_powershell,
                                                                          "powershell_script")
        self.wmi_file_csv = self.initialise_result_file_csv(self.l_csv_header_wmi, "wmi")
        self.windefender_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_windefender,
                                                                        "windefender")

    def close_files_csv(self):
        """
        Function to close all opened stream
        :return:
        """
        if self.logon_res_file_csv:
            self.logon_res_file_csv.close()
        if self.logon_failed_file_csv:
            self.logon_failed_file_csv.close()
        if self.logon_spe_file_csv:
            self.logon_spe_file_csv.close()
        if self.logon_exp_file_csv:
            self.logon_exp_file_csv.close()
        if self.windows_start_stop_res_file_csv:
            self.windows_start_stop_res_file_csv.close()
        if self.task_scheduler_file_csv:
            self.task_scheduler_file_csv.close()
        if self.remote_rdp_file_csv:
            self.remote_rdp_file_csv.close()
        if self.local_rdp_file_csv:
            self.local_rdp_file_csv.close()
        if self.bits_file_csv:
            self.bits_file_csv.close()
        if self.service_file_csv:
            self.service_file_csv.close()
        if self.powershell_file_csv:
            self.powershell_file_csv.close()
        if self.powershell_script_file_csv:
            self.powershell_script_file_csv.close()
        if self.wmi_file_csv:
            self.wmi_file_csv.close()

    def format_system_time(self, evt_timestamp):
        try:
            if evt_timestamp == "-":
                return
            l_time = evt_timestamp.split("T")
            if l_time:
                ts_date = l_time[0]
                ts_time = l_time[1].split(".")[0]
                return ts_date, ts_time
        except:
            return evt_timestamp, "-"

    def parse_logon(self, event):
        """
        Parse 4624 event ID
        :param event: dict
        :return:
        """
        event_code = "4624"

        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        subject_user_name = event.get("Event", {}).get("EventData", {}).get("SubjectUserName", "-")
        target_user_name = event.get("Event", {}).get("EventData", {}).get("TargetUserName", "-")
        ip_address = event.get("Event", {}).get("EventData", {}).get("IpAddress", "-")
        ip_port = event.get("Event", {}).get("EventData", {}).get("IpPort", "-")
        logon_type = event.get("Event", {}).get("EventData", {}).get("LogonType", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                      ts_time, self.separator,
                                                      event_code, self.separator,
                                                      subject_user_name, self.separator,
                                                      target_user_name, self.separator,
                                                      ip_address, self.separator,
                                                      ip_port, self.separator,
                                                      logon_type)
        self.logon_res_file_csv.write(res)
        self.logon_res_file_csv.write('\n')

    def parse_failed_logon(self, event):
        """
        parse 4625 event id
        :param event: dict
        :return:
        """
        event_code = "4625"

        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        subject_user_name = event.get("Event", {}).get("EventData", {}).get("SubjectUserName", "-")
        target_user_name = event.get("Event", {}).get("EventData", {}).get("TargetUserName", "-")
        ip_address = event.get("Event", {}).get("EventData", {}).get("IpAddress", "-")
        ip_port = event.get("Event", {}).get("EventData", {}).get("IpPort", "-")
        logon_type = event.get("Event", {}).get("EventData", {}).get("LogonType", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                      ts_time, self.separator,
                                                      event_code, self.separator,
                                                      subject_user_name, self.separator,
                                                      target_user_name, self.separator,
                                                      ip_address, self.separator,
                                                      ip_port, self.separator,
                                                      logon_type)
        self.logon_failed_file_csv.write(res)
        self.logon_failed_file_csv.write('\n')

    def parse_spe_logon(self, event):
        """
        Parse 4672 event id
        :param event: dict
        :return:
        """
        event_code = "4672"

        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        subject_user_name = event.get("Event", {}).get("EventData", {}).get("SubjectUserName", "-")
        target_user_name = event.get("Event", {}).get("EventData", {}).get("TargetUserName", "-")
        ip_address = event.get("Event", {}).get("EventData", {}).get("IpAddress", "-")
        ip_port = event.get("Event", {}).get("EventData", {}).get("IpPort", "-")
        logon_type = event.get("Event", {}).get("EventData", {}).get("LogonType", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                      ts_time, self.separator,
                                                      event_code, self.separator,
                                                      subject_user_name, self.separator,
                                                      target_user_name, self.separator,
                                                      ip_address, self.separator,
                                                      ip_port, self.separator,
                                                      logon_type)
        self.logon_spe_file_csv.write(res)
        self.logon_spe_file_csv.write('\n')

    def parse_exp_logon(self, event):
        """
        Parse 4648 event id
        :param event: dict
        :return:
        """
        event_code = "4648"

        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        subject_user_name = event.get("Event", {}).get("EventData", {}).get("SubjectUserName", "-")
        target_user_name = event.get("Event", {}).get("EventData", {}).get("TargetUserName", "-")
        ip_address = event.get("Event", {}).get("EventData", {}).get("IpAddress", "-")
        ip_port = event.get("Event", {}).get("EventData", {}).get("IpPort", "-")
        logon_type = event.get("Event", {}).get("EventData", {}).get("LogonType", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                      ts_time, self.separator,
                                                      event_code, self.separator,
                                                      subject_user_name, self.separator,
                                                      target_user_name, self.separator,
                                                      ip_address, self.separator,
                                                      ip_port, self.separator,
                                                      logon_type)
        self.logon_exp_file_csv.write(res)
        self.logon_exp_file_csv.write('\n')

    def parse_new_proc(self, event):
        """
        Parse 4688 event ID
        :param event: dict
        :return:
        """
        event_code = "4688"
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        subject_user_name = event.get("Event", {}).get("EventData", {}).get("SubjectUserName", "-")
        target_user_name = event.get("Event", {}).get("EventData", {}).get("TargetUserName", "-")
        parent_proc_name = event.get("Event", {}).get("EventData", {}).get("ParentProcessName", "-")
        new_proc_name = event.get("Event", {}).get("EventData", {}).get("NewProcessName", "-")
        cmd_line = event.get("Event", {}).get("EventData", {}).get("CommandLine", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                      ts_time, self.separator,
                                                      event_code, self.separator,
                                                      subject_user_name, self.separator,
                                                      target_user_name, self.separator,
                                                      parent_proc_name, self.separator,
                                                      new_proc_name, self.separator,
                                                      cmd_line)
        self.new_proc_file_csv.write(res)
        self.new_proc_file_csv.write('\n')

    def parse_security_evtx(self, file_path):
        """
        Main function to parse evtx security json files
        :param event: str: path to json converted security evtx file
        :return:
        """

        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["4624"]:
                    self.parse_logon(ev)
                if event_code in ["4625"]:
                    self.parse_failed_logon(ev)

                if event_code in ["4672"]:
                    self.parse_spe_logon(ev)

                if event_code in ["4648"]:
                    self.parse_exp_logon(ev)

                if event_code in ["4688"]:
                    self.parse_new_proc(ev)

    def parse_task_scheduler_new(self, event):
        """
        Parse task scheduler event ID for newer logs of windows
        :param event: dict
        :return:
        """

        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")
        name = event.get("Event", {}).get("EventData", {}).get("Name", "-")
        task_name = event.get("Event", {}).get("EventData", {}).get("TaskName", "-")
        instance_id = event.get("Event", {}).get("EventData", {}).get("InstanceId", "-")
        action_name = event.get("Event", {}).get("EventData", {}).get("ActionName", "-")
        result_code = event.get("Event", {}).get("EventData", {}).get("ResultCode", "-")
        user_name = event.get("Event", {}).get("EventData", {}).get("UserName", "-")
        user_context = event.get("Event", {}).get("EventData", {}).get("UserContext", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                              ts_time, self.separator,
                                                              event_code, self.separator,
                                                              name, self.separator,
                                                              task_name, self.separator,
                                                              instance_id, self.separator,
                                                              action_name, self.separator,
                                                              result_code, self.separator,
                                                              user_name, self.separator,
                                                              user_context)
        self.task_scheduler_file_csv.write(res)
        self.task_scheduler_file_csv.write('\n')

    def parse_task_scheduler(self, file_path):
        """
       Main function to parse evtx task scheduler json files
        :param file_path: str : path to the json converted evtx file
        :return:
        """
        with open(file_path, 'r') as scheduled_file:
            for event in scheduled_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["106", "107", "140", "141", "200", "201"]:
                    self.parse_task_scheduler_new(ev)

    def parse_rdp_remote_connexion(self, event):
        """
        Parse task rdp remote connexion event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")
        user_name = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("Param1", "-")
        ip_addr = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("Param3", "-")

        res = "{}{}{}{}{}{}InitConnexion{}{}{}{}".format(ts_date, self.separator,
                                                         ts_time, self.separator,
                                                         event_code, self.separator,
                                                         self.separator,
                                                         user_name, self.separator,
                                                         ip_addr)
        self.remote_rdp_file_csv.write(res)
        self.remote_rdp_file_csv.write('\n')

    def parse_rdp_remote_evtx(self, file_path):
        """
       Main function to parse evtx rdp remote json files
        :param file_path: str : path to the json converted evtx file
        :return:
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["1149"]:
                    self.parse_rdp_remote_connexion

    def parse_rdp_local_connexion(self, event):
        """
        Parse task rdp local connexion event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        user_name = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("User", "-")
        ip_addr = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("Adress", "-")
        session_id = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("SessionID", "-")
        source = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("Source", "-")
        target_session = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("TargetSession", "-")
        reason_n = event.get("Event", {}).get("UserData", {}).get("EventXML", {}).get("Reason", "-")
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")

        reason = "-"
        if event_code == "21":
            reason = "AuthSuccess"
        if event_code == "24":
            reason = "UserDisconnected"
        if event_code == "25":
            reason = "UserReconnected"
        if event_code == "39":
            reason = "UserHasBeenDisconnected"
        if event_code == "40":
            reason = "UserHasBeenDisconnected"

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                              ts_time, self.separator,
                                                              event_code, self.separator,
                                                              user_name, self.separator,
                                                              ip_addr, self.separator,
                                                              session_id, self.separator,
                                                              source, self.separator,
                                                              target_session, self.separator,
                                                              reason_n, self.separator,
                                                              reason)
        self.local_rdp_file_csv.write(res)
        self.local_rdp_file_csv.write('\n')

    def parse_rdp_local_evtx(self, file_path):
        """
       Main function to parse rdp local json files
        :param file_path: str : path to the json converted evtx file
        :return:
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["21", "24", "25", "39", "40"]:
                    self.parse_rdp_local_connexion(ev)

    def parse_bits(self, file_path):
        """
       Main function to parse evtx bits json files
        :param file_path: str : path to the json converted evtx file
        :return:
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["3", "4", "59", "60", "61"]:
                    self.parse_bits_evtx(ev)

    def parse_bits_evtx(self, event):
        """
        Parse bits event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")
        identifiant = event.get("Event", {}).get("EventData", {}).get("Id", "-")
        job_id = event.get("Event", {}).get("EventData", {}).get("jobId", "-")
        job_title = event.get("Event", {}).get("EventData", {}).get("jobTitle", "-")
        job_owner = event.get("Event", {}).get("EventData", {}).get("jobOwner", "-")
        user = event.get("Event", {}).get("EventData", {}).get("User", "-")
        bytes_total = event.get("Event", {}).get("EventData", {}).get("bytesTotal", "-")
        bytes_transferred = event.get("Event", {}).get("EventData", {}).get("bytesTransferred", "-")
        file_count = event.get("Event", {}).get("EventData", {}).get("fileCount", "-")
        file_length = event.get("Event", {}).get("EventData", {}).get("fileLength", "-")
        file_time = event.get("Event", {}).get("EventData", {}).get("fileTime", "-")
        name = event.get("Event", {}).get("EventData", {}).get("name", "-")
        url = event.get("Event", {}).get("EventData", {}).get("url", "-")
        process_path = event.get("Event", {}).get("EventData", {}).get("processPath", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                                                      ts_time, self.separator,
                                                                                      event_code, self.separator,
                                                                                      identifiant, self.separator,
                                                                                      job_id, self.separator,
                                                                                      job_title, self.separator,
                                                                                      job_owner, self.separator,
                                                                                      user, self.separator,
                                                                                      bytes_total, self.separator,
                                                                                      bytes_transferred,
                                                                                      self.separator,
                                                                                      file_count, self.separator,
                                                                                      file_length, self.separator,
                                                                                      file_time, self.separator,
                                                                                      name, self.separator,
                                                                                      url, self.separator,
                                                                                      process_path)
        self.bits_file_csv.write(res)
        self.bits_file_csv.write('\n')

    def parse_system_evtx(self, file_path):
        """
        Main function to parse system type logs
        :param file_path: (str) path to the evtx json file,
        :return: None
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                try:
                    event_code = ev.get("Event", {}).get("System", {}).get("EventID", {}).get("Value", "-")
                except:
                    event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["7034", "7045"]:
                    self.parse_service_evtx(ev)

    def parse_service_evtx(self, event):
        """
        Parse services (7045) event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", {}).get("Value", "-")
        account_name = event.get("Event", {}).get("EventData", {}).get("AccountName", "-")
        img_path = event.get("Event", {}).get("EventData", {}).get("ImagePath", "-")
        service_name = event.get("Event", {}).get("EventData", {}).get("ServiceName", "-")
        start_type = event.get("Event", {}).get("EventData", {}).get("StartType", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              event_code, self.separator,
                                              account_name, self.separator,
                                              img_path, self.separator,
                                              service_name, self.separator,
                                              start_type)

        self.service_file_csv.write(res)
        self.service_file_csv.write('\n')

    def parse_powershell_script(self, event):
        """
        Parse powershell script event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")
        path_to_script = event.get("Event", {}).get("EventData", {}).get("Path", "-")
        script_block_text = event.get("Event", {}).get("EventData", {}).get("ScriptBlockText", "-")

        res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                          ts_time, self.separator,
                                          event_code, self.separator,
                                          path_to_script, self.separator,
                                          script_block_text)
        self.powershell_script_file_csv.write(res)
        self.powershell_script_file_csv.write('\n')

    def parse_powershell_cmd(self, event):
        """
        Parse powershell cmd event ID
        :param event: dict
        :return:
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", {}).get("Value", "-")
        cmdu = "-"

        evt_data = event.get("Event", {}).get("EventData", {}).get("Data", "-")
        for line in evt_data:
            if "HostApplication=" in line:
                l2 = line.split("\n")
                for i in l2:
                    if "HostApplication" in i:
                        cmdu = i.split("HostApplication=")[1].replace("\n", " ").replace("\t", "").replace("\r", "")

        res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                      ts_time, self.separator,
                                      event_code, self.separator,
                                      cmdu)

        self.powershell_file_csv.write(res)
        self.powershell_file_csv.write('\n')

    def parse_powershell_operationnal(self, file_path):
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["4104"]:
                    self.parse_powershell_script(ev)

    def parse_windows_powershell(self, file_path):
        """
       Main function to parse evtx powershell json files
        :param file_path: str : path to the json converted evtx file
        :return:
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", {}).get("Value", "-")
                if event_code in ["400", "600"]:
                    self.parse_powershell_cmd(ev)

    def parse_wmi_evtx(self, event):
        """
        Function to parse wmi log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")

        operation_name = list(event.get("Event", {}).get("UserData", {}).keys())[0]
        op_dict = event.get("Event", {}).get("UserData", {}).get(operation_name, {})

        user = op_dict.get("User", "-")
        namespace = op_dict.get("NamespaceName", "-")
        consumer = op_dict.get("CONSUMER", "-")
        cause = op_dict.get("PossibleCause", "-")
        query = op_dict.get("Query", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          operation_name, self.separator,
                                                          user, self.separator,
                                                          namespace, self.separator,
                                                          consumer, self.separator,
                                                          cause, self.separator,
                                                          query)

        self.wmi_file_csv.write(res)
        self.wmi_file_csv.write('\n')

    def parse_wmi_failure_evtx(self, event):
        """
        Function to parse wmi failure log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the evtx json file,
        :return: None
        """
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)
        event_code = event.get("Event", {}).get("System", {}).get("EventID", "-")

        operation_name = list(event.get("Event", {}).get("UserData", {}).keys())[0]
        op_dict = event.get("Event", {}).get("UserData", {}).get(operation_name, {})

        user = op_dict.get("User", "-")
        namespace = op_dict.get("NamespaceName", "-")
        consumer = op_dict.get("CONSUMER", "-")
        cause = op_dict.get("PossibleCause", "-")
        query = op_dict.get("Query", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          operation_name, self.separator,
                                                          user, self.separator,
                                                          namespace, self.separator,
                                                          consumer, self.separator,
                                                          cause, self.separator,
                                                          query)

        self.wmi_file_csv.write(res)
        self.wmi_file_csv.write('\n')

    def parse_wmi(self, file_path):
        """
        Main function to parse wmi type logs
        :param file_path: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if str(event_code) in ["5860", "5861"]:
                    self.parse_wmi_evtx(ev)
                if str(event_code) in ["5858"]:
                    self.parse_wmi_failure_evtx(ev)

    def parse_windows_defender(self, file_path):
        """
        Main function to parse windows defender logs
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        with open(file_path, 'r') as secu_file:
            for event in secu_file.readlines():
                ev = json.loads(event)
                event_code = ev.get("Event", {}).get("System", {}).get("EventID", "-")
                if event_code in ["1116"]:
                    self.parse_windef_detection_from_xml(ev)
                if event_code in ["1117", "1118", "1119"]:
                    self.parse_windef_action_from_xml(ev)
                if event_code in ["1006", "1007"]:
                    pass # lacking data to parse

    def parse_windef_detection_from_xml(self, event):
        """
        Function to parse windefender detection log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1116 - Detection"
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)

        threat_name = event.get("Event", {}).get("EventData", {}).get("Threat Name", "-")
        severity = event.get("Event", {}).get("EventData", {}).get("Severity Name", "-")
        process_name = event.get("Event", {}).get("EventData", {}).get("Process Name", "-")
        detection_user = event.get("Event", {}).get("EventData", {}).get("Detection User", "-")
        path = event.get("Event", {}).get("EventData", {}).get("Path", "-")
        action = event.get("Event", {}).get("EventData", {}).get("Action Name", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          threat_name, self.separator,
                                                          severity, self.separator,
                                                          detection_user, self.separator,
                                                          process_name, self.separator,
                                                          path, self.separator,
                                                          action)
        self.windefender_res_file_csv.write(res)
        self.windefender_res_file_csv.write('\n')

    def parse_windef_action_from_xml(self, event):
        """
        Function to parse windefender action log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        evt_code = event.get("Event", {}).get("System", {}).get("EventID", "-")
        event_code = "{} - Action".format(evt_code)
        creation_time = event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime", "-")
        ts_date, ts_time = self.format_system_time(creation_time)

        threat_name = event.get("Event", {}).get("EventData", {}).get("Threat Name", "-")
        severity = event.get("Event", {}).get("EventData", {}).get("Severity Name", "-")
        process_name = event.get("Event", {}).get("EventData", {}).get("Process Name", "-")
        detection_user = event.get("Event", {}).get("EventData", {}).get("Detection User", "-")
        path = event.get("Event", {}).get("EventData", {}).get("Path", "-")
        action = event.get("Event", {}).get("EventData", {}).get("Action Name", "-")

        res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          threat_name, self.separator,
                                                          severity, self.separator,
                                                          detection_user, self.separator,
                                                          process_name, self.separator,
                                                          path, self.separator,
                                                          action)
        self.windefender_res_file_csv.write(res)
        self.windefender_res_file_csv.write('\n')

    def parse_all(self):
        """
        Main function to parse all  evtx jsonfiles
        """
        search_security = [f for f in os.listdir(self.work_dir) if re.search(r'_Security\.json$', f)]
        search_security2 = [f for f in os.listdir(self.work_dir) if re.search(r'^Security\.json$', f)]
        search_all_security = search_security + search_security2
        if search_all_security:
            relative_file_path = Path(os.path.join(self.work_dir, search_all_security[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_security_evtx(absolute_file_path)

        search_task_scheduler = [f for f in os.listdir(self.work_dir) if
                                 re.search(r'Microsoft-Windows-TaskScheduler%4Operational\.json$', f)]
        if search_task_scheduler:
            relative_file_path = Path(os.path.join(self.work_dir, search_task_scheduler[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_task_scheduler(absolute_file_path)

        search_remot_rdp = [f for f in os.listdir(self.work_dir) if
                            re.search(r'Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational\.json$',
                                      f)]
        if search_remot_rdp:
            relative_file_path_remot = Path(os.path.join(self.work_dir, search_remot_rdp[0]))
            absolute_file_path_remot = relative_file_path_remot.absolute()  # absolute is a Path object
            self.parse_rdp_remote_evtx(absolute_file_path_remot)

        search_local_rdp = [f for f in os.listdir(self.work_dir) if
                            re.search(r'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational\.json$', f)]
        if search_local_rdp:
            relative_file_path_local = Path(os.path.join(self.work_dir, search_local_rdp[0]))
            absolute_file_path_local = relative_file_path_local.absolute()  # absolute is a Path object
            self.parse_rdp_local_evtx(absolute_file_path_local)

        search_bits = [f for f in os.listdir(self.work_dir) if
                       re.search(r'Microsoft-Windows-Bits-Client%4Operational\.json$', f)]
        if search_bits:
            relative_file_path = Path(os.path.join(self.work_dir, search_bits[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_bits(absolute_file_path)

        search_powershell_operational = [f for f in os.listdir(self.work_dir) if
                                         re.search(r'Microsoft-Windows-PowerShell%4Operational\.json$', f)]
        if search_powershell_operational:
            relative_file_path = Path(os.path.join(self.work_dir, search_powershell_operational[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_powershell_operationnal(absolute_file_path)

        search_windows_powershell = [f for f in os.listdir(self.work_dir) if
                                     re.search(r'Microsoft-Windows-PowerShell\.json$', f)]
        if search_windows_powershell:
            relative_file_path = Path(os.path.join(self.work_dir, search_windows_powershell[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_powershell_cmd(absolute_file_path)

        search_wmi = [f for f in os.listdir(self.work_dir) if
                      re.search(r'Microsoft-Windows-WMI-Activity%4Operational\.json$', f)]
        if search_wmi:
            relative_file_path = Path(os.path.join(self.work_dir, search_wmi[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_wmi(absolute_file_path)

        search_system = [f for f in os.listdir(self.work_dir) if
                         re.search(r'System\.json$', f)]
        if search_system:
            relative_file_path = Path(os.path.join(self.work_dir, search_system[0]))
            absolute_file_path = relative_file_path.absolute()  # absolute is a Path object
            self.parse_system_evtx(absolute_file_path)

class RegistryParser:
    """
       Class to Registry
       """

    def __init__(self, logger_run) -> None:
        """
        The constructor for RegistryParser
        """
        self.logger_run = logger_run

    def parse_amcache_regpy(self, input_dir: str, dir_out: str):
        """
        Main function to parse amcache with regipy.

        Args:
            input_dir: path to the dir containing the amcache.
            dir_out: Path to the results folder where files will be saved.
        """
        amcache_patterns = [r'Amcache\.hve$']

        self.logger_run.info("[PARSING][AMCACHE][REGPY]", header="START", indentation=2)

        for amcache_pattern in amcache_patterns:
            hve_l = self.recursive_file_search(input_dir, amcache_pattern)
            for file_path in hve_l:
                try:
                    if not os.path.exists(file_path):
                        self.logger_run.error(
                            "[PARSING][AMCACHE][REGPY]: File not found {}".format(traceback.format_exc()),
                            header="ERROR",
                            indentation=2)
                        return

                    reg = RegistryHive(file_path)
                    parsed_data = run_relevant_plugins(reg, as_json=True)

                    # --- Step 2: Extract, format, and prepare data for CSV ---
                    # Use .get() with an empty list as a default to avoid key errors
                    amcache_entries: List[Dict[str, Any]] = parsed_data.get("amcache", [])

                    if not amcache_entries:
                        self.logger_run.warning("[PARSING][AMCACHE][REGPY] Regpy could'nt parse Amcache", header="FAILED", indentation=2)
                        return

                    formatted_for_csv = []
                    for entry in amcache_entries:
                        timestamp_str = entry.get("timestamp")

                        try:
                            dt_obj = datetime.fromisoformat(timestamp_str)
                            date_str = dt_obj.strftime("%Y-%m-%d")
                            time_str = dt_obj.strftime("%H:%M:%S")
                        except (ValueError, TypeError):
                            self.logger_run.print_warning_failed_sub_2(
                                "[PARSING][AMCACHE][REGPY]: Could not parse timestamp: {}. Skipping row".format(
                                    timestamp_str))
                            continue  # Skip to the next entry

                        # Build the dictionary for this row
                        formatted_for_csv.append({
                            "Date": date_str,
                            "Time": time_str,
                            "Name": entry.get("original_file_name", "-"),
                            "Hash": entry.get("sha1", "-")
                        })

                    # --- Step 3: Sort the data ---
                    if formatted_for_csv:
                        formatted_for_csv.sort(key=lambda x: (x.get("Date"), x.get("Time")))

                    # --- Step 4: Write the formatted data to a CSV file ---
                    if formatted_for_csv:
                        path_out_csv = os.path.join(dir_out, f"{os.path.basename(file_path)}_regpy.csv")
                        header_list = ["Date", "Time", "Name", "Hash"]

                        # Using csv.DictWriter is the standard and most robust way
                        with open(path_out_csv, 'w', newline='', encoding='utf-8') as outfile:
                            writer = csv.DictWriter(outfile, fieldnames=header_list, delimiter='|')
                            writer.writeheader()
                            writer.writerows(formatted_for_csv)
                        self.logger_run.info("[PARSING][AMCACHE][REGPY]", header="FINISHED", indentation=2)

                except FileNotFoundError:
                    self.logger_run.error(
                        "[PARSING][AMCACHE][REGPY]: File not found {}".format(traceback.format_exc()), header="ERROR",
                        indentation=2)

                except Exception as e:
                    self.logger_run.error(
                        "[PARSING][AMCACHE][REGPY]: An unexpected error occurred{}".format(traceback.format_exc()),
                        header="ERROR",
                        indentation=2)

    def _recursively_read_key(self, key):
        """
        Parcourt une clé de registre de manière récursive et collecte ses informations.
        """
        key_info = {
            "name": key.name(),
            "last_written_timestamp": key.last_written_timestamp().isoformat() if key.last_written_timestamp() else None,
            "values": {},
            "subkeys": {}
        }

        # Collecter les valeurs
        try:
            for value in key.values():
                value_info = {
                    "type": value.type_str(),
                    "size": value.data_size(),
                    "data": None
                }
                try:
                    # Tenter de décoder les données dans un format lisible
                    data = value.data()
                    if isinstance(data, (bytes, bytearray)):
                        value_info["data"] = data.hex()
                    elif isinstance(data, list):
                        value_info["data"] = [s.strip('\x00') for s in data]
                    elif isinstance(data, str):
                        value_info["data"] = data.strip('\x00')
                    else:
                        value_info["data"] = data
                except (UnicodeDecodeError, Registry.WalkException):
                    value_info["data"] = value.data_raw().hex()

                key_info["values"][value.name()] = value_info
        except Registry.WalkException as e:
            self.logger_run.error(
                "[PARSING][HIVE][YARP]: error reading key {}: {}".format(
                    key.path(), e),
                header="ERROR",
                indentation=2)


        # Parcourir les sous-clés de manière récursive
        try:
            for subkey in key.subkeys():
                subkey_name = subkey.name()
                # Utiliser un bloc try-except pour gérer les clés qui pourraient être illisibles
                try:
                    key_info["subkeys"][subkey_name] = self._recursively_read_key(subkey)
                except Registry.WalkException as e:
                    self.logger_run.error(
                        "[PARSING][HIVE][YARP]: error reading key {}: {}".format(
                            key.path(), e),
                        header="ERROR",
                        indentation=2)

                    key_info["subkeys"][subkey_name] = {"error": str(e)}

        except Registry.WalkException as e:
            self.logger_run.error(
                "[PARSING][HIVE][YARP]: error reading key {}: {}".format(key.path(), e),
                header="ERROR", indentation=2)

        return key_info

    def _recursively_write_key(self, key, output_file, parent_path=""):
        """
        Parcourt une clé de registre de manière récursive et écrit chaque clé
        sur une ligne distincte du fichier de sortie au format JSON Lines.
        """
        # Construire le chemin complet de la clé actuelle
        current_path = parent_path + "\\" + key.name() if parent_path else key.name()

        # Préparer les données de la clé pour l'exportation
        key_data = {
            "path": current_path,
            "name": key.name(),
            "last_written_timestamp": key.last_written_timestamp().isoformat() if key.last_written_timestamp() else None,
            "values": {}
        }

        # Collecter les valeurs de la clé actuelle
        try:
            for value in key.values():
                value_info = {
                    "type": value.type_str(),
                    "size": value.data_size(),
                    "data": None
                }
                try:
                    data = value.data()
                    if isinstance(data, (bytes, bytearray)):
                        value_info["data"] = data.hex()
                    elif isinstance(data, list):
                        value_info["data"] = [s.strip('\x00') for s in data]
                    elif isinstance(data, str):
                        value_info["data"] = data.strip('\x00')
                    else:
                        value_info["data"] = data
                except (UnicodeDecodeError, Registry.WalkException):
                    value_info["data"] = value.data_raw().hex()

                key_data["values"][value.name()] = value_info
        except Registry.WalkException as e:
            self.logger_run.error(
                "[PARSING][HIVE][YARP]: error reading key {}: {}".format( key.path(), e), header="ERROR", indentation=2)
            key_data["error_values"] = str(e)

        output_file.write(json.dumps(key_data, ensure_ascii=False) + "\n")
        try:
            for subkey in key.subkeys():
                self._recursively_write_key(subkey, output_file, current_path)

        except Registry.WalkException as e:
            self.logger_run.error(
                "[PARSING][HIVE][YARP]: error reading key {}: {}".format( key.path(), e), header="ERROR", indentation=2)

    def export_hive_to_jsonl(self, hive_file_path, output_path):
        """
        Exporte le contenu d'une ruche de registre en un fichier JSON Lines,
        avec une entrée par clé de registre.

        Args:
            hive_file_path (str): Le chemin vers le fichier de la ruche.
            output_jsonl_path (str): Le chemin où enregistrer le fichier JSON Lines.
        """
        try:
            hv_name = os.path.basename(hive_file_path)
            output_jsonl_path = os.path.join(output_path, "{}_yarp.jsonl".format(hv_name))
            self.logger_run.info("[PARSING][HIVE][YARP] {}".format(hv_name), header="START", indentation=2)

            with open(hive_file_path, "rb") as f_hive, open(output_jsonl_path, "w", encoding="utf-8") as f_jsonl:
                hive = Registry.RegistryHive(f_hive)
                root_key = hive.root_key()

                # Écrire un objet pour la ruche elle-même
                hive_info = {
                    "hive_path": str(hive_file_path),
                    "last_written": hive.last_written_timestamp().isoformat() if hive.last_written_timestamp() else None,
                    "last_reorganized": hive.last_reorganized_timestamp().isoformat() if hive.last_reorganized_timestamp() else None,
                }
                f_jsonl.write(json.dumps(hive_info, ensure_ascii=False) + "\n")

                # Commencer le parcours récursif à partir de la clé racine
                self._recursively_write_key(root_key, f_jsonl)

            self.logger_run.info("[PARSING][HIVE][YARP] {}".format(hv_name), header="FINISHED", indentation=2)
            return True

        except Exception as e:
            self.logger_run.error(
                "[PARSING][HIVE][YARP]: An unexpected error occurred{}".format(traceback.format_exc()),
                header="ERROR",
                indentation=2)

    def export_hive_to_json(self, hive_file_path, output_path):
        """
        Exporte le contenu complet d'une ruche de registre en un fichier JSON.

        Args:
            hive_file_path (str): Le chemin vers le fichier de la ruche.
            output_json_path (str): Le chemin où enregistrer le fichier JSON.
        """
        try:
            hv_name = os.path.basename(hive_file_path)

            with open(hive_file_path, "rb") as f:
                hive = Registry.RegistryHive(f)
                root_key = hive.root_key()

                hive_data = {
                    "hive_info": {
                        "last_written": hive.last_written_timestamp().isoformat() if hive.last_written_timestamp() else None,
                        "last_reorganized": hive.last_reorganized_timestamp().isoformat() if hive.last_reorganized_timestamp() else None,
                    },
                    "root_key": self._recursively_read_key(root_key)
                }
                output_json_path = os.path.join(output_path,"{}_yarp.json".format(hv_name))
                with open(output_json_path, "w", encoding="utf-8") as json_file:
                    json.dump(hive_data, json_file, ensure_ascii=False)

                self.logger_run.info("[PARSING][HIVE][YARP] {}".format(hv_name), header="FINISHED", indentation=2)
                return True

        except Exception as e:
            self.logger_run.error(
                "[PARSING][HIVE][YARP]: An unexpected error occurred{}".format(traceback.format_exc()),
                header="ERROR", indentation=2)
            return False

    def export_amcache_to_jsonl(self, hive_file_dir, output_path):
        """
        Exporte le contenu d'une ruche de registre en un fichier JSON Lines,
        avec une entrée par clé de registre.

        Args:
            hive_file_dir (str): Le chemin vers le dossier de la ruche.
            output_path (str): Le chemin où enregistrer le fichier JSON Lines.
        """
        try:
            amcache_files = {
                "amcache": r'Amcache\.hve$',
                "log1": r'Amcache\.hve.LOG1$',
                "log2": r'Amcache\.hve.LOG2$',
                "log3": r'Amcache\.hve.LOG3$'
            }

            primary_file_path_l = self.recursive_file_search(hive_file_dir, amcache_files.get("amcache"))
            log1_file_path_l = self.recursive_file_search(hive_file_dir, amcache_files.get("log1"))
            log2_file_path_l = self.recursive_file_search(hive_file_dir, amcache_files.get("log2"))
            log3_file_path_l = self.recursive_file_search(hive_file_dir, amcache_files.get("log3"))

            log1 = None
            log2 = None
            log3 = None

            if primary_file_path_l:
                hv_name = os.path.basename(primary_file_path_l[0])
                output_jsonl_path = os.path.join(output_path, "{}_yarp.jsonl".format(hv_name))
                primary_file = open(primary_file_path_l[0], 'rb')
                hive = Registry.RegistryHive(primary_file)

                if log1_file_path_l :
                    log1 = open(log1_file_path_l[0], 'rb')
                if log2_file_path_l:
                    log2 = open(log2_file_path_l[0], 'rb')
                if log3_file_path_l:
                    log3 = open(log3_file_path_l[0], 'rb')

                recovery_result = hive.recover_auto(log1, log2, log3)

                if recovery_result.recovered:
                    self.logger_run.info("[PARSING][AMCACHE][YARP] The hive {} has been recovered".format(hv_name),
                                         header="SUCCESS", indentation=2)

                else:
                    self.logger_run.warning("[PARSING][AMCACHE][YARP] The hive {} has NOT been recovered".format(hv_name),
                                         header="SUCCESS", indentation=2)

                with open(output_jsonl_path, "w", encoding="utf-8") as f_jsonl:
                    root_key = hive.root_key()

                    # Écrire un objet pour la ruche elle-même
                    hive_info = {
                        "last_written": hive.last_written_timestamp().isoformat() if hive.last_written_timestamp() else None,
                        "last_reorganized": hive.last_reorganized_timestamp().isoformat() if hive.last_reorganized_timestamp() else None,
                    }
                    f_jsonl.write(json.dumps(hive_info, ensure_ascii=False) + "\n")

                    # Commencer le parcours récursif à partir de la clé racine
                    self._recursively_write_key(root_key, f_jsonl)

                self.logger_run.info("[PARSING][AMCACHE][YARP]" , header="FINISHED", indentation=2)
                return True

        except Exception as e:
            self.logger_run.error(
                "[PARSING][AMCACHE][YARP]: An unexpected error occurred{}".format(traceback.format_exc()),
                header="ERROR", indentation=2)
            return False

    def parse_all_hives_yarp(self, dir_to_reg, out_folder):
        """
        Main function to parse all hives with regipy.

        :param dir_to_reg: str: Path to the folder containing all hives to parse.
        :param out_folder: str: Path to the result folder.
        """
        # Define a dictionary to map a regex pattern to the parsing function
        hive_parterns = [
            r'SECURITY$',
            r'SYSTEM$',
            r'SAM$',
            r'NTUSER.DAT$',
            r'UsrClass.dat$',
            r'SOFTWARE$',
        ]

        for pattern in hive_parterns:
            l_res = self.recursive_file_search(dir_to_reg, pattern)
            for res in l_res:
                self.export_hive_to_jsonl(res, out_folder)

        self.export_amcache_to_jsonl(dir_to_reg, out_folder)

    def recursive_file_search(self, input_dir, reg_ex):
        files = []
        for element in os.listdir(input_dir):
            full_path = os.path.join(input_dir, element)
            if os.path.isfile(full_path):
                if re.search(reg_ex, element):  # ,  re.IGNORECASE):
                    if full_path not in files:
                        files.append(full_path)
            elif os.path.isdir(full_path):
                files.extend(self.recursive_file_search(full_path, reg_ex))
        return files

class LinkParser:
    """
    Class to parse lnk files and extract key information.
    """

    def __init__(self, logger_run, dir_out, separator="|") -> None:
        """
        The constructor for LnkParser Class.
        :param logger_run: Logger object for logging messages.
        :param dir_out: (str) The directory path to store output files.
        :param separator: (str) The delimiter for the CSV output file.
        """
        self.logger_run = logger_run
        self.dir_out = Path(dir_out)
        self.separator = separator

        self.lnk_header = ["CreationTime", "AccessTime", "ModifiedTime", "Target/Path/Description", "lnkName"]
        self.lnk_result_csv_path = os.path.join(self.dir_out,"lnk_parsed.csv")

        # Initialise the CSV writer
        self.csv_file = open(self.lnk_result_csv_path, 'w', newline='', encoding='utf-8')
        self.csv_writer = csv.writer(self.csv_file, delimiter=self.separator)
        self.csv_writer.writerow(self.lnk_header)

    def __del__(self):
        """
        Ensure the CSV file is closed when the object is destroyed.
        """
        if hasattr(self, 'csv_file') and not self.csv_file.closed:
            self.csv_file.close()

    def parse_lnk_to_json(self, file_path: Path):
        """
        Parses a single lnk file and saves its data to a JSON file and a CSV file.
        :param file_path: (str) Path to the lnk file.
        """
        lnk_name = Path(file_path).name
        path_out_json = os.path.join(self.dir_out,"{}.json".format(Path(file_path).stem))

        try:
            with open(file_path, 'rb') as file_in:
                lnk = LnkParse3.lnk_file(file_in)
                lnk_data = lnk.get_json()

            if lnk_data:
                self.parse_lnk_json_to_csv(lnk_data, lnk_name)

                with open(path_out_json, "w") as outfile:
                    json.dump(lnk_data, outfile, indent=4, default=str)

        except Exception as e:
            self.logger_run.error("[PARSING][LNK] Could not parse {}: {}".format(file_path, traceback.format_exc()),
                                  header="ERROR", indentation=1)


    def parse_all_lnk(self, input_dir: Path):
        """
        Recursively searches for all .lnk files in a directory and parses them.
        :param input_dir: (Path) The root directory to search.
        """
        lnk_files = Path(input_dir).rglob("*.lnk")
        for file_path in lnk_files:
            self.parse_lnk_to_json(file_path)

    def parse_lnk_json_to_csv(self, lnk_as_json: dict, file_name: str):
        """
        Extracts key info from the JSON data and writes it as a row to the CSV file.
        :param lnk_as_json: (dict) Dictionary containing the lnk info.
        :param file_name: (str) The name of the lnk file.
        """
        try:
            creation_time = lnk_as_json.get("header", {}).get("creation_time", "-")
            accessed_time = lnk_as_json.get("header", {}).get("accessed_time", "-")
            modified_time = lnk_as_json.get("header", {}).get("modified_time", "-")

            local_path = (
                    lnk_as_json.get("link_info", {}).get("local_base_path") or
                    lnk_as_json.get("extra", {}).get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK", {}).get("target_ansi") or
                    lnk_as_json.get("data", {}).get("description", "-")
            )

            row = [creation_time, accessed_time, modified_time, local_path, file_name]
            self.csv_writer.writerow(row)
        except Exception as e:
            self.logger_run.error("[PARSING][LNK] Could not parse {}: {}".format(file_name, traceback.format_exc()),
                                  header="ERROR", indentation=1)

class PrefetchParser:
    """
       Class parse prefetch
    """

    def __init__(self, logger_run) -> None:
        """
        The constructor for PrefetchParser class.
        """
        self.logger_run = logger_run
        self.output = {}

    # Parse individual file. Output is placed in 'output' dictionary
    def parse_file(self, pf_file, volume_information):
        try:
            scca = pyscca.open(pf_file)
            last_run_times = []
            for x in range(8):
                if scca.get_last_run_time_as_integer(x) > 0:
                    last_run_times.append(scca.get_last_run_time(x).strftime("%Y-%m-%d %H:%M:%S")) #str conversion utilized to change from datetime into human-readable
                else:
                    last_run_times.append('N/A')
            self.output[str(scca.executable_filename)] = [str(scca.run_count), format(scca.prefetch_hash, 'x').upper(), last_run_times]

            if volume_information:
                self.output[str(scca.executable_filename)].append(scca.number_of_volumes)
                volumes = []
                for i in range(scca.number_of_volumes):
                    volume = [str(scca.get_volume_information(i).device_path), scca.get_volume_information(i).creation_time.strftime("%Y-%m-%d %H:%M:%S"), format(scca.get_volume_information(i).serial_number,'x').upper()]
                    volumes.append(volume)

                self.output[str(scca.executable_filename)].append(volumes)
            return self.output
        except IOError:
            self.logger_run.warning("[PARSING][PREFETCH] {}".format(traceback.format_exc()), header="WARNING",
                                  indentation=2)
        except:
            self.logger_run.error("[PARSING][PREFETCH] {}".format(traceback.format_exc()), header="ERROR", indentation=2)


    # Parse an entire directory of Prefetch files. Note that it searches based on .pf extension
    def parse_dir(self, directo, volume_information):
        for item in os.listdir(directo):
            if item.endswith(".pf"):  # Only focus on .pf files
                self.parse_file(os.path.join(directo, item), volume_information)
            else:
                continue
        return self.output

    def outputResults(self, output, output_file=None, output_type=None, volume_information=False):
        if output_type:
            for k, v in output.items():
                json_output = {
                    'Executable Name' : k,
                    'Run Count' : v[0],
                    'Prefetch Hash' :  v[1],
                }
                #Let the script iterate through run times for us, instead of just dumping a list
                run_list = {}
                for i in range(8):
                    run_list['Run Time {}'.format(i)] = v[2][i]

                json_output['Run Times'] = run_list
                # Logic to include volume information if its requested by the analyst
                if volume_information:
                    volume_list = {}
                    for i in range(v[3]):
                        volume_info = {
                            'Volume Name' : v[4][i][0],
                            'Creation Time' : v[4][i][1],
                            'Serial Number' : v[4][i][2]
                        }
                        volume_list['Volume {}'.format(i)] = volume_info

                    volumes = {
                        'Number of Volumes' : v[3],
                        'Volume Information' : volume_list
                    }
                    json_output['Volumes'] = volumes

                if output_file:
                    with open(output_file, 'w') as file:
                        json.dump(json_output, file)
                else:
                    print(json.dumps(json_output, indent=4, sort_keys=True))
        else:
            if output_file:
                f = open(output_file, 'a')  # opens file for writing (erases contents)
                csv_out = csv.writer(f, delimiter="|")
            else:
                csv_out = csv.writer(sys.stdout, delimiter="|")

            headers = ['Executable Name', 'Run Count', 'Prefetch Hash']
            for i in range(8): # Loop through numbers to create headers
                headers.append('Last Run Time {}'.format(i))
            # Check to see if we want volume information
            # TODO: Make this section more efficient
            if volume_information:
                # Add in number of volumes header
                headers.append('Number of Volumes')

                # Need to get the max value of the number of volumes, and create our headers accordingly. Note that some files will have less volumes than others, and will have blank cells where appropriate
                volume_count = []
                for k, v in output.items():
                    volume_count.append(v[3])
                for i in range(max(volume_count)):
                    # Adding in volume-specific headers one-by-one, simply to avoid list formatting in the CSV output
                    headers.append(str('Volume {} Name').format(i))
                    headers.append(str('Volume {} Creation Time').format(i))
                    headers.append(str('Volume {} Serial Number').format(i))

            csv_out.writerow(headers)
            for k, v in output.items():
                row = [k, v[0], v[1]]
                for i in range(8): # Loop through range again to get each sub-value for times
                    row.append(v[2][i])
                if volume_information:
                    row.append(v[3])
                    for i in range(v[3]):
                        #Iterate through each volume information list to include values
                        for j in range(3):
                            row.append(v[4][i][j])
                csv_out.writerow(row)

class MaximumPlasoParserJson:
    """
       Class MaximumPlasoParser
       MPP or MaximumPlasoParser is a python script that will parse a plaso - Log2Timeline json timeline file.
       The goal is to provide easily readable and straight forward files for the Forensic analyst.
       MPP will create a file for each artefact.
       Attributes :
       None
    """

    def __init__(self, path_to_timeline, output_directory, output_type="csv", separator="|", case_name=None,
                 config_file=None,
                 machine_name="", init_dir=True) -> None:
        """
        Constructor for the MaximumPlasoParser Class

        :param output_directory: (str) directory where the results file will be written
        :param output_type: (str) output format, can be csv or json
        :param separator: (str) separator for csv output file
        :param case_name:  (str) name that will be set into json result files (for practical purpose with elk)
        :param config_file: (str) full path to a json file containing a configuration
        """
        self.path_to_timeline = path_to_timeline
        self.dir_out = output_directory
        self.output_type = output_type.lower()
        self.separator = separator
        self.case_name = case_name
        if machine_name:
            self.machine_name = machine_name
        else:
            self.machine_name = "no_name"

        self.current_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        self.work_dir = os.path.join(os.path.abspath(self.dir_out), "mpp_{}_{}".format(self.machine_name, self.current_date))
        self.csv_dir = os.path.join(self.work_dir, "csv_results")
        self.json_dir = os.path.join(self.work_dir, "json_results")
        if init_dir:
            self.initialise_working_directories()

        if config_file:
            self.config = self.read_json_config(config_file)
        else:
            self.config = {
                "user_logon_id4624": 1,
                "user_failed_logon_id4625": 1,
                "user_special_logon_id4672": 1,
                "user_explicit_logon_id4648": 1,
                "new_proc_file_id4688": 1,
                "windows_Start_Stop": 1,
                "task_scheduler": 1,
                "remote_rdp": 1,
                "local_rdp": 1,
                "bits": 1,
                "service": 1,
                "powershell": 1,
                "powershell_script": 1,
                "wmi": 1,
                "app_exp": 1,
                "amcache": 1,
                "app_compat": 1,
                "sam": 1,
                "user_assist": 1,
                "mru": 1,
                "ff_history": 1,
                "edge_history": 1,
                "chrome_history": 1,
                "prefetch": 1,
                "srum": 1,
                "run": 1,
                "lnk": 1,
                "mft": 1,
                "windefender": 1,
                "common_registry_key": 1,
                "windows_info": 1,
                "timeline": 1
            }

        self.d_regex_type_artefact = {
            "evtx": re.compile(r'winevtx'),
            "hive": re.compile(r'winreg'),
            "db": re.compile(r'(sqlite)|(esedb)'),
            "winFile": re.compile(r'(lnk)|(text)|(prefetch)'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)')
        }
        self.d_regex_aterfact_by_file_name = {
            "security": re.compile(r'((s|S)ecurity\.evtx|(s|S)ecurity\.evt)'),
            "system": re.compile(r'((s|S)ystem\.evtx|(s|S)ystem\.evt)'),
            "taskScheduler": re.compile(r'.*TaskScheduler%4Operational\.evtx'),
            "bits": re.compile(r'.*Bits-Client%4Operational\.evtx'),
            "rdp_local": re.compile(r'.*TerminalServices-LocalSessionManager%4Operational\.evtx'),
            "rdp_remot": re.compile(r'.*TerminalServices-RemoteConnectionManager%4Operational\.evtx'),
            "powershell": re.compile(
                r'(.*Microsoft-Windows-PowerShell%4Operational\.evtx)|(.*Windows_PowerShell\.evtx)'),
            "wmi": re.compile(r'.*Microsoft-Windows-WMI-Activity%4Operational\.evtx'),
            "application_experience": re.compile(
                r'.*Microsoft-Windows-Application-Experience%4Program-Telemetry\.evtx'),
            "amcache": re.compile(r'.*(A|a)mcache\.hve'),
            "appCompat": re.compile(r'.*(A|a)mcache\.hve')
        }
        self.d_regex_artefact_by_source_name = {
            "security": re.compile(r'Microsoft-Windows-Security-Auditing'),
            "system": re.compile(r'Service Control Manager'),
            "taskScheduler": re.compile(r'Microsoft-Windows-TaskScheduler'),
            "bits": re.compile(r'Microsoft-Windows-Bits-Client'),
            "rdp_local": re.compile(r'Microsoft-Windows-TerminalServices-LocalSessionManager'),
            "rdp_remote": re.compile(r'Microsoft-Windows-TerminalServices-RemoteConnectionManager'),
            "powershell": re.compile(r'(Microsoft-Windows-PowerShell)|(PowerShell)'),
            "wmi": re.compile(r'Microsoft-Windows-WMI-Activity'),
            "application_experience": re.compile(r'Microsoft-Windows-Application-Experience'),
            "windefender": re.compile(r'Microsoft-Windows-Windows Defender')
            # .*Microsoft-Windows-Windows_Defender%4Operational
        }
        self.d_regex_artefact_by_parser_name = {

            "ff_history": re.compile(r'firefox'),
            "chrome_history": re.compile(r'chrome'),
            "edge_history": re.compile(r'edge'),
            "prefetch": re.compile(r'prefetch'),
            "lnk": re.compile(r'lnk'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)'),

            "winreg-srum": re.compile(r'srum'),
            "winreg-amcache": re.compile(r'amcache'),
            "winreg-appCompat": re.compile(r'appcompatcache'),
            "winreg-userassist": re.compile(r'userassist'),
            #"winreg-mru": re.compile(r'(bagmru)|(mru)'),
            "winreg-mru-shell_items": re.compile(r'winreg/bagmru/shell_items'),
            "winreg-mru-exe_shell_items_list": re.compile(r'winreg/mrulistex_shell_item_list'),
            "winreg-mru-listex_str": re.compile(r'winreg/mrulistex_string'),
            "winreg-mru-str_and_shellitem": re.compile(r'winreg/mrulistex_string_and_shell_item'),

            "winreg_default": re.compile(r'winreg/winreg_default'),
            "winreg-msie_zone": re.compile(r'winreg/msie_zone'),
            "winreg-networks": re.compile(r'winreg/networks'),
            "winreg-windows_boot_execute": re.compile(r'winreg/windows_boot_execute'),
            "winreg-windows-run": re.compile(r'winreg/windows_run'),
            "winreg-windows_sam_users": re.compile(r'winreg/windows_sam_users'),
            "winreg-windows_services": re.compile(r'winreg/windows_services'),
            "winreg-windows_shutdown": re.compile(r'winreg/windows_shutdown'),
            "winreg-windows_task_cache": re.compile(r'winreg/windows_task_cache'),
            "winreg-windows_usb_devices": re.compile(r'winreg/windows_usb_devices'),
            "winreg-windows_version": re.compile(r'winreg/windows_version'),
            "winreg-windows_timezone": re.compile(r'winreg/windows_timezone'),
            "winreg-explorer_mountpoints2": re.compile(r'winreg/explorer_mountpoints2'),
            "winreg-explorer_programscache": re.compile(r'winreg/explorer_programscache"'),
            "winreg-windows_typed_urls": re.compile(r'winreg/windows_typed_urls'),
            "winreg-winlogon": re.compile(r'winreg/winlogon')
        }

        self.l_csv_header_timeline = ["Date", "Time", "SourceArtefact", "Other"]
        self.l_csv_header_4624 = ["Date", "Time", "event_code", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port", "logon_type"]
        self.l_csv_header_4625 = ["Date", "Time", "event_code","subject_user_name",
                                  "target_user_name", "ip_address", "ip_port","logon_type","failure_reason"]
        self.l_csv_header_4672 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port"]
        self.l_csv_header_4648 = ["Date", "Time", "event_code", "logon_type", "subject_user_name",
                                  "target_user_name", "ip_address", "ip_port"]
        self.l_csv_header_4688 = ["Date", "Time", "event_code", "subject_user_name", "target_user_name",
                                  "parent_process_name", "new_process_name", "command_line"]
        self.l_csv_header_tscheduler = ["Date", "Time", "event_code", "name", "task_name", "instance_id",
                                        "action_name", "result_code", "user_name", "user_context"]
        self.l_csv_header_remote_rdp = ["Date", "Time", "event_code", "user_name", "ip_addr"]
        self.l_csv_header_local_rdp = ["Date", "Time", "event_code", "user_name", "ip_addr", "session_id",
                                       "source", "target_session", "reason_n", "reason"]
        self.l_csv_header_bits = ["Date", "Time", "event_code", "id", "job_id", "job_title", "job_owner",
                                  "user", "bytes_total", "bytes_transferred", "file_count", "file_length", "file_Time",
                                  "name", "url", "process_path"]
        self.l_csv_header_7045 = ["Date", "Time", "event_code", "account_name", "img_path", "service_name",
                                  "start_type"]
        self.l_csv_header_powershell = ["Date", "Time", "event_code", "path_to_script", "script_block_text"]
        self.l_csv_header_script_powershell = ["Date", "Time", "event_code", "cmd"]
        self.l_csv_header_wmi = ["Date", "Time", "user", "nameSpace", "Query"]
        self.l_csv_header_app_exp = ["Date", "Time", "ExePath", "FixName", "Query"]
        self.l_csv_header_amcache = ["Date", "Time", "Name", "FullPath", "id", "Hash"]
        self.l_csv_header_appcompat = ["Date", "Time", "Name", "FullPath", "Hash"]
        self.l_csv_header_sam = ["Date", "Time", "username", "login_count"]
        self.l_csv_header_usserassit = ["Date", "Time", "valueName", "appFocus", "appDuration"]
        self.l_csv_header_mru = ["Date", "Time", "TYPE", "NAME", "entries"]
        self.l_csv_header_srum = ["Date", "Time", "description"]
        self.l_csv_header_run = ["Date", "Time", "entrie"]
        self.l_csv_header_comon_reg = ["Date", "Time", "type", "other"]
        self.l_csv_header_mui_cache = ["Date", "Time", "type", "name", "data"]
        self.l_csv_header_ff_history = ["Date", "Time", "type", "url", "visit_count", "visit_type", "isType", "from_visit"]
        self.l_csv_header_edge_history = ["Date", "Time", "type", "url", "visit_count", "visit_type", "isType", "from_visit"]
        self.l_csv_header_chrome_history = ["Date", "Time", "type", "url", "visit_count", "visit_type", "isType", "from_visit"]
        self.l_csv_header_prefetch = ["Date", "Time", "name", "path", "nbExec", "sha256"]
        self.l_csv_header_lnk = ["Date", "Time", "description", "working_dir"]
        self.l_csv_header_mft = ["Date", "Time", "source","fileType", "action", "fileName"]
        self.l_csv_header_windefender = ["Date", "Time", "Event", "ThreatName", "Severity", "User", "ProcessName",
                                         "Path", "Action"]
        self.l_csv_header_start_stop = ["Date", "Time", "message"]
        self.l_csv_header_mru_run = ["Date", "Time", "cmd"]

        self.amcache_res_file_csv = ""
        self.app_exp_file_csv = ""
        self.app_compat_res_file_csv = ""
        self.bits_file_csv = ""
        self.chrome_history_res_file_csv = ""
        self.common_reg_file_csv = ""
        self.ff_history_res_file_csv = ""
        self.ie_history_res_file_csv = ""
        self.local_rdp_file_csv = ""
        self.logon_res_file_csv = ""
        self.logon_failed_file_csv = ""
        self.logon_spe_file_csv = ""
        self.logon_exp_file_csv = ""
        self.lnk_res_file_csv = ""
        self.mft_res_file_csv = ""
        self.mru_res_file_csv = ""
        self.mui_res_file_csv = ""
        self.new_proc_file_csv = ""
        self.powershell_file_csv = ""
        self.powershell_script_file_csv = ""
        self.prefetch_res_file_csv = ""
        self.remote_rdp_file_csv = ""
        self.run_res_file_csv = ""
        self.sam_res_file_csv = ""
        self.service_file_csv = ""
        self.srum_res_file_csv = ""
        self.task_scheduler_file_csv = ""
        self.timeline_file_csv = ""
        self.user_assist_file_csv = ""
        self.windows_general_info_csv = ""
        self.windefender_res_file_csv = ""
        self.windows_start_stop_res_file_csv = ""
        self.wmi_file_csv = ""

        self.amcache_res_file_json = ""
        self.app_compat_res_file_json = ""
        self.app_exp_file_json = ""
        self.bits_file_json = ""
        self.chrome_history_res_file_json = ""
        self.common_reg_file_json = ""
        self.ff_history_res_file_json = ""
        self.ie_history_res_file_json = ""
        self.logon_res_file_json = ""
        self.logon_failed_file_json = ""
        self.logon_spe_file_json = ""
        self.logon_exp_file_json = ""
        self.local_rdp_file_json = ""
        self.lnk_res_file_json = ""
        self.mft_res_file_json = ""
        self.mru_res_file_json = ""
        self.mui_res_file_json = ""
        self.new_proc_file_json = ""
        self.powershell_file_json = ""
        self.powershell_script_file_json = ""
        self.prefetch_res_file_json = ""
        self.remote_rdp_file_json = ""
        self.run_res_file_json = ""
        self.sam_res_file_json = ""
        self.service_file_json = ""
        self.srum_res_file_json = ""
        self.task_scheduler_file_json = ""
        self.timeline_file_json = ""
        self.user_assist_file_json = ""
        self.windefender_res_file_json = ""
        self.windows_general_info_json = ""
        self.windows_start_stop_res_file_json = ""
        self.wmi_file_json = ""
        if init_dir:
            self.initialise_results_files()


    def initialise_working_directories(self):
        """
        To create directories where the results will be written
        :return:
        """
        try:
            # print("creating {}".format(self.work_dir))
            os.makedirs(self.work_dir, exist_ok=True)
            if self.output_type == "csv" or self.output_type == "all":
                os.makedirs(self.csv_dir, exist_ok=True)
            if self.output_type == "json" or self.output_type == "all":
                os.makedirs(self.json_dir, exist_ok=True)

            print("result directory is located at : {}".format(self.work_dir))
        except:
            sys.stderr.write("\nfailed to initialises directories {}\n".format(traceback.format_exc()))

    @staticmethod
    def read_json_config(path_to_config):
        """
        Function to read and load a json file into a dict
        :param path_to_config: (str) full path to a json file
        :return: (dict) dict containing the content of the json file
        """
        with open(path_to_config, 'r') as config:
            return json.load(config)

    @staticmethod
    def convert_epoch_to_date(epoch_time):
        """
        Function to convert an epoch time (nanoseconds) into date and time.
        Split into 2 variable date and time
        :param epoch_time: (int) epoch time to be converted
        :return:
        (str) date in format %Y-%m-%d
        (str) time in format %H:%M:%S
        """
        dt = datetime.fromtimestamp(epoch_time / 1000000).strftime('%Y-%m-%dT%H:%M:%S.%f')
        l_dt = dt.split("T")
        return l_dt[0], l_dt[1]

    def initialise_result_file_csv(self, header, file_name, extension="csv"):
        """
        initialise a result file, write the header into it and return a stream to this file
        :param header: (list[str]) list containing all column name
        :param file_name: (str) the name of the file containing
        :param extension: (str) the name of the extension of the file
        :return: stream to a file
        """
        result_file_stream = open(os.path.join(self.csv_dir, "{}.{}".format(file_name, extension)), 'a')
        result_file_stream.write(self.separator.join(header))
        result_file_stream.write("\n")
        return result_file_stream

    def initialise_result_file_json(self, file_name, extension="json"):
        """
        initialise a result file, write the header into it and return a stream to this file
        :param file_name: (str) the name of the file containing
        :param extension: (str) the name of the extension of the file
        :return: stream to a file
        """
        result_file_stream = open(os.path.join(self.json_dir, "{}.{}".format(file_name, extension)), 'a')
        return result_file_stream

    def initialise_results_files(self):
        if self.output_type in ["all", "csv"]:
            self.initialise_results_files_csv()
        if self.output_type in ["all", "json"]:
            self.initialise_results_files_json()

    def initialise_results_files_csv(self):
        """
        Function that will initialise all csv result file.
        It will open a stream to all results file and write header into it.
        Stream are keeped open to avoid opening and closing multiple file every new line of the timeline
        :return: None
        """

        if self.config.get("windows_info", 0):
            self.windows_general_info_csv = self.initialise_result_file_csv([], "windows_general_info")

        # ----------------------------- EVTX ------------------------------------------------
        if self.config.get("user_logon_id4624", 0):
            self.logon_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_4624, "4624usrLogon")
        if self.config.get("user_failed_logon_id4625", 0):
            self.logon_failed_file_csv = self.initialise_result_file_csv(self.l_csv_header_4625,
                                                                         "4625usrFailLogon")
        if self.config.get("user_special_logon_id4672", 0):
            self.logon_spe_file_csv = self.initialise_result_file_csv(self.l_csv_header_4672,
                                                                      "4672usrSpeLogon")
        if self.config.get("user_explicit_logon_id4648", 0):
            self.logon_exp_file_csv = self.initialise_result_file_csv(self.l_csv_header_4648,
                                                                      "4648usrExpLogon")
        if self.config.get("new_proc_file_id4688", 0):
            self.new_proc_file_csv = self.initialise_result_file_csv(self.l_csv_header_4688,
                                                                     "4688newProc")
        if self.config.get("windows_Start_Stop", 0):
            self.windows_start_stop_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_start_stop,
                                                                                   "winStartStop")
        if self.config.get("task_scheduler", 0):
            self.task_scheduler_file_csv = self.initialise_result_file_csv(self.l_csv_header_tscheduler,
                                                                           "taskScheduler")

        if self.config.get("remote_rdp", 0):
            self.remote_rdp_file_csv = self.initialise_result_file_csv(self.l_csv_header_remote_rdp,
                                                                       "rdpRemote")

        if self.config.get("local_rdp", 0):
            self.local_rdp_file_csv = self.initialise_result_file_csv(self.l_csv_header_local_rdp,
                                                                      "rdpLocal")
        if self.config.get("bits", 0):
            self.bits_file_csv = self.initialise_result_file_csv(self.l_csv_header_bits, "bits")

        if self.config.get("service", 0):
            self.service_file_csv = self.initialise_result_file_csv(self.l_csv_header_7045, "7045newService")

        if self.config.get("powershell", 0):
            self.powershell_file_csv = self.initialise_result_file_csv(self.l_csv_header_powershell,
                                                                       "powershell")
        if self.config.get("powershell_script", 0):
            self.powershell_script_file_csv = self.initialise_result_file_csv(self.l_csv_header_script_powershell,
                                                                              "powershellScript")

        if self.config.get("wmi", 0):
            self.wmi_file_csv = self.initialise_result_file_csv(self.l_csv_header_wmi, "wmi")

        # ----------------------------- Hives ------------------------------------------------

        if self.config.get("app_exp"):
            self.app_exp_file_csv = self.initialise_result_file_csv(self.l_csv_header_app_exp,
                                                                    "applicationExperience")

        if self.config.get("amcache"):
            self.amcache_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_amcache, "amcache")

        if self.config.get("app_compat"):
            self.app_compat_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_appcompat,
                                                                           "app_compat_cache")

        if self.config.get("sam"):
            self.sam_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_sam, "sam")

        if self.config.get("user_assist"):
            self.user_assist_file_csv = self.initialise_result_file_csv(self.l_csv_header_usserassit, "usrAssist")

        if self.config.get("mru"):
            self.mru_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_mru, "mru")

        if self.config.get("srum"):
            self.srum_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_srum, "srum")

        if self.config.get("run"):
            self.run_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_run, "runKey")

        if self.config.get("common_registry_key"):
            self.common_reg_file_csv = self.initialise_result_file_csv(self.l_csv_header_comon_reg, "common_registry")
            self.mui_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_mui_cache, "mui_cache")

        # ----------------------------- Other ------------------------------------------------

        if self.config.get("ff_history"):
            self.ff_history_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_ff_history, "ff_history")

        if self.config.get("edge_history"):
            self.ie_history_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_edge_history, "edge_History")

        if self.config.get("chrome_history"):
            self.chrome_history_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_chrome_history, "chrome_History")

        if self.config.get("prefetch"):
            self.prefetch_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_prefetch, "prefetch")

        if self.config.get("lnk"):
            self.lnk_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_lnk, "lnk")

        if self.config.get("mft"):
            self.mft_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_mft, "mft")

        if self.config.get("windefender"):
            self.windefender_res_file_csv = self.initialise_result_file_csv(self.l_csv_header_windefender,
                                                                            "windefender")

    def initialise_results_files_json(self):
        """
        Function that will initialise all csv result file.
        It will open a stream to all results file and write header into it.
        Stream are keeped open to avoid opening and closing multiple file every new line of the timeline
        :return: None
        """

        if self.config.get("windows_info", 0):
            self.windows_general_info_json = self.initialise_result_file_json("windows_general_info")

        if self.config.get("user_logon_id4624", 0):
            self.logon_res_file_json = self.initialise_result_file_json("user_logon_id4624")

        if self.config.get("user_failed_logon_id4625", 0):
            self.logon_failed_file_json = self.initialise_result_file_json("user_failed_logon_id4625")

        if self.config.get("user_special_logon_id4672", 0):
            self.logon_spe_file_json = self.initialise_result_file_json("user_special_logon_id4672")

        if self.config.get("user_explicit_logon_id4648", 0):
            self.logon_exp_file_json = self.initialise_result_file_json("user_explicit_logon_id4648")

        if self.config.get("new_proc_file_id4688", 0):
            self.new_proc_file_json = self.initialise_result_file_json("new_proc_file_id4688")

        if self.config.get("windows_Start_Stop", 0):
            self.windows_start_stop_res_file_json = self.initialise_result_file_json("windows_start_stop")

        if self.config.get("task_scheduler", 0):
            self.task_scheduler_file_json = self.initialise_result_file_json("task_scheduler")

        if self.config.get("remote_rdp", 0):
            self.remote_rdp_file_json = self.initialise_result_file_json("remote_rdp")

        if self.config.get("local_rdp", 0):
            self.local_rdp_file_json = self.initialise_result_file_json("local_rdp")

        if self.config.get("bits", 0):
            self.bits_file_json = self.initialise_result_file_json("bits")

        if self.config.get("service", 0):
            self.service_file_json = self.initialise_result_file_json("7045")

        if self.config.get("powershell", 0):
            self.powershell_file_json = self.initialise_result_file_json("powershell")

        if self.config.get("powershell_script", 0):
            self.powershell_script_file_json = self.initialise_result_file_json("powershell_script")

        if self.config.get("wmi", 0):
            self.wmi_file_json = self.initialise_result_file_json("wmi")

        # ----------------------------- Hives ------------------------------------------------

        if self.config.get("app_exp"):
            self.app_exp_file_json = self.initialise_result_file_json("application_experience")

        if self.config.get("amcache"):
            self.amcache_res_file_json = self.initialise_result_file_json("amcache")

        if self.config.get("app_compat"):
            self.app_compat_res_file_json = self.initialise_result_file_json("app_compat_cache")
        if self.config.get("sam"):
            self.sam_res_file_json = self.initialise_result_file_json("sam")

        if self.config.get("user_assist"):
            self.user_assist_file_json = self.initialise_result_file_json("user_assist")

        if self.config.get("mru"):
            self.mru_res_file_json = self.initialise_result_file_json("mru")

        if self.config.get("srum"):
            self.srum_res_file_json = self.initialise_result_file_json("srum")

        if self.config.get("run"):
            self.run_res_file_json = self.initialise_result_file_json("run_key")

        if self.config.get("common_reg"):
            self.common_reg_file_json = self.initialise_result_file_json("common_registry")
            self.mui_res_file_json= self.initialise_result_file_json("mui_cache")

        # ----------------------------- Other ------------------------------------------------

        if self.config.get("ff_history"):
            self.ff_history_res_file_json = self.initialise_result_file_json("ff_history")

        if self.config.get("ie_history"):
            self.ie_history_res_file_json = self.initialise_result_file_json("ie_history")

        if self.config.get("chrome_history"):
            self.chrome_history_res_file_json = self.initialise_result_file_json("chrome_history")

        if self.config.get("prefetch"):
            self.prefetch_res_file_json = self.initialise_result_file_json("prefetch")

        if self.config.get("lnk"):
            self.lnk_res_file_json = self.initialise_result_file_json("lnk")

        if self.config.get("mft"):
            self.mft_res_file_json = self.initialise_result_file_json("mft")

        if self.config.get("windefender"):
            self.windefender_res_file_json = self.initialise_result_file_json("windefender")

    def identify_type_artefact_by_parser(self, line):
        """
        Function to indentify an artefact type depending on the plaso parser used
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the parser
        """
        for key, value in self.d_regex_type_artefact.items():
            if re.search(value, line.get("parser")):
                return key

    def identify_artefact_by_parser_name(self, line):
        """
        Function to indentify an artefact depending on the plaso parser used
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the parser
        """
        for key, value in self.d_regex_artefact_by_parser_name.items():
            if re.search(value, line.get("parser")):
                return key

    def identify_artefact_by_filename(self, line):
        """
        Function to indentify an artefact type depending on the name of the file that was parsed
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the filename
        """
        for key, value in self.d_regex_aterfact_by_file_name.items():
            if re.search(value, line.get("filename")):
                return key

    def identify_artefact_by_source_name(self, line):
        """
        Function to indentify an artefact type depending on the source type of the file that was parsed
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the source name
        """
        for key, value in self.d_regex_artefact_by_source_name.items():
            if re.search(value, line.get("source_name")):
                return key

    def assign_parser(self, line, type_artefact):
        """
        Function to assign a parser depending on the artefact type
        :param line: (dict) dict containing one line of the plaso timeline,
        :param type_artefact: (str) type of artefact
        :return: None
        """
        # print('type artefact is {}'.format(type_artefact))
        if type_artefact == "evtx":
            self.parse_logs(line)
        if type_artefact == "hive":
            self.parse_hives(line)
        if type_artefact == "db":
            self.parse_db(line)
        if type_artefact == "winFile":
            self.parse_win_file(line)
        if type_artefact == "mft":
            self.parse_mft(line)

    def close_files_leg(self):
        """
        Function to close all opened stream
        :return:
        """
        self.timeline_file_csv.close()
        self.logon_res_file.close()
        self.logon_failed_file.close()
        self.logon_spe_file.close()
        self.new_proc_file.close()
        self.logon_exp_file.close()
        self.task_scheduler_file.close()
        self.remote_rdp_file.close()
        self.local_rdp_file.close()
        self.bits_file.close()
        self.service_file.close()
        self.powershell_file.close()
        self.powershell_script_file.close()
        self.wmi_file.close()
        self.app_exp_file.close()

        self.amcache_res_file.close()
        self.app_compat_res_file.close()
        self.sam_res_file.close()
        self.user_assist_file.close()
        self.srum_res_file.close()
        self.run_res_file.close()

        self.ff_history_res_file.close()
        self.ie_history_res_file.close()

        self.prefetch_res_file.close()
        self.lnk_res_file.close()
        self.mft_res_file.close()

    def close_files(self):
        if self.output_type in ["all", "csv"]:
            self.close_files_csv()
        if self.output_type in ["all", "json"]:
            self.close_files_json()

    def close_files_csv(self):
        """
        Function to close all opened stream
        :return:
        """

        if self.logon_res_file_csv:
            self.logon_res_file_csv.close()
        if self.logon_failed_file_csv:
            self.logon_failed_file_csv.close()
        if self.logon_spe_file_csv:
            self.logon_spe_file_csv.close()
        if self.logon_exp_file_csv:
            self.logon_exp_file_csv.close()
        if self.windows_start_stop_res_file_csv:
            self.windows_start_stop_res_file_csv.close()
        if self.task_scheduler_file_csv:
            self.task_scheduler_file_csv.close()
        if self.remote_rdp_file_csv:
            self.remote_rdp_file_csv.close()
        if self.local_rdp_file_csv:
            self.local_rdp_file_csv.close()
        if self.bits_file_csv:
            self.bits_file_csv.close()
        if self.service_file_csv:
            self.service_file_csv.close()
        if self.powershell_file_csv:
            self.powershell_file_csv.close()
        if self.powershell_script_file_csv:
            self.powershell_script_file_csv.close()
        if self.wmi_file_csv:
            self.wmi_file_csv.close()
        if self.app_exp_file_csv:
            self.app_exp_file_csv.close()

        if self.amcache_res_file_csv:
            self.amcache_res_file_csv.close()
        if self.app_compat_res_file_csv:
            self.app_compat_res_file_csv.close()
        if self.sam_res_file_csv:
            self.sam_res_file_csv.close()
        if self.user_assist_file_csv:
            self.user_assist_file_csv.close()
        if self.srum_res_file_csv:
            self.srum_res_file_csv.close()
        if self.run_res_file_csv:
            self.run_res_file_csv.close()

        if self.ff_history_res_file_csv:
            self.ff_history_res_file_csv.close()
        if self.ie_history_res_file_csv:
            self.ie_history_res_file_csv.close()

        if self.chrome_history_res_file_csv:
            self.chrome_history_res_file_csv.close()
        if self.prefetch_res_file_csv:
            self.prefetch_res_file_csv.close()
        if self.lnk_res_file_csv:
            self.lnk_res_file_csv.close()
        if self.mft_res_file_csv:
            self.mft_res_file_csv.close()

    def close_files_json(self):
        """
        Function to close all opened stream
        :return:
        """
        if self.logon_res_file_json:
            self.logon_res_file_json.close()
        if self.logon_failed_file_json:
            self.logon_failed_file_json.close()
        if self.logon_spe_file_json:
            self.logon_spe_file_json.close()
        if self.logon_exp_file_json:
            self.logon_exp_file_json.close()
        if self.windows_start_stop_res_file_json:
            self.windows_start_stop_res_file_json.close()
        if self.task_scheduler_file_json:
            self.task_scheduler_file_json.close()
        if self.remote_rdp_file_json:
            self.remote_rdp_file_json.close()
        if self.local_rdp_file_json:
            self.local_rdp_file_json.close()
        if self.bits_file_json:
            self.bits_file_json.close()
        if self.service_file_json:
            self.service_file_json.close()
        if self.powershell_file_json:
            self.powershell_file_json.close()
        if self.powershell_script_file_json:
            self.powershell_script_file_json.close()
        if self.wmi_file_json:
            self.wmi_file_json.close()
        if self.app_exp_file_json:
            self.app_exp_file_json.close()

        if self.amcache_res_file_json:
            self.amcache_res_file_json.close()
        if self.app_compat_res_file_json:
            self.app_compat_res_file_json.close()
        if self.sam_res_file_json:
            self.sam_res_file_json.close()
        if self.user_assist_file_json:
            self.user_assist_file_json.close()
        if self.srum_res_file_json:
            self.srum_res_file_json.close()
        if self.run_res_file_json:
            self.run_res_file_json.close()

        if self.ff_history_res_file_json:
            self.ff_history_res_file_json.close()
        if self.ie_history_res_file_json:
            self.ie_history_res_file_json.close()
        if self.chrome_history_res_file_json:
            self.chrome_history_res_file_json.close()
        if self.prefetch_res_file_json:
            self.prefetch_res_file_json.close()
        if self.lnk_res_file_json:
            self.lnk_res_file_json.close()
        if self.mft_res_file_json:
            self.mft_res_file_json.close()

    def parse_timeline(self):
        """
        Main function to parse the plaso timeline
        :param path_to_tl: (str) full path to the timeline
        :return: None
        """
        try:
            with open(self.path_to_timeline) as timeline:
                for line in timeline:
                    try:
                        d_line = json.loads(line)
                    except:
                        print("could not load json line, skiping line")
                        print(traceback.format_exc())
                        continue
                    type_artefact = self.identify_type_artefact_by_parser(d_line)
                    if type_artefact:
                        self.assign_parser(d_line, type_artefact)

            self.close_files()
            self.clean_duplicates(self.work_dir)
            if self.config.get("timeline", 0):
                self.create_timeline()

        except Exception as ex:
            print("error with parsing")
            print("error is {}".format(traceback.format_exc()))
            self.close_files()

    #  -------------------------------------------------------------  Logs ---------------------------------------------

    def parse_logs(self, line):
        """
        Main function to parse log type artefacts
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        log_type = self.identify_artefact_by_source_name(line)
        if log_type == "security":
            self.parse_security_evtx(line)
        if log_type == "taskScheduler":
            self.parse_task_scheduler(line)
        if log_type == "bits":
            self.parse_bits(line)
        if log_type == "system":
            self.parse_system_evtx(line)
        if log_type == "rdp_local":
            self.parse_rdp_local(line)
        if log_type == "rdp_remote":
            self.parse_rdp_remote(line)
        if log_type == "powershell":
            self.parse_powershell(line)
        if log_type == "wmi":
            self.parse_wmi(line)
        if log_type == "application_experience":
            self.parse_app_experience(line)
        if log_type == "windefender":
            self.parse_windows_defender(line)

    #  ----------------------------------------  Wmi ---------------------------------------------
    def parse_wmi(self, event):
        """
        Main function to parse wmi type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.wmi_file_csv or self.wmi_file_json:
            if str(event_code) in ["5860", "5861"]:
                self.parse_wmi_evtx_from_xml(event)
            if str(event_code) in ["5858"]:
                self.parse_wmi_failure_from_xml(event)

    def parse_wmi_evtx_from_xml(self, event):
        """
        Function to parse wmi log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {})

        operation_name = list(event_data.keys())[0]
        op_dict = event_data.get(operation_name, {})
        namespace = op_dict.get("NamespaceName", "-")
        user = op_dict.get("User", "-")
        cause = op_dict.get("PossibleCause", "-").replace("\n", "")
        query = op_dict.get("Query", "-").replace("\n", "")
        consumer = op_dict.get("CONSUMER", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                              ts_time, self.separator,
                                                              event_code, self.separator,
                                                              operation_name, self.separator,
                                                              user, self.separator,
                                                              namespace, self.separator,
                                                              consumer, self.separator,
                                                              cause, self.separator,
                                                              query)

            self.wmi_file_csv.write(res)
            self.wmi_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "operation_name": operation_name,
                "user": user,
                "namespace": namespace,
                "consumer": consumer,
                "cause": cause,
                "query": query,
                "Artefact": "WMI"
            }
            json.dump(res, self.wmi_file_json)
            self.wmi_file_json.write('\n')

    def parse_wmi_failure_from_xml(self, event):
        """
        Function to parse wmi failure log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {})

        operation_name = list(event_data.keys())[0]
        op_dict = event_data.get(operation_name, {})
        namespace = op_dict.get("NamespaceName", "-")
        user = op_dict.get("User", "-")
        cause = op_dict.get("PossibleCause", "-").replace("\n", "")
        query = op_dict.get("Operation", "-").replace("\n", "")
        consumer = op_dict.get("CONSUMER", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                              ts_time, self.separator,
                                                              event_code, self.separator,
                                                              operation_name, self.separator,
                                                              user, self.separator,
                                                              namespace, self.separator,
                                                              consumer, self.separator,
                                                              cause, self.separator,
                                                              query)

            self.wmi_file_csv.write(res)
            self.wmi_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "operation_name": operation_name,
                "user": user,
                "namespace": namespace,
                "consumer": consumer,
                "cause": cause,
                "query": query,
                "Artefact": "WMI"
            }
            json.dump(res, self.wmi_file_json)
            self.wmi_file_json.write('\n')

    #  ----------------------------------------  RDP ---------------------------------------------
    def parse_rdp_local(self, event):
        """
        Main function to parse rdp local type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.local_rdp_file_csv or self.local_rdp_file_json:
            if str(event_code) in ["21", "24", "25", "39", "40"]:
                self.parse_rdp_local_evtx_from_xml(event)

    def parse_rdp_remote(self, event):
        """
        Main function to parse rdp remot type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.remote_rdp_file_csv or self.remote_rdp_file_json:
            if str(event_code) in ["1149"]:
                self.parse_rdp_remote_evtx_from_xml(event)

    def parse_rdp_remote_evtx_from_xml(self, event):
        """
        Function to parse remote rdp log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {}).get("EventXML", {})

        event_code = event.get("event_identifier")
        user_name = event_data.get("Param1", "-")
        ip_addr = event_data.get("Param3", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}InitConnexion{}{}{}{}".format(ts_date, self.separator,
                                                             ts_time, self.separator,
                                                             event_code, self.separator,
                                                             self.separator,
                                                             user_name, self.separator,
                                                             ip_addr)
            self.remote_rdp_file_csv.write(res)
            self.remote_rdp_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "user_name": user_name,
                "ip_address": ip_addr,
                "Artefact": "EVTX_REMOTE_RDP"
            }
            json.dump(res, self.remote_rdp_file_json)
            self.remote_rdp_file_json.write('\n')

    def parse_rdp_local_evtx_from_xml(self, event):
        """
        Function to parse local rdp log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("UserData", {}).get("EventXML", [])
        event_code = str(event.get("event_identifier"))
        user_name = event_data.get("User", "-")
        ip_addr = event_data.get("Adress", "-")
        session_id = event_data.get("SessionID", "-")
        source = event_data.get("Source", '-')
        reason_n = event_data.get("Reason", "-")
        target_session = event_data.get("", "-")

        if event_code == "21":
            reason = "AuthSuccess"
        elif event_code == "24":
            reason = "UserDisconnected"
        elif event_code == "25":
            reason = "UserReconnected"
        elif event_code == "39":
            reason = "UserHasBeenDisconnected"
        elif event_code == "40":
            reason = "UserHasBeenDisconnected"
        else:
            reason = "-"

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                                  ts_time, self.separator,
                                                                  event_code, self.separator,
                                                                  user_name, self.separator,
                                                                  ip_addr, self.separator,
                                                                  session_id, self.separator,
                                                                  source, self.separator,
                                                                  target_session, self.separator,
                                                                  reason_n, self.separator,
                                                                  reason)
            self.local_rdp_file_csv.write(res)
            self.local_rdp_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "case_name": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "event_code": event_code,
                "user_name": user_name,
                "ip_address": ip_addr,
                "session_id": session_id,
                "source": source,
                "target_session": target_session,
                "reason_n": reason_n,
                "reason": reason,
                "Artefact": "EVTX_LOCAL_RDP"
            }
            json.dump(res, self.local_rdp_file_json)
            self.local_rdp_file_json.write('\n')

    #  ----------------------------------------  Bits ---------------------------------------------

    def parse_bits(self, event):
        """
        Main function to parse bits type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        if self.bits_file_csv or self.bits_file_json:
            event_code = event.get("event_identifier")
            if str(event_code) in ["3", "4", "59", "60", "61"]:
                self.parse_bits_evtx_from_xml(event)

    def parse_bits_evtx_from_xml(self, event):
        """
        Function to parse remote bits log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        user = "-"
        identifiant = "-"
        job_owner = "-"
        job_id = "-"
        job_title = "-"
        bytes_total = "-"
        bytes_transferred = "-"
        file_count = "-"
        file_length = "-"
        file_time = "-"
        name = "-"
        url = "-"
        process_path = "-"

        for data in event_data:
            if data.get("@Name", "") == "User":
                user = data.get("#text", "-")

            elif data.get("@Name", "") == "Id":
                identifiant = data.get("#text", "-")

            elif data.get("@Name", "") == "jobOwner":
                job_owner = data.get("#text", "-")

            elif data.get("@Name", "") == "jobId":
                job_id = data.get("#text", "-")

            elif data.get("@Name", "") == "jobTitle":
                job_title = data.get("#text", "-")

            elif data.get("@Name", "") == "bytesTotal":
                bytes_total = data.get("#text", "-")

            elif data.get("@Name", "") == "bytesTransferred":
                bytes_transferred = data.get("#text", "-")

            elif data.get("@Name", "") == "fileCount":
                file_count = data.get("#text", "-")

            elif data.get("@Name", "") == "fileLength":
                file_length = data.get("#text", "-")

            elif data.get("@Name", "") == "fileTime":
                file_time = data.get("#text", "-")

            elif data.get("@Name", "") == "name":
                name = data.get("#text", "-")

            elif data.get("@Name", "") == "url":
                url = data.get("#text", "-")

            elif data.get("@Name", "") == "processPath":
                process_path = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                                                          ts_time, self.separator,
                                                                                          event_code, self.separator,
                                                                                          identifiant, self.separator,
                                                                                          job_id, self.separator,
                                                                                          job_title, self.separator,
                                                                                          job_owner, self.separator,
                                                                                          user, self.separator,
                                                                                          bytes_total, self.separator,
                                                                                          bytes_transferred,
                                                                                          self.separator,
                                                                                          file_count, self.separator,
                                                                                          file_length, self.separator,
                                                                                          file_time, self.separator,
                                                                                          name, self.separator,
                                                                                          url, self.separator,
                                                                                          process_path)
            self.bits_file_csv.write(res)
            self.bits_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "identifiant": identifiant,
                "job_id": job_id,
                "job_title": job_title,
                "job_owner": job_owner,
                "user": bytes_total,
                "bytes_transferred": bytes_transferred,
                "file_count": file_count,
                "file_length": file_length,
                "file_time": file_time,
                "name": name,
                "url": url,
                "process_path": process_path,
                "Artefact": "BITS"
            }
            json.dump(res, self.bits_file_json)
            self.bits_file_json.write('\n')

    #  ----------------------------------------  Security ---------------------------------------------

    def parse_security_evtx(self, event):
        """
        Main function to parse security type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if event_code == 4624:
            if self.logon_res_file_csv or self.logon_res_file_json:
                self.parse_logon_from_xml(event)

        if event_code == 4625:
            if self.logon_failed_file_csv or self.logon_failed_file_json:
                self.parse_failed_logon_from_xml(event)

        if event_code == 4672:
            if self.logon_spe_file_csv or self.logon_spe_file_json:
                self.parse_spe_logon_from_xml(event)

        if event_code == 4648:
            if self.logon_exp_file_csv or self.logon_exp_file_json:
                self.parse_logon_exp_from_xml(event)

        if event_code == 4688:
            if self.new_proc_file_csv or self.new_proc_file_json:
                self.parse_new_proc_from_xml(event)

        if event_code == 4608 or event_code == 4609:
            if self.windows_start_stop_res_file_csv or self.windows_start_stop_res_file_json:
                self.parse_windows_startup_shutdown(event)

    def parse_logon_from_xml(self, event):
        """
        Function to parse logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4624"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"
        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          subject_user_name, self.separator,
                                                          target_user_name, self.separator,
                                                          ip_address, self.separator,
                                                          ip_port, self.separator,
                                                          logon_type)
            self.logon_res_file_csv.write(res)
            self.logon_res_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.logon_res_file_json)
            self.logon_res_file_json.write('\n')

    def parse_failed_logon_from_xml(self, event):
        """
        Function to parse failed logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4625"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"
        reason = "-"
        d_status = {
            "0XC000005E": "NoLogServAvailable",
            "0xC0000064": "BadUserAccount",
            "0xC000006A": "BadUserNameOrPasswd",
            "0XC000006D": "BadUserNameOrPasswd",
            "0xC000006F": "LogonOutSideHours",
            "0xC0000070": "LogonFromUnauthorizedWordstation",
            "0xC0000072": "UserLogonDisabledByAdmin",
            "0XC000015B": "UserGotNotLogonRight",
            "0XC0000192": "NetLogonWasNotStarted",
            "0xC0000193": "LogonWExpiredAccount",
            "0XC0000413": "AccountNotauthorizedOnMachine",
            "-": "-"
        }

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")
            elif data.get("@Name", "") == "Status":
                reason = d_status.get(str(data.get("#text", "-")).upper(),str(data.get("#text", "-")).upper())

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          subject_user_name, self.separator,
                                                          target_user_name, self.separator,
                                                          ip_address, self.separator,
                                                          ip_port, self.separator,
                                                          logon_type, self.separator,
                                                          reason)
            self.logon_failed_file_csv.write(res)
            self.logon_failed_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type,
                "failed_reason": reason,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.logon_failed_file_json)
            self.logon_failed_file_json.write('\n')

    def parse_spe_logon_from_xml(self, event):
        """
        Function to parse special logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4672"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          subject_user_name, self.separator,
                                                          target_user_name, self.separator,
                                                          ip_address, self.separator,
                                                          ip_port, self.separator,
                                                          logon_type)
            self.logon_spe_file_csv.write(res)
            self.logon_spe_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.logon_spe_file_json)
            self.logon_spe_file_json.write('\n')

    def parse_logon_exp_from_xml(self, event):
        """
        Function to explicit logon log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4648"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        ip_address = "-"
        ip_port = "-"
        logon_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "IpAddress":
                ip_address = data.get("#text", "-")
            elif data.get("@Name", "") == "IpPort":
                ip_port = data.get("#text", "-")
            elif data.get("@Name", "") == "LogonType":
                logon_type = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          subject_user_name, self.separator,
                                                          target_user_name, self.separator,
                                                          ip_address, self.separator,
                                                          ip_port, self.separator,
                                                          logon_type)
            self.logon_exp_file_csv.write(res)
            self.logon_exp_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "ip_address": ip_address,
                "ip_port": ip_port,
                "logon_type": logon_type,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.logon_exp_file_json)
            self.logon_exp_file_json.write('\n')

    def parse_new_proc_from_xml(self, event):
        """
        Function to parse new process log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "4688"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        subject_user_name = "-"
        target_user_name = "-"
        cmd_line = "-"
        new_proc_name = "-"
        parent_proc_name = "-"

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                subject_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TargetUserName":
                target_user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "CommandLine":
                cmd_line = data.get("#text", "-")
            elif data.get("@Name", "") == "NewProcessName":
                new_proc_name = data.get("#text", "-")
            elif data.get("@Name", "") == "ParentProcessName":
                parent_proc_name = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          subject_user_name, self.separator,
                                                          target_user_name, self.separator,
                                                          parent_proc_name, self.separator,
                                                          new_proc_name, self.separator,
                                                          cmd_line)
            self.new_proc_file_csv.write(res)
            self.new_proc_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "subject_user_name": subject_user_name,
                "target_user_name": target_user_name,
                "new_process_name": new_proc_name,
                "parent_process_name": parent_proc_name,
                "cmd_line": cmd_line,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.new_proc_file_json)
            self.new_proc_file_json.write('\n')

    #  ----------------------------------------  System ---------------------------------------------
    def parse_system_evtx(self, event):
        """
        Main function to parse system type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if event_code == 7045:
            if self.service_file_csv or self.service_file_json:
                self.parse_service_from_xml(event)

    def parse_service_from_xml(self, event):
        """
        Function to parse service creation log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        account_name = "-"
        img_path = "-"
        service_name = "-"
        start_type = "-"

        for data in event_data:
            if data.get("@Name", "") == "AccountName":
                account_name = data.get("#text", "-")

            elif data.get("@Name", "") == "ImagePath":
                img_path = data.get("#text", "-")

            elif data.get("@Name", "") == "ServiceName":
                service_name = data.get("#text", "-")

            elif data.get("@Name", "") == "StartType":
                start_type = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  event_code, self.separator,
                                                  account_name, self.separator,
                                                  img_path, self.separator,
                                                  service_name, self.separator,
                                                  start_type)

            self.service_file_csv.write(res)
            self.service_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "account_name": account_name,
                "imgage_path": img_path,
                "service_name": service_name,
                "start_type": start_type,
                "Artefact": "EVTX_SYSTEM"
            }
            json.dump(res, self.service_file_json)
            self.service_file_json.write('\n')

    #  ----------------------------------------  Tasks ---------------------------------------------
    def parse_task_scheduler(self, event):
        """
        Main function to parse task scheduler type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.task_scheduler_file_csv or self.task_scheduler_file_json:
            if str(event_code) in ["106", "107", "140", "141", "200", "201"]:
                self.parse_task_scheduler_from_xml_taskevt(event)
            if event_code == 4698:
                self.parse_task_scheduler_from_xml_security_creation(event)
            if event_code == 4699:
                self.parse_task_scheduler_from_xml_security_deletion(event)
            if event_code == 4702:
                self.parse_task_scheduler_from_xml_security_update(event)

    def parse_task_scheduler_from_xml_taskevt(self, event):
        """
        Function to parse task scheduler log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        event_code = event.get("event_identifier")
        name = "-"
        task_name = "-"
        instance_id = "-"
        action_name = "-"
        result_code = "-"
        user_name = "-"
        user_context = "-"

        for data in event_data:
            if data.get("@Name", "") == "Name":
                name = data.get("#text", "-")
            elif data.get("@Name", "") == "TaskName":
                task_name = data.get("#text", "-")
            elif data.get("@Name", "") == "InstanceId":
                instance_id = data.get("#text", "-")
            elif data.get("@Name", "") == "ActionName":
                action_name = data.get("#text", "-")
            elif data.get("@Name", "") == "ResultCode":
                result_code = data.get("#text", "-")
            elif data.get("@Name", "") == "UserName":
                user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "UserContext":
                user_context = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                                  ts_time, self.separator,
                                                                  event_code, self.separator,
                                                                  name, self.separator,
                                                                  task_name, self.separator,
                                                                  instance_id, self.separator,
                                                                  action_name, self.separator,
                                                                  result_code, self.separator,
                                                                  user_name, self.separator,
                                                                  user_context)
            self.task_scheduler_file_csv.write(res)
            self.task_scheduler_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "name": name,
                "task_name": task_name,
                "instance_id": instance_id,
                "action_name": action_name,
                "result_code": result_code,
                "user_name": user_name,
                "user_context": user_context,
                "Artefact": "EVTX_TASK_SCHEDULER"
            }

            json.dump(res, self.task_scheduler_file_json)
            self.task_scheduler_file_json.write('\n')

    def parse_task_scheduler_from_xml_security_creation(self, event):

        """
        Function to parse task scheduler log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        event_code = event.get("event_identifier")
        user_name = "-"
        task_name = "-"
        command = "-"
        arguments = "-"
        action_type = "TaskCreated"
        task_content = {}

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TaskName":
                task_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TaskContent":
                task_content = data.get("#text", {})

        task_content_json = xmltodict.parse(task_content)
        if isinstance(task_content_json, dict):
            task_root = task_content_json.get("Task")
            if isinstance(task_root, dict):
                action = task_root.get("Actions")
                if isinstance(action, dict):
                    execc = action.get("Exec")
                    if isinstance(execc, dict):
                        command = execc.get("Command", "-")
                        arguments = execc.get("Arguments", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          action_type, self.separator,
                                                          user_name, self.separator,
                                                          task_name, self.separator,
                                                          command, self.separator,
                                                          arguments
                                                          )
            self.task_scheduler_file_csv.write(res)
            self.task_scheduler_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "action_type": action_type,
                "user_name": user_name,
                "task_name": task_name,
                "command": command,
                "arguments": arguments,
                "Artefact": "EVTX_TASK_SCHEDULER"
            }
            json.dump(res, self.task_scheduler_file_json)
            self.task_scheduler_file_json.write('\n')

    def parse_task_scheduler_from_xml_security_deletion(self, event):

        """
        Function to parse task scheduler log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        event_code = event.get("event_identifier")
        user_name = "-"
        task_name = "-"
        command = "-"
        arguments = "-"
        action_type = "TaskDeleted"
        task_content = {}

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TaskName":
                task_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TaskContent":
                task_content = data.get("#text", "-")

        if isinstance(task_content, dict):
            task_content_json = xmltodict.parse(task_content)
            if isinstance(task_content_json, dict):
                task_root = task_content_json.get("Task")
                if isinstance(task_root, dict):
                    action = task_root.get("Actions")
                    if isinstance(action, dict):
                        execc = action.get("Exec")
                        if isinstance(execc, dict):
                            command = execc.get("Command", "-")
                            arguments = execc.get("Arguments", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          action_type, self.separator,
                                                          user_name, self.separator,
                                                          task_name, self.separator,
                                                          command, self.separator,
                                                          arguments
                                                          )
            self.task_scheduler_file_csv.write(res)
            self.task_scheduler_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "action_type": action_type,
                "user_name": user_name,
                "task_name": task_name,
                "command": command,
                "arguments": arguments,
                "Artefact": "EVTX_TASK_SCHEDULER"
            }
            json.dump(res, self.task_scheduler_file_json)
            self.task_scheduler_file_json.write('\n')

    def parse_task_scheduler_from_xml_security_update(self, event):

        """
        Function to parse task scheduler log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        event_code = event.get("event_identifier")
        user_name = "-"
        task_name = "-"
        command = "-"
        arguments = "-"
        action_type = "TaskUpdated"
        task_content = {}

        for data in event_data:
            if data.get("@Name", "") == "SubjectUserName":
                user_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TaskName":
                task_name = data.get("#text", "-")
            elif data.get("@Name", "") == "TaskContentNew":
                task_content = data.get("#text", {})

        task_content_json = xmltodict.parse(task_content)
        if isinstance(task_content_json, dict):
            task_root = task_content_json.get("Task")
            if isinstance(task_root, dict):
                action = task_root.get("Actions")
                if isinstance(action, dict):
                    execc = action.get("Exec")
                    if isinstance(execc, dict):
                        command = execc.get("Command", "-")
                        arguments = execc.get("Arguments", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          action_type, self.separator,
                                                          user_name, self.separator,
                                                          task_name, self.separator,
                                                          command, self.separator,
                                                          arguments
                                                          )

            self.task_scheduler_file_csv.write(res)
            self.task_scheduler_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "action_type": action_type,
                "user_name": user_name,
                "task_name": task_name,
                "command": command,
                "arguments": arguments,
                "Artefact": "EVTX_TASK_SCHEDULER"
            }
            json.dump(res, self.task_scheduler_file_json)
            self.task_scheduler_file_json.write('\n')

    #  ----------------------------------------  PowerShell ---------------------------------------------
    def parse_powershell(self, event):
        """
        Main function to parse powershell type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        event_code = event.get("event_identifier")
        if self.powershell_script_file_csv or self.powershell_script_file_json:
            if str(event_code) in ["4104", "4105", "4106"]:
                self.parse_powershell_script_from_xml(event)
        if self.powershell_file_csv or self.powershell_file_json:
            if str(event_code) in ["400", "600"]:
                self.parse_powershell_cmd_from_xml(event)

    def parse_powershell_script_from_xml(self, event):
        """
        Function to parse powershell script execution log type.
        It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        path_to_script = "-"
        script_block_text = "-"

        for data in event_data:
            if data.get("@Name", "") == "Path":
                path_to_script = data.get("#text", "-")

            elif data.get("@Name", "") == "ScriptBlockText":
                script_block_text = str(data.get("#text", "-")).replace("\n", "")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              event_code, self.separator,
                                              path_to_script, self.separator,
                                              script_block_text)
            self.powershell_script_file_csv.write(res)
            self.powershell_script_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "path_to_script": path_to_script,
                "script_block_text": script_block_text,
                "Artefact": "EVTX_POWERSHELL"
            }

            json.dump(res, self.powershell_script_file_json)
            self.powershell_script_file_json.write('\n')

    def parse_powershell_cmd_from_xml(self, event):
        """
        Function to parse powershell cmdu execution log type. It will parse and write results to the appropriate
        result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])
        cmdu = "-"

        for line in event_data:
            if "HostApplication=" in line:
                l2 = line.split("\n")
                for i in l2:
                    if "HostApplication" in i:
                        cmdu = i.split("HostApplication=")[1].replace("\n", " ").replace("\t", "").replace("\r", "")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                          ts_time, self.separator,
                                          event_code, self.separator,
                                          cmdu)
            self.powershell_file_csv.write(res)
            self.powershell_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "cmdu": cmdu,
                "Artefact": "POWERSHELL"
            }

            json.dump(res, self.powershell_file_json)
            self.powershell_file_json.write('\n')

    #  ----------------------------------------  App Experience ---------------------------------------------
    def parse_app_experience(self, event):
        """
        Main function to parse application experience type logs
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        if self.app_exp_file_csv or self.app_exp_file_json:
            if str(event_code) in ["500", "505", "17"]:
                self.parse_app_experience_from_xml(event)

    def parse_app_experience_from_xml(self, event):
        """
        Function to parse application experience log type.
        It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)

        fix_name = evt_as_json.get("Event", {}).get("UserData", {}).get("CompatibilityFixEvent", {}).get("FixName")
        exe_path = evt_as_json.get("Event", {}).get("UserData", {}).get("CompatibilityFixEvent", {}).get("ExePath")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              event_code, self.separator,
                                              fix_name, self.separator,
                                              exe_path)
            self.app_exp_file_csv.write(res)
            self.app_exp_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "fix_name": fix_name,
                "exe_path": exe_path,
                "Artefact": "APP_EXPERIENCE"
            }

            json.dump(res, self.app_exp_file_json)
            self.app_exp_file_json.write('\n')

    #  -------------------------------------------------------------  Hives --------------------------------------------

    def parse_hives(self, line):
        """
        Main function to parse windows hive type artefact
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        hive_type = self.identify_artefact_by_parser_name(line)

        if hive_type == "winreg-amcache":
            if self.amcache_res_file_csv or self.amcache_res_file_json:
                self.parse_amcache(line)

        if hive_type == "winreg-appCompat":
            if self.app_compat_res_file_csv or self.app_compat_res_file_json:
                self.parse_app_compat_cache(line)

        if hive_type == "winreg-windows_sam_users":
            if self.sam_res_file_csv or self.sam_res_file_json:
                self.parse_sam(line)

        if hive_type == "winreg-userassist":
            if self.user_assist_file_csv or self.user_assist_file_json:
                self.parse_user_assist(line)

        if hive_type == "winreg-mru":
            if self.mru_res_file_csv or self.mru_res_file_json:
                self.parse_mru(line)

        if hive_type == "winreg-mru-shell_items":
            if self.mru_res_file_csv or self.mru_res_file_json:
                self.parse_mru_shell_item(line)

        if hive_type == "winreg-mru-exe_shell_items_list":
            if self.mru_res_file_csv or self.mru_res_file_json:
                self.parse_mru_exe_shell_items_list(line)

        if hive_type == "winreg-mru-listex_str":
            if self.mru_res_file_csv or self.mru_res_file_json:
                self.parse_mru_listex_str(line)

        if hive_type == "winreg-mru-str_and_shellitem":
            if self.mru_res_file_csv or self.mru_res_file_json:
                self.parse_mru_listex_str_shellitem(line)

        if hive_type == "winreg-windows-run":
            if self.run_res_file_csv or self.run_res_file_json:
                self.parse_run(line)

        if hive_type == "winreg-windows_usb_devices":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_usb(line)

        if hive_type == "winreg_default":
            if 'HKEY_LOCAL_MACHINE\Software' in line.get("key_path") or 'HKEY_CURRENT_USER\Software' in line.get("key_path"):
                self.parse_software(line)

            if 'HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache' in line.get("key_path") :
                self.parse_mui_cache(line)

        if hive_type == "winreg-networks":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_network(line)

        if hive_type == "winreg-windows_boot_execute":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_bootexec(line)

        if hive_type == "winreg-windows_services":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_win_services(line)

        if hive_type == "winreg-windows_shutdown":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_win_shutdown(line)

        if hive_type == "winreg-windows_task_cache":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_task_cache(line)

        if hive_type == "winreg-windows_timezone":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_timezone(line)

        if hive_type == "winreg-winlogon":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_winlogon(line)

        if hive_type == "winreg-windows_typed_urls":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_typed_url(line)

        if hive_type == "winreg-explorer_mountpoints2":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_mountpoint(line)

        if hive_type == "winreg-explorer_programscache":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_programscache(line)

        if hive_type == "winreg-windows_version":
            if self.common_reg_file_csv or self.common_reg_file_json:
                self.parse_reg_version(line)

        if hive_type == "winreg-msie_zone":
            if self.common_reg_file_csv or self.common_reg_file_json:
                #self.parse_reg_msie(line)
                pass # Need better parsing and will flood output

    def parse_reg_usb(self, event):
        msg = event.get("message", "-").replace(
            "[HKEY_LOCAL_MACHINE\System\ControlSet002\Enum\\USB]", "")
        key = "USB"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key , self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "USB_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_msie(self, event):
        msg = event.get("settings", "-")
        key = "MSIE"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "MSIE_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_network(self, event):
        msg = event.get("message", "-")
        key = "NETWORK"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "NETWORK_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_bootexec(self, event):
        msg = event.get("message", "-").replace("[HKEY_LOCAL_MACHINE\System\ControlSet001\Control\Session Manager]", "")
        key = "BOOTEXEC"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "BOOTEXEC_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_win_services_leg(self, event):
        msg = event.get("message", "-").replace("[HKEY_LOCAL_MACHINE\\System\\ControlSet001\\Services\\", "")
        key = "WINSERVICES"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "WINSERVICES_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_win_services(self, event):
        values = event.get("values", [])
        key = "WINSERVICE"
        l_formated_value = []
        if isinstance(values, list):
            for value in values:
                if isinstance(value, dict):
                    l_formated_value.append("{}:{}".format(value.get("name"), value.get("data")))

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator,
                                          self.separator.join(l_formated_value))
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": values,
                "Artefact": "WINSERVICES_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_win_shutdown(self, event):
        msg = event.get("message", "-").replace("[HKEY_LOCAL_MACHINE\\System\\ControlSet002\\Control\\Windows]", "")
        key = "WINSHUTDOWN"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "WINSHUTDOWN_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_task_cache(self, event):
        msg = event.get("message", "-").replace("[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache]", "")
        key = "TASKCACHE"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "TASKCACHE_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_timezone(self, event):
        msg = event.get("message", "-").replace(
            "[HKEY_LOCAL_MACHINE\\System\\ControlSet002\\Control\\TimeZoneInformation]", "").replace(
            "[HKEY_LOCAL_MACHINE\\System\\ControlSet002\\Control\\TimeZoneInformation]", "")
        key = "TIMEZONE"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "TIMEZONE_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_typed_url(self, event):
        msg = event.get("entries", "-")
        key = "TYPEDURL"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "TYPEDURL_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_winlogon(self, event):
        msg = event.get("message", "-").replace("[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]", "")
        key = "WINLOGON"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "WINLOGON_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_mountpoint(self, event):
        msg = event.get("message", "-").replace("[HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2]", "")
        key = "MOUNTPOINT"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "MOUNTPOINT_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_programscache(self, event):
        msg = event.get("message", "-").replace("[HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartPage]", "")
        key = "STARTPAGE"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, key, self.separator, msg)
            self.common_reg_file_csv.write(res)
            self.common_reg_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": msg,
                "Artefact": "STARTPAGE_REGISTRY"
            }
            json.dump(res, self.common_reg_file_json)
            self.common_reg_file_json.write('\n')

    def parse_reg_version(self, event):
        values = event.get("values", [])
        l_formated_entries = []
        if isinstance(values, list):
            for value in values:
                if isinstance(value, dict):
                    entry = "{}:    {}".format(value.get("name"), value.get("data"))
                    l_formated_entries.append(entry)

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            for f_entry in l_formated_entries:
                self.windows_general_info_csv.write(f_entry)
                self.windows_general_info_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "entry": values,
                "Artefact": "VERSION_REGISTRY"
            }
            json.dump(res, self.windows_general_info_json)
            self.windows_general_info_json.write('\n')

    def parse_software(self, event):
        """
        Function to parse software reg key entries.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        if "Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" in event.get("key_path", "-"):
            self.get_mru_runbox_cmd(event)

    def get_mru_runbox_cmd(self, event):
        runcmd = event.get("message", "-").replace(
            "[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU]", "")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, runcmd)
            self.mru_res_file_csv.write(res)
            self.mru_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "cmd": runcmd,
                "Artefact": "RunMRU"
            }
            json.dump(res, self.mru_res_file_json)
            self.mru_res_file_json.write('\n')

    def parse_amcache(self, event):
        """
        Function to parse amcache hive type.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        full_path = event.get("full_path", "-")
        if full_path != "-":
            name = full_path.split("\\")[-1]
            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
            identifier = event.get("program_identifier", "-")
            sha256_hash = event.get("sha256_hash", "-")

            if self.output_type in ["csv", "all"]:
                # res = "{}{}{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, name, self.separator, identifier)
                res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  name, self.separator,
                                                  full_path, self.separator,
                                                  identifier, self.separator,
                                                  sha256_hash)
                self.amcache_res_file_csv.write(res)
                self.amcache_res_file_csv.write('\n')

            if self.output_type in ["json", "all"]:
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "name": name,
                    "fullPath": full_path,
                    "identifier": identifier,
                    "hash": sha256_hash,
                    "Artefact": "AMCACHE"
                }
                json.dump(res, self.amcache_res_file_json)
                self.amcache_res_file_json.write('\n')

    def parse_app_compat_cache(self, event):
        """
        Function to parse app compat hive type.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        full_path = event.get("path", "-")
        if full_path != "-":
            name = full_path.split("\\")[-1]
            ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
            sha256_hash = event.get("sha256_hash", "-")

            if self.output_type in ["csv", "all"]:
                res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  name, self.separator,
                                                  full_path, self.separator,
                                                  sha256_hash)
                self.app_compat_res_file_csv.write(res)
                self.app_compat_res_file_csv.write('\n')

            if self.output_type in ["json", "all"]:
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "name": name,
                    "identifier": full_path,
                    "hash": sha256_hash,
                    "Artefact": "APP_COMPAT_CACHE"
                }
                json.dump(res, self.app_compat_res_file_json)
                self.app_compat_res_file_json.write('\n')

    def parse_sam(self, event):
        """
        Function to parse sam hive type.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        user_name = event.get("username", "-")
        login_count = event.get("login_count", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                          ts_time, self.separator,
                                          user_name, self.separator,
                                          login_count)
            self.sam_res_file_csv.write(res)
            self.sam_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "user_name": user_name,
                "login_count": login_count,
                "Artefact": "SAM"
            }
            json.dump(res, self.sam_res_file_json)
            self.sam_res_file_json.write('\n')

    def parse_user_assist(self, event):
        """
        Function to user assist artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        value_name = event.get("value_name", "-")
        application_focus_count = event.get("application_focus_count", "-")
        application_focus_duration = event.get("application_focus_duration", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              value_name, self.separator,
                                              application_focus_count, self.separator,
                                              application_focus_duration)
            self.user_assist_file_csv.write(res)
            self.user_assist_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "value_name": value_name,
                "application_focus_count": application_focus_count,
                "application_focus_duration": application_focus_duration,
                "Artefact": "USER_ASSIST"
            }
            json.dump(res, self.user_assist_file_json)
            self.user_assist_file_json.write('\n')

    def parse_mru(self, event):
        """
        Function to parse mru artefact.
        It will parse and write results to the appr)à   opriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            if event.get("parser") == "winreg/bagmru/shell_items":
                shell_item_path = event.get("shell_item_path", "-")
                name = event.get("name", "-")

                if self.output_type in ["csv", "all"]:
                    res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  name, self.separator,
                                                  shell_item_path)
                    self.mru_res_file_csv.write(res)
                    self.mru_res_file_csv.write('\n')

                if self.output_type in ["json", "all"]:
                    res = {
                        "caseName": self.case_name,
                        "workstation_name": self.machine_name,
                        "timestamp": "{}T{}".format(ts_date, ts_time),
                        "name": name,
                        "shell_item_path": shell_item_path,
                        "Artefact": "MRU"
                    }
                    json.dump(res, self.mru_res_file_json)
                    self.mru_res_file_json.write('\n')

            elif event.get("entries"):
                entries = event.get("entries")
                if type(entries) == list:
                    for entrie_item in entries:
                        splited_entrie = entrie_item.split("Index:")
                        for entrie in splited_entrie:
                            header = r'( \d{1,9} \[MRU Value \d{1,9}\]: Shell item path:)|(<UNKNOWN: .*?>)|((\d|[a-z]){1,9} \[MRU Value .{1,9}\]:)'
                            cleaned = re.sub(header, '', entrie).strip()
                            if cleaned:
                                if self.output_type in ["csv", "all"]:
                                    res = "{}{}{}{}-{}{}".format(ts_date, self.separator,
                                                                 ts_time, self.separator,
                                                                 self.separator,
                                                                 cleaned)
                                    self.mru_res_file_csv.write(res)
                                    self.mru_res_file_csv.write('\n')

                                if self.output_type in ["json", "all"]:
                                    res = {
                                        "caseName": self.case_name,
                                        "workstation_name": self.machine_name,
                                        "timestamp": "{}T{}".format(ts_date, ts_time),
                                        "mru_entrie": cleaned,
                                        "Artefact": "MRU"
                                    }
                                    json.dump(res, self.mru_res_file_json)
                                    self.mru_res_file_json.write('\n')
                else:
                    splited_entrie = entries.split("Index:")
                    for entrie in splited_entrie:
                        header = r'( \d{1,9} \[MRU Value \d{1,9}\]: Shell item path:)|(<UNKNOWN: .*?>)|((\d|[a-z]){1,9} \[MRU Value .{1,9}\]:)'
                        cleaned = re.sub(header, '', entrie).strip()
                        if cleaned:
                            if self.output_type in ["csv", "all"]:
                                res = "{}{}{}{}-{}{}".format(ts_date, self.separator,
                                                             ts_time, self.separator,
                                                             self.separator,
                                                             cleaned)
                                self.mru_res_file_csv.write(res)
                                self.mru_res_file_csv.write('\n')

                            if self.output_type in ["json", "all"]:
                                res = {
                                    "caseName": self.case_name,
                                    "workstation_name": self.machine_name,
                                    "timestamp": "{}T{}".format(ts_date, ts_time),
                                    "mru_entrie": cleaned,
                                    "Artefact": "MRU"
                                }
                                json.dump(res, self.mru_res_file_json)
                                self.mru_res_file_json.write('\n')
        except:
            print("Error parsing MRU entries")
            print(traceback.format_exc())

    def parse_mru_shell_item(self, event):
        """
        Function to parse mru artefact.
        It will parse and write results to the appr)à   opriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            shell_item_path = event.get("shell_item_path", "-")
            name = event.get("name", "-")
            type_reg = "MRUSHELLITEM"
            if self.output_type in ["csv", "all"]:
                res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  type_reg, self.separator,
                                                  name, self.separator,
                                                  shell_item_path)
                self.mru_res_file_csv.write(res)
                self.mru_res_file_csv.write('\n')

            if self.output_type in ["json", "all"]:
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "name": name,
                    "shell_item_path": shell_item_path,
                    "Artefact": "MRU"
                }
                json.dump(res, self.mru_res_file_json)
                self.mru_res_file_json.write('\n')

        except:
            print("Error parsing MRU SHELL ITEM entries")
            print(traceback.format_exc())

    def parse_mru_exe_shell_items_list(self, event):
        """
        Function to parse mru artefact.
        It will parse and write results to the appr)à   opriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            entries = event.get("entries", "-")
            name = event.get("name", "-")
            type_reg = "MRUSHELLITEMEXE"
            if isinstance(entries, list):
                for entry in entries:
                    if self.output_type in ["csv", "all"]:
                        res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          type_reg, self.separator,
                                                          name, self.separator,
                                                          entry)
                        self.mru_res_file_csv.write(res)
                        self.mru_res_file_csv.write('\n')

                    if self.output_type in ["json", "all"]:
                        res = {
                            "caseName": self.case_name,
                            "workstation_name": self.machine_name,
                            "timestamp": "{}T{}".format(ts_date, ts_time),
                            "name": name,
                            "entry": entry,
                            "Artefact": "MRU"
                        }
                        json.dump(res, self.mru_res_file_json)
                        self.mru_res_file_json.write('\n')

        except:
            print("Error parsing MRU SHELL ITEM EXE entry")
            print(traceback.format_exc())

    def parse_mru_listex_str_shellitem(self, event):
        """
        Function to parse mru artefact.
        It will parse and write results to the appr)à   opriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            entries = event.get("entries", "-")
            name = event.get("name", "-")
            type_reg = "MRULISTEXSHELL"
            if isinstance(entries, list):
                for entry in entries:
                    if self.output_type in ["csv", "all"]:
                        res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          type_reg, self.separator,
                                                          name, self.separator,
                                                          entry)
                        self.mru_res_file_csv.write(res)
                        self.mru_res_file_csv.write('\n')

                    if self.output_type in ["json", "all"]:
                        res = {
                            "caseName": self.case_name,
                            "workstation_name": self.machine_name,
                            "timestamp": "{}T{}".format(ts_date, ts_time),
                            "name": name,
                            "entry": entry,
                            "Artefact": "MRU"
                        }
                        json.dump(res, self.mru_res_file_json)
                        self.mru_res_file_json.write('\n')

        except:
            print("Error parsing MRU SHELL ITEM EXE entry")
            print(traceback.format_exc())

    def parse_mru_listex_str(self, event):
        """
        Function to parse mru artefact.
        It will parse and write results to the appr)à   opriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            entries = event.get("entries", "-")
            name = event.get("name", "-")
            type_reg = "MRULISTEX"
            if isinstance(entries, list):
                for entry in entries:
                    if self.output_type in ["csv", "all"]:
                        res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          type_reg, self.separator,
                                                          name, self.separator,
                                                          entry)
                        self.mru_res_file_csv.write(res)
                        self.mru_res_file_csv.write('\n')

                    if self.output_type in ["json", "all"]:
                        res = {
                            "caseName": self.case_name,
                            "workstation_name": self.machine_name,
                            "timestamp": "{}T{}".format(ts_date, ts_time),
                            "name": name,
                            "entry": entry,
                            "Artefact": "MRU"
                        }
                        json.dump(res, self.mru_res_file_json)
                        self.mru_res_file_json.write('\n')

        except:
            print("Error parsing MRU SHELL ITEM EXE entry")
            print(traceback.format_exc())

    def parse_mui_cache(self, event):
        """
        Function to parse mru artefact.
        It will parse and write results to the appr)à   opriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        try:
            entries = event.get("values", "-")
            type_reg = "MUICACHE"
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        name = entry.get("name", "-")
                        data = entry.get("data", "-")
                        if self.output_type in ["csv", "all"]:
                            res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                              ts_time, self.separator,
                                                              type_reg, self.separator,
                                                              name, self.separator,
                                                              data)
                            self.mui_res_file_csv.write(res)
                            self.mui_res_file_csv.write('\n')

                        if self.output_type in ["json", "all"]:
                            res = {
                                "caseName": self.case_name,
                                "workstation_name": self.machine_name,
                                "timestamp": "{}T{}".format(ts_date, ts_time),
                                "name": name,
                                "data": data,
                                "Artefact": "MUICACHE"
                            }
                            json.dump(res, self.mui_res_file_json)
                            self.mui_res_file_json.write('\n')

        except:
            print("Error parsing MUI CACHE entry")
            print(traceback.format_exc())

    def parse_run(self, event):
        """
        Function to parse run/RunOnce reg key entries.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        entries = event.get("entries", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if entries:
            for entrie in entries:
                if self.output_type in ["csv", "all"]:
                    res = "{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              entrie)
                    self.run_res_file_csv.write(res)
                    self.run_res_file_csv.write('\n')

                if self.output_type in ["json", "all"]:
                    res = {
                        "caseName": self.case_name,
                        "workstation_name": self.machine_name,
                        "timestamp": "{}T{}".format(ts_date, ts_time),
                        "run_entrie": entrie,
                        "Artefact": "RUN_KEY"
                    }
                    json.dump(res, self.run_res_file_json)
                    self.run_res_file_json.write('\n')

    #  -------------------------------------------------------------  DB -----------------------------------------------

    def parse_db(self, line):
        """
        Main function to parse db type artefact
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        db_type = self.identify_artefact_by_parser_name(line)
        if db_type == "ff_history":
            if self.ff_history_res_file_csv or self.ff_history_res_file_json:
                self.parse_ff_history(line)
        if db_type == "edge_history":
            if self.ie_history_res_file_csv or self.ie_history_res_file_json:
                self.parse_edge_history(line)
        if db_type == "chrome_history":
            if self.chrome_history_res_file_csv or self.chrome_history_res_file_json:
                self.parse_chrome_history(line)

        if db_type == "srum":
            if self.srum_res_file_csv or self.srum_res_file_json:
                self.parse_srum(line)

    def parse_srum(self, event):
        """
        Function to parse srum artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        description = event.get("message", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}".format(ts_date, self.separator,
                                      ts_time, self.separator,
                                      description)
            self.srum_res_file_csv.write(res)
            self.srum_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "description": description,
                "Artefact": "SRUM"
            }
            json.dump(res, self.srum_res_file_json)
            self.srum_res_file_json.write('\n')

    def parse_ff_history(self, event):
        """
        Function to parse firefox history.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        url = event.get("url", "-")
        visit_count = event.get("visit_count", "-")
        visit_type = event.get("visit_type", "-")
        is_typed = event.get("typed", "-")
        from_visit = event.get("from_visit", "-")
        data_type = event.get("data_type", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          data_type, self.separator,
                                                          url, self.separator,
                                                          visit_count, self.separator,
                                                          visit_type, self.separator,
                                                          is_typed, self.separator,
                                                          from_visit)
            self.ff_history_res_file_csv.write(res)
            self.ff_history_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "data_type": data_type,
                "url": url,
                "visit_count": visit_count,
                "visit_type": visit_type,
                "is_typed": is_typed,
                "from_visit": from_visit,
                "Artefact": "FF_HISTORY"
            }
            json.dump(res, self.ff_history_res_file_json)
            self.ff_history_res_file_json.write('\n')

    def parse_chrome_history(self, event):
        """
        Function to parse firefox history.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        url = event.get("url", "-")
        visit_count = event.get("visit_count", "-")
        visit_type = event.get("visit_type", "-")
        is_typed = event.get("typed", "-")
        from_visit = event.get("from_visit", "-")
        data_type = event.get("data_type", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          data_type, self.separator,
                                                          url, self.separator,
                                                          visit_count, self.separator,
                                                          visit_type, self.separator,
                                                          is_typed, self.separator,
                                                          from_visit)
            self.chrome_history_res_file_csv.write(res)
            self.chrome_history_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "data_type": data_type,
                "url": url,
                "visit_count": visit_count,
                "visit_type": visit_type,
                "is_typed": is_typed,
                "from_visit": from_visit,
                "Artefact": "CHROME_HISTORY"
            }
            json.dump(res, self.chrome_history_res_file_json)
            self.chrome_history_res_file_json.write('\n')

    def parse_edge_history(self, event):
        """
        Function to parse firefox history.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """

        url = event.get("url", "-")
        visit_count = event.get("visit_count", "-")
        visit_type = event.get("visit_type", "-")
        is_typed = event.get("typed", "-")
        from_visit = event.get("from_visit", "-")
        data_type = event.get("data_type", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          data_type, self.separator,
                                                          url, self.separator,
                                                          visit_count, self.separator,
                                                          visit_type, self.separator,
                                                          is_typed, self.separator,
                                                          from_visit)
            self.ie_history_res_file_csv.write(res)
            self.ie_history_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "data_type": data_type,
                "url": url,
                "visit_count": visit_count,
                "visit_type": visit_type,
                "is_typed": is_typed,
                "from_visit": from_visit,
                "Artefact": "IE_HISTORY"
            }
            json.dump(res, self.ie_history_res_file_json)
            self.ie_history_res_file_json.write('\n')

    #  ------------------------------------------------------  Win Files -----------------------------------------------

    def parse_win_file(self, line):
        """
        Main function to parse windows type artefact
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        file_type = self.identify_artefact_by_parser_name(line)
        if file_type == "prefetch":
            if self.prefetch_res_file_csv or self.prefetch_res_file_json:
                self.parse_prefetch(line)
        if file_type == "lnk":
            if self.lnk_res_file_csv or self.lnk_res_file_json:
                self.parse_lnk(line)

    def parse_prefetch(self, event):
        """
        Function to parse prefetch files.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        run_count = event.get("run_count", "-")
        path_hints = event.get("path_hints", "-")
        executable = event.get("executable", "-")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              executable, self.separator,
                                              path_hints, self.separator,
                                              run_count)
            self.prefetch_res_file_csv.write(res)
            self.prefetch_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "executable": executable,
                "path_hints": path_hints,
                "run_count": run_count,
                "Artefact": "PREFETCH"
            }
            json.dump(res, self.prefetch_res_file_json)
            self.prefetch_res_file_json.write('\n')

    def parse_lnk(self, event):
        """
        Function to parse lnk type artefact.
        It will parse and write results to the appropriate result file.
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        description = event.get("description", "-")
        working_directory = event.get("working_directory", "-")

        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if description != "-" and working_directory != "-":
            if self.output_type in ["csv", "all"]:
                res = "{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                              ts_time, self.separator,
                                              description, self.separator,
                                              working_directory)
                self.lnk_res_file_csv.write(res)
                self.lnk_res_file_csv.write('\n')

            if self.output_type in ["json", "all"]:
                res = {
                    "caseName": self.case_name,
                    "workstation_name": self.machine_name,
                    "timestamp": "{}T{}".format(ts_date, ts_time),
                    "description": description,
                    "working_directory": working_directory,
                    "Artefact": "LNK"
                }
                json.dump(res, self.lnk_res_file_json)
                self.lnk_res_file_json.write('\n')

    #  -------------------------------------------------------------  MFT --------------------------------------------

    def parse_mft(self, line):
        """
        Main function to parse windows mft
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        reg_ntfs = re.compile(r'NTFS')
        if not self.config.get("mft", "") or not line:
            return
        parser = line.get("parser")
        if parser in ["usnjrnl"]:
            self.parse_usnjrl(line)
        elif parser in ["mft"]:
            self.parse_file_mft(line)
        elif parser in ["filestat"] and re.search(reg_ntfs, json.dumps(line)):
            self.parse_filestat(line)

    # TODO: Improve name regex
    def parse_usnjrl(self, event):
        """
        :param event: (dict) dict containing one line of the plaso timeline,
        :return:
        """
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        msg = event.get("message")
        file_name_re = re.compile(r'^(.{1,}\.){1,}(\w){1,3}')
        file_name = re.search(file_name_re, msg)
        update_reason_reg = re.compile(r'Update reason: (.*)')
        update_reason = re.search(update_reason_reg, msg)
        if update_reason:
            try:
                update_reason = update_reason.group(1).replace(',', '')
            except:
                update_reason = "noReason"
        if file_name:
            try:
                file_name = file_name.group()
            except:
                pass

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  "USNJRNL", self.separator,
                                                  "N/A", self.separator,
                                                  update_reason, self.separator,
                                                  file_name)
            self.mft_res_file_csv.write(res)
            self.mft_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "workstation_name": self.machine_name,
                "message": msg,
                "file_name": file_name,
                "Artefact": "NTFS_USN"

            }
            json.dump(res, self.mft_res_file_json)
            self.mft_res_file_json.write('\n')

    def parse_filestat(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        file_name_path = event.get("filename")
        file_type = event.get("file_entry_type")
        action = event.get("timestamp_desc")
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                  ts_time, self.separator,
                                                  'FILESTAT', self.separator,
                                                  file_type, self.separator,
                                                  action, self.separator,
                                                  file_name_path)
            self.mft_res_file_csv.write(res)
            self.mft_res_file_csv.write('\n')
        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "timestamp": "{}T{}".format(ts_date, ts_time, ),
                "workstation_name": self.machine_name,
                "action": action,
                "file_type": file_type,
                "path": file_name_path,
                "Artefact": "NTFS_FILESTAT"
            }
            json.dump(res, self.mft_res_file_json)
            self.mft_res_file_json.write('\n')

    def parse_file_mft(self, event):
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        action = event.get("timestamp_desc")
        path_int = event.get("path_hints", [])
        if isinstance(path_int, list):
            for path in path_int:
                if self.output_type in ["csv", "all"]:
                    res = "{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                      ts_time, self.separator,
                                                      "MFT", self.separator,
                                                       action, self.separator,
                                                       path)

                    self.mft_res_file_csv.write(res)
                    self.mft_res_file_csv.write('\n')

                if self.output_type in ["json", "all"]:
                    res = {
                        "caseName": self.case_name,
                        "timestamp": "{}T{}".format(ts_date, ts_time, ),
                        "workstation_name": self.machine_name,
                        "action": action,
                        "path": path,
                        "Artefact": "NTFS_MFT"
                    }
                    json.dump(res, self.mft_res_file_json)
                    self.mft_res_file_json.write('\n')

    def parse_windows_defender(self, line):
        """
        Main function to parse windows defender logs
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        if not self.config.get("windefender", "") or not line:
            return
        event_code = str(line.get("event_identifier"))
        if event_code in ["1116"]:
            if self.windefender_res_file_csv or self.windefender_res_file_json:
                self.parse_windef_detection_from_xml(line)
        if event_code in ["1117", "1118", "1119"]:
            if self.windefender_res_file_csv or self.windefender_res_file_json:
                self.parse_windef_action_from_xml(line)
        if event_code in ["1006"]:
            if self.windefender_res_file_csv or self.windefender_res_file_json:
                pass
                # self.parse_windef_detection_from_xml_legacy(line)
        if event_code in ["1007"]:
            if self.windefender_res_file_csv or self.windefender_res_file_json:
                pass
                # self.parse_windef_action_from_xml_legacy(line)

    def parse_windef_detection_from_xml(self, event):
        """
        Function to parse windefender detection log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1116 - Detection"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                              ts_time, self.separator,
                                                              event_code, self.separator,
                                                              threat_name, self.separator,
                                                              severity, self.separator,
                                                              detection_user, self.separator,
                                                              process_name, self.separator,
                                                              path, self.separator,
                                                              action)
            self.windefender_res_file_csv.write(res)
            self.windefender_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action,
                "Artefact": "EVTX_WINDOWS_DEFENDER"
            }
            json.dump(res, self.windefender_res_file_json)
            self.windefender_res_file_json.write('\n')

    def parse_windef_action_from_xml(self, event):
        """
        Function to parse windefender action log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        evt_code = str(event.get("event_identifier"))
        event_code = "{} - Action".format(evt_code)
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          threat_name, self.separator,
                                                          severity, self.separator,
                                                          detection_user, self.separator,
                                                          process_name, self.separator,
                                                          action)
            self.windefender_res_file_csv.write(res)
            self.windefender_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action,
                "Artefact": "EVTX_WINDOWS_DEFENDER"
            }
            json.dump(res, self.windefender_res_file_json)
            self.windefender_res_file_json.write('\n')

    def parse_windef_detection_from_xml_legacy(self, event):
        """
        Function to parse windefender detection log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1006"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          threat_name, self.separator,
                                                          severity, self.separator,
                                                          detection_user, self.separator,
                                                          process_name, self.separator,
                                                          action)
            self.windefender_res_file_csv.write(res)
            self.windefender_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action,
                "Artefact": "EVTX_WINDOWS_DEFENDER"
            }
            json.dump(res, self.logon_res_file_json)
            self.windefender_res_file_json.write('\n')

    def parse_windef_action_from_xml_legacy(self, event):
        """
        Function to parse windefender action log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = "1117"
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        evt_as_xml = event.get("xml_string")
        evt_as_json = xmltodict.parse(evt_as_xml)
        event_data = evt_as_json.get("Event", {}).get("EventData", {}).get("Data", [])

        threat_name = "-"
        severity = "-"
        process_name = "-"
        detection_user = "-"
        path = "-"
        action = "-"

        for data in event_data:
            if data.get("@Name", "") == "Action Name":
                action = data.get("#text", "-")
            if data.get("@Name", "") == "Threat Name":
                threat_name = data.get("#text", "-")
            if data.get("@Name", "") == "Severity Name":
                severity = data.get("#text", "-")
            elif data.get("@Name", "") == "Process Name":
                process_name = data.get("#text", "-")
            elif data.get("@Name", "") == "Detection User":
                detection_user = data.get("#text", "-")
            elif data.get("@Name", "") == "Path":
                path = data.get("#text", "-")

        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}".format(ts_date, self.separator,
                                                          ts_time, self.separator,
                                                          event_code, self.separator,
                                                          threat_name, self.separator,
                                                          severity, self.separator,
                                                          detection_user, self.separator,
                                                          process_name, self.separator,
                                                          action)
            self.windefender_res_file_csv.write(res)
            self.windefender_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "threat_name": threat_name,
                "severity": severity,
                "detection_user": detection_user,
                "process_name": process_name,
                "path": path,
                "action": action,
                "Artefact": "EVTX_WINDOWS_DEFENDER"
            }
            json.dump(res, self.windefender_res_file_json)
            self.windefender_res_file_json.write('\n')

    def parse_windows_startup_shutdown(self, event):
        """
        Function to parse windefender detection log type. It will parse and write results to the appropriate result file.
        The function will get the interesting information from the xml string
        :param event: (dict) dict containing one line of the plaso timeline,
        :return: None
        """
        event_code = event.get("event_identifier")
        ts_date, ts_time = self.convert_epoch_to_date(event.get("timestamp"))
        if event_code == 4608:
            msg = "WINDOWS STARTUP"
        elif event_code == 4609:
            msg = "WINDOWS SHUTDOWN"
        else:
            msg = "-"
        if self.output_type in ["csv", "all"]:
            res = "{}{}{}{}{}".format(ts_date, self.separator, ts_time, self.separator, msg)
            self.windows_start_stop_res_file_csv.write(res)
            self.windows_start_stop_res_file_csv.write('\n')

        if self.output_type in ["json", "all"]:
            res = {
                "caseName": self.case_name,
                "workstation_name": self.machine_name,
                "timestamp": "{}T{}".format(ts_date, ts_time),
                "eventCode": event_code,
                "action": msg,
                "Artefact": "EVTX_SECURITY"
            }
            json.dump(res, self.windows_start_stop_res_file_json)
            self.windows_start_stop_res_file_json.write('\n')

    def list_files_recursive(self, folder_path, glob_pattern):
        l_file = []
        path_folder = Path(folder_path)
        for item in path_folder.rglob(glob_pattern):
            if item.is_file():
                l_file.append(item)
        return l_file

    def clean_duplicates(self, dir_to_clean):

        """
        To clean duplicates line in file
        :return:
        """
        try:
            l_file = self.list_files_recursive(dir_to_clean, "*")
            for file in l_file:
                self.clean_duplicate_in_file(file)
        except:
            print(traceback.format_exc())

    def clean_duplicate_in_file(self, file):

        seen_lines = set()
        l_temp = []

        with open(file, 'r') as f:
            for line in f:
                if line not in seen_lines:
                    seen_lines.add(line)
                    l_temp.append(line)

        with open(file, 'w') as f:
            f.writelines(l_temp)

    def create_timeline(self):
        timeline = []
        for file in self.list_files_recursive(self.work_dir, "*.csv"):
            try:
                with open(file) as f:
                    next(f)
                    for line in f:
                        f_line = self.format_line(line, file.stem)
                        if f_line:
                            timeline.append(f_line)
            except StopIteration:
                print("stop iteration in file {}, skipping".format(str(file)))
            except:
                print(traceback.format_exc())

        self.timeline_file_csv = self.initialise_result_file_csv(self.l_csv_header_timeline, "timeline")
        sorted_timeline = sorted(timeline)
        for entry in sorted_timeline:
            self.timeline_file_csv.write(entry)
        self.timeline_file_csv.close()

    def merge_new_file_to_timeline(self, current_timeline, new_element, out_path):
        current_timeline_as_list = []
        print("reading timeline")
        with open(current_timeline) as current_timeline_file:
            current_timeline_as_list = current_timeline_file.readlines()
        print("timeline ingested")
        new_elem_formated = self.format_result_file_for_timeline_ingestion(new_element)
        print("merging files")
        new_timeline_as_list = [*current_timeline_as_list, *new_elem_formated]
        print("sorting timeline")
        sorted_timeline = sorted(new_timeline_as_list)
        print("writing new timeline")
        new_timeline = os.path.join(out_path, "new_timeline.csv")
        with open(new_timeline, "a") as new_timeline_file:
            for entry in sorted_timeline:
                new_timeline_file.write(entry)

    def format_result_file_for_timeline_ingestion(self, result_file):
        new_element_formated_as_list = []
        print("ingesting new file, it can take a while")
        with open(result_file, "r") as new_element_file:
            try:
                next(new_element_file)
                for line in new_element_file:
                    f_line = self.format_line(line, Path(result_file).stem)
                    if f_line:
                        new_element_formated_as_list.append(f_line)
            except StopIteration:
                print("stop iteration in file {}, skipping".format(str(result_file)))
            except:
                print(traceback.format_exc())

        return new_element_formated_as_list

    def format_line(self, line, source):
        try:
            l_line = line.split("|")
            l_line.insert(2, source)
            return "|".join(l_line)
        except:
            print(traceback.format_exc())

class PlasoToELK:
    """
       Class PlasoToELK
       PlasoToELK is a python script that will parse a plaso - Log2Timeline json timeline file and send correct
       results to elk so they can be queryables.
       Attributes :
       None
    """

    def __init__(self, logger_run, path_to_timeline, case_name=None, machine_name=None, elk_ip="localhost",
                 elk_port="9200") -> None:

        self.logger_run = logger_run
        self.path_to_timeline = path_to_timeline
        self.case_name = case_name
        self.machine_name = machine_name

        self.elk_ip = os.environ.get('ELK_HOST', elk_ip)  # Get host from env, default to provided ip
        self.elk_port = os.environ.get('ELK_PORT', elk_port)  # Get port from env, default to provided port
        self.elk_client = Elasticsearch("https://{}:{}".format(self.elk_ip, self.elk_port),
                                        basic_auth=('elastic', 'changeme'), ca_certs=False, verify_certs=False)
        self.id = 1


    def test_connection(self):
        if self.elk_client.ping():
            self.logger_run.info("[CONNECTING][ELK]", header="SUCCESS", indentation=2)
            return True
        else:
            self.logger_run.error("[CONNECTING][ELK]", header="ERROR", indentation=2)
            return False

    def identify_type_artefact_by_parser(self, line):
        """
        Function to indentify an artefact type depending on the plaso parser used
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the parser
        """
        d_regex_type_artefact = {
            "evtx": re.compile(r'winevtx'),
            "hive": re.compile(r'winreg'),
            "db": re.compile(r'(sqlite)|(esedb)'),
            "winFile": re.compile(r'(lnk)|(text)|(prefetch)'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)')
        }
        for key, value in d_regex_type_artefact.items():
            if re.search(value, line.get("parser")):
                return key

    def format_evt_from_xml(self, event):
        try:
            xml_string_as_xml = event.get("xml_string")
            xml_string_as_json = xmltodict.parse(xml_string_as_xml)

            if xml_string_as_json is None:
                # Handle the case where the XML string is malformed or empty
                self.logger_run.warning(
                    "[PARSING][PLASO2ELK] Skipping event with malformed XML string:{}".format(xml_string_as_xml),
                    header="WARNING", indentation=2)
                return event

            event.pop("message", None)
            event.pop("strings", None)

            event_root = xml_string_as_json.get("Event", None)
            if isinstance(event_root, dict):
                event_data_root = event_root.get("EventData", None)
                if isinstance(event_data_root, dict):
                    event_data_raw = event_data_root.get("Data", [])

                    if event_data_raw:
                        event_data_parsed = {}
                        event_data_other = []
                        if isinstance(event_data_raw, list):
                            for data in event_data_raw:
                                if isinstance(data, dict):
                                    if data.get("@Name", ""):
                                        event_data_parsed[data.get("@Name", "")] = data.get("#text", "-")
                                else:
                                    event_data_other.append(data)

                            event["eventdata_parsed"] = event_data_parsed
                            if event_data_other:
                                event["eventdata_other"] = event_data_other
                        else:
                            event["event_data_raw"] = event_data_raw
                else:
                    event["event_data_raw"] = event_root
            else:
                return event

            es_timstamp = self.format_ts_to_es(event.get("timestamp"))
            event["estimestamp"] = es_timstamp
            return event

        except Exception as e:
            self.logger_run.error("[PARSING][PLASO2ELK] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=2)
            return event

    def format_db_from_xml(self, event):
        try:
            es_timstamp = self.format_ts_to_es(event.get("timestamp"))
            event["estimestamp"] = es_timstamp
            if event.get("file_reference"):
                event["legacy_file_ref"] = event.get("file_reference")
                event.pop("file_reference")

            return event
        except:
            self.logger_run.error("[PARSING][PLASO2ELK] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=2)
            return None

    def generate_documents(self):
        """
        Generator function to read the timeline file line by line
        and yield formatted documents for bulk ingestion.
        """
        it = 0
        with open(self.path_to_timeline) as timeline:
            for line in timeline:
                try:
                    it +=1
                    d_line = json.loads(line)
                    artefact_type = self.identify_type_artefact_by_parser(d_line)

                    if artefact_type == "evtx":
                        formatted_event = self.format_evt_from_xml(d_line)
                    else:
                        formatted_event = self.format_db_from_xml(d_line)

                    if formatted_event:
                        # Yield the document in the format required by the bulk helper
                        yield {
                            "_index": self.index,
                            "_source": formatted_event
                        }
                except json.JSONDecodeError:
                    self.logger_run.error(
                        "[PARSING][PLASO2ELK] Could not load json line, skipping: {}".format(line.strip()),
                        header="ERROR", indentation=2)
                    continue
                except Exception as e:
                    self.logger_run.error("[PARSING][PLASO2ELK] Unexpected ERROR{}".format(traceback.format_exc()),
                                          header="ERROR", indentation=2)
                    continue

    def sanitize_elk_index(self, index_name):
        """
        Sanitizes a string to be a valid Elasticsearch index name.

        Args:
          index_name: The original string for the index name.

        Returns:
          A sanitized string that is a valid Elasticsearch index name.
        """
        # Convert to lowercase
        sanitized_name = index_name.lower()

        # Replace invalid characters with a hyphen
        # Invalid characters include: \ / * ? " < > | , (space)
        # The `re.sub` function finds all matches and replaces them.
        sanitized_name = re.sub(r'[\s\\/\"*?<>|,]+', '-', sanitized_name)

        # Remove leading/trailing hyphens and multiple hyphens
        sanitized_name = re.sub(r'^-+|-+$', '', sanitized_name)
        sanitized_name = re.sub(r'-+', '-', sanitized_name)

        return sanitized_name

    def send_to_elk_in_bulk(self):
        """
        Main function to orchestrate the bulk ingestion process.
        """
        self.logger_run.info("[PARSING][PLASO2ELK] BULK ingestion started", header="STARTED", indentation=2)
        try:
            self.index = self.sanitize_elk_index("{}_{}".format(self.case_name, self.machine_name))

            # Check if the index exists. If not, create it with a custom mapping.
            if not self.elk_client.indices.exists(index=self.index):
                self.mapping = {
                    "properties": {
                        "legacy_file_ref": {
                            "type": "keyword"  # Use keyword for string values you don't need to analyze
                        },
                        "timestamp": {
                            "type": "date",
                            "format": "epoch_second"
                        }
                    }
                }
                self.elk_client.indices.create(index=self.index, body={"mappings": self.mapping})
                self.logger_run.info(
                    "[PARSING][PLASO2ELK] Index {} created successfully with custom mapping.".format(self.index),
                    header="SUCCESS", indentation=2)
            else:
                self.logger_run.warning(
                    "[PARSING][PLASO2ELK] Index {} already exists. Skipping creation.".format(self.index),
                    header="WARNING", indentation=2)
            # Get the generator for the documents
            docs_generator = self.generate_documents()
            # Use the bulk helper to send documents in chunks.
            # Setting raise_on_error to False allows the process to continue even if a document fails.
            success, failed = bulk(self.elk_client, docs_generator, chunk_size=5000, raise_on_error=False,
                                   raise_on_exception=False)

            self.logger_run.info(
                "[PARSING][PLASO2ELK] BULK ingestion completed, Successfully indexed {} documents.".format(success),
                header="FINISHED", indentation=2)

            if failed:
                self.logger_run.error(
                    "[PARSING][PLASO2ELK] ERROR During ingestion, failed to ingest {} documents".format(len(failed)),
                    header="ERROR",
                    indentation=2)
                '''
                with open("failed_documents.log", "w") as f:
                    for item in failed:
                        f.write(json.dumps(item) + "\n")
                '''
        except Exception as e:
            self.logger_run.error("[PARSING][PLASO2ELK] ERROR During ingestion {}".format(traceback.format_exc()),
                                  header="ERROR",
                                  indentation=2)

    def format_ts_to_es(self, timestamp_ms):
        date_object = datetime.fromtimestamp(timestamp_ms / 1e6)
        iso_format = date_object.isoformat() + "Z"
        return iso_format


class WindowsForensicArtefactParser:
    """
       Class WindowsForensicArtefactParser
       MPP or WindowsForensicArtefactParser is a python script that will parse a plaso - Log2Timeline json timeline file.
       The goal is to provide easily readable and straight forward files for the Forensic analyst.
       MPP will create a file for each artefact.
       Attributes :
       None
    """

    def __init__(self, path_to_archive, output_directory, case_name, machine_name="", separator='|', main_id="",
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
        self.extracted_dir = os.path.join(self.machine_working_folder_path, "extracted_raw")
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
        self.mft_dir = os.path.join(self.parsed_dir, "mft")
        self.initialise_working_directories()

        self.running_log_file_path = os.path.join(self.log_dir, "{}_running.log".format(self.main_id))

        self.logger_run = LoggerManager("running", self.running_log_file_path, "INFO")

        if artefact_config:
            self.artefact_config = artefact_config
            self.logger_run.info(
                "[ARTEFACT][CONFIG] loading custom config  {}".format(json.dumps(self.artefact_config, indent=4)),
                header="INFO", indentation=0)
        else:
            artefact_config_path = "/python-docker/WAPP_MODULE/config/artefact_name_config.json"
            try:
                self.logger_run.info("[ARTEFACT][CONFIG] No config provided, loading default config file {}".format(artefact_config_path), header="INFO", indentation=0)
                with open(artefact_config_path, "r") as config_file_stream:
                    self.artefact_config = json.load(config_file_stream)
            except:
                self.artefact_config = {
                    "orc": {
                        "orc_run_logs": [r"Statistics.json", r"config.xml", r"Config.xml", r"FastFind_result.xml",
                                         r"GetThis*",
                                         r"Statistics_*.json", r"_config.xml", r"getthis"]
                    },
                    "artefacts": {
                        "system": {
                            "system_info": [r"Systeminfo.csv"]
                        },
                        "network": {
                            "tcpvcon": [r"Tcpvcon.txt"],
                            "arp_cache": [r"arp_cache.txt"],
                            "dns_cache": [r"dns_cache.txt"],
                            "netstat": [r"netstat.txt"],
                            "routes": [r"routes.txt"],
                            "hosts": [r"hosts$"],
                            "lmhosts": [r"lmhosts.sam"],
                            "protocol": [r"protocol$"],
                            "services": [r"services$"],
                            "network": [r"networks$"],
                            "bits": [r"BITS_jobs.txt"]
                        },
                        "hives": {
                            "NTUSER": [r"NTUSER.DAT$"],
                            "AMCACHE": [r"Amcache.hve$"],
                            "SOFTWARE": [r"SOFTWARE$"],
                            "SYSTEM": [r"SYSTEM$"],
                            "SECURITY": [r"SECURITY$"],
                            "SAM": [r"SAM$"]
                        },
                        "process": {
                            "process1": [r"process1.csv", r"processes1.csv"],
                            "process2": [r"process2.csv", r"processes2.csv"],
                            "autoruns": [r"autoruns.csv"],
                            "sample_autoruns": [r"GetSamples_autoruns.xml", r"Process_Autoruns.xml"],
                            "sample_timeline": [r"GetSamples_timeline.csv", r"Process_timeline.csv"],
                            "sample_info": [r"GetSamples_sampleinfo.csv", r"Process_sampleinfo.csv"],
                            "handle": [r"handle.txt"],
                            "enum_lock": [r"Enumlocs.txt"],
                            "list_dll": [r"Listdlls.txt"],
                            "ps_services": [r"psService.txt"]
                        },
                        "event_logs": {
                            "evtx": [r".*.evtx"]
                        },
                        "powershell": {
                            "consol_history": [r"ConsoleHost_history.txt"],
                            "Module_Analysis_Cache": [r"ModuleAnalysisCache"]
                        },
                        "master_file_table": {
                            "MFT": [r"MFT$"]
                        },
                        "disk": {
                            "usn_journal": [r"USNInfo.*.csv"],
                            "VSS_List": [r"VSS_list.csv"]
                        },
                        "files": {
                            "Activity_cache": [r"ActivitiesCache.db"],
                            "sdb": [r".*.sdb"],
                            "SRUM": [r"SRUDB.dat", r"SRU.*.log"],
                            "super_fetch": [r"ag.*.db"],
                            "Wmi": [r"OBJECTS.DATA", r"INDEX.BTR", r"MAPPING*.MAP"],
                            "prefetch": [r".*.pf"],
                            "lnk": [r".*.lnk"],
                            "recent_file": [r".*-ms"]
                        },
                        "browsers": {
                            "browser_history": [r".*.sqlite"]
                        },
                        "others": {
                            "event_consumer": [r"EventConsumer.txt"],
                            "setup_api": [r"setupapi"],
                            "mrt": [r"mrt"]
                        }
                    }
                }
                self.logger_run.info(
                    "[ARTEFACT][CONFIG] Error loading default config file, loading embedded config {}".format(json.dumps(self.artefact_config, indent=4)),
                    header="INFO", indentation=0)

        if main_config:
            self.main_config = main_config
            self.logger_run.info("[PARSER][CONFIG] Custom config provided using: {}".format(json.dumps(self.main_config, indent=4)),
                                  header="INFO",indentation=0)
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
                    "system_info": 1
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
            print("[CREATING FOLDER] {}".format(self.extracted_dir))
            os.makedirs(self.extracted_dir, exist_ok=True)
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

        except:
            sys.stderr.write("\nfailed to initialises directories {}\n".format(traceback.format_exc()))

    def extract(self):
        """
         to extract orc archives
        :return:
        """
        try:
            extractor = OrcExtractor(self.logger_run)
            self.logger_run.info("[EXTRACTING] archives", header="START", indentation=0)
            cleaned_name_archive = self.clean_archive_name(r'__\d+$', self.path_to_archive)
            root, filename = os.path.split(cleaned_name_archive)  # /blabla/ - orc1.7z
            filename_wo_ext, file_ext = os.path.splitext(filename)  # /blabla/orc1
            if file_ext == ".7z":
                self.logger_run.info("[EXTRACTING] {}".format(self.path_to_archive), header="START", indentation=1)
                extractor.extract_7z_archive(self.path_to_archive, self.extracted_dir)
            if file_ext == ".zip":
                self.logger_run.info("[EXTRACTING] {}".format(self.path_to_archive), header="START", indentation=1)
                extractor.extract_zip_archive(self.path_to_archive, self.extracted_dir)
            self.logger_run.info("[EXTRACTING] archives", header="FINISHED", indentation=0)
        except:
            self.logger_run.error("[EXTRACTING] archives {}".format(traceback.format_exc()), header="ERROR", indentation=0)

    def clean_archive_name(self, pattern, og_name):
        new_name = re.sub(pattern, '', og_name)
        return new_name

    def search_and_copy_artefacts(self, l_file_to_search, out_dir):
        mngr = FileManager()
        for f_patern in l_file_to_search:
            l_file = mngr.recursive_file_search(self.extracted_dir, f_patern)
            if l_file:
                for file in l_file:
                    mngr.copy_file_to_dest(file, out_dir)

    def move_artefact_no_parsing(self):

        for artefact, list_pattern in self.artefact_config.get("orc",{}).items():
            self.search_and_copy_artefacts(list_pattern, self.orc_log_dir)

        for artefact, list_pattern in self.artefact_config.get("artefacts", {}).get("powershell", {}).items():
            self.search_and_copy_artefacts(list_pattern, self.powershell_dir)

        for artefact, list_pattern in self.artefact_config.get("artefacts", {}).get("system", {}).items():
            self.search_and_copy_artefacts(list_pattern, self.parsed_dir)

        all_file_to_search = []
        for k, v in self.artefact_config.get("artefacts", {}).get("network", {}).items():
            if type(v) == list:
                all_file_to_search.extend(v)
            elif type(v) == str:
                all_file_to_search.append(v)
        self.search_and_copy_artefacts(all_file_to_search, self.network_dir)

        all_file_to_search = []
        for k, v in self.artefact_config.get("artefacts", {}).get("process", {}).items():
            if type(v) == list:
                all_file_to_search.extend(v)
            elif type(v) == str:
                all_file_to_search.append(v)
        self.search_and_copy_artefacts(all_file_to_search, self.process_dir)

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
                      "{}".format(self.extracted_dir)]

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
                mngr = FileManager()
                for pattern in evtx_f_pattern:
                    all_evt = mngr.recursive_file_search(self.extracted_dir, pattern)
                    if all_evt:
                        for evt in all_evt:
                            try:
                                evt_name = os.path.basename(evt)
                                evt_name_wo_ext = os.path.splitext(evt_name)[0]
                                evt_json_name = evt_name_wo_ext + ".json"
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
            mngr = FileManager()

            mft_patterns = self.artefact_config.get("artefacts", {}).get("master_file_table", {}).get("MFT", [])
            if mft_patterns and isinstance(mft_patterns, list):
                for mft_pattern in mft_patterns:
                    mft_files = mngr.recursive_file_search(self.extracted_dir,mft_pattern)
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
            mngr = FileManager()
            l_file = mngr.list_files_recursive(dir_to_clean)
            for file in l_file:
                self.clean_duplicate_in_file(file)
            self.logger_run.info("[CLEAN DUPLICATE]", header="FINISH", indentation=1)
        except:
            self.logger_run.error("[CLEAN DUPLICATE] {}".format(traceback.format_exc()), header="ERROR", indentation=1)

    def do_system_info(self):
        try:
            self.logger_run.info("[PARSING][SYSTEMINFO]", header="START", indentation=1)
            s_parser = SystemInfoParser(self.logger_run)
            self.system_info = s_parser.parse_all(self.extracted_dir, self.result_parsed_dir)
            self.logger_run.info("[PARSING][SYSTEMINFO]", header="FINISHED", indentation=1)

            if self.system_info[0].get("Nom d'hôte", ""):
                self.machine_name = self.system_info[0].get("Nom d'hôte", "")
                self.logger_run.info("Machine Name found : {}".format(self.machine_name), header="INFO", indentation=0)
        except Exception as ex:
            self.logger_run.error("[PARSING][SYSTEMINFO] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=0)

    def do_network(self):
        self.logger_run.info("[PARSING][NETWORK]", header="START", indentation=1)
        n_parser = NetWorkParser(self.logger_run)
        n_parser.parse_all(self.network_dir, self.result_parsed_dir )
        self.logger_run.info("[PARSING][NETWORK]", header="FINISHED", indentation=1)

    def do_process(self):
        self.logger_run.info("[PARSING][PROCESS]", header="START", indentation=1)
        p_parser = ProcessParser(self.logger_run)
        p_parser.parse_all(self.process_dir, self.result_parsed_dir)
        self.logger_run.info("[PARSING][PROCESS]", header="FINISHED", indentation=1)

    def do_disk(self):
        """
        To parse USN journal to human readble format (|DATE|TIME|ETC|ETC)
        :return:
        """

        try:
            self.logger_run.info("[PARSING][USNJRNL]", header="START", indentation=1)

            mngr = FileManager()
            d_parser = DiskParser(self.logger_run)
            usn_paterns = self.artefact_config.get("artefacts", {}).get("disk", {}).get("usn_journal")

            all_file_to_search = []
            for k,v in self.artefact_config.get("artefacts", {}).get("disk", {}).items():
                if type(v) == list:
                    all_file_to_search.extend(v)
                elif type(v) == str:
                    all_file_to_search.append(v)
            self.search_and_copy_artefacts(all_file_to_search, self.disk_dir)

            for usn_patern in usn_paterns:
                usn_files = mngr.recursive_file_search(self.extracted_dir, usn_patern)
                for usn_file in usn_files:
                    d_parser.parse_usnjrnl(usn_file, self.result_parsed_dir)

            self.logger_run.info("[PARSING][USNJRNL]", header="FINISHED", indentation=1)

        except:
            self.logger_run.error("[CREATING][USNJRNL] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=1)

    def do_hive(self):

        self.logger_run.info("[PARSING][HIVES]", header="START", indentation=1)
        h_parser = RegistryParser(self.logger_run)
        h_parser.parse_amcache_regpy(self.extracted_dir, self.result_parsed_dir)
        h_parser.parse_all_hives_yarp(self.extracted_dir, self.result_parsed_dir)
        self.logger_run.info("[PARSING][HIVES]", header="FINISHED", indentation=1)

    def do_lnk(self):
        """
        To convert all LNK file to json and parse them to a human friendly format : DATE|TIME|ETC|ETC
        :return:
        """
        try:

            self.logger_run.info("[PARSING][LNK]", header="START", indentation=1)
            lnk_parser = LinkParser(self.logger_run, self.lnk_dir)
            mngr = FileManager()

            lnk_paterns = self.artefact_config.get("artefacts", {}).get("files", {}).get("lnk", "")
            for lnk_patern in lnk_paterns:
                lnk_files = mngr.recursive_file_search(self.extracted_dir, lnk_patern)
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
            mngr = FileManager()
            pf_parser = PrefetchParser(self.logger_run)
            prefetch_final_file = os.path.join(self.result_parsed_dir, "prefetchs.csv")

            l_pf_files = mngr.recursive_file_search(self.extracted_dir, pf_re)
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
            mp = MaximumPlasoParserJson(path_to_timeline=self.timeline_json_path,
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

    def do_mft(self):
        """
        Launch the converting and parsing of mft
        :return:
        """
        try:
            self.logger_run.info("[PARSING][MFT]", header="START", indentation=1)
            mft_result_file = self.convert_mft_to_json()
            if mft_result_file:
                d_parser = DiskParser(self.logger_run)
                d_parser.parse_mft(mft_result_file, self.result_parsed_dir)
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
            e_parser = EventParser(self.evt_dir, self.result_parsed_dir)
            e_parser.parse_all()
            self.logger_run.info("[PARSING][EVTX]", header="FINISHED", indentation=1)
        except:
            self.logger_run.error("[PARSING][EVTX] {}".format(traceback.format_exc()), header="ERROR",
                                  indentation=1)

    def do_elk(self):
        p_agent = PlasoToELK(self.logger_run, self.timeline_json_path, self.case_name, self.machine_name)
        if p_agent.test_connection():
            p_agent.send_to_elk_in_bulk()

        else:
            self.logger_run.error("[CONNECTING][ELK] aboarding", header="ERROR", indentation=1)

    def do(self):
        self.extract()
        f_manager = FileManager()
        f_manager.rename_nested_folder(self.extracted_dir)
        self.move_artefact_no_parsing()
        self.logger_run.info("[PARSING][ARTEFACTS]", header="START", indentation=0)

        if self.main_config.get("system_info", False):
            self.do_system_info()
        if self.main_config.get("network", False):
            self.do_network()
        if self.main_config.get("process", False):
            self.do_process()
        if self.main_config.get("disk", False):
            self.do_disk()
        if self.main_config.get("hive", False):
            self.do_hive()
        if self.main_config.get("lnk", False):
            self.do_lnk()
        if self.main_config.get("prefetch", False):
            self.do_prefetch()
        if self.main_config.get("mft", False):
            self.do_mft()
        if self.main_config.get("evtx", False):
            self.do_evtx()

        self.clean_duplicates(self.result_parsed_dir)  # Need to be fixed

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
        'Solution to parse a json plaso timeline'))

    argument_parser.add_argument('-t', '--timeline', action="store",
                                 required=False, dest="timeline", default=False,
                                 help="path to the timeline , must be json timeline")

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

    argument_parser.add_argument("--type", action="store",
                                 required=False, dest="type_output", default="csv",
                                 choices=["csv", "json", "all"], metavar="csv or json or all for both",
                                 help="type of the output file format : csv or json or both. Default is csv")

    argument_parser.add_argument("-m", "--machine_name", action="store",
                                 required=False, dest="machine_name",
                                 metavar="name of the machine",
                                 help="name of the machine")

    argument_parser.add_argument("--config", action="store",
                                 required=False, dest="config_file", default=None,
                                 help="path to the json config file to be used")

    argument_parser.add_argument("--file_to_append", action="store",
                                 required=False, dest="file_to_append",
                                 help="path to the file to be merge with timeline")

    argument_parser.add_argument("--current_timeline", action="store",
                                 required=False, dest="current_timeline_to_merge",
                                 help="path to the timeline to be merge with new file")
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
location": "Microsoft-Windows-Windows Defender%4Operational.evtx
location": "Microsoft-Windows-Windows Defender%4WHC.evtx
event id 1116 1117 1015 1013 1014 1012 1011 1010 1009 1008 1007 1006 1005 1004 1003 1002 

location": "Microsoft-Windows-Windows Firewall With Advanced Security%4ConnectionSecurity.evtx
location": "Microsoft-Windows-Windows Firewall With Advanced Security%4FirewallDiagnostics.evtx
location": "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx
location": "Microsoft-Windows-WindowsUpdateClient%4Operational.evtx
location": "Microsoft-Windows-WinINet-Config%4ProxyConfigChanged.evtx
location": "Microsoft-Windows-Winlogon%4Operational.evtx
location": "Microsoft-Windows-WinRM%4Operational.evtx
location": "Microsoft-Windows-WMI-Activity%4Operational.evtx
  
4614 This event is generated when a user attempts to change their password. It is logged on domain controllers 
and member computers. 

Send json to ELK with index through curl, doesnt work with big files
jq -c -r '. | {"index": {"_index": "geelong"}}, .' amcache.json | curl -XPOST "http://localhost:9200/_bulk?pretty" -H "Content-Type: application/json" --data-binary @-


Multiple plaso parser name
"parser": "pe",
"parser": "winreg/msie_zone",
"""

#!/usr/bin/python3
import argparse
import csv
from datetime import datetime, timedelta
import json
import os
import re
from regipy.registry import RegistryHive
from regipy.plugins.utils import run_relevant_plugins
import traceback
from typing import Dict, List, Any
from yarp import * # must be install from github : https://github.com/msuhanov/yarp/releases
from pathlib import Path

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
                        self.logger_run.warning(f"[PARSING][AMCACHE][REGPY] Regpy could'nt parse Amcache", header="FAILED", indentation=2)
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

                    if formatted_for_csv:
                        formatted_for_csv.sort(key=lambda x: (x.get("Date"), x.get("Time")))

                    if formatted_for_csv:
                        path_out_csv = os.path.join(dir_out, f"{os.path.basename(file_path)}.csv")
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

    def format_amcache_from_json_yarp(self, amcache_file: str, dir_out: str, output_delimiter='|'):
        """
        Parses an AmCache file in JSON Lines format (from YARP) and converts it to a CSV file.

        This improved function correctly handles file reading line-by-line, separates parsing
        from writing, provides more robust error handling, and uses the csv module
        correctly to write the output.

        Args:
            amcache_file (str): Path to the input JSONL file containing AmCache data.
            dir_out (str): Path to the directory where the output CSV file will be saved.
            output_delimiter (str): The delimiter to use for the output CSV file.
        """
        output_file = os.path.join(dir_out, "amcache_yarp.csv")
        parsed_data = []

        # --- Step 1: Read and parse the JSONL file ---
        try:
            with open(amcache_file, 'r', encoding='utf-8') as infile:
                for i, line in enumerate(infile):
                    try:
                        entry = json.loads(line)
                        if isinstance(entry, dict):
                            # Extract data with safe fallbacks using .get()
                            timestamp = entry.get("last_written_timestamp", "1970-01-01T00:00:00.000000")
                            date, time = timestamp.split("T", 1)  # Split only on the first T
                            name = entry.get("name", "N/A")
                            path = entry.get("path", "N/A")
                            parsed_data.append([date, time, name, path])

                    except json.JSONDecodeError:
                        self.logger_run.error(f"[PARSING][AMCACHE] Line {i + 1}: Skipping malformed JSON line.")
                    except (KeyError, ValueError) as e:
                        self.logger_run.error(f"[PARSING][AMCACHE] Line {i + 1}: Error processing entry. Error: {e}")

        except FileNotFoundError:
            self.logger_run.error(f"[PARSING][AMCACHE] Input file not found: {amcache_file}")
            return
        except Exception as e:
            self.logger_run.error(f"[PARSING][AMCACHE] An unexpected error occurred while reading the file: {e}")
            return

        # --- Step 1.5: Sort the data by date ---
        if parsed_data:
            # Sorts the list of lists. As the date is the first element and in
            # YYYY-MM-DD format, a standard sort is sufficient.
            parsed_data.sort()

        # --- Step 2: Write the parsed data to a CSV file ---
        if not parsed_data:
            self.logger_run.warning("[PARSING][AMCACHE] No data was parsed. The output file will not be created.")
            return

        try:
            # Ensure the output directory exists
            os.makedirs(dir_out, exist_ok=True)

            with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
                writer = csv.writer(outfile, delimiter=output_delimiter, quoting=csv.QUOTE_MINIMAL)

                # Define and write the header
                header = ['Date', 'Time', 'name', 'path']
                writer.writerow(header)

                # Write all the parsed data at once
                writer.writerows(parsed_data)

            self.logger_run.info(f"[PARSING][AMCACHE] Successfully created CSV file at {output_file}")

        except IOError as e:
            self.logger_run.error(f"[PARSING][AMCACHE] Could not write to output file: {output_file}. Error: {e}")

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
                "log1": r'Amcache.hve.LOG1$',
                "log2": r'Amcache.hve.LOG2$',
                "log3": r'Amcache.hve.LOG3$'
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
                self.format_amcache_from_json_yarp(output_jsonl_path, output_path)
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
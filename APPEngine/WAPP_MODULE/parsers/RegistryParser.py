#!/usr/bin/python3
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

    def parse_amcache_regpy(self, file_path: str, dir_out: str):
        """
        Main function to parse amcache with regipy from a specific file.

        Args:
            file_path: path to the amcache file.
            dir_out: Path to the results folder where files will be saved.
        """
        self.logger_run.info("[PARSING][AMCACHE][REGPY]", header="START", indentation=2)

        try:
            if not os.path.exists(file_path):
                self.logger_run.error(
                    "[PARSING][AMCACHE][REGPY]: File not found {}".format(traceback.format_exc()),
                    header="ERROR",
                    indentation=2)
                return

            path_out_json = os.path.join(dir_out, f"{os.path.basename(file_path)}_regpy.json")
            reg = RegistryHive(file_path)
            parsed_data = run_relevant_plugins(reg, as_json=True)
            with open(path_out_json, "w") as outfile:
                json.dump(parsed_data, outfile, indent=4)

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
                    continue

                formatted_for_csv.append({
                    "Date": date_str,
                    "Time": time_str,
                    "Name": entry.get("original_file_name", "-"),
                    "Hash": entry.get("sha1", "-")
                })

            if formatted_for_csv:
                formatted_for_csv.sort(key=lambda x: (x.get("Date"), x.get("Time")))
                path_out_csv = os.path.join(dir_out, f"{os.path.basename(file_path)}.csv")
                header_list = ["Date", "Time", "Name", "Hash"]

                with open(path_out_csv, 'w', newline='', encoding='utf-8') as outfile:
                    writer = csv.DictWriter(outfile, fieldnames=header_list, delimiter='|')
                    writer.writeheader()
                    writer.writerows(formatted_for_csv)
                self.logger_run.info("[PARSING][AMCACHE][REGPY]", header="FINISHED", indentation=2)
            return path_out_json
        except Exception as e:
            self.logger_run.error(
                "[PARSING][AMCACHE][REGPY]: An unexpected error occurred{}".format(traceback.format_exc()),
                header="ERROR",
                indentation=2)

    def format_amcache_from_json_yarp(self, amcache_file: str, dir_out: str, output_delimiter='|'):
        output_file = os.path.join(dir_out, "amcache_yarp.csv")
        parsed_data = []

        try:
            with open(amcache_file, 'r', encoding='utf-8') as infile:
                for i, line in enumerate(infile):
                    try:
                        entry = json.loads(line)
                        if isinstance(entry, dict):
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

        if parsed_data:
            parsed_data.sort()

        if not parsed_data:
            self.logger_run.warning("[PARSING][AMCACHE] No data was parsed. The output file will not be created.")
            return

        try:
            os.makedirs(dir_out, exist_ok=True)

            with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
                writer = csv.writer(outfile, delimiter=output_delimiter, quoting=csv.QUOTE_MINIMAL)
                header = ['Date', 'Time', 'name', 'path']
                writer.writerow(header)
                writer.writerows(parsed_data)

            self.logger_run.info(f"[PARSING][AMCACHE] Successfully created CSV file at {output_file}")
            return output_file
        except IOError as e:
            self.logger_run.error(f"[PARSING][AMCACHE] Could not write to output file: {output_file}. Error: {e}")

    def _recursively_read_key(self, key):
        key_info = {
            "name": key.name(),
            "last_written_timestamp": key.last_written_timestamp().isoformat() if key.last_written_timestamp() else None,
            "values": {},
            "subkeys": {}
        }

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

                key_info["values"][value.name()] = value_info
        except Registry.WalkException as e:
            self.logger_run.error(
                "[PARSING][HIVE][YARP]: error reading key {}: {}".format(
                    key.path(), e),
                header="ERROR",
                indentation=2)

        try:
            for subkey in key.subkeys():
                subkey_name = subkey.name()
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
        current_path = parent_path + "\\" + key.name() if parent_path else key.name()

        key_data = {
            "path": current_path,
            "name": key.name(),
            "last_written_timestamp": key.last_written_timestamp().isoformat() if key.last_written_timestamp() else None,
            "values": {}
        }

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
        try:
            hv_name = os.path.basename(hive_file_path)
            output_jsonl_path = os.path.join(output_path, "{}_yarp.jsonl".format(hv_name))
            self.logger_run.info("[PARSING][HIVE][YARP] {}".format(hv_name), header="START", indentation=2)

            with open(hive_file_path, "rb") as f_hive, open(output_jsonl_path, "w", encoding="utf-8") as f_jsonl:
                hive = Registry.RegistryHive(f_hive)
                root_key = hive.root_key()

                hive_info = {
                    "hive_path": str(hive_file_path),
                    "last_written": hive.last_written_timestamp().isoformat() if hive.last_written_timestamp() else None,
                    "last_reorganized": hive.last_reorganized_timestamp().isoformat() if hive.last_reorganized_timestamp() else None,
                }
                f_jsonl.write(json.dumps(hive_info, ensure_ascii=False) + "\n")

                self._recursively_write_key(root_key, f_jsonl)

            self.logger_run.info("[PARSING][HIVE][YARP] {}".format(hv_name), header="FINISHED", indentation=2)
            return output_jsonl_path, hv_name

        except Exception as e:
            self.logger_run.error(
                "[PARSING][HIVE][YARP]: An unexpected error occurred{}".format(traceback.format_exc()),
                header="ERROR",
                indentation=2)

    def export_hive_to_json(self, hive_file_path, output_path):
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
                return output_json_path, hv_name

        except Exception as e:
            self.logger_run.error(
                "[PARSING][HIVE][YARP]: An unexpected error occurred{}".format(traceback.format_exc()),
                header="ERROR", indentation=2)
            return False

    def export_amcache_to_jsonl(self, hive_file_path, output_path):
        """
        Exporte le contenu d'une ruche de registre en un fichier JSON Lines.

        Args:
            hive_file_path (str): Le chemin exact vers le fichier de la ruche (Amcache.hve).
            output_path (str): Le chemin où enregistrer le fichier JSON Lines.
        """
        try:
            hv_name = os.path.basename(hive_file_path)
            output_jsonl_path = os.path.join(output_path, "{}_yarp.jsonl".format(hv_name))

            primary_file = open(hive_file_path, 'rb')
            hive = Registry.RegistryHive(primary_file)

            # Cherche les logs transactionnels dans le même dossier
            log1_path = hive_file_path + ".LOG1"
            log2_path = hive_file_path + ".LOG2"
            log3_path = hive_file_path + ".LOG3"

            log1 = open(log1_path, 'rb') if os.path.exists(log1_path) else None
            log2 = open(log2_path, 'rb') if os.path.exists(log2_path) else None
            log3 = open(log3_path, 'rb') if os.path.exists(log3_path) else None

            recovery_result = hive.recover_auto(log1, log2, log3)

            if recovery_result.recovered:
                self.logger_run.info("[PARSING][AMCACHE][YARP] The hive {} has been recovered".format(hv_name),
                                     header="SUCCESS", indentation=2)
            else:
                self.logger_run.warning("[PARSING][AMCACHE][YARP] The hive {} has NOT been recovered".format(hv_name),
                                     header="WARNING", indentation=2)

            with open(output_jsonl_path, "w", encoding="utf-8") as f_jsonl:
                root_key = hive.root_key()

                hive_info = {
                    "last_written": hive.last_written_timestamp().isoformat() if hive.last_written_timestamp() else None,
                    "last_reorganized": hive.last_reorganized_timestamp().isoformat() if hive.last_reorganized_timestamp() else None,
                }
                f_jsonl.write(json.dumps(hive_info, ensure_ascii=False) + "\n")

                self._recursively_write_key(root_key, f_jsonl)

            self.format_amcache_from_json_yarp(output_jsonl_path, output_path)
            self.logger_run.info("[PARSING][AMCACHE][YARP]" , header="FINISHED", indentation=2)
            return output_jsonl_path

        except Exception as e:
            self.logger_run.error(
                "[PARSING][AMCACHE][YARP]: An unexpected error occurred{}".format(traceback.format_exc()),
                header="ERROR", indentation=2)
            return False
#!/usr/bin/python3
import argparse
import csv
import json
import os
import traceback
import re


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

    def recursive_file_search(self, dir_in, reg_ex):
        files = []
        for element in os.listdir(dir_in):
            full_path = os.path.join(dir_in, element)
            if os.path.isfile(full_path):
                if re.search(reg_ex, element):  # ,  re.IGNORECASE):
                    if full_path not in files:
                        files.append(full_path)
            elif os.path.isdir(full_path):
                files.extend(self.recursive_file_search(full_path, reg_ex))
        return files

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

            file_patterns = self.artefact_config.get("artefacts", {}).get("system", {}).get("system_info", [])
            if not file_patterns:
                self.logger_run.info("[PARSING][SYSTEMINFO] No file patterns configured for systeminfo.", header="FAILED",
                                     indentation=2)
                return system_info

            for file_pattern in file_patterns:
                l_file = self.recursive_file_search(input_dir, file_pattern)
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

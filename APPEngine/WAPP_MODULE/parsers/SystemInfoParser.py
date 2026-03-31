#!/usr/bin/python3
import csv
import json
import os
import traceback

class SystemInfoParser:
    """
    Class to parsed various tool results files into straight forward human readble csv.
    """

    def __init__(self, logger, separator="|") -> None:
        """
        The constructor for ProcessParser classes
        :param separator: str: csv separator default is pipe
        """
        self.logger_run = logger
        self.separator = separator

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
            return out_json_file_path

        else:
            self.logger_run.info("[PARSING][SYSTEMINFO] no data was found or parsed ", header="FAILED", indentation=2)
            return
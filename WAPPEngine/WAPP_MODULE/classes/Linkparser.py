#!/usr/bin/python3
import argparse
import csv
import json
import LnkParse3
import os
from pathlib import Path
import traceback

class LinkParser:
    """
    Class to parse lnk files and extract key information.
    """

    def __init__(self, logger_run, lnk_dir_out, human_parsed_dir, separator="|") -> None:
        """
        The constructor for LnkParser Class.
        :param logger_run: Logger object for logging messages.
        :param dir_out: (str) The directory path to store parsed lnk files.
        :param human_parsed_dir: (str) The directory path to store csv parsed file.
        :param separator: (str) The delimiter for the CSV output file.
        """
        self.logger_run = logger_run
        self.dir_out = Path(lnk_dir_out)
        self.separator = separator

        self.lnk_header = ["CreationTime", "AccessTime", "ModifiedTime", "Target/Path/Description", "lnkName"]
        self.lnk_result_csv_path = os.path.join(human_parsed_dir, "lnk.csv")

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

def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Parser for json formated lnk files'))

    argument_parser.add_argument('-i', '--input', action="store",
                                 required=False, dest="input_file", default=False,
                                 help="path to the input file")

    argument_parser.add_argument('-f', '--folder', action="store",
                                 required=False, dest="input_folder", default=False,
                                 help="path to the input folder")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")

    return argument_parser


if __name__ == '__main__':

    parser = parse_args()
    args = parser.parse_args()

    parser = LinkParser(None, args.output_dir, args.output_dir)
    if args.input_folder:
        parser.parse_all_lnk(args.input_folder)
    if args.input_file:
        parser.parse_lnk_to_json(args.input_file)
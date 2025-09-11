#!/usr/bin/python3
import traceback
import os
import re
import argparse

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
                self.parse_netstat(netstat_file, os.path.join(output_dir, "netstat"))

        tcpvcon_files = self.recursive_file_search(input_dir, self.artefact_config.get("tcpvcon", ""))
        if tcpvcon_files:
            for tcpvcon_file in tcpvcon_files:
                self.logger_run.info("[PARSING][TCPVCON]", header="START", indentation=2)
                self.parse_tcpvcon(tcpvcon_file, os.path.join(output_dir, "tcpvcon"))

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


def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Parser for networks artefacts collected by DFIR ORC'))

    argument_parser.add_argument('-i', '--input', action="store",
                                 required=True, dest="input_dir", default=False,
                                 help="path to the input directory")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")

    return argument_parser

if __name__ == '__main__':

    parser = parse_args()
    args = parser.parse_args()

    nt_parser = NetWorkParser(None)
    nt_parser.parse_all(args.input_dir, args.output_dir)
#!/usr/bin/python3
import traceback
import os
import re

class NetWorkParser:
    """
       Class parse network files to human-readable csv DATE|TIME|ETC|ETC
    """

    def __init__(self, logger, separator="|") -> None:
        """
        The constructor for NetWorkParser classes
        :param separator: str: csv separator default is pipe
        """
        self.logger_run = logger
        self.separator = separator

    def parse_tcpvcon(self, input_filepath, output_filepath):
        """
        Parses a classic CSV file, removes specified header/footer lines,
        removes duplicate lines, and rewrites unique entries to an output file
        with a specified output separator.
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
                        continue

                    should_exclude = False
                    for exclusion_str in exclusion_strings:
                        if exclusion_str in stripped_line:
                            should_exclude = True
                            break

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
        """
        try:
            unique_processed_lines = set()

            with open(input_filepath, 'r', encoding='utf-8', errors='ignore') as infile:
                for line in infile:
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue

                    fields = [field.strip() for field in stripped_line.split()]
                    processed_line = "|".join(fields)
                    unique_processed_lines.add(processed_line)

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
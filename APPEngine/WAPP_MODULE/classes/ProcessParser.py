#!/usr/bin/python3
import argparse
import csv
from datetime import datetime
import os
from pathlib import Path
import re
import traceback
import xmltodict


class ProcessParser:
    """
    Class to parsed various tool results files into straight forward human readble csv.
    (sysinternals Autoruns, DFIR-ORC PROCESS1, DFIR-ORC PROCESS2, DFIR-ORC PROCESS INFO, DFIR-ORC PROCESS_TIMELINE
    DFIR-ORC PROCESS_AUTORUNS)
    """

    def __init__(self, logger, artefact_config=None, separator="|") -> None:
        """
        The constructor for ProcessParser classes
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
        output_filepath  = os.path.join(output_dir, "autoruns.csv")
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
                                    entry_val = l_line[column_indices["Entry Location"]].strip()
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
        out_file = os.path.join(output_dir, "process1")
        out_file_simple = os.path.join(output_dir, "process1_s")
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
        out_file = os.path.join(output_dir, "process_info")
        self.convert_csv_separator(file_path, out_file, output_delimiter)
        self.logger_run.info("[PARSING][PROCESS_INFO]", header="FINISHED", indentation=2)

    def parse_process_timeline(self, file_path: Path, output_dir: Path, output_delimiter: str = '|'):
        """
        Parses a DFIR-ORC GetSample_info CSV file to create a timeline.
        """
        output_file = os.path.join(output_dir, "processtl.csv")

        try:
            with open(file_path, 'r', encoding='utf-8-sig', newline='') as infile:
                with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
                    reader = csv.DictReader(infile)

                    # Define the header for your new, transformed file
                    new_header = ['Date', 'Time', 'Type', 'ParentID', 'ProcessID', 'FullPath', 'ComputerName']

                    writer = csv.writer(outfile, delimiter=output_delimiter, quoting=csv.QUOTE_NONE)
                    writer.writerow(new_header)

                    # Now, each 'row' will be a dictionary
                    for row in reader:
                        try:
                            # And this line will now work correctly!
                            full_timestamp = row['Time']
                            date_part, time_part = full_timestamp.split(' ', 1)

                            transformed_row = [
                                date_part,
                                time_part,
                                row['Type'],
                                row['ParentID'],
                                row['ProcessID'],
                                row['FullPath'],
                                row['ComputerName']
                            ]
                            writer.writerow(transformed_row)
                        except (KeyError, ValueError) as e:
                            self.logger_run.error("[PARSING][PROCESS_TIMELINE] key error", header="ERROR", indentation=2)

                self.logger_run.info("[PARSING][PROCESS_TIMELINE]", header="FINISHED", indentation=2)

        except FileNotFoundError:
            self.logger_run.info(f"[PARSING][PROCESS_TIMELINE]File not found {file_path}", header="ERROR", indentation=2)
        except Exception as e:
            self.logger_run.info(f"[PARSING][PROCESS_TIMELINE] Unexpected ERROR {e}", header="ERROR",
                                 indentation=2)

    def parse_process2(self, file_path, output_dir, output_delimiter='|'):
        """
        Parse the output of DFIR-ORC GetSample_info  to a straight forward human readable csv file
        :param file_path: path of the GetSample__info result file
        :return:
        """
        out_file = os.path.join(output_dir, "process2")
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
        out_file = os.path.join(output_dir, "proc_autoruns.csv")

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
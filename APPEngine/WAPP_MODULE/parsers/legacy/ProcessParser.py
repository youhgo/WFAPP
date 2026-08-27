#!/usr/bin/python3
import csv
from datetime import datetime
import os
from pathlib import Path
import re
import traceback
import xmltodict
from typing import Generator, Any, Dict, Tuple

from ...classes.BaseParser import BaseParser

class ProcessParser(BaseParser):
    """
    Class to parse various tool results files into straightforward human readable formats.
    """

    def parse(self, input_path: Path, category: str = "", **kwargs) -> Generator[Tuple[str, Any], None, None]:
        if not input_path.exists():
            if self.logger:
                self.logger.error(f"[PARSING][PROCESS] File not found {input_path}", header="ERROR")
            return

        if category == "autoruns":
            yield from self._parse_autoruns_sysinternals(input_path)
        elif category == "process1":
            yield from self._parse_process1(input_path, **kwargs)
        elif category == "process2":
            yield from self._parse_process2(input_path)
        elif category == "sample_autoruns":
            yield from self._parse_process_autoruns(input_path)
        elif category == "sample_timeline":
            yield from self._parse_process_timeline(input_path)
        elif category == "sample_info":
            yield from self._parse_process_infos(input_path)

    def _parse_autoruns_sysinternals(self, input_filepath: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        initial_exclusion_patterns = [r"Sysinternals", r"Copyright"]
        full_input_header = [
            "Time", "Entry Location", "Entry", "Enabled", "Category", "Profile",
            "Description", "Signer", "Company", "Image Path", "Version",
            "Launch String", "MD5", "SHA-1", "PESHA-1", "PESHA-256", "SHA-256", "IMP"
        ]
        column_indices = {name: full_input_header.index(name) for name in full_input_header}
        unique_processed_rows = {}

        try:
            with open(input_filepath, 'r', encoding='utf-16', newline='') as infile:
                for line in infile.readlines():
                    skip = False
                    for exclude_pattern in initial_exclusion_patterns:
                        if re.match(exclude_pattern, line, re.IGNORECASE):
                            skip = True
                            break
                    if skip or not line.strip():
                        continue

                    l_line = line.split(",")
                    if len(l_line) < 14:
                        continue
                        
                    raw_timestamp = l_line[column_indices["Time"]].strip()
                    entry_val = l_line[column_indices["Entry Location"]].strip()
                    imgpath_val = l_line[column_indices["Image Path"]].strip()
                    launchstring_val = l_line[column_indices["Launch String"]].strip()
                    md5_val = l_line[column_indices["MD5"]].strip()
                    
                    if len(raw_timestamp) == 15 and raw_timestamp[8] == '-':
                        formatted_date = f"{raw_timestamp[0:4]}-{raw_timestamp[4:6]}-{raw_timestamp[6:8]}"
                        formatted_time = f"{raw_timestamp[9:11]}:{raw_timestamp[11:13]}:{raw_timestamp[13:15]}"
                    else:
                        formatted_date = raw_timestamp
                        formatted_time = ""

                    key = f"{formatted_date}|{formatted_time}|{entry_val}|{imgpath_val}|{launchstring_val}|{md5_val}"
                    if key not in unique_processed_rows:
                        unique_processed_rows[key] = {
                            "Date": formatted_date,
                            "Time": formatted_time,
                            "Entry": entry_val,
                            "Image Path": imgpath_val,
                            "Launch String": launchstring_val,
                            "MD5": md5_val
                        }
                        
            # Yield sorted unique lines
            for key in sorted(unique_processed_rows.keys()):
                yield "autoruns", unique_processed_rows[key]
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][AUTORUNS]: Error {e}", header="ERROR", indentation=2)

    def _parse_process1(self, input_filepath: Path, is_simplified: bool = False) -> Generator[Tuple[str, str], None, None]:
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

        try:
            tree = self._extract_tree_from_process(input_filepath, full_input_header)
            yield from self._yield_process_tree(tree, is_simplified)
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][PROCESS1]: Error {e}", header="ERROR", indentation=2)

    def _extract_tree_from_process(self, file_path, full_input_header):
        column_indices = {name: full_input_header.index(name) for name in full_input_header}
        processes = {}

        with open(file_path, "r") as process:
            csv_reader = csv.reader(process, delimiter=",")
            try:
                next(csv_reader)
            except StopIteration:
                return {"processes": {}, "roots": []}
                
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
                    CreationDate = self._format_wmi_timestamp(line[column_indices["CreationDate"]].strip())
                    InstallDate = self._format_wmi_timestamp(line[column_indices["InstallDate"]].strip())

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

        root_pids = []
        for pid, process_info in processes.items():
            parent_pid = process_info["ParentProcessId"]
            if parent_pid == "0" or parent_pid not in processes:
                root_pids.append(pid)
            else:
                processes[parent_pid]["Children"].append(pid)

        for pid in processes:
            processes[pid]["Children"].sort()

        return {"processes": processes, "roots": sorted(root_pids)}

    def _yield_process_tree(self, tree_data: dict, is_simplified=False, indent_char="----", indent_char_pid="════"):
        processes = tree_data.get("processes", {})
        roots = tree_data.get("roots", [])

        if not processes:
            yield "process1", "No process data to display."
            return

        artifact_name = "process1_s" if is_simplified else "process1"

        for root_pid in roots:
            if is_simplified:
                yield from self._yield_process_node_simplified(artifact_name, processes, indent_char, indent_char_pid, root_pid, 0)
            else:
                yield from self._yield_process_node(artifact_name, processes, indent_char, indent_char_pid, root_pid, 0)

    def _yield_process_node(self, artifact_name, processes, indent_char, indent_char_pid, pid, level):
        if pid not in processes:
            return

        process = processes[pid]
        indent = indent_char * level
        indent_pid = indent_char_pid * level

        yield artifact_name, f"{indent_pid}>({process['ProcessId']}) {process['ProcessName']} (Parent: {process['ParentProcessId']})"
        yield artifact_name, f"{indent}{indent_char}>[CREATED]: {process['CreationDate']}"
        yield artifact_name, f"{indent}{indent_char}>[PATH]: {process['ExecutablePath']}"

        if process['CommandLine']:
            yield artifact_name, f"{indent}{indent_char}>[CMD]: {process['CommandLine']}"

        for child_pid in process['Children']:
            yield from self._yield_process_node(artifact_name, processes, indent_char, indent_char_pid, child_pid, level + 1)

    def _yield_process_node_simplified(self, artifact_name, processes, indent_char, indent_char_pid, pid, level):
        if pid not in processes:
            return

        process = processes[pid]
        indent_pid = indent_char_pid * level
        
        line = f"{indent_pid}>({process['ProcessId']}) {process['ProcessName']} (Parent: {process['ParentProcessId']}) | [CREATED]: {process['CreationDate']} | [PATH]: {process['ExecutablePath']}"
        yield artifact_name, line

        for child_pid in process['Children']:
            yield from self._yield_process_node_simplified(artifact_name, processes, indent_char, indent_char_pid, child_pid, level + 1)

    def _format_wmi_timestamp(self, wmi_timestamp_str: str) -> str:
        if not wmi_timestamp_str or len(wmi_timestamp_str) < 14:
            return wmi_timestamp_str

        output_format = "%Y-%m-%d|%H:%M:%S"
        possible_input_formats = ["%Y%m%d%H%M%S", "%Y%m%d-%H%M%S"]

        for input_format in possible_input_formats:
            datetime_part_len = 14 if input_format == "%Y%m%d%H%M%S" else 15
            if len(wmi_timestamp_str) < datetime_part_len:
                continue
            datetime_part = wmi_timestamp_str[:datetime_part_len]
            try:
                dt_object = datetime.strptime(datetime_part, input_format)
                return dt_object.strftime(output_format)
            except ValueError:
                continue
        return wmi_timestamp_str

    def _parse_process_infos(self, file_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        try:
            with open(file_path, "r") as process:
                reader = csv.DictReader(process, delimiter=",")
                for row in reader:
                    yield "process_info", row
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][PROCESS_INFO] Error {e}", header="ERROR", indentation=2)

    def _parse_process_timeline(self, file_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        try:
            with open(file_path, 'r', encoding='utf-8-sig', newline='') as infile:
                reader = csv.DictReader(infile)
                for row in reader:
                    try:
                        full_timestamp = row['Time']
                        date_part, time_part = full_timestamp.split(' ', 1)

                        record = {
                            "Date": date_part,
                            "Time": time_part,
                            "Type": row.get('Type', ''),
                            "ParentID": row.get('ParentID', ''),
                            "ProcessID": row.get('ProcessID', ''),
                            "FullPath": row.get('FullPath', ''),
                            "ComputerName": row.get('ComputerName', '')
                        }
                        yield "processtl", record
                    except (KeyError, ValueError):
                        pass
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][PROCESS_TIMELINE] Error {e}", header="ERROR", indentation=2)

    def _parse_process2(self, file_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        try:
            with open(file_path, "r") as process:
                reader = csv.DictReader(process, delimiter=",")
                for row in reader:
                    yield "process2", row
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][PROCESS2] Error {e}", header="ERROR", indentation=2)

    def _parse_process_autoruns(self, file_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        unique_records = {}
        try:
            with open(file_path, 'r') as autorun_file:
                file_as_json = xmltodict.parse(autorun_file.read())
                for key, values in file_as_json.items():
                    for key1, values1 in values.items():
                        for item in values1:
                            date_time = self._format_wmi_timestamp(item.get("time", "-"))
                            launchstr = item.get("launchstring", "-")
                            path = item.get("imagepath", "-")
                            hash = item.get("md5hash", "-")

                            uid = f"{date_time}|{path}|{launchstr}|{hash}"
                            if uid not in unique_records:
                                unique_records[uid] = {
                                    "DateTime": date_time,
                                    "ImagePath": path,
                                    "LaunchString": launchstr,
                                    "MD5": hash
                                }

            for uid in sorted(unique_records.keys()):
                yield "proc_autoruns", unique_records[uid]
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][PROCESS_AUTORUNS] Error {e}", header="ERROR", indentation=2)
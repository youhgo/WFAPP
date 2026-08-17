#!/usr/bin/python3
import csv
import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Dict, Any, Tuple

from ..classes.BaseParser import BaseParser

class DiskParser(BaseParser):
    """
    Class to parse disk info related artefacts, such as USN Journal logs or MFT files.
    """
    def parse(self, input_path: Path, category: str = "usnjrnl") -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        if not input_path.exists():
            if self.logger:
                self.logger.error(f"[PARSING][DISK] File not found: {input_path}", header="ERROR")
            return

        if category == "usnjrnl":
            yield from self._parse_usnjrnl(input_path)
        elif category == "mft_csv":
            yield from self._parse_mft_csv(input_path)
        elif category == "mft_json":
            yield from self._parse_mft_json(input_path)
        elif category == "plaso_csv":
            yield from self._parse_plaso_csv(input_path)

    def _parse_usnjrnl(self, input_filepath: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        try:
            with open(input_filepath, 'r', newline='', encoding='utf-8', errors='ignore') as infile:
                reader = csv.reader(infile)
                header = [h.strip() for h in next(reader)]
                try:
                    date_time_col_idx = header.index("TimeStamp")
                    file_name_col_idx = header.index("File")
                    file_path_col_idx = header.index("FullPath")
                    reason_col_idx = header.index("Reason")
                except ValueError as e:
                    if self.logger:
                        self.logger.error(f"[PARSING][USNJOURNAL]: bad header column: {e}", header="ERROR", indentation=2)
                    return

                for row_num, line in enumerate(reader, 2):
                    if not line:
                        continue
                    try:
                        date_time_str = line[date_time_col_idx]
                        date, time = date_time_str.split(" ", 1)
                        record = {
                            "Date": date,
                            "Time": time,
                            "FileName": line[file_name_col_idx],
                            "Reason": line[reason_col_idx],
                            "FilePath": line[file_path_col_idx]
                        }
                        yield "USN", record
                    except (IndexError, ValueError):
                        pass
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][USNJOURNAL]: Unexpected Error: {e}", header="ERROR", indentation=2)

    def _parse_mft_csv(self, input_filepath: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        required_headers = [
            "Record Number", "File Type", "Filename", "Filepath",
            "SI Creation Time", "SI Modification Time", "SI Access Time", "SI Entry Time",
            "FN Creation Time", "FN Modification Time", "FN Access Time", "FN Entry Time",
            "Logged Utility Stream"
        ]
        timestamp_fields = [
            "SI Creation Time", "SI Modification Time", "SI Access Time", "SI Entry Time",
            "FN Creation Time", "FN Modification Time", "FN Access Time", "FN Entry Time"
        ]
        timeline_events = []

        try:
            with open(input_filepath, 'r', newline='', encoding='utf-8', errors='ignore') as infile:
                reader = csv.reader(infile)
                header = [h.strip() for h in next(reader)]
                col_indices = {h: header.index(h) for h in required_headers}

                for row in reader:
                    lus_raw = row[col_indices["Logged Utility Stream"]]
                    lus_processed = "Present"
                    if lus_raw and lus_raw.strip() and lus_raw != 'N/A':
                        if lus_raw.startswith('$Txf'):
                            lus_processed = "$Txf"
                        elif "EFS" in lus_raw.upper():
                            lus_processed = "EFS"

                    common_data = {
                        "RecordNumber": row[col_indices["Record Number"]],
                        "FileType": row[col_indices["File Type"]],
                        "Filename": row[col_indices["Filename"]],
                        "Filepath": row[col_indices["Filepath"]],
                        "LoggedUtilityStream": lus_processed
                    }

                    for ts_field in timestamp_fields:
                        timestamp_str = row[col_indices[ts_field]]
                        if timestamp_str and timestamp_str.strip() and timestamp_str != 'N/A':
                            timeline_events.append({
                                **common_data,
                                "timestamp": timestamp_str.replace(" ", "T"),
                                "EventType": ts_field
                            })
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][MFT_CSV] Error: {e}", header="ERROR", indentation=2)
            return

        timeline_events.sort(key=lambda x: x["timestamp"])

        for event in timeline_events:
            try:
                date, time_part = event["timestamp"].split("T")
                time = time_part.split(".")[0]
                record = {
                    "Date": date,
                    "Time": time,
                    "EventType": event["EventType"],
                    "Filename": event["Filename"],
                    "FileType": event["FileType"],
                    "RecordNumber": event["RecordNumber"],
                    "Filepath": event["Filepath"],
                    "LoggedUtilityStream": event["LoggedUtilityStream"]
                }
                yield "MFT_Timeline", record
            except ValueError:
                pass

    def _parse_mft_json(self, json_filepath: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        try:
            with open(json_filepath, 'r', encoding='utf-8') as json_file:
                json_records = json.load(json_file)

            timeline_events = []
            for record in json_records:
                try:
                    fn_times = record.get('fn_times', {})
                    for ts_type in ['crtime', 'atime', 'mtime']:
                        if ts_type in fn_times and fn_times[ts_type]:
                            timeline_events.append({
                                "timestamp": fn_times[ts_type],
                                "event_type": ts_type,
                                "filename": record.get('filename', ''),
                                "filesize": record.get('filesize', ''),
                                "recordnum": record.get('recordnum', '')
                            })
                    if 'fn_times' in record and record['fn_times'] and 'btime' in record['fn_times'] and record['fn_times']['btime']:
                        timeline_events.append({
                            "timestamp": record['fn_times']['btime'],
                            "event_type": "btime",
                            "filename": record.get('filename', ''),
                            "filesize": record.get('filesize', ''),
                            "recordnum": record.get('recordnum', '')
                        })
                except Exception:
                    continue

            timeline_events.sort(key=lambda event: event.get('timestamp', '0'))

            for event in timeline_events:
                try:
                    ev_date, ev_time = event.get('timestamp', "NATNA").split("T")
                    record = {
                        "Date": ev_date,
                        "Time": ev_time,
                        "event_type": event['event_type'],
                        "filename": event['filename'],
                        "filesize": event['filesize'],
                        "recordnum": event['recordnum']
                    }
                    yield "mft", record
                except Exception:
                    pass
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][MFT_JSON]: Error: {e}", header="ERROR", indentation=2)

    def _parse_plaso_csv(self, input_filepath: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        header_list = ["Date", "Time", "Source", "EventType", "Col5", "Col6", "Col7", "Col8", "Filename", "Inode", "Col11", "Col12", "Col13", "Col14"]
        try:
            with open(input_filepath, 'r', newline='', encoding='utf-8', errors='ignore') as infile:
                reader = csv.reader(infile, delimiter='|')
                for row in reader:
                    if not row:
                        continue
                    try:
                        unix_timestamp_str = row[0]
                        unix_timestamp = float(unix_timestamp_str)
                        try:
                            dt_object = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
                        except OverflowError:
                            if unix_timestamp > 1_000_000_000:
                                unix_timestamp_seconds = unix_timestamp / 1_000_000_000
                                dt_object = datetime.fromtimestamp(unix_timestamp_seconds, tz=timezone.utc)
                            else:
                                continue

                        date_str = dt_object.strftime('%Y-%m-%d')
                        time_str = dt_object.strftime('%H:%M:%S.%f')
                        new_row = [date_str, time_str] + row[1:]
                        
                        # Pad or truncate to match header length
                        if len(new_row) >= len(header_list):
                            line_dict = dict(zip(header_list, new_row[:len(header_list)]))
                        else:
                            line_dict = {h: new_row[i] if i < len(new_row) else "" for i, h in enumerate(header_list)}
                            
                        yield "mft", line_dict

                    except (ValueError, IndexError):
                        continue
        except Exception as e:
            if self.logger:
                self.logger.error(f"Critical error parsing Plaso CSV: {e}", header="ERROR")
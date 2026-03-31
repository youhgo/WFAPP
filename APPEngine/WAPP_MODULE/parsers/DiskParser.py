 #!/usr/bin/python3
import argparse
import csv
import json
import traceback
import os
import time
from datetime import datetime, timezone
from typing import List

class DiskParser:
    """
    Class to parse disk info related artefacts, such as USN Journal logs or MFT files.
    This is the standalone parser from WAPP : https://github.com/youhgo/WFAPP
    MFT JSON Input must be from analyzemft : https://github.com/rowingdude/analyzeMFT
    USN Journal input must be from DFIR-Orc
    """

    def __init__(self, logger_run, separator: str = "|") -> None:
        """
        The constructor for DiskParser classes.

        Args:
            separator: The separator to use for the output CSV file.
            logger_run: The logger for normal runtime information.
        """
        self.separator = separator
        self.logger_run = logger_run

    def parse_mft_csv(self, input_file_path: str, output_path: str):
        """
        Parses an MFT CSV from AnalyzeMFT, unnests timestamps into a timeline,
        and saves it to a new pipe-separated CSV file.

        Args:
            input_file_path: Full path of the MFT CSV file to parse.
            output_path: Directory where the formatted CSV results will be written.
        """
        output_file_path = os.path.join(output_path, "MFT_Timeline.csv")
        self.logger_run.info(f"[PARSING][MFT_CSV] Starting MFT CSV parsing for {input_file_path}", header="START",
                             indentation=1)

        # Correctly define all required headers, including Record Number and File Type
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
            with open(input_file_path, 'r', newline='', encoding='utf-8') as infile:
                reader = csv.reader(infile)
                header = [h.strip() for h in next(reader)]

                try:
                    col_indices = {h: header.index(h) for h in required_headers}
                except ValueError as e:
                    self.logger_run.error(f"[PARSING][MFT_CSV] Missing required column in input file: {e}",
                                          header="ERROR", indentation=2)
                    return

                for row in reader:
                    # Parse the Logged Utility Stream into a clean keyword.
                    lus_raw = row[col_indices["Logged Utility Stream"]]
                    lus_processed = ""
                    if lus_raw and lus_raw.strip() and lus_raw != 'N/A':
                        if lus_raw.startswith('$Txf'):
                            lus_processed = "$Txf"
                        elif "EFS" in lus_raw.upper():
                            lus_processed = "EFS"
                        else:
                            lus_processed = "Present"

                    # This data is common to all timestamps in the current row
                    common_data = {
                        "Record Number": row[col_indices["Record Number"]],
                        "File Type": row[col_indices["File Type"]],
                        "Filename": row[col_indices["Filename"]],
                        "Filepath": row[col_indices["Filepath"]],
                        "Logged Utility Stream": lus_processed
                    }

                    # Un-nest the timestamps: create a new timeline event for each one
                    for ts_field in timestamp_fields:
                        timestamp_str = row[col_indices[ts_field]]
                        if timestamp_str and timestamp_str.strip() and timestamp_str != 'N/A':
                            timeline_events.append({
                                **common_data,
                                "timestamp": timestamp_str.replace(" ", "T"),
                                "EventType": ts_field
                            })

        except FileNotFoundError:
            self.logger_run.error(f"[PARSING][MFT_CSV] Input file not found at '{input_file_path}'.", header="ERROR",
                                  indentation=2)
            return
        except Exception as e:
            self.logger_run.error(
                f"[PARSING][MFT_CSV] Unexpected error while reading input file: {traceback.format_exc()}",
                header="ERROR", indentation=2)
            return

        try:
            # Sort all events chronologically
            timeline_events.sort(key=lambda x: x["timestamp"])

            os.makedirs(output_path, exist_ok=True)

            with open(output_file_path, 'w', newline='', encoding='utf-8') as outfile:
                # Update the output header to include the new fields
                output_header = ["Date", "Time", "EventType", "Filename", "FileType", "RecordNumber", "Filepath",
                                 "LoggedUtilityStream"]
                writer = csv.writer(outfile, delimiter=self.separator)
                writer.writerow(output_header)

                for event in timeline_events:
                    try:
                        date, time_part = event["timestamp"].split("T")
                        time = time_part.split(".")[0]
                        # Write the data in the correct order
                        writer.writerow([
                            date,
                            time,
                            event["EventType"],
                            event["Filename"],
                            event["File Type"],
                            event["Record Number"],
                            event["Filepath"],
                            event["Logged Utility Stream"]
                        ])
                    except ValueError:
                        self.logger_run.warning(f"Could not parse timestamp for event: {event}", header="WARNING",
                                                indentation=3)
                        continue

            self.logger_run.info(f"[PARSING][MFT_CSV] Finished. Output written to {output_file_path}",
                                 header="FINISHED", indentation=2)

        except Exception:
            self.logger_run.error(
                f"[PARSING][MFT_CSV] Unexpected error while writing output file: {traceback.format_exc()}",
                header="ERROR", indentation=2)

    def parse_usnjrnl(self, input_file_path: str, output_path: str):
        """
        Parses a USN Journal CSV file, reformats the data, and saves it
        to a new CSV file.

        Args:
            input_file_path: Full path of the USN CSV file to parse.
            output_path: Full path where the reformatted CSV results will be written.
        """

        output_file_path = os.path.join(output_path, "USN.csv")
        try:
            with open(input_file_path, 'r', newline='', encoding='utf-8') as infile, \
                    open(output_file_path, 'w', newline='', encoding='utf-8') as outfile:
                reader = csv.reader(infile)
                header = [h.strip() for h in next(reader)]
                try:
                    date_time_col_idx = header.index("TimeStamp")
                    file_name_col_idx = header.index("File")
                    file_path_col_idx = header.index("FullPath")
                    reason_col_idx = header.index("Reason")
                except ValueError as e:
                    self.logger_run.error(
                        "[PARSING][USNJOURNAL]: ad header column: {}".format(traceback.format_exc()), header="ERROR",
                        indentation=2)
                    return

                output_header = ["Date", "Time", "FileName", "Reason", "FilePath"]
                writer = csv.writer(outfile, delimiter=self.separator)
                writer.writerow(output_header)

                for row_num, line in enumerate(reader, 2):
                    if not line:
                        continue
                    try:
                        date_time_str = line[date_time_col_idx]
                        file_name = line[file_name_col_idx]
                        file_path = line[file_path_col_idx]
                        reason = line[reason_col_idx]
                        date, time = date_time_str.split(" ", 1)
                        writer.writerow([date, time, file_name, reason, file_path])

                    except IndexError:
                        # Handle cases where a row might have fewer columns than expected
                        pass
                    except ValueError:
                        pass
            self.logger_run.info("[PARSING][USNJOURNAL]", header="FINISHED", indentation=2)
            return output_file_path


        except FileNotFoundError:
            self.logger_run.error(
                "[PARSING][USNJOURNAL]: Input file not found at '{}'.".format(input_file_path), header="ERROR",
                indentation=2)

        except Exception:
            self.logger_run.error(
                "[PARSING][USNJOURNAL]: Unexpected Error: {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

    def parse_mft_json(self, json_file_path, output_path):
        """
        Converts a JSON-formatted MFT bodyfile into a pipe-separated CSV timeline.

        This function reads a JSON file and extracts key forensic data points. It
        creates a new entry for each timestamp (creation, access, modification),
        effectively "flattening" the data into a chronological timeline format.

        :param json_file_path: The path to the input MFT JSON file.
        :type json_file_path: str
        :param output_path: The path for the output pipe-separated CSV file.
        :type output_path: str
        :return: None
        """

        csv_file_path = os.path.join(output_path, "mft.csv")
        try:
            # Step 1: Open the input JSON file and load the data.
            with open(json_file_path, 'r', encoding='utf-8') as json_file:
                json_records = json.load(json_file)

            # Step 2: Flatten the data into a list of timeline events.
            timeline_events = []
            for record in json_records:
                try:
                    fn_times = record.get('fn_times', {})

                    # Check for the presence of each timestamp and add a new event to the list.
                    # 'crtime' (Creation Time)
                    if 'crtime' in fn_times and fn_times['crtime']:
                        timeline_events.append({
                            "timestamp": fn_times['crtime'],
                            "event_type": "crtime",
                            "filename": record.get('filename', ''),
                            "filesize": record.get('filesize', ''),
                            "recordnum": record.get('recordnum', '')
                        })

                    # 'atime' (Access Time)
                    if 'atime' in fn_times and fn_times['atime']:
                        timeline_events.append({
                            "timestamp": fn_times['atime'],
                            "event_type": "atime",
                            "filename": record.get('filename', ''),
                            "filesize": record.get('filesize', ''),
                            "recordnum": record.get('recordnum', '')
                        })

                    # 'mtime' (Modification Time)
                    if 'mtime' in fn_times and fn_times['mtime']:
                        timeline_events.append({
                            "timestamp": fn_times['mtime'],
                            "event_type": "mtime",
                            "filename": record.get('filename', ''),
                            "filesize": record.get('filesize', ''),
                            "recordnum": record.get('recordnum', '')
                        })

                    # 'fn_times' is a special case for MFT body files, representing an entry.
                    # We can also include this for a complete timeline.
                    if 'fn_times' in record and record['fn_times'] and 'btime' in record['fn_times'] and \
                            record['fn_times']['btime']:
                        timeline_events.append({
                            "timestamp": record['fn_times']['btime'],
                            "event_type": "btime",
                            "filename": record.get('filename', ''),
                            "filesize": record.get('filesize', ''),
                            "recordnum": record.get('recordnum', '')
                        })

                except (ValueError, TypeError) as e:
                    #print(f"Skipping malformed record during flattening: {record}. Error: {e}")
                    continue

            # Step 3: Sort the flattened events chronologically.
            timeline_events.sort(key=lambda event: event.get('timestamp', '0'))

            # Step 4: Open the output CSV file and write the sorted data.
            with open(csv_file_path, 'w', encoding='utf-8', newline='') as csv_file:
                # Create the csv writer with the pipe delimiter.
                writer = csv.writer(csv_file, delimiter='|', quoting=csv.QUOTE_NONE, escapechar='\\')

                # Write the header row.
                header = ["Date", "Time", "event_type", "filename", "filesize", "recordnum"]
                writer.writerow(header)

                # Write the new rows to the CSV file.
                for event in timeline_events:
                    try:
                        ev_date, ev_time = event.get('timestamp', "NATNA").split("T")
                        row_data = [
                            ev_date,
                            ev_time,
                            event['event_type'],
                            event['filename'],
                            event['filesize'],
                            event['recordnum']
                        ]
                        writer.writerow(row_data)
                    except Exception as ex:
                        self.logger_run.error(f"[PARSING][MFT] Error parsing entry {ex} ", header="FAILED",
                                              indentation=3)
            self.logger_run.info("[PARSING][MFT]", header="FINISHED", indentation=2)

        except json.JSONDecodeError as e:
            self.logger_run.error(
                "[PARSING][MFT]: Input file not a valid json '{} error: {}'.".format(json_file_path, e), header="ERROR",
                indentation=2)

        except FileNotFoundError:
            self.logger_run.error(
                "[PARSING][MFT]: Input file not found at '{}'.".format(json_file_path), header="ERROR",
                indentation=2)

        except Exception:
            self.logger_run.error(
                "[PARSING][MFT]: Unexpected Error: {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

    def parse_plaso_csv(self, input_file_path: str, output_path: str):
        """
        Parses a Plaso-like/TLN CSV file with a Unix timestamp in the first column.
        Converts timestamp to UTC Date and Time (with microseconds).
        Handles 'OverflowError' by attempting to divide the timestamp
        (assuming nanoseconds/hundreds of nanoseconds).
        """
        output_file_path = os.path.join(output_path, "mft.csv")
        out_delimiter = getattr(self, 'separator', ',')

        self.logger_run.info(f"[PARSING][PLASO_CSV] Starting parsing for {input_file_path}", header="START",
                             indentation=1)
        try:
            os.makedirs(output_path, exist_ok=True)

            with open(input_file_path, 'r', newline='', encoding='utf-8') as infile, \
                    open(output_file_path, 'w', newline='', encoding='utf-8') as outfile:

                reader = csv.reader(infile, delimiter='|')
                writer = csv.writer(outfile, delimiter=out_delimiter)

                output_header: List[str] = [
                    "Date", "Time", "Source", "EventType",
                    "Col5", "Col6", "Col7", "Col8",
                    "Filename", "Inode",
                    "Col11", "Col12", "Col13", "Col14"
                ]
                writer.writerow(output_header)

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
                                raise ValueError(f"Timestamp {unix_timestamp} is out of expected range.")

                        date_str = dt_object.strftime('%Y-%m-%d')
                        time_str = dt_object.strftime('%H:%M:%S.%f')

                        new_row = [date_str, time_str] + row[1:]
                        writer.writerow(new_row)

                    except (ValueError, IndexError, OverflowError) as e:
                        #self.logger_run.warning(f"Skipping malformed row: {row}. Error: {e}", header="WARNING", indentation=3)

                        continue

            self.logger_run.info(f"[PARSING][PLASO_CSV] Finished. Output: {output_file_path}", header="FINISHED",
                                 indentation=2)
            return output_file_path

        except Exception as e:
            self.logger_run.error(f"Critical error parsing Plaso CSV: {e}", header="ERROR")

def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Solution to parse a mft to more redable format'))

    argument_parser.add_argument('-u', '--usnjrnl', action="store",
                                 required=False, dest="usnjrnl", default=False,
                                 help="path to the usnjrnl file")

    argument_parser.add_argument('-mj', '--mft_json', action="store",
                                 required=False, dest="mft_json", default=False,
                                 help="path to the mft json file")

    argument_parser.add_argument('-mc', '--mft_csv', action="store",
                                 required=False, dest="mft_csv", default=False,
                                 help="path to the mft csv file")

    # NOUVEAU
    argument_parser.add_argument('-p', '--plaso_csv', action="store",
                                 required=False, dest="plaso_csv", default=False,
                                 help="path to the plaso-like csv file with Unix timestamp")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")
    return argument_parser


if __name__ == '__main__':
    # A dummy logger for standalone execution
    class DummyLogger:
        def __getattr__(self, name):
            return lambda *args, **kwargs: print(f"[{name.upper()}] {' '.join(map(str, args))}")


    arg_parser = parse_args()
    args = arg_parser.parse_args()

    start_time = time.time()
    now = datetime.now()
    date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
    print(f"Started at: {date_time}")

    # NOUVEAU : Ajout de args.plaso_csv à la vérification
    if not any([args.usnjrnl, args.mft_json, args.mft_csv, args.plaso_csv]):
        print("Error: at least one input file (--usnjrnl, --mft_json, --mft_csv, or --plaso_csv) must be provided.")
        arg_parser.print_help()
        exit(1)

    # 4. Initialize your custom parser and run the logic.
    disk_parser = DiskParser(DummyLogger())  # Use a different name
    if args.usnjrnl:
        disk_parser.parse_usnjrnl(args.usnjrnl, args.output_dir)
    if args.mft_json:
        disk_parser.parse_mft_json(args.mft_json, args.output_dir)
    if args.mft_csv:
        disk_parser.parse_mft_csv(args.mft_csv, args.output_dir)
    # NOUVEAU : Appel de la nouvelle fonction
    if args.plaso_csv:
        disk_parser.parse_plaso_csv(args.plaso_csv, args.output_dir)

    print(f"Finished in: {time.time() - start_time:.2f} seconds")
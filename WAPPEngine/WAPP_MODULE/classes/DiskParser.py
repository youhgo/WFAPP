#!/usr/bin/python3
import argparse
import csv
import json
import traceback
import os
import time
from datetime import datetime


class DiskParser:
    """
    Class to parse disk info related artefacts, such as USN Journal logs.
    This is the standalone parser from WAPP : https://github.com/youhgo/WFAPP
    MFT Input must be from analyzemft : https://github.com/rowingdude/analyzeMFT
    USN Journal input must be from DFIR-Orc
    """

    def __init__(self,  logger_run, separator: str = "|") -> None:
        """
        The constructor for DiskParser class.

        Args:
            separator: The separator to use for the output CSV file.
            logger_run: The logger for normal runtime information.
        """
        self.separator = separator
        self.logger_run = logger_run

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

        except FileNotFoundError:
            self.logger_run.error(
                "[PARSING][USNJOURNAL]: Input file not found at '{}'.".format(input_file_path), header="ERROR",
                indentation=2)

        except Exception:
            self.logger_run.error(
                "[PARSING][USNJOURNAL]: Unexpected Error: {}".format(traceback.format_exc()), header="ERROR",
                indentation=2)

    def parse_mft(self, json_file_path, output_path):
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

        csv_file_path =  os.path.join(output_path, "mft.csv")
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
                    print(f"Skipping malformed record during flattening: {record}. Error: {e}")
                    continue

            # Step 3: Sort the flattened events chronologically.
            timeline_events.sort(key=lambda event: event.get('timestamp', '0'))

            # Step 4: Open the output CSV file and write the sorted data.
            with open(csv_file_path, 'w', encoding='utf-8', newline='') as csv_file:
                # Create the csv writer with the pipe delimiter.
                writer = csv.writer(csv_file, delimiter='|', quoting=csv.QUOTE_NONE, escapechar='\\')

                # Write the header row.
                header = ["Date","Time", "event_type", "filename", "filesize", "recordnum"]
                writer.writerow(header)

                # Write the new rows to the CSV file.
                for event in timeline_events:
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

def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Solution to parse a json plaso timeline'))

    argument_parser.add_argument('-u', '--usnjrnl', action="store",
                                 required=False, dest="usnjrnl", default=False,
                                 help="path to the usnjrnl file")

    argument_parser.add_argument('-m', '--mft', action="store",
                                 required=False, dest="mft", default=False,
                                 help="path to the mft file")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")
    return argument_parser

if __name__ == '__main__':

    arg_parser = parse_args()
    args = arg_parser.parse_args()

    start_time = time.time()
    now = datetime.now()
    date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
    print(f"Started at: {date_time}")

    if not args.usnjrnl and not args.mft:
        print("Error: --mft or --usnjrnl argument must be provided.")
        arg_parser.print_help()
        exit(1)

    # 4. Initialize your custom parser and run the logic.
    disk_parser = DiskParser(None) # Use a different name
    if args.usnjrnl:
        disk_parser.parse_usnjrnl(args.usnjrnl, args.output_dir)
    if args.mft:
        disk_parser.parse_mft(args.mft, args.output_dir)

    print(f"Finished in: {time.time() - start_time:.2f} seconds")

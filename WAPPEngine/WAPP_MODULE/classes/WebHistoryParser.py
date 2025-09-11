import os
import sqlite3
import shutil
import argparse
import glob
import csv
import traceback
from datetime import datetime, timedelta


class HistoryExporter:
    """
    Finds all Chrome/Edge History files recursively, parses them for URL visits
    and downloads, sorts the combined data by date, and exports it to a CSV file.
    """

    def __init__(self, logger_run, search_directory, output_file):
        """
        Initializes the exporter.

        Args:
            logger_run (logger) : logger for output
            search_directory (str): The root directory to search for History files.
            output_file (str): The path to the output CSV file.
        """
        if not os.path.isdir(search_directory):
            self.logger_run.error(
                f"[PARSING][WEBHISTORY]Error: The specified search directory {search_directory} does not exist.",
                header="ERROR",
                indentation=2)
            return
        self.search_dir = search_directory
        self.output_file = output_file
        self.all_entries = []
        self.logger_run = logger_run

    @staticmethod
    def _convert_webkit_timestamp(webkit_timestamp):
        """Converts a WebKit/Chrome timestamp to a Python datetime object."""
        if webkit_timestamp > 0:
            return datetime(1601, 1, 1) + timedelta(microseconds=webkit_timestamp)
        return None

    def _parse_history_file(self, db_path):
        """
        Parses a single History database and adds its contents to the instance's
        all_entries list.
        """
        self.logger_run.info(f"[PARSING][WEBHISTORY] Parsing file: {db_path}", header="START", indentation=2)
        temp_db_path = f"temp_copy_{os.path.basename(db_path)}_{datetime.now().strftime('%f')}.db"

        try:
            shutil.copyfile(db_path, temp_db_path)
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()

            history_query = "SELECT url, title, last_visit_time FROM urls"
            cursor.execute(history_query)
            for url, title, last_visit_time in cursor.fetchall():
                ts = self._convert_webkit_timestamp(last_visit_time)
                if ts:
                    self.all_entries.append({
                        "timestamp": ts,
                        "type": "URL Visit",
                        "data1": url,
                        "data2": title,
                        "data3": ""
                    })

            downloads_query = "SELECT target_path, tab_url, total_bytes, start_time FROM downloads"
            cursor.execute(downloads_query)
            for target_path, tab_url, total_bytes, start_time in cursor.fetchall():
                ts = self._convert_webkit_timestamp(start_time)
                if ts:
                    self.all_entries.append({
                        "timestamp": ts,
                        "type": "Download",
                        "data1": target_path,
                        "data2": f"Source: {tab_url}",
                        "data3": f"Size: {total_bytes} bytes"
                    })

        except sqlite3.Error as e:
            self.logger_run.error(f"[PARSING][WEBHISTORY] error Parsing file: {db_path}, {e}", header="ERROR", indentation=2)
        finally:
            if 'conn' in locals() and conn:
                conn.close()
            if os.path.exists(temp_db_path):
                os.remove(temp_db_path)

    def write_to_csv(self):
        """Sorts all collected entries and writes them to the output CSV file."""
        if not self.all_entries:
            self.logger_run.warning(f"[PARSING][WEBHISTORY] No history entries found", header="WARNING", indentation=2)
            return

        self.all_entries.sort(key=lambda x: x["timestamp"])


        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter='|')
                writer.writerow(['DATE', 'TYPE', 'PRIMARY_DATA', 'SECONDARY_DATA', 'ADDITIONAL_INFO'])

                for entry in self.all_entries:
                    writer.writerow([
                        entry["timestamp"].strftime('%Y-%m-%d %H:%M:%S'),
                        entry["type"],
                        entry["data1"],
                        entry["data2"],
                        entry["data3"]
                    ])
            self.logger_run.info(f"[PARSING][WEBHISTORY]", header="FINISHED", indentation=2)
        except IOError as e:
            self.logger_run.error(
                f"[PARSING][WEBHISTORY] Error Writing to file: {self.output_file}, {traceback.format_exc()}",
                header="ERROR", indentation=2)

    def run(self):
        """
        Finds all History files, parses them, and exports the data to a CSV.
        """
        search_path = os.path.join(self.search_dir, '**', '*History*')
        files_found = glob.glob(search_path, recursive=True)

        if not files_found:
            self.logger_run.warning(f"[PARSING][WEBHISTORY] No history files found", header="WARNING", indentation=2)
            return

        for file_path in files_found:
            if os.path.isfile(file_path):
                self._parse_history_file(file_path)

        self.write_to_csv()


def main():
    """Main function to handle command-line arguments and run the exporter."""
    parser = argparse.ArgumentParser(
        description="Recursively find and parse Chrome/Edge History files, then export the sorted data to a single CSV."
    )
    parser.add_argument("-d", "--directory", required=True, help="The root directory to search for History files.")
    parser.add_argument("-o", "--output", required=True, help="The path for the output CSV file.")
    args = parser.parse_args()

    try:
        exporter = HistoryExporter(None, args.directory, args.output)
        exporter.run()
    except FileNotFoundError as e:
        print(e)


if __name__ == "__main__":
    main()
import os
import sqlite3
import shutil
import csv
import traceback
from datetime import datetime, timedelta, timezone


class HistoryExporter:
    """
    Parses Chrome/Edge History files for URL visits and downloads,
    sorts the combined data by date, and exports it to a CSV file.
    """

    def __init__(self, logger_run, output_file):
        """
        Initializes the exporter.

        Args:
            logger_run (logger) : logger for output
            output_file (str): The path to the output CSV file.
        """
        self.output_file = output_file
        self.all_entries = []
        self.logger_run = logger_run

    @staticmethod
    def _convert_webkit_timestamp(webkit_timestamp):
        """
        Converts a WebKit/Chrome timestamp to a Python datetime object.
        The timestamp is explicitly set to UTC (Timezone Aware).
        """
        if webkit_timestamp > 0:
            # WebKit/Chrome timestamps are microseconds since 1601-01-01 00:00:00 UTC.
            base_time = datetime(1601, 1, 1, tzinfo=timezone.utc)
            return base_time + timedelta(microseconds=webkit_timestamp)
        return None

    def _parse_history_file(self, db_path):
        """
        Parses a single History database and adds its contents to the instance's
        all_entries list.
        """
        self.logger_run.info(f"[PARSING][WEBHISTORY] Parsing file: {db_path}", header="START", indentation=2)
        # Unique temporary filename using microseconds
        temp_db_path = f"temp_copy_{os.path.basename(db_path)}_{datetime.now().strftime('%f')}.db"

        try:
            shutil.copyfile(db_path, temp_db_path)
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()

            # --- URL VISITS ---
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

            # --- DOWNLOADS ---
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
            self.logger_run.error(f"[PARSING][WEBHISTORY] error Parsing file: {db_path}, {e}", header="ERROR",
                                  indentation=2)
        finally:
            if 'conn' in locals() and conn:
                conn.close()
            if os.path.exists(temp_db_path):
                try:
                    os.remove(temp_db_path)
                except Exception:
                    pass

    def write_to_csv(self):
        """Sorts all collected entries and writes them to the output CSV file."""
        if not self.all_entries:
            self.logger_run.warning(f"[PARSING][WEBHISTORY] No history entries found", header="WARNING", indentation=2)
            return

        # Sort based on the timezone-aware datetime object
        self.all_entries.sort(key=lambda x: x["timestamp"])

        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter='|')
                writer.writerow(
                    ['DATE', 'TIME', 'TIMEZONE', 'TYPE', 'PRIMARY_DATA', 'SECONDARY_DATA', 'ADDITIONAL_INFO'])

                for entry in self.all_entries:
                    # Explicitly convert to UTC and extract components
                    utc_ts = entry["timestamp"].astimezone(timezone.utc)

                    date_str = utc_ts.strftime('%Y-%m-%d')
                    time_str = utc_ts.strftime('%H:%M:%S.%f')[:-3]  # Truncate microseconds to milliseconds
                    timezone_str = 'UTC'  # Known timezone

                    writer.writerow([
                        date_str,
                        time_str,
                        timezone_str,
                        entry["type"],
                        entry["data1"],
                        entry["data2"],
                        entry["data3"]
                    ])
            self.logger_run.info(f"[PARSING][WEBHISTORY] Finished. Output written to {self.output_file}",
                                 header="FINISHED", indentation=2)
            return self.output_file

        except IOError as e:
            self.logger_run.error(
                f"[PARSING][WEBHISTORY] Error Writing to file: {self.output_file}, {traceback.format_exc()}",
                header="ERROR", indentation=2)
            return

    def parse_file(self, file_path):
        """
        Parses a single History file. Called by the Dispatcher Pipeline.
        """
        if os.path.isfile(file_path):
            self._parse_history_file(file_path)
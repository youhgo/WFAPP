import os
import sqlite3
import shutil
from datetime import datetime, timedelta, timezone
from typing import Generator, Dict, Any, Tuple
from pathlib import Path

from ..classes.BaseParser import BaseParser

class WebHistoryParser(BaseParser):
    """
    Parses Chrome/Edge History files for URL visits and downloads.
    """

    @staticmethod
    def _convert_webkit_timestamp(webkit_timestamp):
        if webkit_timestamp > 0:
            base_time = datetime(1601, 1, 1, tzinfo=timezone.utc)
            return base_time + timedelta(microseconds=webkit_timestamp)
        return None

    def parse(self, input_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        if not input_path.exists():
            if self.logger:
                self.logger.error(f"[PARSING][WEBHISTORY] File not found: {input_path}", header="ERROR")
            return
            
        if self.logger:
            self.logger.info(f"[PARSING][WEBHISTORY] Parsing file: {input_path}", header="START", indentation=2)

        temp_db_path = f"temp_copy_{input_path.name}_{datetime.now().strftime('%f')}.db"

        try:
            shutil.copyfile(str(input_path), temp_db_path)
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()

            # --- URL VISITS ---
            history_query = "SELECT url, title, last_visit_time FROM urls"
            try:
                cursor.execute(history_query)
                for url, title, last_visit_time in cursor.fetchall():
                    ts = self._convert_webkit_timestamp(last_visit_time)
                    if ts:
                        utc_ts = ts.astimezone(timezone.utc)
                        date_str = utc_ts.strftime('%Y-%m-%d')
                        time_str = utc_ts.strftime('%H:%M:%S.%f')[:-3]
                        
                        record = {
                            "DATE": date_str,
                            "TIME": time_str,
                            "TIMEZONE": "UTC",
                            "TYPE": "URL Visit",
                            "PRIMARY_DATA": url,
                            "SECONDARY_DATA": title,
                            "ADDITIONAL_INFO": ""
                        }
                        yield "web_history", record
            except sqlite3.OperationalError:
                pass # Table might not exist

            # --- DOWNLOADS ---
            downloads_query = "SELECT target_path, tab_url, total_bytes, start_time FROM downloads"
            try:
                cursor.execute(downloads_query)
                for target_path, tab_url, total_bytes, start_time in cursor.fetchall():
                    ts = self._convert_webkit_timestamp(start_time)
                    if ts:
                        utc_ts = ts.astimezone(timezone.utc)
                        date_str = utc_ts.strftime('%Y-%m-%d')
                        time_str = utc_ts.strftime('%H:%M:%S.%f')[:-3]
                        
                        record = {
                            "DATE": date_str,
                            "TIME": time_str,
                            "TIMEZONE": "UTC",
                            "TYPE": "Download",
                            "PRIMARY_DATA": target_path,
                            "SECONDARY_DATA": f"Source: {tab_url}",
                            "ADDITIONAL_INFO": f"Size: {total_bytes} bytes"
                        }
                        yield "web_history", record
            except sqlite3.OperationalError:
                pass # Table might not exist

        except sqlite3.Error as e:
            if self.logger:
                self.logger.error(f"[PARSING][WEBHISTORY] error Parsing file: {input_path}, {e}", header="ERROR", indentation=2)
        finally:
            if 'conn' in locals() and conn:
                conn.close()
            if os.path.exists(temp_db_path):
                try:
                    os.remove(temp_db_path)
                except Exception:
                    pass
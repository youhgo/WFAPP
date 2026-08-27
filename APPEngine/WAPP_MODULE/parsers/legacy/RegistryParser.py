#!/usr/bin/python3
from datetime import datetime
import traceback
import os
from typing import Generator, Dict, Any, Tuple
from pathlib import Path

from regipy.registry import RegistryHive
from regipy.plugins.utils import run_relevant_plugins
from yarp import * # must be install from github : https://github.com/msuhanov/yarp/releases

from ...classes.BaseParser import BaseParser

class RegistryParser(BaseParser):
    """
    Class to parse Registry Hives
    """

    def parse(self, input_path: Path, category: str = "hive", hive_name: str = "") -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        if not input_path.exists():
            if self.logger:
                self.logger.error(f"[PARSING][REGISTRY] File not found {input_path}", header="ERROR")
            return

        if category == "amcache_regpy":
            yield from self._parse_amcache_regpy(input_path)
        elif category == "amcache_yarp":
            yield from self._export_amcache_to_jsonl(input_path, hive_name)
        elif category == "hive_yarp":
            yield from self._export_hive_to_jsonl(input_path, hive_name)
        elif category == "hive_regpy":
            yield from self._parse_hive_regpy(input_path, hive_name)

    def _parse_amcache_regpy(self, file_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        if self.logger:
            self.logger.info("[PARSING][AMCACHE][REGPY]", header="START", indentation=2)
        try:
            reg = RegistryHive(str(file_path))
            parsed_data = run_relevant_plugins(reg, as_json=True)
            
            amcache_entries = parsed_data.get("amcache", [])
            if not amcache_entries:
                if self.logger:
                    self.logger.warning(f"[PARSING][AMCACHE][REGPY] Regpy could'nt parse Amcache", header="FAILED", indentation=2)
                return

            for entry in amcache_entries:
                timestamp_str = entry.get("timestamp")
                try:
                    dt_obj = datetime.fromisoformat(timestamp_str)
                    date_str = dt_obj.strftime("%Y-%m-%d")
                    time_str = dt_obj.strftime("%H:%M:%S")
                except (ValueError, TypeError):
                    continue

                record = {
                    "Date": date_str,
                    "Time": time_str,
                    "Name": entry.get("original_file_name", "-"),
                    "Hash": entry.get("sha1", "-")
                }
                yield "amcache_regpy", record
                
            if self.logger:
                self.logger.info("[PARSING][AMCACHE][REGPY]", header="FINISHED", indentation=2)
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][AMCACHE][REGPY]: An unexpected error occurred: {e}", header="ERROR", indentation=2)

    def _parse_hive_regpy(self, file_path: Path, hive_name: str) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        if self.logger:
            self.logger.info(f"[PARSING][HIVE][REGPY] {hive_name}", header="START", indentation=2)
        try:
            reg = RegistryHive(str(file_path))
            parsed_data = run_relevant_plugins(reg, as_json=True)
            
            if not parsed_data:
                if self.logger:
                    self.logger.warning(f"[PARSING][HIVE][REGPY] Regipy couldn't parse any plugins for {hive_name}", header="FAILED", indentation=2)
                return

            for plugin_name, entries in parsed_data.items():
                if isinstance(entries, list):
                    for entry in entries:
                        yield f"{plugin_name}_regipy", entry
                elif isinstance(entries, dict):
                    yield f"{plugin_name}_regipy", entries

            if self.logger:
                self.logger.info(f"[PARSING][HIVE][REGPY] {hive_name}", header="FINISHED", indentation=2)
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][HIVE][REGPY]: An unexpected error occurred: {e}", header="ERROR", indentation=2)

    def _recursively_yield_key(self, key, hive_name: str, parent_path="") -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        current_path = parent_path + "\\" + key.name() if parent_path else key.name()

        key_data = {
            "path": current_path,
            "name": key.name(),
            "last_written_timestamp": key.last_written_timestamp().isoformat() if key.last_written_timestamp() else None,
            "values": {}
        }

        try:
            for value in key.values():
                value_info = {
                    "type": value.type_str(),
                    "size": value.data_size(),
                    "data": None
                }
                try:
                    data = value.data()
                    if isinstance(data, (bytes, bytearray)):
                        value_info["data"] = data.hex()
                    elif isinstance(data, list):
                        value_info["data"] = [s.strip('\x00') for s in data]
                    elif isinstance(data, str):
                        value_info["data"] = data.strip('\x00')
                    else:
                        value_info["data"] = data
                except Exception:
                    value_info["data"] = value.data_raw().hex()

                key_data["values"][value.name()] = value_info
        except Exception as e:
            key_data["error_values"] = str(e)

        yield f"registry_{hive_name}", key_data

        try:
            for subkey in key.subkeys():
                yield from self._recursively_yield_key(subkey, hive_name, current_path)
        except Exception:
            pass

    def _get_recovered_hive(self, hive_file_path: Path, files_to_close: list):
        f_hive = open(str(hive_file_path), "rb")
        files_to_close.append(f_hive)
        hive = Registry.RegistryHive(f_hive)

        def get_log(ext_upper):
            for ext in [ext_upper, ext_upper.lower()]:
                path = str(hive_file_path) + ext
                if os.path.exists(path):
                    f = open(path, 'rb')
                    files_to_close.append(f)
                    return f
            return None

        log1 = get_log(".LOG1")
        log2 = get_log(".LOG2")
        log3 = get_log(".LOG3")

        recovery_result = hive.recover_auto(log1, log2, log3)
        return hive, recovery_result

    def _export_hive_to_jsonl(self, hive_file_path: Path, hive_name: str) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        files_to_close = []
        try:
            if self.logger:
                self.logger.info(f"[PARSING][HIVE][YARP] {hive_name}", header="START", indentation=2)

            hive, recovery_result = self._get_recovered_hive(hive_file_path, files_to_close)

            if self.logger:
                if recovery_result.recovered:
                    self.logger.info(f"[PARSING][HIVE][YARP] The hive {hive_name} has been recovered", header="SUCCESS", indentation=2)
                else:
                    self.logger.warning(f"[PARSING][HIVE][YARP] The hive {hive_name} has NOT been recovered", header="WARNING", indentation=2)

            root_key = hive.root_key()

            hive_info = {
                "hive_path": str(hive_file_path),
                "last_written": hive.last_written_timestamp().isoformat() if hive.last_written_timestamp() else None,
                "last_reorganized": hive.last_reorganized_timestamp().isoformat() if hive.last_reorganized_timestamp() else None,
            }
            yield f"registry_{hive_name}", hive_info
            yield from self._recursively_yield_key(root_key, hive_name)

            if self.logger:
                self.logger.info(f"[PARSING][HIVE][YARP] {hive_name}", header="FINISHED", indentation=2)

        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][HIVE][YARP]: An unexpected error occurred: {e}", header="ERROR", indentation=2)
        finally:
            for f in files_to_close:
                try:
                    f.close()
                except Exception:
                    pass

    def _export_amcache_to_jsonl(self, hive_file_path: Path, hive_name: str) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        files_to_close = []
        try:
            hive, recovery_result = self._get_recovered_hive(hive_file_path, files_to_close)

            if self.logger:
                if recovery_result.recovered:
                    self.logger.info(f"[PARSING][AMCACHE][YARP] The hive {hive_name} has been recovered", header="SUCCESS", indentation=2)
                else:
                    self.logger.warning(f"[PARSING][AMCACHE][YARP] The hive {hive_name} has NOT been recovered", header="WARNING", indentation=2)

            root_key = hive.root_key()

            hive_info = {
                "last_written": hive.last_written_timestamp().isoformat() if hive.last_written_timestamp() else None,
                "last_reorganized": hive.last_reorganized_timestamp().isoformat() if hive.last_reorganized_timestamp() else None,
            }
            yield "amcache_yarp", hive_info
            
            # Note: The artifact_type is slightly different here to match the old logic
            for _, record in self._recursively_yield_key(root_key, hive_name):
                yield "amcache_yarp", record

            if self.logger:
                self.logger.info("[PARSING][AMCACHE][YARP]", header="FINISHED", indentation=2)
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][AMCACHE][YARP]: An unexpected error occurred: {e}", header="ERROR", indentation=2)
        finally:
            for f in files_to_close:
                try:
                    f.close()
                except Exception:
                    pass
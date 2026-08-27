import json
from pathlib import Path
from typing import Generator, Dict, Any, Tuple
from ...classes.BaseParser import BaseParser

class OgreLnkParser(BaseParser):
    """
    Parses DFIR-Ogre LNK and jumplist JSONL output files into structured dictionaries.
    """

    def parse(self, input_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    data_type = event.get("data_type", "")
                    
                    if data_type == "lnk":
                        yield self.parse_lnk(event)
                    else:
                        yield self.parse_generic(event, data_type)
                        
                except json.JSONDecodeError:
                    if self.logger:
                        self.logger.warning(f"[PARSING][OGRE_LNK] Error decoding JSON line: {line}", header="WARNING")
                    continue
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[PARSING][OGRE_LNK] Unexpected error: {e}", header="ERROR")
                    continue

    def parse_lnk(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        main_data = event.get("data", {})
        
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
                
        nested_data = main_data.get("data", {})
        link_info = main_data.get("link_info", {})
        
        data_dict = {
            "DATE": date_part,
            "TIME": time_part,
            "local_base_path": link_info.get("local_base_path", ""),
            "command_line_arguments": nested_data.get("command_line_arguments", ""),
            "relative_path": nested_data.get("relative_path", ""),
            "working_directory": nested_data.get("working_directory", ""),
            "description": nested_data.get("description", "")
        }
        
        return "ogre_lnk", data_dict

    def parse_generic(self, event: Dict[str, Any], data_type: str) -> Tuple[str, Dict[str, Any]]:
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
                
        data_dict = {
            "date": date_part,
            "time": time_part,
            "description": event.get("description", ""),
            "additional_description": event.get("additional_description", "")
        }
                
        tag = f"ogre_{data_type}" if data_type else "ogre_lnk_generic"
        return tag, data_dict


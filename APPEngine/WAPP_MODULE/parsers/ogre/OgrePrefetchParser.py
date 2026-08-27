import json
from pathlib import Path
from typing import Generator, Dict, Any, Tuple
from ...classes.BaseParser import BaseParser

class OgrePrefetchParser(BaseParser):
    """
    Parses DFIR-Ogre Prefetch JSONL output files into structured dictionaries.
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
                    
                    if data_type == "prefetch":
                        yield self.parse_prefetch(event)
                    else:
                        yield self.parse_generic(event, data_type)
                        
                except json.JSONDecodeError:
                    if self.logger:
                        self.logger.warning(f"[PARSING][OGRE_PREFETCH] Error decoding JSON line: {line}", header="WARNING")
                    continue
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[PARSING][OGRE_PREFETCH] Unexpected error: {e}", header="ERROR")
                    continue

    def parse_prefetch(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
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
                
        def get_val(*keys):
            for k in keys:
                if k in main_data:
                    return main_data[k]
            return None
            
        path_hints = get_val("path_hints", "PathHints") or []
        
        data_dict = {
            "date": date_part,
            "time": time_part,
            "executable": get_val("executable", "Executable") or "",
            "path_hints": ", ".join(path_hints) if isinstance(path_hints, list) else str(path_hints)
        }
        
        return "ogre_prefetch", data_dict

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
                
        tag = f"ogre_{data_type}" if data_type else "ogre_prefetch_generic"
        return tag, data_dict


import json
from pathlib import Path
from typing import Generator, Dict, Any, Tuple
from ...classes.BaseParser import BaseParser

class OgreSrumParser(BaseParser):
    """
    Parses DFIR-Ogre SRUM JSONL output files into structured dictionaries.
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
                    yield self.parse_srum(event, data_type)
                        
                except json.JSONDecodeError:
                    if self.logger:
                        self.logger.warning(f"[PARSING][OGRE_SRUM] Error decoding JSON line: {line}", header="WARNING")
                    continue
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[PARSING][OGRE_SRUM] Unexpected error: {e}", header="ERROR")
                    continue

    def parse_srum(self, event: Dict[str, Any], data_type: str) -> Tuple[str, Dict[str, Any]]:
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
        
        tag = f"ogre_{data_type}" if data_type else "ogre_srum_generic"
        return tag, data_dict

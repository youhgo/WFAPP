import json
from pathlib import Path
from typing import Generator, Dict, Any, Tuple
from ...classes.BaseParser import BaseParser

class OgreBrowserParser(BaseParser):
    """
    Parses DFIR-Ogre browser history JSONL output files into structured dictionaries.
    Handles specific event types like browser_history and browser_download_history.
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
                    
                    if data_type == "browser_history":
                        yield self.parse_browser_history(event)
                    elif data_type == "browser_download_history":
                        yield self.parse_browser_download_history(event)
                    else:
                        yield self.parse_generic(event, data_type)
                        
                except json.JSONDecodeError:
                    if self.logger:
                        self.logger.warning(f"[PARSING][OGRE_BROWSER] Error decoding JSON line: {line}", header="WARNING")
                    continue
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[PARSING][OGRE_BROWSER] Unexpected error: {e}", header="ERROR")
                    continue

    def _split_timestamp(self, ts: str) -> Tuple[str, str]:
        date_part, time_part = "", ""
        if "T" in ts:
            date_part, time_part = ts.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
        return date_part, time_part

    def parse_browser_history(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        data = event.get("data", {})
        
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = self._split_timestamp(timestamp_raw)
        
        def get_val(*keys):
            for k in keys:
                if k in data:
                    return data[k]
            return None
            
        data_dict = {
            "DATE": date_part,
            "TIME": time_part,
            "visit_date": get_val("visit_date", "visitDate"),
            "visit_count": get_val("visit_count", "visitCount"),
            "url": get_val("url", "URL", "Url"),
            "referer": get_val("referer", "Referer")
        }
        
        return "ogre_browser_history", data_dict

    def parse_browser_download_history(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        data = event.get("data", {})
        
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = self._split_timestamp(timestamp_raw)
        
        def get_val(*keys):
            for k in keys:
                if k in data:
                    return data[k]
            return None
            
        data_dict = {
            "DATE": date_part,
            "TIME": time_part,
            "end_time": get_val("end_time", "endTime"),
            "danger_type": get_val("danger_type", "dangerType"),
            "opened": get_val("opened", "Opened"),
            "received_bytes": get_val("received_bytes", "receivedBytes"),
            "total_bytes": get_val("total_bytes", "totalBytes"),
            "url": get_val("url", "URL", "Url"),
            "target_path": get_val("target_path", "targetPath")
        }
        
        return "ogre_browser_download_history", data_dict

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
                
        tag = f"ogre_{data_type}" if data_type else "ogre_browser_generic"
        return tag, data_dict


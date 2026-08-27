import json
from pathlib import Path
from typing import Generator, Dict, Any, Tuple
import traceback
import LnkParse3

from ...classes.BaseParser import BaseParser

class LinkParser(BaseParser):
    """
    Class to parse lnk files and extract key information.
    """

    def parse(self, input_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Parses a single lnk file and yields its data.
        Returns a dictionary containing the CSV record, plus the raw JSON under '_raw_json'.
        """
        lnk_name = input_path.name
        
        try:
            with open(input_path, 'rb') as file_in:
                lnk = LnkParse3.lnk_file(file_in)
                lnk_data = lnk.get_json()

            if lnk_data:
                creation_time = lnk_data.get("header", {}).get("creation_time", "-")
                accessed_time = lnk_data.get("header", {}).get("accessed_time", "-")
                modified_time = lnk_data.get("header", {}).get("modified_time", "-")

                local_path = (
                    lnk_data.get("link_info", {}).get("local_base_path") or
                    lnk_data.get("extra", {}).get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK", {}).get("target_ansi") or
                    lnk_data.get("data", {}).get("description", "-")
                )

                record = {
                    "CreationTime": creation_time,
                    "AccessTime": accessed_time,
                    "ModifiedTime": modified_time,
                    "Target/Path/Description": local_path,
                    "lnkName": lnk_name,
                    "_raw_json": lnk_data
                }
                
                yield "lnk", record
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][LNK] Could not parse {input_path}: {traceback.format_exc()}", header="ERROR", indentation=1)
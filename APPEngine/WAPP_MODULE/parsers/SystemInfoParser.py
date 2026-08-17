#!/usr/bin/python3
import csv
import traceback
from pathlib import Path
from typing import Generator, Dict, Any, Tuple

from ..classes.BaseParser import BaseParser

class SystemInfoParser(BaseParser):
    """
    Classe pour parser les résultats de SystemInfo.
    """

    def parse(self, input_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        if not input_path.exists():
            return
            
        if self.logger:
            self.logger.info("[PARSING][SYSTEMINFO]", header="START", indentation=2)
            
        try:
            # Note: cp850 est souvent utilisé par les outils Windows FR. 
            with open(input_path, 'r', encoding='cp850', errors='ignore') as system_info_file:
                reader = csv.reader(system_info_file)
                header = next(reader)

                for line in reader:
                    if not line or len(line) != len(header):
                        if self.logger:
                            self.logger.error(f"[PARSING][SYSTEMINFO]: Ligne mal formée ignorée : {line}", header="ERROR", indentation=2)
                        continue

                    line_dict = dict(zip(header, line))
                    yield "systeminfo", line_dict

        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][SYSTEMINFO]: Erreur inattendue {traceback.format_exc()}", header="ERROR", indentation=2)

        if self.logger:
            self.logger.info("[PARSING][SYSTEMINFO]", header="FINISHED", indentation=2)
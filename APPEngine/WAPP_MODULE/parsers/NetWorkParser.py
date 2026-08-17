#!/usr/bin/python3
import traceback
from pathlib import Path
from typing import Generator, Dict, Any, Tuple

from ..classes.BaseParser import BaseParser

class NetWorkParser(BaseParser):
    """
    Class parse network files to human-readable csv DATE|TIME|ETC|ETC
    """

    def parse(self, input_path: Path, category: str = "tcpvcon") -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        if category == "tcpvcon":
            yield from self._parse_tcpvcon(input_path)
        elif category == "netstat":
            yield from self._parse_netstat(input_path)

    def _parse_tcpvcon(self, input_filepath: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        exclusion_strings = [
            "Sysinternals - www.sysinternals.com",
            "Copyright (C) 1996-2023 Mark Russinovich & Bryce Cogswell"
        ]
        header_list = ["Protocol", "Process", "PID", "State", "Local Addr", "Distant Addr"]
        unique_lines = set()

        try:
            with open(input_filepath, 'r', encoding='utf-8', errors='ignore') as file_in:
                for line in file_in:
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue

                    should_exclude = False
                    for exclusion_str in exclusion_strings:
                        if exclusion_str in stripped_line:
                            should_exclude = True
                            break

                    if should_exclude:
                        continue

                    # On stocke d'abord la ligne traitée dans le set pour dédoublonner
                    fields = [field.strip() for field in stripped_line.split(',')]
                    processed_line = "|".join(fields)
                    unique_lines.add(processed_line)

            # Une fois dédoublonné, on yield les dicts
            for line in sorted(list(unique_lines)):
                fields = line.split("|")
                # Gestion de la taille variable potentielle
                if len(fields) >= len(header_list):
                    line_dict = dict(zip(header_list, fields[:len(header_list)]))
                else:
                    # Padding avec des vides
                    line_dict = {h: fields[i] if i < len(fields) else "" for i, h in enumerate(header_list)}
                yield "tcpvcon", line_dict

        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][TCPVCON]:  {traceback.format_exc()}", header="ERROR", indentation=2)

    def _parse_netstat(self, input_filepath: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        try:
            unique_lines = set()
            with open(input_filepath, 'r', encoding='utf-8', errors='ignore') as infile:
                for line in infile:
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue

                    fields = [field.strip() for field in stripped_line.split()]
                    processed_line = "|".join(fields)
                    unique_lines.add(processed_line)

            # Les fichiers netstat n'ont pas toujours un header fixe clair sans contexte,
            # mais on peut créer des clés dynamiques basées sur l'index (Col_0, Col_1...)
            # ou essayer de détecter l'en-tête natif. Pour garder la compatibilité avec
            # l'ancien parseur, nous allons séparer les champs.
            lines_fields = [line.split("|") for line in sorted(list(unique_lines))]
            max_fields = max((len(fields) for fields in lines_fields), default=0)

            for fields in lines_fields:
                line_dict = {f"Col_{i}": fields[i] if i < len(fields) else "" for i in range(max_fields)}
                yield "netstat", line_dict

        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][NETSTAT]:  {traceback.format_exc()}", header="ERROR", indentation=2)
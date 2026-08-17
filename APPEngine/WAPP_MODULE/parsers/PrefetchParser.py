#!/usr/bin/env python3
import sys
import traceback
from pathlib import Path
from typing import Generator, Dict, Any, Tuple

from ..classes.BaseParser import BaseParser

try:
    import pyscca
except ImportError:
    print("Please install libscca with Python bindings (pip install libscca-python)")
    sys.exit(1)


class PrefetchParser(BaseParser):
    """
    Classe pour parser les fichiers prefetch Windows.
    """

    def parse(self, input_path: Path, volume_information: bool = True) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Parse un fichier .pf et yield le dictionnaire aplati.
        """
        if not input_path.exists():
            if self.logger:
                self.logger.error(f"[PARSING][PREFETCH] Fichier introuvable: {input_path}", header="ERROR")
            return

        try:
            scca = pyscca.open(str(input_path))
            
            # Initialisation du dict avec les valeurs de base
            parsed_data = {
                'Executable Name': str(scca.executable_filename),
                'Run Count': scca.run_count,
                'Prefetch Hash': format(scca.prefetch_hash, 'x').upper(),
            }

            # Récupération des 8 derniers Run Times
            for x in range(8):
                if scca.get_last_run_time_as_integer(x) > 0:
                    parsed_data[f'Last Run Time {x}'] = scca.get_last_run_time(x).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    parsed_data[f'Last Run Time {x}'] = 'N/A'

            if volume_information:
                parsed_data['Number of Volumes'] = scca.number_of_volumes
                # Extraction du premier volume (le principal) pour ne pas casser le CSV dynamique
                # (ou extraction de max 2 volumes pour rester plat)
                for i in range(min(2, scca.number_of_volumes)):
                    vol = scca.get_volume_information(i)
                    parsed_data[f'Volume {i} Name'] = str(vol.device_path)
                    parsed_data[f'Volume {i} Creation Time'] = vol.creation_time.strftime("%Y-%m-%d %H:%M:%S")
                    parsed_data[f'Volume {i} Serial Number'] = format(vol.serial_number, 'x').upper()

            yield "prefetch", parsed_data

        except IOError:
            if self.logger:
                self.logger.warning(f"[PARSING][PREFETCH] Erreur IO sur {input_path}: {traceback.format_exc()}",
                                    header="WARNING", indentation=2)
        except Exception:
            if self.logger:
                self.logger.error(f"[PARSING][PREFETCH] Erreur inattendue sur {input_path}: {traceback.format_exc()}",
                                  header="ERROR", indentation=2)
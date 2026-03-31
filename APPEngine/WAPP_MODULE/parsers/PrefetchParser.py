#!/usr/bin/env python3
import csv
import json
import sys
import traceback
import os
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    import pyscca
except ImportError:
    print("Please install libscca with Python bindings (pip install libscca-python)")
    sys.exit(1)


class PrefetchParser:
    """
    Classe pour parser les fichiers prefetch Windows.
    """

    def __init__(self, logger_run) -> None:
        """
        Constructeur de la classe PrefetchParser.
        """
        self.logger_run = logger_run
        # Utilisation d'une liste pour éviter d'écraser les prefetch de même nom (ex: multiples cmd.exe)
        self.output: List[Dict[str, Any]] = []

    def parse_file(self, pf_file: str, volume_information: bool = False) -> Optional[Dict[str, Any]]:
        """
        Parse un fichier .pf et stocke le résultat.
        """
        pf_path = Path(pf_file)
        if not pf_path.exists():
            self.logger_run.error(f"[PARSING][PREFETCH] Fichier introuvable: {pf_file}", header="ERROR")
            return None

        try:
            scca = pyscca.open(str(pf_path))
            last_run_times = []

            for x in range(8):
                if scca.get_last_run_time_as_integer(x) > 0:
                    last_run_times.append(scca.get_last_run_time(x).strftime("%Y-%m-%d %H:%M:%S"))
                else:
                    last_run_times.append('N/A')

            # Stockage dans une structure propre plutôt que dans des listes imbriquées
            parsed_data = {
                'Executable Name': str(scca.executable_filename),
                'Run Count': scca.run_count,
                'Prefetch Hash': format(scca.prefetch_hash, 'x').upper(),
                'Run Times': last_run_times
            }

            if volume_information:
                parsed_data['Number of Volumes'] = scca.number_of_volumes
                volumes = []
                for i in range(scca.number_of_volumes):
                    vol = scca.get_volume_information(i)
                    volumes.append({
                        'Volume Name': str(vol.device_path),
                        'Creation Time': vol.creation_time.strftime("%Y-%m-%d %H:%M:%S"),
                        'Serial Number': format(vol.serial_number, 'x').upper()
                    })
                parsed_data['Volumes'] = volumes

            self.output.append(parsed_data)
            return parsed_data

        except IOError:
            self.logger_run.warning(f"[PARSING][PREFETCH] Erreur IO sur {pf_file}: {traceback.format_exc()}",
                                    header="WARNING", indentation=2)
        except Exception:
            self.logger_run.error(f"[PARSING][PREFETCH] Erreur inattendue sur {pf_file}: {traceback.format_exc()}",
                                  header="ERROR", indentation=2)
        return None

    def output_results(self, output_file: Optional[str] = None, output_format: str = 'csv',
                       volume_information: bool = False) -> None:
        """
        Exporte les résultats parsés.
        Note: Le nom de méthode a été modifié en snake_case (PEP8).
        """
        if not self.output:
            self.logger_run.warning("Aucune donnée Prefetch à exporter.")
            return

        if output_format.lower() == 'json':
            self._export_json(output_file, volume_information)
        elif output_format.lower() == 'csv':
            self._export_csv(output_file, volume_information)
        else:
            self.logger_run.error(f"Format de sortie non supporté: {output_format}")

    def _export_json(self, output_file: Optional[str], volume_information: bool) -> None:
        json_results = []

        for item in self.output:
            json_output = {
                'Executable Name': item['Executable Name'],
                'Run Count': item['Run Count'],
                'Prefetch Hash': item['Prefetch Hash'],
            }

            json_output['Run Times'] = {f'Run Time {i}': time for i, time in enumerate(item['Run Times'])}

            if volume_information and 'Volumes' in item:
                vol_list = {f'Volume {i}': vol for i, vol in enumerate(item['Volumes'])}
                json_output['Volumes'] = {
                    'Number of Volumes': item['Number of Volumes'],
                    'Volume Information': vol_list
                }

            json_results.append(json_output)

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as file:
                json.dump(json_results, file, indent=4, sort_keys=True)
        else:
            print(json.dumps(json_results, indent=4, sort_keys=True))

    def _export_csv(self, output_file: Optional[str], volume_information: bool) -> None:
        # Construit les en-têtes
        headers = ['Executable Name', 'Run Count', 'Prefetch Hash']
        headers.extend([f'Last Run Time {i}' for i in range(8)])

        if volume_information:
            headers.append('Number of Volumes')
            # Trouve le nombre maximum de volumes parmi tous les prefetchs pour aligner les colonnes
            max_volumes = max((item.get('Number of Volumes', 0) for item in self.output), default=0)

            for i in range(max_volumes):
                headers.extend([f'Volume {i} Name', f'Volume {i} Creation Time', f'Volume {i} Serial Number'])

        # Détermine où écrire (fichier ou console)
        file_handle = open(output_file, 'a', newline='', encoding='utf-8') if output_file else sys.stdout

        try:
            csv_out = csv.writer(file_handle, delimiter="|")

            # Écriture de l'en-tête (si le fichier est nouveau ou sur sys.stdout)
            if not output_file or os.stat(output_file).st_size == 0:
                csv_out.writerow(headers)

            # Écriture des données
            for item in self.output:
                row = [item['Executable Name'], item['Run Count'], item['Prefetch Hash']]
                row.extend(item['Run Times'])

                if volume_information:
                    num_vols = item.get('Number of Volumes', 0)
                    row.append(num_vols)

                    # Ajouter les infos de volume existantes
                    for vol in item.get('Volumes', []):
                        row.extend([vol['Volume Name'], vol['Creation Time'], vol['Serial Number']])

                    # Remplir de colonnes vides si ce fichier a moins de volumes que le maximum
                    empty_cols_needed = (max_volumes - num_vols) * 3
                    row.extend([''] * empty_cols_needed)

                csv_out.writerow(row)
        finally:
            if output_file:
                file_handle.close()
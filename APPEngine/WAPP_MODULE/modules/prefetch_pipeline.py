import re
import json
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers.PrefetchParser import PrefetchParser


class PrefetchPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        # Dossiers de sortie
        self.out_prefetch_dir = self.context.parsed_dir / "prefetch"
        self.out_dir = self.context.result_parsed_dir

        self.out_prefetch_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Initialisation du parser
        self.parser = PrefetchParser(self.logger)
        self.config_prefetch = self.context.artefact_config.get("artefacts", {}).get("prefetch", {})

    def get_regex_patterns(self):
        """Récupère les patterns depuis la config. Fallback sur .pf si vide."""
        patterns = []
        if not self.config_prefetch:
            return [r"\.pf$"]

        for v in self.config_prefetch.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns

    def process(self, file_path: Path):
        """Parse chaque fichier prefetch et génère un JSON individuel."""
        self.logger.info(f"[PIPELINE][PREFETCH] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            is_prefetch = False
            for reg_pattern in self.get_regex_patterns():
                if re.search(reg_pattern, file_path.name, re.IGNORECASE):
                    is_prefetch = True
                    break

            if is_prefetch:
                # 1. Parsing du fichier (le parser stocke aussi en mémoire pour le CSV final)
                parsed_data = self.parser.parse_file(str(file_path), volume_information=True)

                if parsed_data:
                    # 2. Formatage des données pour le JSON individuel
                    json_output = {
                        'Executable Name': parsed_data.get('Executable Name'),
                        'Run Count': parsed_data.get('Run Count'),
                        'Prefetch Hash': parsed_data.get('Prefetch Hash'),
                        'Run Times': {f'Run Time {i}': time for i, time in enumerate(parsed_data.get('Run Times', []))}
                    }

                    if 'Volumes' in parsed_data:
                        vol_list = {f'Volume {i}': vol for i, vol in enumerate(parsed_data['Volumes'])}
                        json_output['Volumes'] = {
                            'Number of Volumes': parsed_data.get('Number of Volumes'),
                            'Volume Information': vol_list
                        }

                    # 3. Écriture du fichier JSON individuel
                    json_file_path = self.out_prefetch_dir / f"{file_path.stem}.json"
                    with open(json_file_path, 'w', encoding='utf-8') as f:
                        json.dump(json_output, f, indent=4, sort_keys=True)

                    # 4. Ajout du JSON parsé (et non l'artefact brut) à la config Wazuh
                    self.context.wazuh_importer_file_config["files"].append({
                        "path": str(json_file_path),
                        "type": f"prefetch"
                    })

        except Exception as e:
            self.logger.error(f"[PIPELINE][PREFETCH] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        """
        Exporte les données accumulées au format CSV global.
        Le JSON global a été supprimé puisque nous générons 1 JSON par fichier.
        """
        if not self.parser.output:
            self.logger.info("[PIPELINE][PREFETCH] Aucun fichier Prefetch n'a été parsé.")
            return

        output_csv = self.out_dir / "prefetch_results.csv"
        self.logger.info(f"[PIPELINE][PREFETCH] Export du CSV global : {output_csv}", indentation=1)

        try:
            self.parser.output_results(
                output_file=str(output_csv),
                output_format='csv',
                volume_information=True
            )

        except Exception as e:
            self.logger.error(f"[PIPELINE][PREFETCH] Erreur lors de l'export CSV : {e}", header="ERROR", indentation=1)
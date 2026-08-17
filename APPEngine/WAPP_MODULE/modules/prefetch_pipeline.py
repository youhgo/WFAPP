import re
import json
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink
from ..parsers.PrefetchParser import PrefetchParser

@register_pipeline(name="prefetch")
class PrefetchPipeline(BaseArtefactPipeline):
    DEFAULT_PATTERNS = {"super_fetch": ["ag.*.db"], "prefetch": [".*.pf"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        # Dossiers de sortie
        self.out_prefetch_dir = self.context.parsed_dir / "prefetch"
        self.out_prefetch_dir.mkdir(parents=True, exist_ok=True)

        # Initialisation du parser
        self.parser = PrefetchParser(self.logger, separator=self.context.separator)
        self.config_prefetch = self.context.artefact_config.get("artefacts", {}).get("prefetch", {})
        
        # Sink CSV
        self.csv_sink = None


        """Récupère les patterns depuis la config. Fallback sur .pf si vide."""
        patterns = []
        if not self.config_prefetch:
            return [r"\.pf$"]

        for v in self.config_prefetch.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns

    def process(self, file_path: Path):
        """Parse chaque fichier prefetch et génère un JSON individuel + CSV."""
        self.logger.info(f"[PIPELINE][PREFETCH] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return

            for artifact_type, record in self.parser.parse(file_path, volume_information=True):
                # 1. Ecriture dans le Sink CSV
                if not self.csv_sink:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.csv_sink = CsvOutputSink(csv_path, separator=self.context.separator)
                
                self.csv_sink.write_record(record)
                
                # 2. Écriture du fichier JSON individuel pour Wazuh
                json_file_path = self.out_prefetch_dir / f"{file_path.stem}.json"
                with open(json_file_path, 'w', encoding='utf-8') as f:
                    json.dump(record, f, indent=4, sort_keys=True)

                self.context.wazuh_importer_file_config["files"].append({
                    "path": str(json_file_path),
                    "type": "prefetch"
                })

            self.logger.info(f"[PIPELINE][PREFETCH] Succès pour {file_path.name}", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][PREFETCH] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        """Ferme le fichier CSV."""
        if self.csv_sink:
            self.csv_sink.close()
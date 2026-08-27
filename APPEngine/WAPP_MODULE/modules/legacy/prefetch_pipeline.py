import re
import json
from pathlib import Path

from ...classes.BaseArtefactPipelines import BaseArtefactPipeline
from ...classes.WappContext import WappContext
from ...classes.Registry import register_pipeline
from ...classes.BaseParser import DualOutputSink
from ...parsers.legacy.PrefetchParser import PrefetchParser

@register_pipeline(name="prefetch")
class PrefetchPipeline(BaseArtefactPipeline):
    """
    Parse les fichiers Prefetch pour l'historique d'exécution.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
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


    def process(self, file_path: Path):
        """Parses each prefetch file and generates an individual JSON + CSV."""
        self.logger.info(f"[PIPELINE][PREFETCH] Processing {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return

            for artifact_type, record in self.parser.parse(file_path, volume_information=True):
                # 1. Write to CSV Sink
                if not self.csv_sink:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.csv_sink = DualOutputSink(csv_path, separator=self.context.separator, jsonl_dir=self.context.siem_ingestion_dir, context=self.context)
                
                self.csv_sink.write_record(record)
                
                # 2. Write individual JSON file for Wazuh
                json_file_path = self.out_prefetch_dir / f"{file_path.stem}.json"
                with open(json_file_path, 'w', encoding='utf-8') as f:
                    json.dump(record, f, indent=4, sort_keys=True)

                self.context.wazuh_importer_file_config["files"].append({
                    "path": str(json_file_path),
                    "type": "prefetch"
                })

            self.logger.info(f"[PIPELINE][PREFETCH] Success for {file_path.name}", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][PREFETCH] Error on {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        """Closes the CSV file."""
        if self.csv_sink:
            self.csv_sink.close()
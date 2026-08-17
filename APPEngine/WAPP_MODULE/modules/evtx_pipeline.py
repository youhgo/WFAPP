import subprocess
from pathlib import Path
from typing import Dict

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink
from ..parsers.EventParser import EventParser


@register_pipeline(name="evtx")
class EvtxPipeline(BaseArtefactPipeline):
    DEFAULT_PATTERNS = {"evtx": [".*.evtx"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.evt_dir = self.context.parsed_dir / "event"
        self.evt_dir.mkdir(exist_ok=True)
        
        # Le parseur pour les événements
        self.parser = EventParser(separator=self.context.separator)
        
        # Sinks (fichiers de sortie) ouverts pendant le process
        self.sinks: Dict[str, CsvOutputSink] = {}


        """Récupère les patterns de regex de manière sécurisée."""
        if isinstance(self.config_process, list):
            return self.config_process

        patterns = []
        for v in self.config_process.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][EVTX] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            evt_json_name = f"{file_path.stem}.evtx.json"
            out_file = self.evt_dir / evt_json_name

            # Enregistrement pour Wazuh
            self.context.wazuh_importer_file_config["files"].append({"path": str(out_file), "type": "evtx"})

            # Conversion via evtx_dump (Binaire -> JSON)
            my_cmd = [str(self.context.evtx_dump_path), str(file_path)]
            with open(out_file, "w") as outfile:
                subprocess.run(my_cmd, stdout=outfile)

            # Étape de Parsing et d'Écriture (JSON -> CSV)
            # On itère sur le générateur (Yield) du parser
            for artifact_type, record in self.parser.parse(out_file):
                # Si le sink (fichier CSV) pour ce type d'artefact n'existe pas encore, on le crée
                if artifact_type not in self.sinks:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.sinks[artifact_type] = CsvOutputSink(csv_path, separator=self.context.separator)
                
                # On écrit la ligne
                self.sinks[artifact_type].write_record(record)
                
            self.logger.info(f"[PIPELINE][EVTX] Succès pour {file_path.name}", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][EVTX] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        # Fermeture propre de tous les fichiers ouverts par les sinks
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()
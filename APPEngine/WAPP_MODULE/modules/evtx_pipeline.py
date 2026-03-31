import subprocess
import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers import EventParser


class EvtxPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.evt_dir = self.context.parsed_dir / "event"
        self.evt_dir.mkdir(exist_ok=True)

        # Le parseur pour les événements
        self.parser = EventParser.EventParser(str(self.context.result_parsed_dir), separator=self.context.separator)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("event_logs", {})

    def get_regex_patterns(self):
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

            # Conversion via evtx_dump
            my_cmd = [str(self.context.evtx_dump_path), str(file_path)]
            with open(out_file, "w") as outfile:
                subprocess.run(my_cmd, stdout=outfile)

            # Parsing CSV
            self.parser.parse_generic_evtx_file(str(out_file))
            self.logger.info(f"[PIPELINE][EVTX] Succès pour {file_path.name}", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][EVTX] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        self.parser.close_files()
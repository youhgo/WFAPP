from pathlib import Path
import re
from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers.WebHistoryParser import HistoryExporter

class WebHistoryPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_file = self.context.result_parsed_dir / "web_history.csv"
        self.out_dir = self.context.result_parsed_dir
        self.parser = HistoryExporter(self.logger, str(self.out_file))
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("browsers", {})

    def get_regex_patterns(self):
        patterns = []
        for v in self.config_process.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns

    def _matches_category(self, file_name, category_key):
        patterns = self.config_process.get(category_key, [])
        for p in patterns:
            if re.search(p, file_name, re.IGNORECASE):
                return True
        return False

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][WEBHISTORY] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            res_file = self.parser.parse_file(str(file_path))
            self.context.wazuh_importer_file_config["files"].append({"path": str(res_file), "type": f"web_history"})
        except Exception as e:
            self.logger.error(f"[PIPELINE][WEBHISTORY] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        # A la toute fin du parcours des fichiers, on génère le CSV fusionné
        self.logger.info("[PIPELINE][WEBHISTORY] Finalisation et écriture CSV", header="START", indentation=1)
        self.parser.write_to_csv()
from pathlib import Path
import re
from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink
from ..parsers.WebHistoryParser import WebHistoryParser

@register_pipeline(name="browsers")
class WebHistoryPipeline(BaseArtefactPipeline):
    DEFAULT_PATTERNS = {"browser_history": [".*.sqlite"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = WebHistoryParser(self.logger, separator=self.context.separator)
        self.csv_sink = None


        patterns = []
        for v in self.config_process.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns


        patterns = self.config_process.get(category_key, [])
        for p in patterns:
            if re.search(p, file_name, re.IGNORECASE):
                return True
        return False

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][WEBHISTORY] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return
                
            for artifact_type, record in self.parser.parse(file_path):
                if not self.csv_sink:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.csv_sink = CsvOutputSink(csv_path, separator=self.context.separator)
                    self.context.wazuh_importer_file_config["files"].append({"path": str(csv_path), "type": "web_history"})
                self.csv_sink.write_record(record)
                
            self.logger.info(f"[PIPELINE][WEBHISTORY] Succès", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][WEBHISTORY] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        if self.csv_sink:
            self.csv_sink.close()
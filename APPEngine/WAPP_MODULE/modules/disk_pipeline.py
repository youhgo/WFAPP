from pathlib import Path
import re

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink
from ..parsers.DiskParser import DiskParser

@register_pipeline(name="disk")
class DiskPipeline(BaseArtefactPipeline):
    DEFAULT_PATTERNS = {"usn_journal": ["USNInfo.*.csv"], "VSS_List": ["VSS_list.csv"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = DiskParser(self.logger, separator=self.context.separator)
        self.out_disk_dir = self.context.parsed_dir / "disk"
        self.out_dir = self.context.result_parsed_dir
        self.out_disk_dir.mkdir(parents=True, exist_ok=True)
        self.sinks = {}


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
        self.logger.info(f"[PIPELINE][DISK] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            if self._matches_category(file_path.name, "VSS_List"):
                self.copy_raw_artefact(file_path, self.out_disk_dir)
                self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": "disk"})

            elif self._matches_category(file_path.name, "usn_journal"):
                self.copy_raw_artefact(file_path, self.out_disk_dir)
                self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": "usnjrnl"})
                
                # Parsing via Sink
                for artifact_type, record in self.parser.parse(file_path, category="usnjrnl"):
                    if artifact_type not in self.sinks:
                        csv_path = self.out_dir / f"{artifact_type}.csv"
                        self.sinks[artifact_type] = CsvOutputSink(csv_path, separator=self.context.separator)
                    self.sinks[artifact_type].write_record(record)

        except Exception as e:
            self.logger.error(f"[PIPELINE][DISK] Erreur: {e}", header="ERROR", indentation=1)

    def finalize(self):
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()
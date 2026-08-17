from pathlib import Path
import re

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink, JsonlOutputSink
from ..parsers.RegistryParser import RegistryParser


@register_pipeline(name="hives")
class HivePipeline(BaseArtefactPipeline):
    """
    Parses Windows registry hives.
    """
    recommended = True
    DEFAULT_PATTERNS = {"NTUSER": [r"NTUSER(?:_\d+)?\.DAT(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"], "USRCLASS": [r"UsrClass(?:_\d+)?\.dat(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"], "AMCACHE": [r"Amcache(?:_\d+)?\.hve(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"], "SOFTWARE": [r"SOFTWARE(?:_\d+)?(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"], "SYSTEM": [r"SYSTEM(?:_\d+)?(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"], "SECURITY": [r"SECURITY(?:_\d+)?(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"], "SAM": [r"SAM(?:_\d+)?(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = RegistryParser(self.logger, separator=self.context.separator)
        self.csv_sinks = {}
        self.jsonl_sinks = {}

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][HIVE] Processing {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return
                
            hv_name = file_path.name

            if self._matches_category(file_path.name, "AMCACHE"):
                # YARP (JSONL)
                for artifact_type, record in self.parser.parse(file_path, category="amcache_yarp", hive_name=hv_name):
                    if artifact_type not in self.jsonl_sinks:
                        jsonl_path = self.context.result_parsed_dir / f"{file_path.name}_yarp.jsonl"
                        self.jsonl_sinks[artifact_type] = JsonlOutputSink(jsonl_path, context=self.context)
                        self.context.wazuh_importer_file_config["files"].append({"path": str(jsonl_path), "type": "amcache_yarp"})
                    self.jsonl_sinks[artifact_type].write_record(record)
                
                # REGPY (CSV)
                for artifact_type, record in self.parser.parse(file_path, category="amcache_regpy", hive_name=hv_name):
                    if artifact_type not in self.csv_sinks:
                        csv_path = self.context.result_parsed_dir / f"{file_path.name}.csv"
                        self.csv_sinks[artifact_type] = CsvOutputSink(csv_path, separator=self.context.separator)
                        self.context.wazuh_importer_file_config["files"].append({"path": str(csv_path), "type": "amcache_regpy"})
                    self.csv_sinks[artifact_type].write_record(record)
            else:
                # Standard Hive (YARP JSONL)
                for artifact_type, record in self.parser.parse(file_path, category="hive_yarp", hive_name=hv_name):
                    if artifact_type not in self.jsonl_sinks:
                        jsonl_path = self.context.result_parsed_dir / f"{file_path.name}_yarp.jsonl"
                        self.jsonl_sinks[artifact_type] = JsonlOutputSink(jsonl_path, context=self.context)
                        self.context.wazuh_importer_file_config["files"].append({"path": str(jsonl_path), "type": artifact_type})
                    self.jsonl_sinks[artifact_type].write_record(record)

            self.logger.info(f"[PIPELINE][HIVE] Success", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][HIVE] Error on {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        for sink in self.csv_sinks.values():
            sink.close()
        for sink in self.jsonl_sinks.values():
            sink.close()
        self.csv_sinks.clear()
        self.jsonl_sinks.clear()
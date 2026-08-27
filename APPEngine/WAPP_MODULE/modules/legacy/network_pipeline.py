import re
from pathlib import Path

from ...classes.BaseArtefactPipelines import BaseArtefactPipeline
from ...classes.WappContext import WappContext
from ...classes.Registry import register_pipeline
from ...classes.BaseParser import DualOutputSink
from ...parsers.legacy.NetWorkParser import NetWorkParser


@register_pipeline(name="network")
class NetworkPipeline(BaseArtefactPipeline):
    """
    Parses network configuration artifacts.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
    DEFAULT_PATTERNS = {"tcpvcon": [r"Tcpvcon(?:_\d+)?\.txt"], "arp_cache": [r"arp_cache(?:_\d+)?\.txt"], "dns_cache": [r"dns_cache(?:_\d+)?\.txt"], "netstat": [r"netstat(?:_\d+)?\.txt"], "routes": [r"routes(?:_\d+)?\.txt"], "hosts": [r"hosts(?:_\d+)?(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"], "lmhosts": [r"lmhosts(?:_\d+)?\.sam"], "protocol": [r"protocol(?:_\d+)?(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"], "services": [r"services(?:_\d+)?(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"], "network": [r"networks(?:_\d+)?(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"], "bits": [r"BITS_jobs(?:_\d+)?\.txt"], "dns_records": [r"DNS_records(?:_\d+)?\.txt"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_network_dir = self.context.parsed_dir / "network"
        self.out_dir = self.context.result_parsed_dir
        self.out_network_dir.mkdir(exist_ok=True)
        
        self.parser = NetWorkParser(self.logger, separator=self.context.separator)
        self.sinks = {}

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][NETWORK] Processing {file_path.name}", header="START", indentation=1)
        try:
            is_network = False
            for reg_pattern in self.get_regex_patterns():
                if re.search(reg_pattern, file_path.name, re.IGNORECASE):
                    is_network = True
                    break

            if not is_network:
                return

            self.copy_raw_artefact(file_path, self.out_network_dir)
            self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": f"network_{file_path.stem}"})
            self.context.siem_ingestion_files.append(str(file_path))

            category = None
            if self._matches_category(file_path.name, "tcpvcon"):
                category = "tcpvcon"
            elif self._matches_category(file_path.name, "netstat"):
                category = "netstat"
            
            if category:
                for artifact_type, record in self.parser.parse(file_path, category=category):
                    if artifact_type not in self.sinks:
                        csv_path = self.out_dir / f"{artifact_type}_parsed.csv"
                        self.sinks[artifact_type] = DualOutputSink(csv_path, separator=self.context.separator, jsonl_dir=self.context.siem_ingestion_dir, context=self.context)
                    self.sinks[artifact_type].write_record(record)

        except Exception as e:
            self.logger.error(f"[PIPELINE][NETWORK] Error on {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()
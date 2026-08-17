import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink
from ..parsers.NetWorkParser import NetWorkParser


@register_pipeline(name="network")
class NetworkPipeline(BaseArtefactPipeline):
    DEFAULT_PATTERNS = {"tcpvcon": ["Tcpvcon.txt"], "arp_cache": ["arp_cache.txt"], "dns_cache": ["dns_cache.txt"], "netstat": ["netstat.txt"], "routes": ["routes.txt"], "hosts": ["hosts$"], "lmhosts": ["lmhosts.sam"], "protocol": ["protocol$"], "services": ["services$"], "network": ["networks$"], "bits": ["BITS_jobs.txt"], "dns_records": ["DNS_records.txt"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_network_dir = self.context.parsed_dir / "network"
        self.out_dir = self.context.result_parsed_dir
        self.out_network_dir.mkdir(exist_ok=True)
        
        self.parser = NetWorkParser(self.logger, separator=self.context.separator)
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
        self.logger.info(f"[PIPELINE][NETWORK] Traitement de {file_path.name}", header="START", indentation=1)
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

            category = None
            if self._matches_category(file_path.name, "tcpvcon"):
                category = "tcpvcon"
            elif self._matches_category(file_path.name, "netstat"):
                category = "netstat"
            
            if category:
                for artifact_type, record in self.parser.parse(file_path, category=category):
                    if artifact_type not in self.sinks:
                        csv_path = self.out_dir / f"{artifact_type}_parsed.csv"
                        self.sinks[artifact_type] = CsvOutputSink(csv_path, separator=self.context.separator)
                    self.sinks[artifact_type].write_record(record)

        except Exception as e:
            self.logger.error(f"[PIPELINE][NETWORK] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()
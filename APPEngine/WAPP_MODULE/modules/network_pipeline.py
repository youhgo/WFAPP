from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers.NetWorkParser import NetWorkParser
import re

class NetworkPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.out_network_dir = self.context.parsed_dir / "network"
        self.out_dir = self.context.result_parsed_dir
        self.out_network_dir.mkdir(exist_ok=True)
        self.parser = NetWorkParser(self.logger, separator=self.context.separator)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("network", {})

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
        self.logger.info(f"[PIPELINE][NETWORK] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            for reg_pattern in self.get_regex_patterns():
                if re.search(reg_pattern, file_path.name, re.IGNORECASE):
                    self.copy_raw_artefact(file_path, self.out_network_dir)
                    self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": f"network_{file_path.stem}"})
            if self._matches_category(file_path.name, "network_tcpvcon"):
                self.parser.parse_tcpvcon(str(file_path), str(self.out_dir / f"{file_path.name}_parsed.csv"))
            elif self._matches_category(file_path.name, "network_netstat"):
                self.parser.parse_netstat(str(file_path), str(self.out_dir / f"{file_path.name}_parsed.csv"))

        except Exception as e:
            self.logger.error(f"[PIPELINE][NETWORK] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)
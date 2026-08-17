import re
import json
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink
from ..parsers.SystemInfoParser import SystemInfoParser

@register_pipeline(name="system_info")
class SystemInfoPipeline(BaseArtefactPipeline):
    DEFAULT_PATTERNS = {"system_info": ["Systeminfo.csv"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = SystemInfoParser(self.logger, separator=self.context.separator)
        self.csv_sink = None
        self.all_data = []


        patterns = []
        for v in self.config_process.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][SYSINFO] Traitement de {file_path.name}", header="START", indentation=1)
        try:
            if not self.can_process(file_path):
                return
                
            has_data = False
            for artifact_type, record in self.parser.parse(file_path):
                has_data = True
                
                # Ecriture CSV
                if not self.csv_sink:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.csv_sink = CsvOutputSink(csv_path, separator=self.context.separator)
                self.csv_sink.write_record(record)
                
                # On garde en mémoire pour générer le txt/json final (petit volume de données)
                self.all_data.append(record)

            if has_data:
                # Création des versions JSON/TXT 
                out_txt = self.context.result_parsed_dir / "systeminfo.txt"
                out_json = self.context.result_parsed_dir / "systeminfo.json"
                
                with open(out_json, 'w', encoding='utf-8') as f:
                    json.dump(self.all_data, f, indent=4)
                    
                with open(out_txt, 'w', encoding='utf-8') as f:
                    for entry in self.all_data:
                        for k, v in entry.items():
                            f.write(f"{k}:{v}\n")
                        f.write("\n")
                
                self.context.wazuh_importer_file_config["files"].append({"path": str(out_json), "type": "systemInfo"})
                self.logger.info(f"[PIPELINE][SYSINFO] Traitement de {file_path.name}", header="SUCCESS", indentation=2)

        except Exception as e:
            self.logger.error(f"[PIPELINE][SYSINFO] Erreur: {e}", header="ERROR", indentation=2)

        self.logger.info(f"[PIPELINE][SYSINFO] Traitement de {file_path.name}", header="FINISHED", indentation=1)
        
    def finalize(self):
        if self.csv_sink:
            self.csv_sink.close()
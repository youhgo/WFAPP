from pathlib import Path
from typing import Dict

from ...classes.BaseArtefactPipelines import BaseArtefactPipeline
from ...classes.WappContext import WappContext
from ...classes.Registry import register_pipeline
from ...classes.BaseParser import CsvOutputSink
from ...parsers.ogre.OgreHiveParser import OgreHiveParser

@register_pipeline(name="ogre_hive")
class OgreHivePipeline(BaseArtefactPipeline):
    """
    Parses DFIR-Ogre Registry hive output files.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
    DEFAULT_PATTERNS = {
        "ogre_hive": [
            r".*\.reg_keys\.jsonl$",
            r".*\.reg_systeminfo\.jsonl$",
            r".*\.reg_autoruns\.jsonl$",
            r".*\.x509_cert\.jsonl$",
            r".*\.clsid\.jsonl$",
            r".*\.scheduled_tasks\.jsonl$",
            r".*\.shim_db\.jsonl$",
            r".*\.user_profile\.jsonl$",
            r".*\.subject_interface_package\.jsonl$",
            r".*\.app_compat_cache\.jsonl$",
            r".*\.bam_dam\.jsonl$",
            r".*\.mass_storage\.jsonl$",
            r".*\.network_config\.jsonl$",
            r".*\.pending_rename\.jsonl$",
            r".*\.services\.jsonl$",
            r".*\.backup_exclude\.jsonl$",
            r".*\.amcache_driver\.jsonl$",
            r".*\.amcache_file\.jsonl$",
            r".*\.amcache_program\.jsonl$",
            r".*\.acmru\.jsonl$",
            r".*\.antifishing_file\.jsonl$",
            r".*\.explorer_search_history\.jsonl$",
            r".*\.recent_app\.jsonl$",
            r".*\.run_mru\.jsonl$",
            r".*\.user_assist\.jsonl$",
            r".*\.mui_cache\.jsonl$",
            r".*\.shellbags\.jsonl$",
            r".*\.hive\.jsonl$"
        ]
    }

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = OgreHiveParser(separator=self.context.separator)
        self.sinks: Dict[str, CsvOutputSink] = {}
        

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][OGRE_HIVE] Processing {file_path.name}", header="START", indentation=1)
        try:
            
            self.context.siem_ingestion_files.append(str(file_path))
            self.context.wazuh_importer_file_config["files"].append({"path": str(file_path), "type": "registry"})

            for artifact_type, record in self.parser.parse(file_path):
                if artifact_type not in self.sinks:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.sinks[artifact_type] = CsvOutputSink(csv_path, separator=self.context.separator)
                
                self.sinks[artifact_type].write_record(record)
            self.logger.info(f"[PIPELINE][OGRE_HIVE] Success for {file_path.name}", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][OGRE_HIVE] Error on {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()

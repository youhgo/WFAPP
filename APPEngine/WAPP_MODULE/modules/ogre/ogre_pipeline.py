from pathlib import Path
from typing import Dict

from ...classes.BaseArtefactPipelines import BaseArtefactPipeline
from ...classes.WappContext import WappContext
from ...classes.Registry import register_pipeline
from ...classes.BaseParser import CsvOutputSink
from ...parsers.ogre.OgreParser import OgreParser

@register_pipeline(name="ogre")
class OgrePipeline(BaseArtefactPipeline):
    """
    Parses DFIR-Ogre JSONL output files.
    """
    recommended = True
    importance = "Mandatory"
    speed = "Fast"
    DEFAULT_PATTERNS = {"ogre": [".*.jsonl"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.parser = OgreParser(separator=self.context.separator)
        self.sinks: Dict[str, CsvOutputSink] = {}

    def can_process(self, file_path: Path) -> bool:
        name = file_path.name
        # Exclude everything handled by the specialized Ogre pipelines
        suffixes = [
            ".windows_events.jsonl",
            ".ntfsinfo.jsonl",
            ".i30info.jsonl",
            ".usninfo.jsonl",
            ".vss_snapshot.jsonl",
            ".volstats.jsonl",
            ".prefetch.jsonl",
            ".browser_history.jsonl",
            ".browser_download_history.jsonl",
            ".firefox_extension.jsonl",
            ".firefox_history.jsonl",
            ".chrome_extension.jsonl",
            ".ie_webcache_history.jsonl",
            ".systeminfo.jsonl",
            ".reg_systeminfo.jsonl",
            ".processes_orc.jsonl",
            ".lnk.jsonl",
            ".jumplist.jsonl",
            ".getthis.jsonl"
        ]
        if any(name.endswith(s) for s in suffixes):
            return False
            
        reg_suffixes = [".reg_keys.jsonl", ".reg_autoruns.jsonl", ".x509_cert.jsonl", ".clsid.jsonl", 
                        ".scheduled_tasks.jsonl", ".shim_db.jsonl", ".user_profile.jsonl", 
                        ".subject_interface_package.jsonl", ".app_compat_cache.jsonl", ".bam_dam.jsonl", 
                        ".mass_storage.jsonl", ".network_config.jsonl", ".pending_rename.jsonl", 
                        ".services.jsonl", ".backup_exclude.jsonl", ".amcache_driver.jsonl", 
                        ".amcache_file.jsonl", ".amcache_program.jsonl", ".acmru.jsonl", 
                        ".antifishing_file.jsonl", ".explorer_search_history.jsonl", ".recent_app.jsonl", 
                        ".run_mru.jsonl", ".user_assist.jsonl", ".mui_cache.jsonl", ".shellbags.jsonl",
                        ".hive.jsonl"]
        if any(name.endswith(s) for s in reg_suffixes):
            return False

        srum_suffixes = [
            ".srum_application_resources.jsonl", ".srum_app_timeline.jsonl", 
            ".srum_energy_estimation.jsonl", ".srum_energy_usage.jsonl", 
            ".srum_energy_usage_long_term.jsonl", ".srum_network_connectivity_usage.jsonl", 
            ".srum_network_data_usage.jsonl", ".srum_sdp_cpu.jsonl", 
            ".srum_sdp_network.jsonl", ".srum_sdp_physical_disk.jsonl", 
            ".srum_sdp_volume.jsonl", ".srum_tagged_energy.jsonl", 
            ".srum_vfuprov.jsonl", ".srum_wpn_provider.jsonl"
        ]
        if any(name.endswith(s) for s in srum_suffixes):
            return False

        return super().can_process(file_path)

    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][OGRE] Processing {file_path.name}", header="START", indentation=1)
        try:
            for artifact_type, record in self.parser.parse(file_path):
                if artifact_type not in self.sinks:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.sinks[artifact_type] = CsvOutputSink(csv_path, separator=self.context.separator)
                
                self.sinks[artifact_type].write_record(record)
            self.logger.info(f"[PIPELINE][OGRE] Success for {file_path.name}", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][OGRE] Error on {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()

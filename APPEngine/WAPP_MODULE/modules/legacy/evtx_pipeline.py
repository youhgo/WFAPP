import subprocess
from pathlib import Path
from typing import Dict

from ...classes.BaseArtefactPipelines import BaseArtefactPipeline
from ...classes.WappContext import WappContext
from ...classes.Registry import register_pipeline
from ...classes.BaseParser import CsvOutputSink
from ...parsers.legacy.EventParser import EventParser


@register_pipeline(name="evtx")
class EvtxPipeline(BaseArtefactPipeline):
    """
    Parses Windows event logs.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
    DEFAULT_PATTERNS = {"evtx": [".*.evtx"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.evt_dir = self.context.parsed_dir / "event"
        self.evt_dir.mkdir(exist_ok=True)
        
        # The event parser
        self.parser = EventParser(separator=self.context.separator)
        
        # Sinks (output files) opened during the process
        self.sinks: Dict[str, CsvOutputSink] = {}


    def process(self, file_path: Path):
        self.logger.info(f"[PIPELINE][EVTX] Processing {file_path.name}", header="START", indentation=1)
        try:
            evt_json_name = f"{file_path.stem}.evtx.jsonl"
            out_file = self.evt_dir / evt_json_name
            self.context.siem_ingestion_files.append(str(out_file))

            # Registration for Wazuh
            self.context.wazuh_importer_file_config["files"].append({"path": str(out_file), "type": "evtx"})

            # Conversion via evtx_dump (Binary -> JSON)
            my_cmd = [str(self.context.evtx_dump_path), str(file_path)]
            with open(out_file, "w") as outfile:
                subprocess.run(my_cmd, stdout=outfile)

            # Parsing and Writing Step (JSON -> CSV)
            # We iterate over the parser's generator (Yield)
            for artifact_type, record in self.parser.parse(out_file):
                # If the sink (CSV file) for this artifact type doesn't exist yet, we create it
                if artifact_type not in self.sinks:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.sinks[artifact_type] = CsvOutputSink(csv_path, separator=self.context.separator)
                
                # We write the line
                self.sinks[artifact_type].write_record(record)
                
            self.logger.info(f"[PIPELINE][EVTX] Success for {file_path.name}", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][EVTX] Error on {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        # Clean closure of all files opened by sinks
        for sink in self.sinks.values():
            sink.close()
        self.sinks.clear()
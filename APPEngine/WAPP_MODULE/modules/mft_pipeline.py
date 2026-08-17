import subprocess
import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import DualOutputSink
from ..parsers.DiskParser import DiskParser

@register_pipeline(name="master_file_table")
class MftPipeline(BaseArtefactPipeline):
    """
    Parses the MFT to retrieve file history.
    """
    recommended = True
    DEFAULT_PATTERNS = {"MFT": [r"\$?MFT(?:_\d+)?(?:_\{[a-fA-F0-9\-]+\}(?:\.data)?)?$"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.mft_dir = self.context.parsed_dir / "disk"
        self.mft_dir.mkdir(parents=True, exist_ok=True)
        self.parser = DiskParser(self.logger, separator=self.context.separator)
        self.csv_sink = None

    def process(self, file_path: Path):
        try:
            if not self.can_process(file_path):
                return
                
            clean_mft_name = file_path.name.replace("$", "")
            self.logger.info(f"[PIPELINE][MFT] Processing {clean_mft_name}", header="START", indentation=1)

            mft_result_file = self.mft_dir / f"{clean_mft_name}.timeline"
            self.context.wazuh_importer_file_config["files"].append({
                "path": str(mft_result_file),
                "type": "mft_timeline"
            })

            my_cmd = [
                "python3", str(self.context.analyze_mft_tool_path),
                "-f", str(file_path),
                "-o", str(mft_result_file),
                "--timeline"
            ]
            subprocess.run(my_cmd, stderr=None, check=True)

            # Parsing via Sink
            for artifact_type, record in self.parser.parse(mft_result_file, category="plaso_csv"):
                if not self.csv_sink:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.csv_sink = DualOutputSink(csv_path, separator=self.context.separator, jsonl_dir=self.context.siem_ingestion_dir, context=self.context)
                self.csv_sink.write_record(record)

            self.logger.info(f"[PIPELINE][MFT] Success", header="FINISHED", indentation=1)

        except subprocess.CalledProcessError as e:
            self.logger.error(f"[PIPELINE][MFT] External tool failed for {file_path.name}", header="ERROR", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][MFT] Error on {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        if self.csv_sink:
            self.csv_sink.close()
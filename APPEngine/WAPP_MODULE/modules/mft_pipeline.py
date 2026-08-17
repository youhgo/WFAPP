import subprocess
import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink
from ..parsers.DiskParser import DiskParser

@register_pipeline(name="master_file_table")
class MftPipeline(BaseArtefactPipeline):
    DEFAULT_PATTERNS = {"MFT": ["MFT$"]}

    def __init__(self, context: WappContext):
        super().__init__(context)
        self.mft_dir = self.context.parsed_dir / "disk"
        self.mft_dir.mkdir(parents=True, exist_ok=True)
        self.parser = DiskParser(self.logger, separator=self.context.separator)
        self.csv_sink = None


        patterns = []
        for v in self.config_process.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns

    def clean_forensic_name(self, filename):
        pattern = r'^\._\$(.*)$'
        match = re.match(pattern, filename)
        if match:
            return f"{match.group(1).lower()}_file"
        return filename

    def rename_on_disk(self, file_path: Path) -> Path:
        new_name = self.clean_forensic_name(file_path.name)
        if new_name == file_path.name:
            return file_path
        new_path = file_path.with_name(new_name)
        try:
            if new_path.exists():
                new_path.unlink()
            file_path.rename(new_path)
            self.logger.info(f"[PIPELINE][MFT] Renommage disque : {file_path.name} -> {new_name}", indentation=2)
            return new_path
        except Exception as e:
            self.logger.error(f"[PIPELINE][MFT] Impossible de renommer sur disque : {e}", indentation=2)
            return file_path

    def process(self, file_path: Path):
        try:
            if not self.can_process(file_path):
                return
                
            file_path = self.rename_on_disk(file_path)
            clean_mft_name = file_path.name
            self.logger.info(f"[PIPELINE][MFT] Traitement de {clean_mft_name}", header="START", indentation=1)

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
            subprocess.run(my_cmd, stderr=subprocess.DEVNULL, check=True)

            # Parsing via Sink
            for artifact_type, record in self.parser.parse(mft_result_file, category="plaso_csv"):
                if not self.csv_sink:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.csv_sink = CsvOutputSink(csv_path, separator=self.context.separator)
                self.csv_sink.write_record(record)

            self.logger.info(f"[PIPELINE][MFT] Succès", header="FINISHED", indentation=1)

        except subprocess.CalledProcessError as e:
            self.logger.error(f"[PIPELINE][MFT] L'outil externe a échoué pour {file_path.name}", header="ERROR", indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][MFT] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)

    def finalize(self):
        if self.csv_sink:
            self.csv_sink.close()
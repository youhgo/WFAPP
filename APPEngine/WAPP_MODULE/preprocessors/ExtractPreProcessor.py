import os
import re
from ..classes.BasePreProcessor import BasePreProcessor
from ..classes.Registry import register_preprocessor
from ..classes.OrcExtractor import OrcExtractor

@register_preprocessor('extract')
class ExtractPreProcessor(BasePreProcessor):
    """
    Decompresses the original archive. Required to start the analysis.
    """
    recommended = True
    importance = "Mandatory"
    speed = "Fast"
    priority = 0
    requires = []
    default_enabled = True

    def run(self) -> None:
        extraction_successful = False
        try:
            extractor = OrcExtractor(self.logger, "avproof")
            self.logger.info("[EXTRACTING] archives", header="START")

            archive_path = str(self.context.path_to_archive)
            archive_filename = os.path.basename(archive_path)
            cleaned_filename = re.sub(r'^[a-f0-9]+__', '', archive_filename)
            file_ext = os.path.splitext(cleaned_filename)[1].lower()

            self.logger.info(f"[EXTRACTING] cleaning archive name to {cleaned_filename}", header="INFO")
            self.logger.info(f"[EXTRACTING] found extension {file_ext}", header="INFO")

            if file_ext in [".7z", ".zip"]:
                extraction_successful = extractor.extract_recursively(file_ext,
                                                                      archive_path,
                                                                      str(self.context.extracted_dir))
            self.logger.info("[EXTRACTING] archives", header="FINISHED")
        except Exception as e:
            self.logger.error(f"[EXTRACTING] Error: {e}", header="ERROR")

        if not extraction_successful:
            raise Exception("Extraction failed or archive format not supported.")

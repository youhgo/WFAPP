from ..classes.BasePostProcessor import BasePostProcessor
from ..classes.Registry import register_postprocessor
import subprocess

@register_postprocessor('plaso')
class PlasoPostProcessor(BasePostProcessor):
    """
    Generates a complete Plaso dump in CSV and JSONL (long).
    Highly recommended.
    Plaso running almost last and the previous plugins already giving good visibility on events,
    It is therefore recommended to enable it as it does not slow down the analysis and often provides complementary and valuable results.
    Moreover, its format is more easily ingestible in Wazuh.
    """
    recommended = True

    priority = 10
    requires = []

    def run(self) -> None:
        self.logger.info("[TOOLING][PLASO] Log2Timeline", header="START")
        
        plaso_storage_file = self.context.timeline_dir / "timeline.plaso"
        l2t_log_file = self.context.timeline_dir / "l2t.log.gz"
        psort_log_file = self.context.timeline_dir / "psort.log.gz"
        timeline_json_path = self.context.timeline_dir / "timeline.json"
        timeline_csv_path = self.context.timeline_dir / "timeline.csv"
        
        try:
            subprocess.run(
                ["log2timeline.py", "--logfile", str(l2t_log_file), "--storage-file", str(plaso_storage_file),
                 str(self.context.extracted_main_dir)])
            self.logger.info("[PARSING][PSORT] to JSON", header="START")
            subprocess.run(["psort.py", "-o", "json_line", "--logfile", str(psort_log_file), "-w",
                            str(timeline_json_path), str(plaso_storage_file)])
            subprocess.run(
                ["psort.py", "-o", "l2tcsv", "--logfile", str(psort_log_file), "-w", str(timeline_csv_path),
                 str(plaso_storage_file)])
        except Exception as e:
            self.logger.error(f"[TOOLING][PLASO] Error: {e}", header="ERROR")

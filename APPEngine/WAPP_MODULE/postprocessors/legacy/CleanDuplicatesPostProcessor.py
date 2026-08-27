from pathlib import Path
from ...classes.BasePostProcessor import BasePostProcessor
from ...classes.Registry import register_postprocessor

@register_postprocessor('clean_duplicates')
class CleanDuplicatesPostProcessor(BasePostProcessor):
    """
    Cleans duplicated lines to lighten exports.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"

    priority = 1
    requires = []
    default_enabled = True

    def run(self) -> None:
        dir_to_clean = self.context.result_parsed_dir
        self.logger.info("[CLEAN DUPLICATE] Start", header="START")
        try:
            for file in Path(dir_to_clean).rglob("*"):
                if file.is_file():
                    seen_lines = set()
                    l_temp = []
                    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if line not in seen_lines:
                                seen_lines.add(line)
                                l_temp.append(line)
                    with open(file, 'w', encoding='utf-8') as f:
                        f.writelines(l_temp)
            self.logger.info("[CLEAN DUPLICATE] Finished", header="FINISHED")
        except Exception as e:
            self.logger.error(f"[CLEAN DUPLICATE] Error: {e}", header="ERROR")

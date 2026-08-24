import csv
from ..classes.BasePostProcessor import BasePostProcessor
from ..classes.Registry import register_postprocessor

@register_postprocessor('create_timeline')
class CreateTimelinePostProcessor(BasePostProcessor):
    """
    Merges all generated CSV files into a small timeline (small_timeline.csv).
    Warning: this is not PLASO.
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"

    priority = 2
    requires = ['clean_duplicates']
    default_enabled = True

    def _parse_sort_key(self, row: list) -> str:
        """
        Generates a chronological key combining Date (column 0) and Time (column 1)
        or ISO timestamp.
        """
        if not row:
            return "9999-99-99 99:99:99"
        
        date_part = str(row[0]).strip() if len(row) > 0 else ""
        time_part = str(row[1]).strip() if len(row) > 1 else ""

        if not date_part or date_part == "-":
            return "9999-99-99 99:99:99"

        # If date_part already contains time (e.g. ISO 8601 format like 2026-08-24T08:15:27Z)
        if " " in date_part or "T" in date_part:
            return date_part

        # Combine date and time for complete chronological sorting
        if time_part and time_part != "-":
            return f"{date_part} {time_part}"
        
        return date_part

    def run(self) -> None:
        self.logger.info("[CREATING][TIMELINE]", header="START")
        timeline_entries = []
        final_header = None
        SOURCE_FILE_COLUMN_INDEX = 2

        EXCLUDED_KEYWORDS = [
            "consolehost",
            "powershell",
            "script",
            "process",
            "raw_text",
            "dump"
        ]

        for file_path in self.context.result_parsed_dir.rglob("*.csv"):
            if file_path.name == "small_timeline.csv":
                continue

            stem_lower = file_path.stem.lower()
            if any(kw in stem_lower for kw in EXCLUDED_KEYWORDS):
                self.logger.info(f"[TIMELINE][EXCLUDED] Skipping non-timeline file: {file_path.name}")
                continue

            try:
                with file_path.open('r', newline='', encoding='utf-8') as f:
                    reader = csv.reader(f, delimiter='|')
                    try:
                        header = next(reader)
                        if not header or len(header) < 1:
                            continue

                        # Ensure header[0] contains a timestamp or date-related column name
                        first_col = header[0].strip().lower()
                        valid_time_indicators = ["date", "time", "timestamp", "datetime", "lastwritten"]
                        if not any(indicator in first_col for indicator in valid_time_indicators):
                            self.logger.info(f"[TIMELINE][EXCLUDED] Skipping CSV without Date/Time header: {file_path.name}")
                            continue

                        if final_header is None:
                            final_header = header[:]
                            final_header.insert(SOURCE_FILE_COLUMN_INDEX, 'SourceFile')
                    except StopIteration:
                        continue
                    for row in reader:
                        if not row:
                            continue
                        row.insert(SOURCE_FILE_COLUMN_INDEX, file_path.stem)
                        timeline_entries.append(row)
            except Exception:
                pass

        if timeline_entries:
            sorted_timeline = sorted(timeline_entries, key=self._parse_sort_key)

            timeline_path = self.context.result_parsed_dir / "small_timeline.csv"
            with open(timeline_path, 'w', newline='', encoding='utf-8') as tl:
                writer = csv.writer(tl, delimiter='|')
                if final_header:
                    writer.writerow(final_header)
                writer.writerows(sorted_timeline)
        self.logger.info("[CREATING][TIMELINE]", header="FINISHED")

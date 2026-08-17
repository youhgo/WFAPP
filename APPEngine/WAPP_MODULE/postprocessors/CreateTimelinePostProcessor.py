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

    priority = 2
    requires = ['clean_duplicates']
    default_enabled = True

    def run(self) -> None:
        self.logger.info("[CREATING][TIMELINE]", header="START")
        timeline_entries = []
        final_header = None
        SOURCE_FILE_COLUMN_INDEX = 2

        for file_path in self.context.result_parsed_dir.rglob("*.csv"):
            if file_path.name == "small_timeline.csv": continue
            try:
                with file_path.open('r', newline='', encoding='utf-8') as f:
                    reader = csv.reader(f, delimiter='|')
                    try:
                        header = next(reader)
                        if final_header is None:
                            final_header = header[:]
                            final_header.insert(SOURCE_FILE_COLUMN_INDEX, 'SourceFile')
                    except StopIteration:
                        continue
                    for row in reader:
                        if not row: continue
                        row.insert(SOURCE_FILE_COLUMN_INDEX, file_path.stem)
                        timeline_entries.append(row)
            except Exception:
                pass

        if timeline_entries:
            try:
                sorted_timeline = sorted(timeline_entries, key=lambda x: x[0])
            except IndexError:
                sorted_timeline = sorted(timeline_entries)

            timeline_path = self.context.result_parsed_dir / "small_timeline.csv"
            with open(timeline_path, 'w', newline='', encoding='utf-8') as tl:
                writer = csv.writer(tl, delimiter='|')
                if final_header: writer.writerow(final_header)
                writer.writerows(sorted_timeline)
        self.logger.info("[CREATING][TIMELINE]", header="FINISHED")

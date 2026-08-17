# 🛠️ WFAPP Developer & Plugin Guide

WFAPP was built from the ground up to be **Plug & Play**. You can add support for a new forensic artifact by writing just a few lines of code. You do not need to modify the core engine, the `dispatcher.py`, or any heavy logic.

WFAPP automatically discovers your module at runtime.

This guide will walk you through creating a new Parser and Pipeline.

---

## 1. The Architecture at a Glance

A module in WFAPP consists of two parts:
1. **The Parser** (`parsers/MyNewParser.py`): Its job is to read the raw data, format it into a dictionary, and **yield** it.
2. **The Pipeline** (`modules/mynew_pipeline.py`): Its job is to find the right files to give to the parser, and use a "Sink" to save the yielded dictionaries to disk.

---

## 2. Creating a Parser

Create a new file in the `parsers/` directory.

### Requirements:
- It must inherit from `BaseParser`.
- It must implement the `parse(self, input_path: Path)` method.
- It must return an iterator (using `yield`). Each yield should be a tuple containing the **artifact_name** (used to name the output file) and a **dictionary** representing the row data.

### Example: `parsers/MyNewParser.py`
```python
import csv
from pathlib import Path
from typing import Generator, Any, Dict, Tuple
from ..classes.BaseParser import BaseParser

class MyNewParser(BaseParser):
    def parse(self, input_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        # 1. Open the file
        with open(input_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            # 2. Yield rows one by one (No memory overload!)
            for row in reader:
                record = {
                    "Date": row.get("timestamp"),
                    "User": row.get("username"),
                    "Action": "Custom Action"
                }
                # "my_custom_artifact" will become my_custom_artifact.csv
                yield "my_custom_artifact", record
```

---

## 3. Creating a Pipeline

Create a new file in the `modules/` directory.

### Requirements:
- It must inherit from `BaseArtefactPipeline`.
- It must be decorated with `@register_pipeline(name="your_config_name")`. The dispatcher uses this name to link your pipeline to the execution config JSON.
- It must implement the `process(self, file_path: Path)` method.

### Example: `modules/mynew_pipeline.py`
```python
from pathlib import Path
from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink
from ..parsers.MyNewParser import MyNewParser

# This decorator makes it Plug & Play!
@register_pipeline(name="my_new_artefact")
class MyNewPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        # Initialize your custom parser
        self.parser = MyNewParser(self.logger, separator=self.context.separator)
        self.csv_sink = None

    def process(self, file_path: Path):
        try:
            # 1. Parse the file using yield
            for artifact_type, record in self.parser.parse(file_path):
                
                # 2. Dynamically create the output sink if it doesn't exist yet
                if not self.csv_sink:
                    csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
                    self.csv_sink = CsvOutputSink(csv_path, separator=self.context.separator)
                    
                    # (Optional) Register it in Wazuh
                    self.context.wazuh_importer_file_config["files"].append(
                        {"path": str(csv_path), "type": artifact_type}
                    )
                
                # 3. Write to disk instantly
                self.csv_sink.write_record(record)
                
        except Exception as e:
            self.logger.error(f"Error: {e}")

    def finalize(self):
        # Always close your sinks when parsing is totally finished
        if self.csv_sink:
            self.csv_sink.close()
```

---

## 4. Output Sinks Available

Instead of handling Python `open()` and `close()` manually, always use the Sinks provided in `BaseParser.py`. They automatically handle headers, append modes, and file creation.

- **`CsvOutputSink`**: Writes flat dictionaries into a piped CSV format.
- **`JsonlOutputSink`**: Writes nested dictionaries into JSON Lines (`.jsonl`). Ideal for huge tree-based data like Windows Registries.
- **`TextOutputSink`**: Writes flat strings into raw text files. Ideal for dumping custom CLI outputs or logs.

---

### You're done! 🎉
As soon as you save these two files, the next time WFAPP boots, the `dispatcher.py` will find `@register_pipeline(name="my_new_artefact")` and automatically route the files to your pipeline if the configuration asks for it.

# WFAPP Developer and Plugin Guide

WFAPP is designed to be highly modular. You can add support for new forensic artifacts by implementing a parser and a pipeline. You do not need to modify the core execution engine or the main dispatcher.

WFAPP automatically discovers new modules at runtime.

This guide details the architecture and walks you through creating a new parser, pipeline, and documenting it for the Web GUI.

---

## 1. Architecture Overview

A module in WFAPP is composed of two main parts:
1. **The Parser** (located in `parsers/`): Reads the raw data, formats it into a dictionary, and yields the records.
2. **The Pipeline** (located in `modules/`): Locates the target evidence files using patterns, runs the parser, and uses an output sink to save the yielded records to disk.

---

## 2. Creating a Parser

Create a new file in the `parsers/` directory.

### Requirements:
- It must inherit from `BaseParser`.
- It must implement the `parse(self, input_path: Path)` method.
- It must return an iterator (using `yield`). Each yielded item must be a tuple containing the `artifact_name` (used for the output filename) and a dictionary representing the record data.

### Example: `parsers/MyNewParser.py`
```python
import csv
from pathlib import Path
from typing import Generator, Any, Dict, Tuple
from ..classes.BaseParser import BaseParser

class MyNewParser(BaseParser):
  def parse(self, input_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
    with open(input_path, 'r', encoding='utf-8') as f:
      reader = csv.DictReader(f)
      for row in reader:
        record = {
          "Date": row.get("timestamp"),
          "User": row.get("username"),
          "Action": "Custom Action"
        }
        # "my_custom_artifact" determines the output filename (my_custom_artifact.csv)
        yield "my_custom_artifact", record
```

---

## 3. Creating a Pipeline

Create a new file in the `modules/` directory.

### Requirements:
- It must inherit from `BaseArtefactPipeline`.
- It must be decorated with `@register_pipeline(name="your_config_name")`. The dispatcher uses this name to route files according to the execution configuration.
- It must implement the `process(self, file_path: Path)` method.

### Example: `modules/mynew_pipeline.py`
```python
from pathlib import Path
from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..classes.Registry import register_pipeline
from ..classes.BaseParser import CsvOutputSink
from ..parsers.MyNewParser import MyNewParser

@register_pipeline(name="my_new_artefact")
class MyNewPipeline(BaseArtefactPipeline):
  """
  Parses custom system log archives.
  This module extracts user activities and normalizes them for SIEM ingestion.
  """
  recommended = True

  def __init__(self, context: WappContext):
    super().__init__(context)
    self.parser = MyNewParser(self.logger, separator=self.context.separator)
    self.csv_sink = None

  def process(self, file_path: Path):
    try:
      for artifact_type, record in self.parser.parse(file_path):
        if not self.csv_sink:
          csv_path = self.context.result_parsed_dir / f"{artifact_type}.csv"
          self.csv_sink = CsvOutputSink(csv_path, separator=self.context.separator)
          
          self.context.wazuh_importer_file_config["files"].append(
            {"path": str(csv_path), "type": artifact_type}
          )
        
        self.csv_sink.write_record(record)
        
    except Exception as e:
      self.logger.error(f"Error during processing: {e}")

  def finalize(self):
    if self.csv_sink:
      self.csv_sink.close()
```

---

## 4. Plugin Documentation and GUI Integration

WFAPP features an automatic documentation engine that displays plugin metadata in the Web GUI without importing the Python modules.

### How Docstrings are Used
The API reads the plugin source code and uses Python's Abstract Syntax Tree (`ast`) module to inspect the registered class definition. It extracts the class-level docstring to serve as the plugin description in the GUI.

To set up a description for your plugin:
- Add a triple-quoted docstring (`"""`) directly beneath the class definition.
- Keep the description concise and descriptive of what the parser does.
- Avoid HTML or markdown markup that might break raw text displays.

### The Recommended Attribute
You can define a class-level variable `recommended` set to `True` or `False`. The AST parser reads this variable to highlight recommended plugins in the GUI checklist.

### Example
```python
@register_pipeline(name="prefetch")
class PrefetchPipeline(BaseArtefactPipeline):
  """
  Parses Windows Prefetch files (.pf) to identify executed programs.
  Extracts executable names, execution counters, and timestamps.
  """
  recommended = True
  # Class implementation...
```

If no docstring is provided, the GUI defaults to displaying "No description available."

---

## 5. Output Sinks

Avoid managing raw file writing manually. Use the built-in Sinks from `BaseParser.py` to handle headers, append modes, and formats.

- **`CsvOutputSink`**: Writes flat dictionaries into pipe-separated CSV format.
- **`JsonlOutputSink`**: Writes nested dictionaries into JSON Lines format. Ideal for complex hierarchical data like Windows Registry entries.
- **`TextOutputSink`**: Writes raw string lines to text files. Helpful for terminal dumps or unstructured text logs.

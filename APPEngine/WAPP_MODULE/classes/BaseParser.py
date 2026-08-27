import csv
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Generator, Any, Dict, Tuple


class BaseParser(ABC):
    """
    Base class for all parsers.
    Parsers must read the raw data, clean it and yield it.
    They no longer need to worry about creating or closing output files.
    """
    
    def __init__(self, logger=None, separator="|"):
        self.logger = logger
        self.separator = separator

    @abstractmethod
    def parse(self, input_path: Path) -> Generator[Tuple[str, Any], None, None]:
        """
        Must read the input file and yield tuples (artifact_type, dictionary or string).
        Ex: yield "prefetch", {"Date": "2023-01-01", "Time": "12:00:00", "Data": "example"}
        """
        pass


class CsvOutputSink:
    """
    Manages standardized writing to a CSV file.
    Takes the dictionaries yielded by the parser and writes them.
    """
    def __init__(self, output_path: Path, separator="|"):
        self.output_path = output_path
        self.separator = separator
        self.file = None
        self.writer = None
        self.headers_written = False

    def write_record(self, record: Dict[str, Any]):
        if not self.file:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            self.file = open(self.output_path, "a", newline="", encoding="utf-8")
            
        if not self.headers_written and self.file.tell() == 0:
            self.writer = csv.DictWriter(self.file, fieldnames=record.keys(), delimiter=self.separator)
            self.writer.writeheader()
            self.headers_written = True
        elif not self.writer:
            self.writer = csv.DictWriter(self.file, fieldnames=record.keys(), delimiter=self.separator)

        self.writer.writerow(record)

    def close(self):
        if self.file:
            self.file.close()
            self.file = None
            self._sort_csv()
            
    def _sort_csv(self):
        """Trie le fichier CSV généré en se basant sur les colonnes de date/heure."""
        if not self.output_path.exists():
            return
            
        try:
            with open(self.output_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f, delimiter=self.separator)
                fieldnames = reader.fieldnames
                if not fieldnames:
                    return
                rows = list(reader)
                
            # Identifier les colonnes de date pour le tri (DATE, TIME, timestamp, etc.)
            # On cherche d'abord DATE puis TIME, ou les colonnes classiques
            sort_cols = []
            upper_fields = {f.upper(): f for f in fieldnames if f}
            
            if "DATE" in upper_fields:
                sort_cols.append(upper_fields["DATE"])
            if "TIME" in upper_fields:
                sort_cols.append(upper_fields["TIME"])
            if not sort_cols and "TIMESTAMP" in upper_fields:
                sort_cols.append(upper_fields["TIMESTAMP"])
                
            if sort_cols:
                def get_sort_key(row):
                    return tuple(row.get(c, "") for c in sort_cols)
                rows.sort(key=get_sort_key)
                
                with open(self.output_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=self.separator)
                    writer.writeheader()
                    writer.writerows(rows)
        except Exception as e:
            # En cas d'erreur de tri, on laisse le fichier tel quel
            pass

class JsonlOutputSink:
    """
    Manages standardized writing to a JSONL (JSON Lines) file.
    """
    def __init__(self, output_path: Path, context=None, ingest_to_siem=True):
        self.output_path = output_path
        self.file = None

    def write_record(self, record: Dict[str, Any]):
        if not self.file:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            self.file = open(self.output_path, "a", encoding="utf-8")
            
        self.file.write(json.dumps(record, ensure_ascii=False) + "\n")

    def close(self):
        if self.file:
            self.file.close()
            self.file = None


class TextOutputSink:
    """
    Manages writing raw text lines.
    """
    def __init__(self, output_path: Path):
        self.output_path = output_path
        self.file = None

    def write_record(self, record: str):
        if not self.file:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            self.file = open(self.output_path, "a", encoding="utf-8")
            
        self.file.write(record + "\n")

    def close(self):
        if self.file:
            self.file.close()
            self.file = None


class DualOutputSink:
    def __init__(self, output_path: Path, separator="|", jsonl_dir: Path = None, context=None, ingest_to_siem=True):
        self.csv_path = output_path
        if jsonl_dir:
            self.jsonl_path = jsonl_dir / f"{output_path.stem}.jsonl"
        else:
            self.jsonl_path = output_path.with_suffix('.jsonl')
        self.separator = separator
        self.csv_file = None
        self.jsonl_file = None
        self.writer = None
        self.headers_written = False

    def write_record(self, record: Dict[str, Any]):
        if not self.csv_file:
            self.csv_path.parent.mkdir(parents=True, exist_ok=True)
            self.csv_file = open(self.csv_path, "a", newline="", encoding="utf-8")
            self.jsonl_file = open(self.jsonl_path, "a", encoding="utf-8")
            
        if not self.headers_written and self.csv_file.tell() == 0:
            self.writer = csv.DictWriter(self.csv_file, fieldnames=record.keys(), delimiter=self.separator)
            self.writer.writeheader()
            self.headers_written = True
        elif not self.writer:
            self.writer = csv.DictWriter(self.csv_file, fieldnames=record.keys(), delimiter=self.separator)

        self.writer.writerow(record)
        self.jsonl_file.write(json.dumps(record, ensure_ascii=False) + "\n")

    def close(self):
        if self.csv_file:
            self.csv_file.close()
            self.csv_file = None
            self._sort_csv()
        if self.jsonl_file:
            self.jsonl_file.close()
            self.jsonl_file = None

    def _sort_csv(self):
        if not self.csv_path.exists():
            return
            
        try:
            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f, delimiter=self.separator)
                fieldnames = reader.fieldnames
                if not fieldnames:
                    return
                rows = list(reader)
                
            sort_cols = []
            upper_fields = {f.upper(): f for f in fieldnames if f}
            
            if "DATE" in upper_fields:
                sort_cols.append(upper_fields["DATE"])
            if "TIME" in upper_fields:
                sort_cols.append(upper_fields["TIME"])
            if not sort_cols and "TIMESTAMP" in upper_fields:
                sort_cols.append(upper_fields["TIMESTAMP"])
                
            if sort_cols:
                def get_sort_key(row):
                    return tuple(row.get(c, "") for c in sort_cols)
                rows.sort(key=get_sort_key)
                
                with open(self.csv_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=self.separator)
                    writer.writeheader()
                    writer.writerows(rows)
        except Exception as e:
            pass

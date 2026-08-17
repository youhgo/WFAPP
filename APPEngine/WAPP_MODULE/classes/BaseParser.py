import csv
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Generator, Any, Dict, Tuple


class BaseParser(ABC):
    """
    Classe de base pour tous les parsers.
    Les parsers doivent lire la donnée brute, la nettoyer et la "yield" (générer).
    Ils ne doivent plus s'occuper de créer ou fermer les fichiers de sortie.
    """
    
    def __init__(self, logger=None, separator="|"):
        self.logger = logger
        self.separator = separator

    @abstractmethod
    def parse(self, input_path: Path) -> Generator[Tuple[str, Any], None, None]:
        """
        Doit lire le fichier d'entrée et yield des tuples (artifact_type, dictionnaire ou string).
        Ex: yield "prefetch", {"Date": "2023-01-01", "Time": "12:00:00", "Data": "example"}
        """
        pass


class CsvOutputSink:
    """
    Gère l'écriture standardisée dans un fichier CSV.
    Prend les dictionnaires "yieldés" par le parser et les écrit.
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


class JsonlOutputSink:
    """
    Gère l'écriture standardisée dans un fichier JSONL (JSON Lines).
    """
    def __init__(self, output_path: Path):
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
    Gère l'écriture de lignes de texte brut.
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

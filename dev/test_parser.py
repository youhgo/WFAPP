#!/usr/bin/env python3
import sys
import os
import argparse
import importlib
import inspect
from pathlib import Path
from pprint import pprint

# Ensure the root of the project is in PYTHONPATH
project_root = Path(os.path.abspath(__file__)).parent.parent
sys.path.insert(0, str(project_root))

from APPEngine.WAPP_MODULE.classes.BaseParser import BaseParser

def get_all_parsers():
    """Scans the parsers directory and returns a dict mapping parser name to class."""
    parsers_dir = project_root / "APPEngine" / "WAPP_MODULE" / "parsers"
    parsers = {}
    
    for root, _, files in os.walk(parsers_dir):
        for file in files:
            if file.endswith('.py') and not file.startswith('__'):
                file_path = Path(root) / file
                # Calculate module path relative to project root
                rel_path = file_path.relative_to(project_root)
                module_name = str(rel_path.with_suffix('')).replace(os.sep, '.')
                
                try:
                    module = importlib.import_module(module_name)
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, BaseParser) and obj is not BaseParser:
                            parsers[name] = obj
                except (Exception, SystemExit) as e:
                    # Optional debug: print(f"Could not import {module_name}: {e}")
                    pass
                    
    return parsers

def test_parser(parser_class, file_path: Path):
    print(f"[*] Initialisation de {parser_class.__name__}...")
    
    try:
        parser = parser_class(separator="|")
    except TypeError:
        # Fallback if __init__ doesn't accept separator
        try:
            parser = parser_class(None, separator="|")
        except TypeError:
            parser = parser_class()
        
    count = 0
    writers = {}
    import csv
    
    print(f"[*] Parsing de {file_path} ...\n")
    try:
        for artifact_type, record in parser.parse(file_path):
            count += 1
            if artifact_type not in writers:
                print(f"\n--- NOUVEL ARTEFACT DÉTECTÉ : {artifact_type} ---")
                writers[artifact_type] = csv.DictWriter(sys.stdout, fieldnames=record.keys(), delimiter="|")
                writers[artifact_type].writeheader()
                
            writers[artifact_type].writerow(record)
    except Exception as e:
        print(f"[!] Erreur pendant le parsing : {e}")
        import traceback
        traceback.print_exc()
        
    print(f"[*] Terminé. Total records parsés : {count}")

def main():
    available_parsers = get_all_parsers()
    parser_names = list(available_parsers.keys())
    
    if not parser_names:
        print("[!] Aucun parser trouvé héritant de BaseParser.")
        sys.exit(1)
        
    arg_parser = argparse.ArgumentParser(description="Outil de test de développement pour les parsers WAPP")
    arg_parser.add_argument("file", help="Chemin vers le fichier source à tester (ex: .jsonl, .csv)")
    
    arg_parser.add_argument(
        "--parser", 
        required=True,
        choices=parser_names, 
        help=f"Nom de la classe du parser à utiliser."
    )
    
    args = arg_parser.parse_args()
    
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"[!] Erreur : Le fichier {file_path} n'existe pas.")
        sys.exit(1)
        
    selected_class = available_parsers[args.parser]
    test_parser(selected_class, file_path)

if __name__ == "__main__":
    main()

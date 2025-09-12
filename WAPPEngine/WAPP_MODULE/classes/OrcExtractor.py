#!/usr/bin/python3
import os
import csv
import shutil
import argparse
import logging
import traceback
import py7zr
import zipfile
from pathlib import Path


class LoggerManager:
    """Gère la création et l'utilisation de loggers."""

    def __init__(self, logger_name, log_file, level=logging.INFO):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(level)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)

        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            self.logger.addHandler(stream_handler)

    def _generic_log(self, msg, level, header_type, indentation):
        message = f"[{header_type.upper()}] {'  ' * indentation}{msg}"
        if level == "info":
            self.logger.info(message)
        elif level == "warning":
            self.logger.warning(message)
        elif level == "error":
            self.logger.error(message)

    def info(self, msg: str, header: str = "INFO", indentation: int = 0):
        self._generic_log(msg, level="info", header_type=header, indentation=indentation)

    def warning(self, msg: str, header: str = "WARNING", indentation: int = 0):
        self._generic_log(msg, level="warning", header_type=header, indentation=indentation)

    def error(self, msg: str, header: str = "FAILED", indentation: int = 0):
        self._generic_log(msg, level="error", header_type=header, indentation=indentation)

class OrcExtractor:
    """Classe pour extraire les archives .7z et .zip de manière récursive."""

    def __init__(self, logger: LoggerManager, password: str):
        self.logger = logger
        self.password = password

    def _extract_7z(self, archive_path, output_folder):
        """Helper to extract a single .7z archive."""
        try:
            with py7zr.SevenZipFile(archive_path, mode='r', password=self.password) as z:
                z.extractall(path=output_folder)
            self.logger.info(f"Extrait (.7z) : '{archive_path}'", header="SUCCESS", indentation=1)
            return True
        except py7zr.exceptions.PasswordRequired:
            self.logger.error(f"Mot de passe incorrect ou requis pour (.7z) '{archive_path}'", header="ERROR",
                              indentation=1)
        except py7zr.Bad7zFile:
            self.logger.error(f"Fichier invalide ou corrompu (.7z) : '{archive_path}'", header="ERROR", indentation=1)
        except Exception as e:
            self.logger.error(f"Erreur inattendue sur (.7z) '{archive_path}': {e}", header="CRITICAL", indentation=1)
        return False

    def _extract_zip(self, archive_path, output_folder):
        """Helper to extract a single .zip archive."""
        try:
            with zipfile.ZipFile(archive_path, 'r') as z:
                z.extractall(path=output_folder, pwd=self.password.encode('utf-8'))
            self.logger.info(f"Extrait (.zip) : '{archive_path}'", header="SUCCESS", indentation=1)
            return True
        except zipfile.BadZipFile:
            self.logger.error(f"Fichier invalide ou corrompu (.zip) : '{archive_path}'", header="ERROR", indentation=1)
        except RuntimeError as e:
            if "password" in str(e).lower():
                self.logger.error(f"Mot de passe incorrect ou requis pour (.zip) '{archive_path}'", header="ERROR",
                                  indentation=1)
            else:
                self.logger.error(f"Erreur inattendue sur (.zip) '{archive_path}': {e}", header="CRITICAL",
                                  indentation=1)
        except Exception as e:
            self.logger.error(f"Erreur inattendue sur (.zip) '{archive_path}': {e}", header="CRITICAL", indentation=1)
        return False

    def extract_recursively(self, extension, initial_archive_path, output_folder):
        self.logger.info(f"Début de l'extraction récursive de : {initial_archive_path}", header="PROCESS")

        main_archive_path = Path(initial_archive_path)
        initial_extract_path = Path(output_folder) / main_archive_path.stem
        initial_extract_path.mkdir(parents=True, exist_ok=True)

        if extension == '.7z':
            if not self._extract_7z(main_archive_path, initial_extract_path): return False
        elif extension == '.zip':
            if not self._extract_zip(main_archive_path, initial_extract_path): return False
        else:
            self.logger.error(f"Format d'archive initial non supporté : '{main_archive_path.suffix}'", header="ERROR")
            return False

        # Loop as long as new archives (.7z or .zip) are found
        while True:
            nested_archives = list(Path(output_folder).rglob('*.7z')) + list(Path(output_folder).rglob('*.zip'))
            if not nested_archives:
                self.logger.info("Aucune archive imbriquée trouvée. Extraction terminée.", header="INFO")
                break

            self.logger.info(f"{len(nested_archives)} archive(s) imbriquée(s) trouvée(s). Traitement...",
                             header="PROCESS")
            for archive in nested_archives:
                extract_to = archive.with_suffix('')
                extract_to.mkdir(exist_ok=True)

                # Call the correct extractor based on file extension
                if archive.suffix == '.7z':
                    self._extract_7z(archive, extract_to)
                elif archive.suffix == '.zip':
                    self._extract_zip(archive, extract_to)

                # Always remove the archive after attempting to extract it to prevent infinite loops
                try:
                    os.remove(archive)
                except OSError as e:
                    self.logger.error(f"Impossible de supprimer l'archive traitée '{archive}': {e}", header="ERROR",
                                      indentation=1)
        return True

class ArtefactRenamer:
    """Renomme les artefacts sur place en utilisant les fichiers GetThis*.csv."""

    def __init__(self, source_dir, logger: LoggerManager):
        self.source_path = Path(source_dir)
        self.logger = logger
        self.renamed_count = 0
        self.error_count = 0

    def _clean_original_path(self, full_name):
        drive, path_no_drive = os.path.splitdrive(full_name)
        return path_no_drive.lstrip('\\/')

    def _get_unique_filename(self, path: Path) -> Path:
        if not path.exists():
            return path
        parent, stem, suffix = path.parent, path.stem, path.suffix
        counter = 1
        while True:
            new_path = parent / f"{stem}_{counter}{suffix}"
            if not new_path.exists():
                return new_path
            counter += 1

    def run(self):
        self.logger.info(f"Renommage sur place des artefacts dans '{self.source_path}'", header="PROCESS")
        getthis_files = list(self.source_path.rglob('GetThis*.csv'))

        if not getthis_files:
            self.logger.warning("Aucun fichier 'GetThis*.csv' trouvé pour le renommage.", header="SKIP")
            return

        self.logger.info(f"{len(getthis_files)} fichier(s) de métadonnées trouvé(s).")
        for csv_file in getthis_files:
            self.logger.info(f"Lecture de : {csv_file.relative_to(self.source_path)}", indentation=1)
            try:
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if 'SampleName' in row and 'FullName' in row:
                            self._process_row(row, csv_file.parent)
            except Exception as e:
                self.logger.error(f"Impossible de lire le fichier CSV {csv_file}: {e}", indentation=2)
                self.error_count += 1

        self.logger.info("Fin du processus de renommage.", header="SUMMARY")
        self.logger.info(f"{self.renamed_count} fichier(s) renommé(s) avec succès.", indentation=1)
        if self.error_count > 0:
            self.logger.warning(f"{self.error_count} erreur(s) rencontrée(s).", indentation=1)

    def _process_row(self, row, current_dir):
        original_full_name, sample_name = row['FullName'], row['SampleName']
        if not original_full_name or not sample_name: return

        source_filename_to_find = Path(sample_name.replace('\\', '/')).name
        source_file_path = current_dir / source_filename_to_find

        if not source_file_path.is_file():
            found = list(self.source_path.rglob(f"**/{source_filename_to_find}"))
            if not found:
                self.logger.warning(f"Fichier source non trouvé pour SampleName : {sample_name}", indentation=2)
                self.error_count += 1
                return
            source_file_path = found[0]

        cleaned_path = self._clean_original_path(original_full_name)
        original_filename = Path(cleaned_path.replace('\\', '/')).name
        if not original_filename: return

        destination_path = source_file_path.parent / original_filename
        unique_destination_path = self._get_unique_filename(destination_path)

        try:
            shutil.move(str(source_file_path), str(unique_destination_path))
            self.renamed_count += 1
        except Exception as e:
            self.logger.error(
                f"Impossible de renommer '{source_file_path.name}' en '{unique_destination_path.name}': {e}",
                indentation=2)
            self.error_count += 1

class ArtefactRestorer:
    """Reconstruit l'arborescence originale des fichiers collectés."""

    def __init__(self, source_dir, destination_dir, logger: LoggerManager):
        self.source_path = Path(source_dir)
        self.destination_path = Path(destination_dir)
        self.logger = logger
        self.processed_count = 0
        self.error_count = 0

    def _clean_original_path(self, full_name):
        drive, path_no_drive = os.path.splitdrive(full_name)
        return path_no_drive.lstrip('\\/')

    def run(self):
        self.logger.info(f"Restauration depuis '{self.source_path}' vers '{self.destination_path}'", header="PROCESS")
        self.destination_path.mkdir(exist_ok=True)
        getthis_files = list(self.source_path.rglob('GetThis*.csv'))
        if not getthis_files:
            self.logger.warning("Aucun fichier 'GetThis*.csv' trouvé.", header="SKIP")
            return
        self.logger.info(f"{len(getthis_files)} fichier(s) de métadonnées trouvé(s).")
        for csv_file in getthis_files:
            self.logger.info(f"Traitement de : {csv_file.relative_to(self.source_path)}", indentation=1)
            try:
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if 'SampleName' in row and 'FullName' in row:
                            self._process_row(row, csv_file.parent)
            except Exception as e:
                self.logger.error(f"Impossible de lire le fichier CSV {csv_file}: {e}", indentation=2)
                self.error_count += 1
        self.logger.info("Fin du processus de restauration.", header="SUMMARY")
        self.logger.info(f"{self.processed_count} fichier(s) restauré(s) avec succès.", indentation=1)
        if self.error_count > 0:
            self.logger.warning(f"{self.error_count} erreur(s) rencontrée(s).", indentation=1)

    def _process_row(self, row, current_dir):
        original_full_name, sample_name = row['FullName'], row['SampleName']
        if not original_full_name or not sample_name: return
        source_filename_to_find = Path(sample_name.replace('\\', '/')).name
        source_file_path = current_dir / source_filename_to_find
        if not source_file_path.is_file():
            found = list(self.source_path.rglob(f"**/{source_filename_to_find}"))
            if not found:
                self.logger.warning(f"Fichier source non trouvé pour SampleName : {sample_name}", indentation=2)
                self.error_count += 1
                return
            source_file_path = found[0]
        cleaned_full_path = self._clean_original_path(original_full_name)
        path_as_posix = cleaned_full_path.replace('\\', '/')
        original_path_object = Path(path_as_posix)
        destination_folder = self.destination_path / original_path_object.parent
        original_filename = original_path_object.name
        if not original_filename: return
        destination_folder.mkdir(parents=True, exist_ok=True)
        destination_file_path = destination_folder / original_filename
        try:
            shutil.move(str(source_file_path), str(destination_file_path))
            self.processed_count += 1
        except Exception as e:
            self.logger.error(f"Impossible de déplacer '{source_file_path.name}' vers '{destination_file_path}': {e}",
                              indentation=2)
            self.error_count += 1

def parse_args():
    """Parse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Extrait et traite des archives d'artefacts forensiques."
    )
    parser.add_argument('-a', '--archive', required=True,
                        help="Chemin vers l'archive racine (.7z ou .zip) à traiter.")
    parser.add_argument('-d', '--destination', required=True,
                        help="Répertoire de base où les dossiers de travail seront créés.")
    parser.add_argument('-p', '--password', default='infected',
                        help="Mot de passe pour les archives (défaut: 'infected').")
    parser.add_argument('--rename-only', action='store_true',
                        help="Si spécifié, renomme les fichiers extraits sur place et s'arrête.")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()

    Path(args.destination).mkdir(parents=True, exist_ok=True)
    logger = LoggerManager("ArtefactProcessor", os.path.join(args.destination, "runlog.log"))

    extracted_raw_path = os.path.join(args.destination, "extracted_raw")
    restored_path = os.path.join(args.destination, "restored")

    # --- Étape 1: Extraction Récursive ---
    extractor = OrcExtractor(logger, args.password)
    extraction_successful = extractor.extract_recursively(args.archive, extracted_raw_path)

    if not extraction_successful:
        logger.error("Le script est arrêté car l'extraction a échoué.", header="ABORT")
    else:
        # --- Étape 2: Choisir l'action à effectuer ---
        if args.rename_only:
            try:
                renamer = ArtefactRenamer(extracted_raw_path, logger)
                renamer.run()
            except Exception as e:
                logger.error(f"Erreur critique durant le renommage : {e}\n{traceback.format_exc()}", header="CRITICAL")
        else:
            try:
                restorer = ArtefactRestorer(extracted_raw_path, restored_path, logger)
                restorer.run()
            except Exception as e:
                logger.error(f"Erreur critique durant la restauration : {e}\n{traceback.format_exc()}",
                             header="CRITICAL")


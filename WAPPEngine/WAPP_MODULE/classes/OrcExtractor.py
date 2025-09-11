#!/usr/bin/python3
import os
import csv
import shutil
import argparse
import logging
import traceback
import py7zr
from pathlib import Path


# ==============================================================================
# CLASSE DE JOURNALISATION (Logging)
# ==============================================================================
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
        elif level == "debug":
            self.logger.debug(message)

    def info(self, msg: str, header: str = "INFO", indentation: int = 0):
        self._generic_log(msg, level="info", header_type=header, indentation=indentation)

    def warning(self, msg: str, header: str = "WARNING", indentation: int = 0):
        self._generic_log(msg, level="warning", header_type=header, indentation=indentation)

    def error(self, msg: str, header: str = "FAILED", indentation: int = 0):
        self._generic_log(msg, level="error", header_type=header, indentation=indentation)


# ==============================================================================
# CLASSE D'EXTRACTION
# ==============================================================================
class OrcExtractor:
    """Classe pour extraire les archives .7z de manière récursive."""

    def __init__(self, logger, password: str):
        self.logger = logger
        self.password = password

    def _extract_single_archive(self, archive_path, output_folder):
        """Helper function to extract a single archive."""
        try:
            with py7zr.SevenZipFile(archive_path, mode='r', password=self.password) as z:
                z.extractall(path=output_folder)
            self.logger.info(f"Extrait : '{archive_path}'", header="SUCCESS", indentation=1)
            return True
        except py7zr.exceptions.PasswordRequired:
            self.logger.error(f"Mot de passe incorrect ou requis pour '{archive_path}'", header="ERROR", indentation=1)
        except py7zr.Bad7zFile:
            self.logger.error(f"Fichier invalide ou corrompu : '{archive_path}'", header="ERROR", indentation=1)
        except Exception as e:
            self.logger.error(f"Erreur inattendue sur '{archive_path}': {e}", header="CRITICAL", indentation=1)
        return False

    def extract_recursively(self, initial_archive_path, output_folder):
        """Extracts the initial archive and any nested .7z archives found within."""
        self.logger.info(f"Début de l'extraction récursive de : {initial_archive_path}", header="PROCESS")

        # 1. Extraire l'archive principale dans un dossier portant son nom
        main_archive_name = Path(initial_archive_path).stem
        initial_extract_path = Path(output_folder) / main_archive_name
        initial_extract_path.mkdir(parents=True, exist_ok=True)

        if not self._extract_single_archive(initial_archive_path, initial_extract_path):
            return False  # Arrêter si l'archive principale échoue

        # 2. Boucler tant que de nouvelles archives sont trouvées
        while True:
            nested_archives = list(Path(output_folder).rglob('*.7z'))
            if not nested_archives:
                self.logger.info("Aucune archive imbriquée trouvée. Extraction terminée.", header="INFO")
                break

            self.logger.info(f"{len(nested_archives)} archive(s) imbriquée(s) trouvée(s). Traitement...",
                             header="PROCESS")

            for archive in nested_archives:
                # Créer un dossier de destination avec le nom de l'archive (sans extension)
                extract_to = archive.with_suffix('')
                extract_to.mkdir(exist_ok=True)

                # Tenter l'extraction
                self._extract_single_archive(archive, extract_to)

                # TOUJOURS supprimer l'archive après la tentative pour éviter les boucles infinies
                try:
                    os.remove(archive)
                except OSError as e:
                    self.logger.error(f"Impossible de supprimer l'archive traitée '{archive}': {e}", header="ERROR",
                                      indentation=1)

        return True


# ==============================================================================
# CLASSE DE RESTAURATION
# ==============================================================================
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
        original_full_name = row['FullName']
        sample_name = row['SampleName']

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


# ==============================================================================
# EXÉCUTION PRINCIPALE
# ==============================================================================
def parse_args():
    """Parse les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Extrait une archive d'artefacts (.7z) de manière récursive puis reconstruit l'arborescence originale."
    )
    parser.add_argument('-a', '--archive', required=True,
                        help="Chemin vers l'archive .7z racine à traiter.")
    parser.add_argument('-d', '--destination', required=True,
                        help="Répertoire de base où les dossiers 'extracted_raw' et 'restored' seront créés.")
    parser.add_argument('-p', '--password', default='infected',
                        help="Mot de passe pour les archives (défaut: 'infected').")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    Path(args.destination).mkdir(parents=True, exist_ok=True)
    logger = LoggerManager("ArtefactProcessor", os.path.join(args.destination, "runlog.log"))

    extracted_raw_path = os.path.join(args.destination, "extracted_raw")
    restored_path = os.path.join(args.destination, "restored")

    extractor = OrcExtractor(logger, args.password)
    extraction_successful = extractor.extract_recursively(args.archive, extracted_raw_path)

    if extraction_successful:
        try:
            restorer = ArtefactRestorer(extracted_raw_path, restored_path, logger)
            restorer.run()
        except Exception as e:
            logger.error(f"Une erreur critique est survenue durant la restauration : {e}\n{traceback.format_exc()}",
                         header="CRITICAL")
    else:
        logger.error("Le processus de restauration est annulé car l'extraction a échoué.", header="ABORT")


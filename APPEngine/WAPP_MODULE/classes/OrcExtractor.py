#!/usr/bin/python3
import os
import csv
import shutil
import argparse
import logging
import traceback
import py7zr
import zipfile
import hashlib
import re
import subprocess  # Nécessaire pour le fallback 7za
from pathlib import Path


def _clean_long_filename(base_name: str) -> str:
    """
    Applique la logique de nettoyage regex pour les noms de fichiers trop longs.
    C'est la logique que vous avez fournie.
    """
    # Ne pas appliquer cette logique si le nom est déjà valide
    if len(base_name.encode('utf-8')) <= 255:
        return base_name

    # Votre logique de nettoyage
    filename_wo_tail1 = re.sub(r'_\{.*\}.data$', '', base_name)
    filename_wo_tail2 = re.sub(r'\_data$', '', filename_wo_tail1)
    new_base_name = re.sub(r'^(([a-zA-Z]|\d){0,30}_){0,3}', '', filename_wo_tail2)

    # Sécurité: si le regex vide le nom, on garde au moins un hash
    if not new_base_name:
        file_hash = hashlib.md5(base_name.encode('utf-8')).hexdigest()[:8]
        file_ext = Path(base_name).suffix
        new_base_name = f"RENAMED_EMPTY_{file_hash}{file_ext}"

    # Sécurité: si le nom est *encore* trop long, le tronquer
    if len(new_base_name.encode('utf-8')) > 255:
        file_ext = Path(new_base_name).suffix
        # Tronque le nom en gardant l'extension
        new_base_name = new_base_name[:(255 - len(file_ext) - 1)] + file_ext

    return new_base_name


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


class OrcExtractor_legacy:
    """Classe pour extraire les archives .7z et .zip de manière récursive."""

    # Limite de caractères pour un nom de fichier sur la plupart des systèmes Linux
    FILENAME_MAX_LENGTH = 255

    def __init__(self, logger: LoggerManager, password: str):
        self.logger = logger
        self.password = password
        self.renamed_file_counter = 0

    def _extract_7z(self, archive_path, output_folder):
        """
        Helper pour extraire une archive .7z, en gérant les noms de fichiers trop longs
        en utilisant la méthode .read() de py7zr (conforme à la nouvelle documentation).
        """
        try:
            with py7zr.SevenZipFile(archive_path, mode='r', password=self.password) as z:

                try:
                    all_filenames = z.getnames()
                except Exception as e:
                    self.logger.error(f"Impossible de lister les fichiers dans l'archive (getnames échoué): {e}",
                                      header="CRITICAL", indentation=1)
                    return False

                files_to_extract = []
                files_to_read = []  # Fichiers avec des noms trop longs

                for filename in all_filenames:
                    dir_path, base_name = os.path.split(filename)
                    if not base_name:  # C'est un dossier
                        continue

                    if len(base_name.encode('utf-8')) <= self.FILENAME_MAX_LENGTH:
                        files_to_extract.append(filename)
                    else:
                        files_to_read.append(filename)

                # --- CAS 1: NOMS COURTS (Rapide) ---
                if files_to_extract:
                    try:
                        z.extract(targets=files_to_extract, path=output_folder)
                    except Exception as extract_err:
                        self.logger.error(f"Erreur py7zr.extract() sur {len(files_to_extract)} fichiers: {extract_err}",
                                          header="ERROR", indentation=1)

                # --- CAS 2: NOMS TROP LONGS (Robuste, via .read()) ---
                if files_to_read:
                    try:
                        # .read() lit les fichiers ciblés en mémoire
                        # Renvoie un dict: {'nom_fichier': <BytesIO object>}
                        file_data_dict = z.read(targets=files_to_read)

                        for filename_in_archive, file_bytes_io in file_data_dict.items():
                            dir_path, base_name = os.path.split(filename_in_archive)
                            new_base_name = _clean_long_filename(base_name)

                            self.logger.warning(
                                f"Nom de fichier trop long détecté : '{filename_in_archive}'. "
                                f"Renommé en : '{Path(dir_path) / new_base_name}'",
                                header="RENAME", indentation=1)

                            # S'assure que le dossier de destination existe
                            target_file_dir = Path(output_folder) / dir_path
                            target_file_dir.mkdir(parents=True, exist_ok=True)

                            target_file_path = target_file_dir / new_base_name

                            # Gérer les collisions (si le nettoyage produit un doublon)
                            if target_file_path.exists():
                                stem, suffix = target_file_path.stem, target_file_path.suffix
                                counter = 1
                                while True:
                                    new_path = target_file_dir / f"{stem}_{counter}{suffix}"
                                    if not new_path.exists():
                                        target_file_path = new_path
                                        break
                                    counter += 1

                            # Écrire le fichier depuis la mémoire
                            try:
                                with open(target_file_path, 'wb') as f_out:
                                    f_out.write(file_bytes_io.getbuffer())
                            except Exception as write_err:
                                self.logger.error(
                                    f"Impossible d'écrire le fichier renommé '{target_file_path}': {write_err}",
                                    header="ERROR", indentation=1)

                    except Exception as read_err:
                        self.logger.error(f"Erreur py7zr.read() sur {len(files_to_read)} fichiers: {read_err}",
                                          header="CRITICAL", indentation=1)

            self.logger.info(f"Extrait (.7z) : '{archive_path}'", header="SUCCESS", indentation=1)
            return True

        except py7zr.exceptions.PasswordRequired:
            self.logger.error(f"Mot de passe incorrect ou requis pour (.7z) '{archive_path}'", header="ERROR",
                              indentation=1)
        except py7zr.Bad7zFile:
            self.logger.error(f"Fichier invalide ou corrompu (.7z) : '{archive_path}'", header="ERROR", indentation=1)
        except OSError as e:
            # Attrape d'autres erreurs potentielles du système de fichiers
            self.logger.error(f"Erreur OS pendant l'extraction (.7z) '{archive_path}': {e}", header="CRITICAL",
                              indentation=1)
        except Exception as e:
            self.logger.error(f"Erreur inattendue sur (.7z) '{archive_path}': {e}", header="CRITICAL", indentation=1)

        return False

    def _extract_zip(self, archive_path, output_folder):
        """Helper to extract a single .zip archive."""
        # Note: zipfile gère mal les noms longs, une logique similaire à 7z est nécessaire
        try:
            with zipfile.ZipFile(archive_path, 'r') as z:
                all_files = z.infolist()

                for member in all_files:
                    filename = member.filename.replace('\\', '/')  # Normaliser les slashes
                    if not filename:
                        continue

                    # zipfile marque les dossiers avec un / à la fin
                    is_directory = filename.endswith('/')

                    dir_path, base_name = os.path.split(filename)

                    target_dir = Path(output_folder) / dir_path
                    if is_directory:
                        # Si c'est un dossier, le chemin complet est le dossier
                        target_dir = Path(output_folder) / filename

                    target_dir.mkdir(parents=True, exist_ok=True)

                    if is_directory:  # Si c'est un dossier, on a fini
                        continue

                    # Si on est ici, c'est un fichier
                    new_base_name = base_name

                    if len(base_name.encode('utf-8')) > self.FILENAME_MAX_LENGTH:
                        new_base_name = _clean_long_filename(base_name)
                        self.logger.warning(
                            f"Nom de fichier trop long détecté (.zip) : '{filename}'. "
                            f"Renommé en : '{target_dir.relative_to(output_folder) / new_base_name}'",
                            header="RENAME", indentation=1)

                    if not new_base_name:  # Ne devrait pas arriver si ce n'est pas un dossier
                        continue

                    target_file_path = target_dir / new_base_name

                    # Gérer les collisions
                    if target_file_path.exists():
                        stem, suffix = target_file_path.stem, target_file_path.suffix
                        counter = 1
                        while True:
                            new_path = target_dir / f"{stem}_{counter}{suffix}"
                            if not new_path.exists():
                                target_file_path = new_path
                                break
                            counter += 1

                    # Écrire le fichier
                    try:
                        with z.open(member, pwd=self.password.encode('utf-8')) as source:
                            with open(target_file_path, 'wb') as target:
                                shutil.copyfileobj(source, target)
                    except Exception as read_err:
                        self.logger.error(f"Impossible de lire/écrire le fichier zip {filename}: {read_err}",
                                          header="ERROR", indentation=1)

            self.logger.info(f"Extrait (.zip) : '{archive_path}'", header="SUCCESS", indentation=1)
            return True
        except zipfile.BadZipFile:
            self.logger.error(f"Fichier invalide ou corrompu (.zip) : '{archive_path}'", header="ERROR", indentation=1)
        except NotADirectoryError as e:
            # Erreur courante si un nom de fichier est traité comme un dossier
            self.logger.error(f"Erreur de structure de dossier (NotADirectoryError) sur (.zip) '{archive_path}': {e}. "
                              "Cela peut être dû à des noms de fichiers très longs.", header="ERROR", indentation=1)
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


class OrcExtractor:
    """Classe pour extraire les archives .7z et .zip de manière récursive."""

    # Limite de caractères pour un nom de fichier sur la plupart des systèmes Linux
    FILENAME_MAX_LENGTH = 255

    def __init__(self, logger, password: str):
        self.logger = logger
        self.password = password
        self.renamed_file_counter = 0

    def _extract_with_7z_binary(self, archive_path, output_folder):
        """
        Méthode de secours utilisant l'exécutable système 7za ou 7z.
        Utile quand py7zr échoue sur des headers complexes ou corrompus.
        """
        # Cherche 7za (souvent standalone), 7z (full package) ou 7zz (modern 7-zip Linux)
        seven_zip_exe = shutil.which('7za') or shutil.which('7z') or shutil.which('7zz')

        if not seven_zip_exe:
            self.logger.warning(f"Fallback impossible : exécutable '7za', '7z' ou '7zz' non trouvé dans le PATH.",
                                header="WARNING", indentation=1)
            return False

        self.logger.info(f"Tentative d'extraction via binaire système ({seven_zip_exe}) : '{archive_path.name}'",
                         header="FALLBACK", indentation=1)

        # Construction de la commande : x (extract with full paths), -y (yes to all prompts), -o (output)
        # -p{password} si nécessaire
        command = [seven_zip_exe, 'x', str(archive_path), f'-o{output_folder}', '-y']
        if self.password:
            command.append(f'-p{self.password}')
        else:
            command.append('-p')  # Tente sans mot de passe, mais avec switch pour éviter prompt interactif

        try:
            # Capture output pour ne pas polluer la stdout, check returncode ensuite
            # On utilise text=True pour avoir des strings en retour (Python 3.7+)
            result = subprocess.run(command, capture_output=True, text=True)

            # 7-Zip Return Codes: 0=Normal, 1=Warning (Non fatal), 2=Fatal Error
            if result.returncode == 0:
                self.logger.info(f"Extraction binaire réussie : '{archive_path.name}'", header="SUCCESS", indentation=1)
                return True
            elif result.returncode == 1:
                self.logger.warning(f"Extraction binaire réussie avec avertissements : '{archive_path.name}'",
                                    header="WARNING", indentation=1)
                return True
            else:
                # Code 2 ou autre (Erreur Fatale / CRC Failed)
                err_msg = result.stderr.strip() if result.stderr else "Erreur inconnue (voir stdout si vide)"

                # VÉRIFICATION DE ROBUSTESSE :
                # Même si 7z renvoie une erreur (ex: CRC Failed sur un fichier),
                output_path = Path(output_folder)
                has_extracted_files = any(
                    output_path.iterdir()) if output_path.exists() and output_path.is_dir() else False

                if has_extracted_files:
                    self.logger.warning(
                        f"Extraction binaire partielle (Code {result.returncode}) : {err_msg}. "
                        f"Des fichiers ont été extraits malgré l'erreur, on continue.",
                        header="WARNING", indentation=1
                    )
                    return True  # On retourne True pour permettre la suite du process (récursion)
                else:
                    self.logger.error(f"Échec extraction binaire (Code {result.returncode}) : {err_msg}",
                                      header="ERROR", indentation=1)
                    return False

        except Exception as e:
            self.logger.error(f"Erreur lors de l'exécution du fallback 7z : {e}", header="ERROR", indentation=1)
            return False

    def _extract_7z(self, archive_path, output_folder):
        """
        Helper pour extraire une archive .7z.
        Tente d'abord py7zr (natif Python). Si échec ou incomplet, tente 7za (binaire).
        Retourne True si succès complet ou partiel (via l'une des deux méthodes), False sinon.
        """
        extracted_something = False
        py7zr_error_occurred = False

        # --- TENTATIVE 1 : PY7ZR (Natif) ---
        try:
            # Vérification préalable si c'est un fichier valide 7z
            if py7zr.is_7zfile(archive_path):
                with py7zr.SevenZipFile(archive_path, mode='r', password=self.password) as z:
                    try:
                        all_filenames = z.getnames()
                    except Exception as e:
                        self.logger.error(f"py7zr: Impossible de lister les fichiers : {e}", header="ERROR",
                                          indentation=1)
                        py7zr_error_occurred = True
                        all_filenames = []

                    files_to_extract = []
                    files_to_read = []

                    for filename in all_filenames:
                        dir_path, base_name = os.path.split(filename)
                        if not base_name: continue

                        if len(base_name.encode('utf-8')) <= self.FILENAME_MAX_LENGTH:
                            files_to_extract.append(filename)
                        else:
                            files_to_read.append(filename)

                    # Noms courts (standard)
                    if files_to_extract:
                        try:
                            z.extract(targets=files_to_extract, path=output_folder)
                            extracted_something = True
                        except Exception as extract_err:
                            self.logger.error(f"py7zr: Erreur extraction standard : {extract_err}", header="ERROR",
                                              indentation=1)
                            py7zr_error_occurred = True

                    # Noms longs (mémoire)
                    if files_to_read:
                        try:
                            file_data_dict = z.read(targets=files_to_read)
                            for filename_in_archive, file_bytes_io in file_data_dict.items():
                                extracted_something = True
                                dir_path, base_name = os.path.split(filename_in_archive)

                                try:
                                    new_base_name = _clean_long_filename(base_name)
                                except NameError:
                                    new_base_name = base_name[:50] + "_renamed" + Path(base_name).suffix

                                self.logger.warning(f"py7zr: Renommage '{base_name}' -> '{new_base_name}'",
                                                    header="RENAME", indentation=1)
                                target_file_dir = Path(output_folder) / dir_path
                                target_file_dir.mkdir(parents=True, exist_ok=True)
                                target_file_path = target_file_dir / new_base_name

                                if target_file_path.exists():
                                    stem, suffix = target_file_path.stem, target_file_path.suffix
                                    counter = 1
                                    while True:
                                        new_path = target_file_dir / f"{stem}_{counter}{suffix}"
                                        if not new_path.exists():
                                            target_file_path = new_path
                                            break
                                        counter += 1

                                with open(target_file_path, 'wb') as f_out:
                                    f_out.write(file_bytes_io.getbuffer())
                        except Exception as read_err:
                            self.logger.error(f"py7zr: Erreur extraction mémoire : {read_err}", header="ERROR",
                                              indentation=1)
                            py7zr_error_occurred = True
            else:
                self.logger.warning(f"py7zr: Header invalide ou format non reconnu pour '{archive_path.name}'",
                                    header="WARNING", indentation=1)
                py7zr_error_occurred = True

        except py7zr.exceptions.PasswordRequired:
            self.logger.error(f"py7zr: Mot de passe incorrect", header="ERROR", indentation=1)
            py7zr_error_occurred = True
        except py7zr.Bad7zFile:
            self.logger.error(f"py7zr: Fichier corrompu", header="ERROR", indentation=1)
            py7zr_error_occurred = True
        except Exception as e:
            self.logger.error(f"py7zr: Erreur inattendue : {e}", header="ERROR", indentation=1)
            py7zr_error_occurred = True

        # Si py7zr a réussi a tout extraire sans erreur apparente
        if extracted_something and not py7zr_error_occurred:
            self.logger.info(f"Extraction terminée (.7z) : '{archive_path.name}'", header="SUCCESS", indentation=1)
            return True

        # --- TENTATIVE 2 : FALLBACK (Si échec ou partiel) ---
        # Si rien n'a été extrait, OU si une erreur est survenue pendant l'extraction (pour tenter de récupérer le reste)
        if not extracted_something or py7zr_error_occurred:
            if self._extract_with_7z_binary(archive_path, output_folder):
                return True

        # Si on arrive ici : py7zr a échoué (ou rien extrait) ET le fallback a échoué (ou n'est pas dispo)
        if extracted_something:
            # On a extrait des trucs, mais avec erreurs, et le fallback a échoué.
            # On considère "Semi-Succès" pour ne pas bloquer, mais on log fortement.
            self.logger.warning(f"Extraction partielle (.7z) : '{archive_path.name}'. Fallback échoué.",
                                header="WARNING", indentation=1)
            return True

        return False

    def _extract_zip(self, archive_path, output_folder):
        """Helper pour extraire une archive .zip."""
        try:
            if not zipfile.is_zipfile(archive_path):
                self.logger.error(f"Ce n'est pas un zip valide : '{archive_path}'", header="ERROR", indentation=1)
                return False

            with zipfile.ZipFile(archive_path, 'r') as z:
                # Test de l'archive avant extraction (rapide pour détecter corruption header)
                if z.testzip() is not None:
                    self.logger.warning(f"Zip potentiellement corrompu (testzip failed) : '{archive_path}'",
                                        header="WARNING", indentation=1)

                all_files = z.infolist()

                for member in all_files:
                    try:
                        filename = member.filename.replace('\\', '/')
                        if not filename: continue

                        is_directory = filename.endswith('/')
                        dir_path, base_name = os.path.split(filename)
                        target_dir = Path(output_folder) / dir_path

                        if is_directory:
                            target_dir = Path(output_folder) / filename

                        target_dir.mkdir(parents=True, exist_ok=True)

                        if is_directory: continue

                        # Gestion fichier
                        new_base_name = base_name
                        if len(base_name.encode('utf-8')) > self.FILENAME_MAX_LENGTH:
                            try:
                                new_base_name = _clean_long_filename(base_name)
                            except NameError:
                                new_base_name = base_name[:50] + "_renamed" + Path(base_name).suffix

                            self.logger.warning(f"Zip nom long renommé : {new_base_name}", header="RENAME",
                                                indentation=1)

                        target_file_path = target_dir / new_base_name

                        # Collisions
                        if target_file_path.exists():
                            stem, suffix = target_file_path.stem, target_file_path.suffix
                            counter = 1
                            while True:
                                new_path = target_dir / f"{stem}_{counter}{suffix}"
                                if not new_path.exists():
                                    target_file_path = new_path
                                    break
                                counter += 1

                        # Extraction streamée
                        with z.open(member, pwd=self.password.encode('utf-8') if self.password else None) as source:
                            with open(target_file_path, 'wb') as target:
                                shutil.copyfileobj(source, target)

                    except Exception as inner_e:
                        # Une erreur sur UN fichier du zip ne doit pas arrêter tout le zip
                        self.logger.error(f"Erreur sur un fichier du zip ({member.filename}) : {inner_e}",
                                          header="ERROR", indentation=2)
                        continue

            self.logger.info(f"Extraction terminée (.zip) : '{archive_path.name}'", header="SUCCESS", indentation=1)
            return True

        except zipfile.BadZipFile:
            self.logger.error(f"Fichier zip invalide/corrompu : '{archive_path.name}'", header="ERROR", indentation=1)
        except RuntimeError as e:
            if "password" in str(e).lower():
                self.logger.error(f"Mot de passe incorrect (.zip) : '{archive_path.name}'", header="ERROR",
                                  indentation=1)
            else:
                self.logger.error(f"Erreur Runtime zip : {e}", header="ERROR", indentation=1)
        except Exception as e:
            self.logger.error(f"Erreur inattendue zip : {e}", header="CRITICAL", indentation=1)

        return False

    def extract_recursively(self, extension, initial_archive_path, output_folder):
        self.logger.info(f"Début de l'extraction récursive de : {initial_archive_path}", header="PROCESS")

        main_archive_path = Path(initial_archive_path)
        initial_extract_path = Path(output_folder) / main_archive_path.stem
        initial_extract_path.mkdir(parents=True, exist_ok=True)

        # Extraction de l'archive "Mère"
        success_main = False
        if extension == '.7z':
            success_main = self._extract_7z(main_archive_path, initial_extract_path)
        elif extension == '.zip':
            success_main = self._extract_zip(main_archive_path, initial_extract_path)
        else:
            self.logger.error(f"Format non supporté : '{main_archive_path.suffix}'", header="ERROR")
            return False

        if not success_main:
            self.logger.error("L'archive principale n'a pas pu être extraite. Arrêt.", header="STOP")
            return False

        # Boucle sur les archives imbriquées
        loop_counter = 0
        MAX_LOOPS = 100  # Sécurité contre boucles infinies théoriques

        while True:
            loop_counter += 1
            if loop_counter > MAX_LOOPS:
                self.logger.warning("Limite de profondeur de récursion atteinte (100 tours).", header="WARNING")
                break

            # On cherche de nouvelles archives.
            # Note: rglob est dynamique, il trouvera les fichiers extraits au tour précédent.
            nested_7z = list(Path(output_folder).rglob('*.7z'))
            nested_zip = list(Path(output_folder).rglob('*.zip'))

            # Filtrer pour ne pas reprendre celles qu'on a renommées en .corrupted
            # (rglob *.zip ne prend pas *.zip.corrupted, donc c'est ok par défaut,
            # mais on s'assure de ne traiter que des fichiers qui ne sont pas marqués).
            nested_archives = nested_7z + nested_zip

            if not nested_archives:
                self.logger.info("Plus aucune archive imbriquée à traiter.", header="INFO")
                break

            self.logger.info(f"Tour {loop_counter}: {len(nested_archives)} archive(s) trouvée(s).", header="PROCESS")

            for archive in nested_archives:
                # --- BLOC DE ROBUSTESSE ---
                # On isole chaque extraction pour qu'un crash ne stoppe pas la boucle 'for'
                try:
                    extract_to = archive.with_suffix('')
                    extract_to.mkdir(exist_ok=True)

                    extraction_success = False

                    # Appel extraction
                    if archive.suffix == '.7z':
                        extraction_success = self._extract_7z(archive, extract_to)
                    elif archive.suffix == '.zip':
                        extraction_success = self._extract_zip(archive, extract_to)

                    # Gestion post-extraction
                    if extraction_success:
                        # Cas Nominal : On supprime l'archive pour ne pas la re-traiter
                        try:
                            os.remove(archive)
                        except OSError as e:
                            self.logger.error(f"Impossible de supprimer l'archive traitée '{archive.name}': {e}",
                                              header="ERROR", indentation=1)
                            # Si on ne peut pas la supprimer, on force un renommage pour éviter boucle infinie
                            try:
                                archive.rename(archive.with_suffix(archive.suffix + ".processed"))
                            except:
                                pass
                    else:
                        # Cas Échec : On renomme l'archive en .corrupted
                        # Cela permet de conserver le fichier pour analyse manuelle
                        # ET cela l'exclut du prochain rglob('*.zip')
                        self.logger.warning(f"Échec extraction : '{archive.name}'. Renommage en .corrupted",
                                            header="FAIL", indentation=1)
                        try:
                            new_name = archive.with_suffix(archive.suffix + ".corrupted")
                            archive.rename(new_name)
                        except OSError as e:
                            self.logger.error(f"Impossible de renommer l'archive corrompue '{archive.name}': {e}",
                                              header="CRITICAL", indentation=1)

                except Exception as critical_loop_error:
                    # Filet de sécurité ultime pour la boucle for
                    self.logger.error(f"Crash inattendu lors du traitement de '{archive}': {critical_loop_error}",
                                      header="CRITICAL", indentation=1)
                    # Tenter de neutraliser le fichier pour éviter boucle infinie au prochain while
                    try:
                        archive.rename(archive.with_suffix(archive.suffix + ".crashed"))
                    except:
                        pass

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
        self.logger.info(f"Looking for file {sample_name}")
        if not original_full_name or not sample_name: return

        source_filename_to_find = Path(sample_name.replace('\\', '/')).name
        source_file_path = current_dir / source_filename_to_find

        if not source_file_path.is_file():
            found = list(self.source_path.rglob(f"**/{source_filename_to_find}"))
            if not found:
                # RECHERCHE MODIFIÉE:
                # Cherche le fichier "nettoyé" si le nom original est trop long
                cleaned_name_to_find = _clean_long_filename(source_filename_to_find)
                if cleaned_name_to_find == source_filename_to_find:
                    # Le nom n'était pas trop long, donc il est vraiment introuvable
                    self.logger.warning(f"Can't find file in directory: {source_filename_to_find}", indentation=2)
                    self.error_count += 1
                    return

                found_cleaned = list(self.source_path.rglob(f"**/{cleaned_name_to_find}"))
                if not found_cleaned:
                    self.logger.warning(
                        f"Can't find file in directory: {source_filename_to_find} (or as cleaned: {cleaned_name_to_find})",
                        indentation=2)
                    self.error_count += 1
                    return

                source_file_path = found_cleaned[0]
            else:
                source_file_path = found[0]

        self.logger.info(f"Founded file : {sample_name} at {source_file_path}")

        cleaned_path = self._clean_original_path(original_full_name)
        original_filename = Path(cleaned_path.replace('\\', '/')).name

        if not original_filename: return

        destination_path = source_file_path.parent / original_filename
        unique_destination_path = self._get_unique_filename(destination_path)

        try:
            shutil.move(str(source_file_path), str(unique_destination_path))
            self.logger.info(f"renaming  {source_file_path} to {unique_destination_path}")
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
                # RECHERCHE MODIFIÉE:
                # Cherche le fichier "nettoyé" si le nom original est trop long
                cleaned_name_to_find = _clean_long_filename(source_filename_to_find)
                if cleaned_name_to_find == source_filename_to_find:
                    self.logger.warning(f"Fichier source non trouvé pour SampleName : {sample_name}", indentation=2)
                    self.error_count += 1
                    return

                found_cleaned = list(self.source_path.rglob(f"**/{cleaned_name_to_find}"))
                if not found_cleaned:
                    self.logger.warning(
                        f"Fichier source non trouvé pour SampleName : {sample_name} (or as cleaned: {cleaned_name_to_find})",
                        indentation=2)
                    self.error_count += 1
                    return

                source_file_path = found_cleaned[0]
            else:
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

    # Détermine le type d'archive avant de commencer
    archive_path = Path(args.archive)
    if not archive_path.exists():
        print(f"Erreur: Le fichier archive '{args.archive}' n'existe pas.")
        exit(1)

    archive_extension = archive_path.suffix.lower()
    if archive_extension not in ['.7z', '.zip']:
        print(f"Erreur: Format d'archive non supporté '{archive_extension}'.")
        exit(1)

    Path(args.destination).mkdir(parents=True, exist_ok=True)
    logger = LoggerManager("ArtefactProcessor", os.path.join(args.destination, "runlog.log"))

    extracted_raw_path = os.path.join(args.destination, "extracted_raw")
    restored_path = os.path.join(args.destination, "restored")

    # --- Étape 1: Extraction Récursive ---
    try:
        extractor = OrcExtractor(logger, args.password)
        extraction_successful = extractor.extract_recursively(archive_extension, args.archive, extracted_raw_path)
    except Exception as e:
        logger.error(f"Erreur critique durant l'initialisation de l'extraction : {e}\n{traceback.format_exc()}",
                     header="CRITICAL")
        extraction_successful = False

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


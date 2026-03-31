#!/usr/bin/python3
import os
import csv
import shutil
import traceback
import zipfile
import hashlib
import re
import subprocess
from pathlib import Path

try:
    import py7zr

    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False


def _clean_long_filename(base_name: str) -> str:
    """
    Nettoie les noms de fichiers trop longs lors de l'extraction (évite les erreurs OS OSError 206/207).
    Utilise la même logique de Regex robuste que le OrcRenamer.
    """
    # Ne pas appliquer cette logique si le nom est déjà valide (< 255 bytes)
    if len(base_name.encode('utf-8')) <= 255:
        return base_name

    # 1. Nettoyage du suffixe ORC ({GUID}.data)
    filename_clean = re.sub(r'_\{[a-fA-F0-9\-]+\}(?:\.data)?$', '', base_name)
    filename_clean = re.sub(r'\_data$', '', filename_clean)

    # 2. Nettoyage des préfixes ORC (3 ou 4 blocs hexadécimaux/numériques séparés par _)
    filename_clean = re.sub(r'^([A-Fa-f0-9]+_){3,4}', '', filename_clean)

    # Sécurité : si la regex a accidentellement vidé le nom, on génère un nom basé sur le hash
    if not filename_clean:
        file_hash = hashlib.md5(base_name.encode('utf-8')).hexdigest()[:8]
        file_ext = "".join(Path(base_name).suffixes)
        filename_clean = f"RENAMED_EMPTY_{file_hash}{file_ext}"

    # Ultime sécurité : si le nom est *encore* trop long, le tronquer brutalement
    if len(filename_clean.encode('utf-8')) > 255:
        name, ext = os.path.splitext(filename_clean)
        # On garde de la place pour l'extension
        filename_clean = name[:200] + ext

    return filename_clean


class OrcExtractor:
    """
    Classe gérant l'extraction (récursive) des archives DFIR-ORC (.zip, .7z).
    """

    def __init__(self, logger, password=None):
        self.logger = logger
        self.password = password

    def extract_recursively(self, archive_ext, archive_path, dest_dir):
        """
        Extrait l'archive principale, puis cherche et extrait toutes les archives imbriquées.
        """
        self.logger.info(f"[EXTRACTOR] Début de l'extraction principale de {archive_path}", header="START")

        # 1. Extraction de l'archive racine
        success = self._extract_archive(archive_ext, archive_path, dest_dir)
        if not success:
            return False

        # 2. Boucle pour l'extraction récursive des archives imbriquées (créées par ORC)
        archives_to_extract = True
        while archives_to_extract:
            archives_to_extract = False
            for root, dirs, files in os.walk(dest_dir):
                for file in files:
                    if file.endswith('.zip') or file.endswith('.7z'):
                        nested_archive_path = os.path.join(root, file)
                        nested_ext = os.path.splitext(file)[1]

                        self.logger.info(f"[EXTRACTOR] Extraction de l'archive imbriquée: {file}", header="INFO",
                                         indentation=1)

                        if self._extract_archive(nested_ext, nested_archive_path, root):
                            try:
                                os.remove(nested_archive_path)  # Nettoyage après extraction réussie
                            except OSError:
                                pass
                            archives_to_extract = True  # On continue de chercher au cas où l'archive extraite en contenait d'autres

        self.logger.info("[EXTRACTOR] Extraction récursive terminée", header="FINISHED")
        return True

    def _extract_archive(self, ext, archive_path, dest_dir):
        """Méthode interne gérant la logique d'extraction 7z et Zip."""
        Path(dest_dir).mkdir(parents=True, exist_ok=True)

        try:
            if ext == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    if self.password:
                        zip_ref.setpassword(self.password.encode('utf-8'))

                    for member in zip_ref.infolist():
                        # Utilisation de la fonction de nettoyage des noms longs
                        clean_name = _clean_long_filename(os.path.basename(member.filename))
                        member.filename = os.path.join(os.path.dirname(member.filename), clean_name)
                        zip_ref.extract(member, path=dest_dir)
                return True

            elif ext == '.7z':
                if PY7ZR_AVAILABLE:
                    with py7zr.SevenZipFile(archive_path, mode='r', password=self.password) as z:
                        z.extractall(path=dest_dir)
                    return True
                else:
                    # Fallback utilisant l'exécutable système 7za si py7zr n'est pas installé
                    self.logger.warning("[EXTRACTOR] py7zr non disponible, fallback vers 7za (binaire système)",
                                        indentation=1)
                    cmd = ['7za', 'x', archive_path, f'-o{dest_dir}', '-y']
                    if self.password:
                        cmd.append(f'-p{self.password}')
                    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                    return True
        except Exception as e:
            self.logger.error(f"[EXTRACTOR] Échec de l'extraction {archive_path} : {e}", header="ERROR", indentation=1)
            return False


class ArtefactRestorer:
    """
    Si l'utilisateur demande une restauration de l'arborescence (--restore),
    cette classe reconstruit les dossiers d'origine (ex: C:/Windows/System32/...)
    à partir des fichiers de logs GetThis.
    """

    def __init__(self, extracted_dir: str, restored_dir: str, logger):
        self.extracted_dir = Path(extracted_dir)
        self.restored_dir = Path(restored_dir)
        self.logger = logger
        self.mapping = {}

    def build_mapping(self):
        """
        Identique au OrcRenamer : lit tous les GetThis.csv pour mapper
        le nom généré par ORC vers le chemin complet (FullName).
        """
        getthis_files = [f for f in self.extracted_dir.rglob("*.csv") if "GetThis" in f.name]

        for csv_file in getthis_files:
            try:
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        sample_name = row.get("SampleName")
                        full_name = row.get("FullName")

                        if sample_name and full_name:
                            # Extraction cross-platform sécurisée
                            ugly_basename = sample_name.replace('\\', '/').split('/')[-1]

                            # Nettoyage du FullName pour en faire un chemin relatif propre
                            # Transforme "C:\Windows\..." en "C/Windows/..." pour éviter les bugs
                            clean_path = full_name.replace('\\', '/').lstrip('/')
                            clean_path = clean_path.replace(':', '')

                            self.mapping[ugly_basename] = clean_path
            except Exception as e:
                self.logger.error(f"[RESTORER] Erreur lecture {csv_file.name}: {e}", header="ERROR", indentation=1)

    def run(self):
        self.logger.info("[RESTORER] Démarrage de la restauration de l'arborescence (Virtual FileSystem)",
                         header="START")
        self.build_mapping()

        restored_count = 0
        orphans_count = 0

        for file_path in self.extracted_dir.rglob("*"):
            if not file_path.is_file():
                continue

            original_name = file_path.name

            # On ne déplace pas les fichiers d'inventaire
            if original_name.endswith(".csv") and "GetThis" in original_name:
                continue

            if original_name in self.mapping:
                # Récupère le chemin d'origine (ex: C/Windows/System32/winevt/Logs/Security.evtx)
                relative_target = self.mapping[original_name]
                target_path = self.restored_dir / relative_target

                # Création des dossiers parents automatiquement
                target_path.parent.mkdir(parents=True, exist_ok=True)

                # Gestion anti-écrasement
                counter = 1
                base_target = target_path
                while target_path.exists():
                    target_path = base_target.parent / f"{base_target.stem}_{counter}{base_target.suffix}"
                    counter += 1

                try:
                    # On déplace le fichier vers sa place dans l'arborescence restaurée
                    shutil.move(str(file_path), str(target_path))
                    restored_count += 1
                except Exception as e:
                    self.logger.warning(f"[RESTORER] Impossible de déplacer {original_name}: {e}", header="WARNING",
                                        indentation=2)
            else:
                # Fichiers n'apparaissant pas dans GetThis (Orphelins, métadonnées ORC, logs...)
                target_path = self.restored_dir / "ORC_Metadata_Orphans" / original_name
                target_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.move(str(file_path), str(target_path))
                    orphans_count += 1
                except:
                    pass

        # Nettoyage du dossier d'extraction d'origine qui devrait être vide
        try:
            shutil.rmtree(self.extracted_dir)
        except OSError:
            pass

        self.logger.info(
            f"[RESTORER] Terminée. {restored_count} fichiers replacés et {orphans_count} métadonnées sauvegardées.",
            header="FINISHED")
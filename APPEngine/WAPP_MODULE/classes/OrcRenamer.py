import csv
import os
import re
from pathlib import Path

from .WappContext import WappContext


class OrcRenamer:
    """
    Pré-processeur chargé de renommer les artefacts extraits par DFIR-ORC.
    Il utilise en priorité les fichiers 'GetThis*.csv' pour retrouver le nom d'origine exact.
    En cas d'échec, il utilise un fallback basé sur des expressions régulières.
    """

    def __init__(self, context: WappContext):
        self.context = context
        self.logger = context.logger
        self.mapping = {}

    def build_mapping(self, extracted_dir: Path):
        """
        Parcourt l'arborescence à la recherche de tous les fichiers de log GetThis
        (même dans les sous-dossiers) pour construire un dictionnaire global.
        """
        # Recherche robuste de tous les fichiers GetThis dans tous les sous-dossiers
        getthis_files = [f for f in extracted_dir.rglob("*.csv") if "GetThis" in f.name]

        for csv_file in getthis_files:
            try:
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        sample_name = row.get("SampleName")
                        full_name = row.get("FullName")

                        if sample_name and full_name:
                            # CRITIQUE : ORC génère des chemins Windows (\). Si le script tourne sous
                            # Linux/Docker, Path().name ne fonctionnera pas. On force le split manuel.
                            ugly_basename = sample_name.replace('\\', '/').split('/')[-1]
                            clean_basename = full_name.replace('\\', '/').split('/')[-1]

                            # Stockage dans le mapping
                            self.mapping[ugly_basename] = clean_basename
            except Exception as e:
                self.logger.error(f"[RENAMER] Erreur lors de la lecture de {csv_file.name}: {e}", header="ERROR",
                                  indentation=1)

    def rename_files(self, extracted_dir: Path):
        """
        Parcourt tous les fichiers extraits et les renomme si une correspondance est trouvée.
        """
        self.logger.info("[RENAMER] Démarrage du renommage intelligent des artefacts ORC", header="START")

        # 1. Construction du mapping de vérité
        self.build_mapping(extracted_dir)
        self.logger.info(f"[RENAMER] {len(self.mapping)} correspondances exactes trouvées dans les logs GetThis",
                         header="INFO", indentation=1)

        renamed_count = 0

        # 2. Parcours unique de l'arborescence (O(N))
        for file_path in extracted_dir.rglob("*"):
            if not file_path.is_file():
                continue

            original_name = file_path.name
            new_name = original_name

            # On ignore les fichiers systèmes générés par ORC
            if original_name.endswith(".csv") and "GetThis" in original_name:
                continue

            # Tentative 1 : Correspondance exacte via GetThis.csv
            if original_name in self.mapping:
                new_name = self.mapping[original_name]
            else:
                # Tentative 2 : Fallback avec les Regex
                new_name = self._clean_regex(original_name)

            # Si le nom a changé, on renomme le fichier sur le disque
            if new_name and new_name != original_name:
                new_path = file_path.parent / new_name

                # Gestion des collisions (plusieurs fichiers avec le même nom final)
                counter = 1
                while new_path.exists() and new_path != file_path:
                    new_path = file_path.parent / f"{Path(new_name).stem}_{counter}{Path(new_name).suffix}"
                    counter += 1

                try:
                    file_path.rename(new_path)
                    renamed_count += 1
                except Exception as e:
                    self.logger.warning(f"[RENAMER] Impossible de renommer {original_name} en {new_name} : {e}",
                                        header="WARNING", indentation=2)

        self.logger.info(f"[RENAMER] Renommage terminé. {renamed_count} fichiers renommés proprement.",
                         header="FINISHED")

    def _clean_regex(self, filename: str) -> str:
        """
        Fallback Regex amélioré pour nettoyer les noms si GetThis.csv est manquant.
        Gère le pattern ORC: VolumeID_ParentFRN_FRN_AttributeID_OriginalName_{GUID}.data
        """
        l_file_to_preserve = ["USNInfo", "NTFSInfo", "GetThis"]

        for f in l_file_to_preserve:
            if f in filename:
                return filename

        # 1. Nettoyage du suffixe ORC ({GUID}.data)
        filename_clean = re.sub(r'_\{[a-fA-F0-9\-]+\}(?:\.data)?$', '', filename)
        filename_clean = re.sub(r'\_data$', '', filename_clean)

        # 2. Nettoyage des préfixes ORC (3 ou 4 blocs hexadécimaux/numériques séparés par _)
        # Ex: BEB0FD2161F2A88F_1000000000D33_80000000105C1_4_
        filename_clean = re.sub(r'^([A-Fa-f0-9]+_){3,4}', '', filename_clean)

        return filename_clean if filename_clean else filename
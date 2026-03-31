import re
import shutil
from pathlib import Path
import traceback

# Importe le contexte depuis le même dossier pour le typage
from .WappContext import WappContext


class BaseArtefactPipeline:
    """Classe de base pour tous les pipelines d'artefacts."""

    def __init__(self, context: WappContext):
        self.context = context
        self.logger = context.logger

    def get_regex_patterns(self) -> list:
        return []

    def can_process(self, file_path: Path) -> bool:
        patterns = self.get_regex_patterns()
        for pattern in patterns:
            if re.search(pattern, file_path.name, re.IGNORECASE):
                return True
        return False

    def process(self, file_path: Path):
        raise NotImplementedError

    def copy_raw_artefact(self, file_path: Path, out_dir):
        """
        Fonction utilitaire pour copier l'artefact brut dans un dossier centralisé.
        Tous les pipelines peuvent l'appeler pour sauvegarder le fichier source.
        """
        #out_dir = self.context.parsed_dir  / end_folder
        out_dir.mkdir(parents=True, exist_ok=True)

        dest_file = out_dir / file_path.name

        # Gestion des collisions (plusieurs fichiers avec le même nom final)
        counter = 1
        while dest_file.exists():
            if dest_file.stat().st_size == file_path.stat().st_size:
                return  # Fichier identique (doublon parfait) déjà présent
            dest_file = out_dir / f"{file_path.stem}_{counter}{file_path.suffix}"
            counter += 1

        try:
            shutil.copy2(file_path, dest_file)
            self.logger.info(f"[PIPELINE][COPY] {file_path.name} copié.", header="INFO",
                             indentation=2)
        except Exception as e:
            self.logger.error(f"[PIPELINE][COPY] Erreur copie de {file_path.name}: {traceback.format_exc()}", header="ERROR", indentation=1)

    def finalize(self):
        """Appelé une fois que tous les fichiers ont été parcourus."""
        pass
import subprocess
import os
import re
from pathlib import Path

from ..classes.BaseArtefactPipelines import BaseArtefactPipeline
from ..classes.WappContext import WappContext
from ..parsers import DiskParser


class MftPipeline(BaseArtefactPipeline):
    def __init__(self, context: WappContext):
        super().__init__(context)
        self.mft_dir = self.context.parsed_dir / "disk"
        self.mft_dir.mkdir(parents=True, exist_ok=True)
        self.parser = DiskParser.DiskParser(self.logger, separator=self.context.separator)
        self.config_process = self.context.artefact_config.get("artefacts", {}).get("master_file_table", {})

    def get_regex_patterns(self):
        patterns = []
        for v in self.config_process.values():
            patterns.extend(v if isinstance(v, list) else [v])
        return patterns

    def _matches_category(self, file_name, category_key):
        patterns = self.config_process.get(category_key, [])
        for p in patterns:
            if re.search(p, file_name, re.IGNORECASE):
                return True
        return False

    def clean_forensic_name(self, filename):
        # Capture ce qui est après le $ et transforme en "nom_file" en minuscules
        # Exemple : ._$MFT -> mft_file
        pattern = r'^\._\$(.*)$'
        match = re.match(pattern, filename)

        if match:
            name_part = match.group(1).lower()
            return f"{name_part}_file"

        return filename

    def rename_on_disk(self, file_path: Path) -> Path:
        """
        Renomme physiquement le fichier sur le disque si son nom contient des caractères spéciaux.
        Retourne le nouvel objet Path mis à jour.
        """
        new_name = self.clean_forensic_name(file_path.name)

        # Si le nom n'a pas besoin de nettoyage, on retourne le chemin original
        if new_name == file_path.name:
            return file_path

        new_path = file_path.with_name(new_name)

        try:
            # Gestion de collision : si le fichier cible existe déjà, on le supprime
            if new_path.exists():
                new_path.unlink()

            file_path.rename(new_path)
            self.logger.info(f"[PIPELINE][MFT] Renommage disque : {file_path.name} -> {new_name}", indentation=2)
            return new_path
        except Exception as e:
            self.logger.error(f"[PIPELINE][MFT] Impossible de renommer sur disque : {e}", indentation=2)
            # En cas d'échec du renommage, on continue avec l'ancien chemin pour tenter le parsing quand même
            return file_path

    def process(self, file_path: Path):
        try:
            # 1. Renommage physique du fichier source avant tout traitement
            file_path = self.rename_on_disk(file_path)

            # 2. Utilisation du nom nettoyé pour les logs et les fichiers de sortie
            clean_mft_name = file_path.name

            self.logger.info(f"[PIPELINE][MFT] Traitement de {clean_mft_name}", header="START", indentation=1)

            mft_result_file = self.mft_dir / f"{clean_mft_name}.timeline"
            self.context.wazuh_importer_file_config["files"].append({
                "path": str(mft_result_file),
                "type": "mft_timeline"
            })

            # 3. Utilisation de l'outil externe avec le NOUVEAU chemin (file_path a été mis à jour)
            my_cmd = [
                "python3", str(self.context.analyze_mft_tool_path),
                "-f", str(file_path),
                "-o", str(mft_result_file),
                "--timeline"
            ]

            # Exécution de l'outil
            subprocess.run(my_cmd, stderr=subprocess.DEVNULL, check=True)

            # 4. Parsing final en CSV
            res_file = self.parser.parse_plaso_csv(str(mft_result_file), str(self.context.result_parsed_dir))

            self.logger.info(f"[PIPELINE][MFT] Succès", header="FINISHED", indentation=1)

        except subprocess.CalledProcessError as e:
            self.logger.error(f"[PIPELINE][MFT] L'outil externe a échoué pour {file_path.name}", header="ERROR",
                              indentation=1)
        except Exception as e:
            self.logger.error(f"[PIPELINE][MFT] Erreur sur {file_path.name}: {e}", header="ERROR", indentation=1)
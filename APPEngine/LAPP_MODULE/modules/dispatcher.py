import importlib
import inspect
from pathlib import Path
from typing import List, Dict

from ..classes.LappContext import LappContext
from ..classes.BaseArtefactPipelines import BaseArtefactPipeline


class ArtefactDispatcher:
    """Le Routeur qui inspecte les fichiers et les distribue aux pipelines."""

    def __init__(self, context: LappContext) -> None:
        self.context = context
        self.pipelines: List[BaseArtefactPipeline] = []

        # Chargement dynamique de TOUS les pipelines
        self._load_dynamic_pipelines()

    def _load_dynamic_pipelines(self) -> None:
        """Parcourt le dossier courant et charge tous les pipelines valides."""
        cfg = self.context.main_config
        modules_dir = Path(__file__).parent

        # Mapping : Relie le nom du fichier Python à la clé de ta configuration JSON
        config_mapping: Dict[str, str] = {
            "bodyfile_pipeline": "bodyfile"
        }

        self.context.logger.info("[DISPATCHER] Chargement dynamique des modules en cours...", header="INFO")

        # Parcourt tous les fichiers .py (idéalement, on filtre directement ceux qui finissent par _pipeline)
        for file_path in modules_dir.glob("*.py"):
            module_name = file_path.stem

            if module_name in ["__init__", "dispatcher", "legacy_pipeline"]:
                continue

            config_key = config_mapping.get(module_name)

            # Si le module est listé mais désactivé dans la config, on l'ignore
            if config_key and not cfg.get(config_key, False):
                self.context.logger.info(f"[DISPATCHER] Pipeline ignoré (désactivé via config) : {module_name}")
                continue

            try:
                module = importlib.import_module(f".{module_name}", package=__package__)

                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, BaseArtefactPipeline) and
                            obj is not BaseArtefactPipeline and
                            obj.__module__ == module.__name__):
                        self.pipelines.append(obj(self.context))
                        self.context.logger.info(f" -> Pipeline chargé avec succès : {name}", header="INFO",
                                                 indentation=1)

            except Exception as e:
                self.context.logger.error(f"Erreur critique au chargement du module {module_name}: {e}", header="ERROR",
                                          indentation=1)

    def run_discovery(self, extracted_dir: Path) -> None:
        self.context.logger.info("[DISPATCHER] Lancement du routage (Single Pass)", header="START")

        for file_path in extracted_dir.rglob("*"):
            if file_path.is_file():
                for pipeline in self.pipelines:
                    if pipeline.can_process(file_path):
                        pipeline.process(file_path)

        self.context.logger.info("[DISPATCHER] Routage terminé. Lancement des finalisations...", header="INFO")

        # Sécurisation : on isole les finalisations pour qu'un crash n'impacte pas les autres
        for pipeline in self.pipelines:
            try:
                pipeline.finalize()
            except Exception as e:
                self.context.logger.error(
                    f"[DISPATCHER] Erreur lors de la finalisation du pipeline {pipeline.__class__.__name__} : {e}",
                    header="ERROR",
                    indentation=1
                )
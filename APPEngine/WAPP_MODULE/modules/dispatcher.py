import importlib
import inspect
from pathlib import Path
from typing import List, Dict

from ..classes.WappContext import WappContext
from ..classes.BaseArtefactPipelines import BaseArtefactPipeline


class ArtefactDispatcher:
    """Le Routeur qui inspecte les fichiers et les distribue aux pipelines."""

    def __init__(self, context: WappContext) -> None:
        self.context = context
        self.pipelines: List[BaseArtefactPipeline] = []

        # Chargement dynamique de TOUS les pipelines
        self._load_dynamic_pipelines()

    def _load_dynamic_pipelines(self) -> None:
        """Parcourt le dossier courant et charge tous les pipelines depuis le registre."""
        cfg = self.context.config.get("pipelines", {})
        modules_dir = Path(__file__).parent

        from ..classes.Registry import PIPELINE_REGISTRY

        self.context.logger.info("[DISPATCHER] Chargement dynamique des modules en cours...", header="INFO")

        # Importer tous les modules pour déclencher les décorateurs @register_pipeline
        for file_path in modules_dir.glob("*.py"):
            module_name = file_path.stem

            if module_name in ["__init__", "dispatcher", "legacy_pipeline"]:
                continue

            try:
                importlib.import_module(f".{module_name}", package=__package__)
            except Exception as e:
                self.context.logger.error(f"Erreur critique à l'import du module {module_name}: {e}", header="ERROR", indentation=1)

        # Maintenant que tout est importé, on instancie les pipelines autorisés par la config
        for config_key, pipeline_class in PIPELINE_REGISTRY.items():
            pipeline_cfg = cfg.get(config_key, {})
            is_enabled = pipeline_cfg.get("enabled", True)  # PLUG & PLAY: Enabled by default!
            
            if not is_enabled:
                self.context.logger.info(f"[DISPATCHER] Pipeline ignoré (désactivé via config) : {config_key}")
                continue
                
            try:
                self.pipelines.append(pipeline_class(self.context))
                self.context.logger.info(f" -> Pipeline chargé avec succès : {pipeline_class.__name__} (clé: {config_key})", header="INFO", indentation=1)
            except Exception as e:
                self.context.logger.error(f"Erreur d'instanciation du pipeline {pipeline_class.__name__}: {e}", header="ERROR", indentation=1)

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
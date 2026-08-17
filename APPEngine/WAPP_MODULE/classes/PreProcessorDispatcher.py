import importlib
from pathlib import Path
from typing import List

from .WappContext import WappContext
from .BasePreProcessor import BasePreProcessor


class PreProcessorDispatcher:
    """Router that manages the execution of pre-processors before analysis."""

    def __init__(self, context: WappContext) -> None:
        self.context = context
        self.preprocessors: List[BasePreProcessor] = []

        self._load_dynamic_preprocessors()

    def _load_dynamic_preprocessors(self) -> None:
        """Scans the current folder and loads all pre-processors from the registry."""
        cfg = self.context.main_config
        modules_dir = Path(__file__).parent.parent / "preprocessors"

        from .Registry import PREPROCESSOR_REGISTRY

        self.context.logger.info("[DISPATCHER] Dynamic loading of pre-processors in progress...", header="INFO")

        # Import all modules to trigger @register_preprocessor decorators
        if modules_dir.exists():
            for file_path in modules_dir.glob("*.py"):
                module_name = file_path.stem

                if module_name == "__init__":
                    continue

                try:
                    # Relative import from current package
                    importlib.import_module(f"..preprocessors.{module_name}", package=__package__)
                except Exception as e:
                    self.context.logger.error(f"Critical error importing module {module_name}: {e}", header="ERROR", indentation=1)

        # Instantiate pre-processors authorized by config
        for config_key, processor_class in PREPROCESSOR_REGISTRY.items():
            default_state = getattr(processor_class, 'default_enabled', False)
            is_enabled = bool(cfg.get(config_key, default_state))
            
            if not is_enabled:
                self.context.logger.info(f"[DISPATCHER] Pre-processor ignored (disabled): {config_key}")
                continue
                
            try:
                self.preprocessors.append(processor_class(self.context))
                self.context.logger.info(f" -> Pre-processor loaded: {processor_class.__name__} (key: {config_key})", header="INFO", indentation=1)
            except Exception as e:
                self.context.logger.error(f"Error instantiating pre-processor {processor_class.__name__}: {e}", header="ERROR", indentation=1)
        
        # Tri basé sur les dépendances (requires) et la priorité (priority)
        self._sort_preprocessors()

    def _sort_preprocessors(self):
        """Trie les pré-processeurs par priorité et résout les dépendances."""
        # D'abord par priorité
        self.preprocessors.sort(key=lambda p: p.priority)
        
        # Simple dependency check (requires)
        loaded_keys = [p.__class__.__preprocessor_name__ for p in self.preprocessors]
        for p in self.preprocessors:
            for req in getattr(p, 'requires', []):
                if req not in loaded_keys:
                    self.context.logger.warning(
                        f"[DISPATCHER] Warning: Pre-processor {p.__class__.__preprocessor_name__} "
                        f"requires '{req}', but it is not enabled/loaded."
                    )

    def run(self) -> None:
        self.context.logger.info("[DISPATCHER] Launching pre-processors", header="START")

        for processor in self.preprocessors:
            self.context.logger.info(f"[DISPATCHER] Executing {processor.__class__.__name__}", header="INFO")
            try:
                processor.run()
            except Exception as e:
                import traceback
                self.context.logger.error(
                    f"[DISPATCHER] Error executing {processor.__class__.__name__}: {e}\n{traceback.format_exc()}",
                    header="ERROR",
                    indentation=1
                )
                # Should we raise the exception so the whole process aborts?
                # For pre-processing like extraction, failure is usually fatal.
                # However, for restore/rename it might not be. We will raise it to stop if it's extraction.
                if processor.__class__.__preprocessor_name__ == 'extract':
                    raise e

        self.context.logger.info("[DISPATCHER] Pre-processors completed.", header="FINISHED")

import importlib
from pathlib import Path
from typing import List

from .WappContext import WappContext
from .BasePostProcessor import BasePostProcessor


class PostProcessorDispatcher:
    """Router that manages the execution of post-processors after analysis."""

    def __init__(self, context: WappContext) -> None:
        self.context = context
        self.postprocessors: List[BasePostProcessor] = []

        self._load_dynamic_postprocessors()

    def _load_dynamic_postprocessors(self) -> None:
        """Scans the current folder and loads all post-processors from the registry."""
        cfg = self.context.main_config
        modules_dir = Path(__file__).parent.parent / "postprocessors"

        from .Registry import POSTPROCESSOR_REGISTRY

        self.context.logger.info("[DISPATCHER] Dynamic loading of post-processors in progress...", header="INFO")

        # Import all modules to trigger @register_postprocessor decorators
        if modules_dir.exists():
            for file_path in modules_dir.glob("*.py"):
                module_name = file_path.stem

                if module_name == "__init__":
                    continue

                try:
                    # Relative import from current package
                    importlib.import_module(f"..postprocessors.{module_name}", package=__package__)
                except Exception as e:
                    self.context.logger.error(f"Critical error importing module {module_name}: {e}", header="ERROR", indentation=1)

        # Instantiate post-processors authorized by config
        for config_key, processor_class in POSTPROCESSOR_REGISTRY.items():
            # For post-processors, the config is often just a boolean or 1/0 at the root of main_config, or in a sub-dict.
            # In api_parse, we send { 'elk': 1, 'plaso': 1, ... }
            default_state = getattr(processor_class, 'default_enabled', False)
            is_enabled = bool(cfg.get(config_key, default_state))
            
            if not is_enabled:
                self.context.logger.info(f"[DISPATCHER] Post-processor ignored (disabled): {config_key}")
                continue
                
            try:
                self.postprocessors.append(processor_class(self.context))
                self.context.logger.info(f" -> Post-processor loaded: {processor_class.__name__} (key: {config_key})", header="INFO", indentation=1)
            except Exception as e:
                self.context.logger.error(f"Error instantiating post-processor {processor_class.__name__}: {e}", header="ERROR", indentation=1)
        
        # Sort based on dependencies (requires) and priority
        self._sort_postprocessors()

    def _sort_postprocessors(self):
        """Sorts post-processors by priority and resolves dependencies."""
        # Simple topological sort or by priority.
        # First by priority
        self.postprocessors.sort(key=lambda p: p.priority)
        
        # Simple dependency check (requires)
        loaded_keys = [p.__class__.__postprocessor_name__ for p in self.postprocessors]
        for p in self.postprocessors:
            for req in getattr(p, 'requires', []):
                if req not in loaded_keys:
                    self.context.logger.warning(
                        f"[DISPATCHER] Warning: Post-processor {p.__class__.__postprocessor_name__} "
                        f"requires '{req}', but it is not enabled/loaded."
                    )

    def run(self) -> None:
        self.context.logger.info("[DISPATCHER] Launching post-processors", header="START")

        for processor in self.postprocessors:
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

        self.context.logger.info("[DISPATCHER] Post-processors completed.", header="FINISHED")

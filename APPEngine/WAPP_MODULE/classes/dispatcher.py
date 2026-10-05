import importlib
import inspect
from pathlib import Path
from typing import List, Dict

from .WappContext import WappContext
from .BaseArtefactPipelines import BaseArtefactPipeline


class ArtefactDispatcher:
    """Router that inspects files and distributes them to pipelines."""

    def __init__(self, context: WappContext) -> None:
        self.context = context
        self.pipelines: List[BaseArtefactPipeline] = []

        # Dynamic loading of ALL pipelines
        self._load_dynamic_pipelines()

    def _load_dynamic_pipelines(self) -> None:
        """Scans the current folder and loads all pipelines from the registry."""
        cfg = self.context.config.get("pipelines", {})
        modules_dir = Path(__file__).parent.parent / "modules"

        from .Registry import PIPELINE_REGISTRY

        self.context.logger.info("[DISPATCHER] Dynamic loading of modules in progress...", header="INFO")

        # Import all modules to trigger @register_pipeline decorators
        for file_path in modules_dir.rglob("*.py"):
            module_name = file_path.stem

            if module_name in ["__init__", "dispatcher", "legacy_pipeline"]:
                continue

            try:
                # Get the path relative to WAPP_MODULE and format for import
                rel_path = file_path.relative_to(modules_dir.parent).with_suffix('')
                import_str = ".." + ".".join(rel_path.parts)
                importlib.import_module(import_str, package=__package__)
            except Exception as e:
                self.context.logger.error(f"Critical error importing module {module_name}: {e}", header="ERROR", indentation=1)

        # Now that everything is imported, instantiate pipelines authorized by config
        for config_key, pipeline_class in PIPELINE_REGISTRY.items():
            if config_key in self.context.config and not isinstance(self.context.config[config_key], dict):
                raw_val = self.context.config[config_key]
                if isinstance(raw_val, str):
                    is_enabled = str(raw_val).strip().lower() not in ['0', 'false', '']
                else:
                    is_enabled = bool(raw_val)
            else:
                pipeline_cfg = self.context.config.get(config_key, {})
                raw_val = pipeline_cfg.get("enabled", True)
                if isinstance(raw_val, str):
                    is_enabled = str(raw_val).strip().lower() not in ['0', 'false', '']
                else:
                    is_enabled = bool(raw_val)
            
            if not is_enabled:
                self.context.logger.info(f"[DISPATCHER] Pipeline ignored (disabled via config): {config_key}")
                continue
                
            try:
                self.pipelines.append(pipeline_class(self.context))
                self.context.logger.info(f" -> Pipeline loaded successfully: {pipeline_class.__name__} (key: {config_key})", header="INFO", indentation=1)
            except Exception as e:
                self.context.logger.error(f"Error instantiating pipeline {pipeline_class.__name__}: {e}", header="ERROR", indentation=1)

    def run_discovery(self, extracted_dir: Path) -> None:
        self.context.logger.info("[DISPATCHER] Starting routing (Parallel Pass)", header="START")
        
        import concurrent.futures

        processed_files = []
        unprocessed_files = []

        directories_to_scan = [extracted_dir]
        ogre_dir = self.context.parsed_dir / "ogre"
        if ogre_dir.exists():
            directories_to_scan.append(ogre_dir)

        # 1. Discovery Phase (Map files to pipelines)
        pipeline_tasks = {pipeline: [] for pipeline in self.pipelines}
        
        for directory in directories_to_scan:
            for file_path in directory.rglob("*"):
                if file_path.is_file():
                    is_processed = False
                    for pipeline in self.pipelines:
                        if pipeline.can_process(file_path):
                            pipeline_tasks[pipeline].append(file_path)
                            is_processed = True
                            
                    if is_processed:
                        processed_files.append(str(file_path))
                    else:
                        unprocessed_files.append(str(file_path))

        # 2. Parallel Processing Phase
        def process_pipeline(pipeline, files):
            for f in files:
                pipeline.process(f)

        active_pipelines = {p: files for p, files in pipeline_tasks.items() if files}
        
        if active_pipelines:
            self.context.logger.info(f"[DISPATCHER] Running {len(active_pipelines)} pipelines in parallel...", header="INFO")
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(active_pipelines))) as executor:
                futures = [
                    executor.submit(process_pipeline, pipeline, files) 
                    for pipeline, files in active_pipelines.items()
                ]
                concurrent.futures.wait(futures)

        self.context.logger.info("[DISPATCHER] Processing completed. Starting finalizations...", header="INFO")

        # Write log files to orcLogs directory
        orc_logs_dir = self.context.parsed_dir / "orcLogs"
        orc_logs_dir.mkdir(parents=True, exist_ok=True)
        
        with open(orc_logs_dir / "processed_files.log", "w", encoding="utf-8") as f:
            for p in sorted(processed_files):
                f.write(f"{p}\n")
                
        with open(orc_logs_dir / "unprocessed_files.log", "w", encoding="utf-8") as f:
            for p in sorted(unprocessed_files):
                f.write(f"{p}\n")

        # Security: isolate finalizations so a crash doesn't impact others
        for pipeline in self.pipelines:
            try:
                pipeline.finalize()
            except Exception as e:
                self.context.logger.error(
                    f"[DISPATCHER] Error during finalization of pipeline {pipeline.__class__.__name__}: {e}",
                    header="ERROR",
                    indentation=1
                )
import os
import subprocess
from pathlib import Path
from ..classes.BasePreProcessor import BasePreProcessor
from ..classes.Registry import register_preprocessor

@register_preprocessor('ogre_preprocessor')
class OgrePreProcessor(BasePreProcessor):
    """
    Runs DFIR-Ogre before extraction.
    """
    recommended = True
    importance = "Mandatory"
    speed = "Slow"
    priority = -1  # Runs before ExtractPreProcessor (which is 0)
    requires = []
    default_enabled = True
    hidden = False

    def run(self) -> None:
        if not getattr(self.context, 'is_orc', True):
            self.logger.info("[OGRE] Skipping DFIR-Ogre (is_orc is False)", header="INFO")
            return

        self.logger.info("[OGRE] Launching DFIR-Ogre", header="START")
        try:
            archive_path = str(self.context.path_to_archive)
            case_name = str(self.context.case_name)
            parsed_dir = str(self.context.parsed_dir)
            
            # Use the custom configuration file from the config directory
            wapp_module_dir = Path(__file__).parent.parent
            config_path = wapp_module_dir / "config" / "ogre.yaml"
            
            if not config_path.exists():
                self.logger.warning(f"[OGRE] Configuration file not found at {config_path}.")
            
            cmd = [
                "dfir-ogre",
                "orc",
                "--archive", archive_path,
                "--case", case_name,
                "--configuration", str(config_path)
            ]
            
            self.logger.info(f"[OGRE] Executing: {' '.join(cmd)}", header="INFO")
            
            # Execute in the parsed directory (self.parsed_dir) and stream output in real-time
            process = subprocess.Popen(
                cmd, 
                cwd=parsed_dir, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                bufsize=1
            )
            
            for line in process.stdout:
                print(line, end="", flush=True)
                
            process.wait()
            
            if process.returncode != 0:
                self.logger.error(f"[OGRE] Execution failed with code {process.returncode}", header="ERROR")
            else:
                self.logger.info("[OGRE] Execution completed successfully.", header="INFO")
                
        except Exception as e:
            self.logger.error(f"[OGRE] Error: {e}", header="ERROR")
            raise e
            
        self.logger.info("[OGRE] Launching DFIR-Ogre", header="FINISHED")

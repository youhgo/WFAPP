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
    speed = "Fast"
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
            
            custom_yaml_content = getattr(self.context, 'artefact_config', {}).get('custom_ogre_yaml_content')
            if custom_yaml_content:
                try:
                    import re
                    # Read default config to extract the mandatory output block
                    with open(config_path, 'r', encoding='utf-8') as f:
                        default_content = f.read()
                        
                    # Extract output block up to mapping:
                    output_block_match = re.search(r'^output:.*?^(?=mapping:)', default_content, re.MULTILINE | re.DOTALL)
                    if output_block_match:
                        output_str = output_block_match.group(0)
                        
                        # Remove any existing output block in custom yaml
                        custom_yaml_content = re.sub(r'^output:.*?^(?=mapping:)', '', custom_yaml_content, flags=re.MULTILINE | re.DOTALL)
                        
                        # Strip other mandatory root keys from custom yaml
                        custom_yaml_content = re.sub(r'^(output_folder|report_folder|temp_folder):.*$\n?', '', custom_yaml_content, flags=re.MULTILINE)
                        
                        # Inject default folders and output block before mapping:
                        folders_str = (
                            "output_folder: ./ogre\n"
                            "report_folder: ./ogre/ogre_execution_reports\n"
                            "temp_folder: ./ogre/tmp_ogre\n\n"
                        )
                        
                        if 'mapping:' in custom_yaml_content:
                            custom_yaml_content = custom_yaml_content.replace('mapping:', folders_str + output_str + 'mapping:')
                        else:
                            # Fallback if mapping: is not found in custom config
                            custom_yaml_content = folders_str + output_str + custom_yaml_content
                            
                        # Save the custom config in the parsed directory so dfir-ogre can use it
                        custom_config_path = Path(parsed_dir) / 'custom_ogre.yaml'
                        with open(custom_config_path, 'w', encoding='utf-8') as f:
                            f.write(custom_yaml_content)
                            
                        config_path = custom_config_path
                        self.logger.info(f"[OGRE] Using custom YAML configuration with enforced output structure.", header="INFO")
                except Exception as e:
                    self.logger.error(f"[OGRE] Error processing custom YAML config, falling back to default: {e}")
            
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

import os
import re
import subprocess
from pathlib import Path
from ...classes.BasePostProcessor import BasePostProcessor
from ...classes.Registry import register_postprocessor


@register_postprocessor('ogre_timeline')
class OgreTimelinePostProcessor(BasePostProcessor):
    """
    Generates chronological timeline files using DFIR-Ogre's native timeline engine in folder mode.
    Parses the extracted artifacts folder and outputs the timeline directly in the timeline folder.
    """
    recommended = True
    importance = "Recommended"
    speed = "Medium"
    priority = 5
    requires = []
    default_enabled = True
    hidden = False

    def run(self) -> None:
        if not getattr(self.context, 'is_orc', True):
            self.logger.info("[OGRE_TIMELINE] Skipping Ogre timeline (is_orc is False)", header="INFO")
            return

        self.logger.info("[OGRE_TIMELINE] Generating DFIR-Ogre chronological timeline...", header="START")

        try:
            archive_path = str(self.context.path_to_archive)
            case_name = str(self.context.case_name)
            timeline_folder = Path(self.context.timeline_dir)
            timeline_folder.mkdir(parents=True, exist_ok=True)

            # Locate configuration
            wapp_module_dir = Path(__file__).parent.parent.parent
            base_config_path = wapp_module_dir / "config" / "ogre_timeline.yaml"

            if not base_config_path.exists():
                self.logger.error(f"[OGRE_TIMELINE] Configuration file not found at {base_config_path}", header="ERROR")
                return

            # Read template config and inject dynamic output/temp folders
            with open(base_config_path, 'r', encoding='utf-8') as f:
                yaml_content = f.read()

            output_dir = timeline_folder / "ogre_timeline_data"
            output_dir.mkdir(parents=True, exist_ok=True)
            temp_dir = timeline_folder / "ogre_timeline_tmp"
            temp_dir.mkdir(parents=True, exist_ok=True)

            # Dynamically replace output_folder and temp_folder with current execution paths
            yaml_content = re.sub(
                r'^output_folder:.*$',
                f'output_folder: {output_dir.as_posix()}',
                yaml_content,
                flags=re.MULTILINE
            )
            yaml_content = re.sub(
                r'^temp_folder:.*$',
                f'temp_folder: {temp_dir.as_posix()}',
                yaml_content,
                flags=re.MULTILINE
            )

            # Save the execution-specific configuration file inside the timeline folder
            exec_config_path = timeline_folder / "ogre_timeline_exec.yaml"
            with open(exec_config_path, 'w', encoding='utf-8') as f:
                f.write(yaml_content)

            cmd = [
                "dfir-ogre",
                "timeline",
                "--archive", archive_path,
                "--configuration", str(exec_config_path),
                "--timeline_folder", str(timeline_folder),
                "--case", case_name
            ]

            # Optional password if present in configuration
            password = getattr(self.context, 'artefact_config', {}).get('archive_password')
            if password:
                cmd.extend(["--password", str(password)])

            self.logger.info(f"[OGRE_TIMELINE] Executing: {' '.join(cmd)}", header="INFO")

            # Execute and stream output to running log
            process = subprocess.Popen(
                cmd,
                cwd=str(timeline_folder),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            for line in process.stdout:
                print(line, end="", flush=True)

            process.wait()

            if process.returncode != 0:
                self.logger.warning(
                    f"[OGRE_TIMELINE] DFIR-Ogre command returned non-zero code ({process.returncode})",
                    header="WARNING"
                )
            else:
                self.logger.info("[OGRE_TIMELINE] DFIR-Ogre execution completed successfully.", header="INFO")

            # Check for generated timeline files (jsonl, csv, etc.)
            generated_files = [
                f for f in timeline_folder.rglob("*")
                if f.is_file() and f.suffix in [".jsonl", ".csv"] and f.name != "ogre_timeline_exec.yaml"
            ]

            if generated_files:
                for tf in generated_files:
                    size_mb = tf.stat().st_size / (1024 * 1024)
                    self.logger.info(
                        f"[OGRE_TIMELINE] Generated timeline file: {tf.name} ({size_mb:.2f} MB) in {tf.parent}",
                        header="SUCCESS"
                    )
            else:
                self.logger.warning(
                    f"[OGRE_TIMELINE] No timeline output files found in {timeline_folder}",
                    header="WARNING"
                )

        except Exception as e:
            self.logger.error(f"[OGRE_TIMELINE] Error executing DFIR-Ogre timeline: {e}", header="ERROR")

        self.logger.info("[OGRE_TIMELINE] Generating DFIR-Ogre chronological timeline...", header="FINISHED")

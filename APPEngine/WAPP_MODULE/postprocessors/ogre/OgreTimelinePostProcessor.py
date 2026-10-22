import os
import subprocess
from pathlib import Path
from ...classes.BasePostProcessor import BasePostProcessor
from ...classes.Registry import register_postprocessor


@register_postprocessor('ogre_timeline')
class OgreTimelinePostProcessor(BasePostProcessor):
    """
    Generates a unified chronological timeline CSV using DFIR-Ogre's native timeline engine.
    Parses the ORC archive and creates a sorted timestamped CSV in the timeline folder.
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
            config_path = wapp_module_dir / "config" / "ogre_timeline.yaml"

            if not config_path.exists():
                self.logger.error(f"[OGRE_TIMELINE] Configuration file not found at {config_path}", header="ERROR")
                return

            cmd = [
                "dfir-ogre",
                "timeline",
                "--archive", archive_path,
                "--configuration", str(config_path),
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
                    f"[OGRE_TIMELINE] DFIR-Ogre timeline command returned non-zero code ({process.returncode})",
                    header="WARNING"
                )
            else:
                self.logger.info("[OGRE_TIMELINE] DFIR-Ogre timeline generation completed successfully.", header="INFO")

            # Check for generated timeline CSV files
            generated_timelines = list(timeline_folder.glob("*.timeline.csv"))
            if not generated_timelines:
                generated_timelines = list(timeline_folder.glob("*.csv"))

            if generated_timelines:
                for tl_file in generated_timelines:
                    size_mb = tl_file.stat().st_size / (1024 * 1024)
                    self.logger.info(
                        f"[OGRE_TIMELINE] Generated timeline file: {tl_file.name} ({size_mb:.2f} MB) in {timeline_folder}",
                        header="SUCCESS"
                    )
            else:
                self.logger.warning(f"[OGRE_TIMELINE] No timeline CSV was found in {timeline_folder}", header="WARNING")

        except Exception as e:
            self.logger.error(f"[OGRE_TIMELINE] Error executing DFIR-Ogre timeline: {e}", header="ERROR")

        self.logger.info("[OGRE_TIMELINE] Generating DFIR-Ogre chronological timeline...", header="FINISHED")

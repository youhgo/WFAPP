import subprocess
import logging
import shlex
from typing import Optional


# In your application, you would import your LoggerManager class
# from LggerManager import LoggerManager

class FilebeatIngester:
    """
    A class to handle the ingestion of files into Elasticsearch using Filebeat.
    """

    def __init__(self, logger_run, config_path: str = "/etc/filebeat/filebeat.yml"):
        """
        Initializes the FilebeatIngester.

        Args:
            logger_run: An instance of your custom LoggerManager class.
            config_path (str): The path to the filebeat.yml configuration file.
        """
        self.config_path = config_path
        self.logger = logger_run

    def ingest_file(self, file_path: str, target_index: str, pipeline: str):
        """
        Calls the Filebeat executable to ingest a single file into a specific Elasticsearch index
        using a specified ingest pipeline.

        Args:
            file_path (str): The absolute path to the file inside the container.
            target_index (str): The name of the Elasticsearch index to send the data to.
            pipeline (str): The name of the Elasticsearch ingest pipeline to use.
        """
        self.logger.info(f"Starting Filebeat ingestion for {file_path} into index {target_index}", header="START",
                         indentation=1)

        # The '-once' flag is crucial: it tells Filebeat to process the file and then exit.
        command = [
            "filebeat",
            "-c", self.config_path,
            "-e",
            "-once",
            "-E", f"filebeat.inputs[0].enabled=true",
            "-E", f"filebeat.inputs[0].paths=[{shlex.quote(file_path)}]",
            "-E", f"output.elasticsearch.index={shlex.quote(target_index)}",
            "-E", f"output.elasticsearch.pipeline={shlex.quote(pipeline)}"
        ]

        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=300  # 5-minute timeout
            )
            self.logger.info(f"Successfully ingested {file_path}.", header="SUCCESS", indentation=1)
            self.logger.debug(f"Filebeat stdout: {result.stdout}", header="DEBUG", indentation=2)
            self.logger.debug(f"Filebeat stderr: {result.stderr}", header="DEBUG", indentation=2)
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Filebeat failed for {file_path} with exit code {e.returncode}.", header="FAILED",
                              indentation=1)
            self.logger.error(f"Filebeat stderr: {e.stderr}", header="ERROR", indentation=2)
            return False
        except subprocess.TimeoutExpired:
            self.logger.error(f"Filebeat timed out while processing {file_path}.", header="FAILED", indentation=1)
            return False
        except FileNotFoundError:
            self.logger.error("The 'filebeat' command was not found. Is Filebeat installed in the container's PATH?",
                              header="ERROR", indentation=1)
            return False

    def ingest_evtx_file(self, file_path: str, target_index: str):
        """Wrapper to ingest an EVTX file."""
        return self.ingest_file(file_path, target_index, "winevtlog-pipeline")

    def ingest_csv_file(self, file_path: str, target_index: str):
        """Wrapper to ingest a CSV file."""
        return self.ingest_file(file_path, target_index, "csv-pipeline")


if __name__ == '__main__':
    # --- Example Usage ---

    # NOTE: This class now requires an instance of your LoggerManager.
    # The example below shows the required setup.
    # You would uncomment and use this code in your application.

    # 1. Import your LoggerManager
    # from LoggerManager import LoggerManager

    # 2. Create an instance of your custom logger
    # logger_manager = LoggerManager(logger_name="ingester_test", log_file_path="ingester.log")

    # 3. Pass the logger to the ingester's constructor
    # ingester = FilebeatIngester(logger_run=logger_manager)

    # 4. Ingest files
    # evtx_file = "/python-docker/shared_files/case123/Security.evtx"
    # evtx_index = "winlogs-case-123"
    # ingester.ingest_evtx_file(evtx_file, evtx_index)

    # csv_file = "/python-docker/shared_files/case456/user_activity.csv"
    # csv_index = "user-activity-case-456"
    # ingester.ingest_csv_file(csv_file, csv_index)
    pass


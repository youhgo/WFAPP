#!/usr/bin/python3
import logging
import sys
import traceback
import pathlib

class LoggerManager:
    """
    Class to manage logging, based on Python's `logging` module.
    """

    # Using an internal class to group headers
    class Headers:
        START = "[START]"
        STOP = "[STOP]"
        FINISHED = "[FINISHED]"
        SUCCESS = "[SUCCESS]"
        FAILED = "[FAILED]"
        INFO = "[INFO]"
        PARSING = "[PARSING]"
        WARNING = "[WARNING]"
        ERROR = "[ERROR]"

        @staticmethod
        def get(name):
            return getattr(LoggerManager.Headers, name.upper(), "")

    def __init__(self, logger_name: str, log_file_path: str, level: str = "INFO"):
        """
        Constructor for the LoggerManager class.

        Args:
            logger_name (str): Name of the logger.
            log_file_path (str): Path to the log file.
            level (str, optional): Logging level. Defaults to "INFO".
        """
        self.logLevel = getattr(logging, level.upper(), logging.INFO)
        self.logger_name = logger_name
        self.log_file_path = pathlib.Path(log_file_path)  # Convert to a Path object
        self.my_logger = self._initialise_logging()

        # Add a method to handle all message types
        self.log = self._generic_log

    def _initialise_logging(self) -> logging.Logger:
        """
        Function to initialize the logger object.
        This is an internal method (convention _), as it should not be called directly.
        """
        logger = logging.getLogger(self.logger_name)

        try:
            logger.setLevel(self.logLevel)
            formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')

            # Handler for the console
            stdout_handler = logging.StreamHandler(sys.stderr)
            stdout_handler.setFormatter(formatter)
            stdout_handler.setLevel(self.logLevel)
            logger.addHandler(stdout_handler)

            # --- FIX: Create a stream handler using an explicitly opened file ---
            try:
                # Ensure the parent directory exists
                self.log_file_path.parent.mkdir(parents=True, exist_ok=True)

                file_handler = logging.FileHandler(self.log_file_path)
                file_handler.setFormatter(formatter)
                file_handler.setLevel(self.logLevel)
                logger.addHandler(file_handler)

            except Exception as e:
                # If there's an issue with the file, log a clear error to the console
                # but don't stop the application
                sys.stderr.write(f"\n[ERROR] Failed to set up file logging: {e}\n")

            return logger
        except Exception:
            sys.stderr.write(f"\nErreur lors de l'initialisation du logger:\n{traceback.format_exc()}\n")
            raise

    def get_logger(self) -> logging.Logger:
        """
        Returns the logger object.
        """
        return self.my_logger

    def _generic_log(self, msg: str, level: str = "info", header_type: str = "INFO", indentation: int = 0):
        """
        Generic method to log messages uniformly.
        """
        header = self.Headers.get(header_type)
        indent = "-" * (indentation * 2) if indentation > 0 else ""
        formatted_message = "{}>{} {}".format(indent, header, msg)

        log_method = getattr(self.my_logger, level.lower(), self.my_logger.info)
        log_method(formatted_message)

    def info(self, msg: str, header: str = "INFO", indentation: int = 0):
        self._generic_log(msg, level="info", header_type=header, indentation=indentation)

    def warning(self, msg: str, header: str = "WARNING", indentation: int = 0):
        self._generic_log(msg, level="warning", header_type=header, indentation=indentation)

    def error(self, msg: str, header: str = "FAILED", indentation: int = 0):
        self._generic_log(msg, level="error", header_type=header, indentation=indentation)

    def debug(self, msg: str, header: str = "DEBUG", indentation: int = 0):
        self._generic_log(msg, level="debug", header_type=header, indentation=indentation)
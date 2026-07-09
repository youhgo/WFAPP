import os
import shutil
import argparse
import zipfile
import tarfile
import gzip
import lzma
import logging
import re

class ArchiveExtractor:
    """
    A class to recursively extract archives of various formats.

    It supports nested archives and cleans up by deleting the original
    archive file after a successful extraction.
    """

    def __init__(self, destination_root, logger):
        """
        Initializes the extractor.

        Args:
            destination_root (str): The root directory where archives will be extracted.
            logger (logging.Logger): Logger instance for tracking the process.
        """
        self.logger_run = logger
        self.destination_root = destination_root
        if not os.path.isdir(self.destination_root):
            self.logger_run.info(f"Creating destination directory: {self.destination_root}")
            os.makedirs(self.destination_root, exist_ok=True)

        self.handlers = {
            '.tar.gz': self._extract_tar,
            '.tar.bz2': self._extract_tar,
            '.tar.xz': self._extract_tar,
            '.zip': self._extract_zip,
            '.tar': self._extract_tar,
            '.gz': self._extract_gz,
            '.xz': self._extract_xz,
            '.tgz': self._extract_tar,
            '.tbz2': self._extract_tar,
            '.txz': self._extract_tar,
        }

        self.known_extensions = sorted(self.handlers.keys(), key=len, reverse=True)

    def _get_handler(self, file_path):
        """Finds the correct handler based on the file extension."""
        filename = os.path.basename(file_path).lower()
        for ext, handler in self.handlers.items():
            if filename.endswith(ext):
                return handler
        return None

    def _get_unique_path(self, base_path):
        """
        Vérifie si le chemin existe. Si oui, ajoute un suffixe (_1, _2...)
        jusqu'à trouver un nom de chemin disponible.
        """
        if not os.path.exists(base_path):
            return base_path
        
        counter = 1
        while True:
            new_path = f"{base_path}_{counter}"
            if not os.path.exists(new_path):
                return new_path
            counter += 1

    def _get_output_path(self, file_path):
        """
        Generates a unique output directory name from the archive name, correctly
        handling compound extensions like .tar.gz and avoiding overwrites.
        """
        base_name = os.path.basename(file_path)
        target_path = ""
        for ext in self.known_extensions:
            if base_name.lower().endswith(ext):
                output_dir_name = base_name[:-len(ext)]
                target_path = os.path.join(os.path.dirname(file_path), output_dir_name)
                break
        if not target_path:
            target_path = os.path.join(os.path.dirname(file_path), os.path.splitext(base_name)[0])


        return self._get_unique_path(target_path)

    def _extract_zip(self, file_path, output_path):
        """Extracts a .zip file."""
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(output_path)

    def _extract_tar(self, file_path, output_path):
        """Extracts various .tar files (.tar, .tar.gz, .tar.bz2, etc.)."""
        with tarfile.open(file_path, 'r:*') as tar_ref:
            tar_ref.extractall(output_path)

    def _extract_gz(self, file_path, output_path):
        """Decompresses a .gz file."""
        output_filename = os.path.basename(output_path)
        full_output_path = os.path.join(output_path, output_filename)
        with gzip.open(file_path, 'rb') as f_in:
            with open(full_output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

    def _extract_xz(self, file_path, output_path):
        """Decompresses an .xz file."""
        output_filename = os.path.basename(output_path)
        full_output_path = os.path.join(output_path, output_filename)
        with lzma.open(file_path) as f_in:
            with open(full_output_path, 'wb') as f_out:
                f_out.write(f_in.read())

    def extract_recursively(self, current_path):
        """
        Recursively extracts archives in a given path.

        Args:
            current_path (str): The file or directory to process.
        """
        if os.path.isfile(current_path):
            self._process_file(current_path)
        elif os.path.isdir(current_path):
            for root, _, files in os.walk(current_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    self._process_file(file_path)

    def _process_file(self, file_path):
        """Processes a single file, extracting it if it's a known archive type."""
        handler = self._get_handler(file_path)

        if not handler:
            return

        output_path = self._get_output_path(file_path)

        self.logger_run.info(f"Found archive: {file_path}")
        self.logger_run.info(f"Attempting to extract to: {output_path}")

        try:
            if not os.path.exists(output_path):
                os.makedirs(output_path, exist_ok=True)

            handler(file_path, output_path)
            self.logger_run.info(f"Successfully extracted {os.path.basename(file_path)}")

            os.remove(file_path)
            self.logger_run.info(f"Deleted original archive: {file_path}")

            self.extract_recursively(output_path)

        except (zipfile.BadZipFile, tarfile.TarError, Exception) as e:
            self.logger_run.error(f"Failed to extract {file_path}: {e}")
            self.logger_run.error("Leaving corrupted or problematic archive in place.")

    def run(self, initial_archive_path):
        """
        Starts the extraction process from a main archive file.

        Args:
            initial_archive_path (str): The path to the first archive to extract.
        """
        if not os.path.exists(initial_archive_path):
            self.logger_run.error(f"Initial archive not found: {initial_archive_path}")
            return

        self.logger_run.info(f"Starting process for: {initial_archive_path}")
        cleaned_name_archive = self.clean_archive_name(r'__\d+$', initial_archive_path)
        initial_dest_path = os.path.join(self.destination_root, os.path.basename(cleaned_name_archive))
        initial_dest_path = self._get_unique_path(initial_dest_path)
        shutil.copy(initial_archive_path, initial_dest_path)

        self.extract_recursively(self.destination_root)
        self.logger_run.info("Extraction process finished.")

    def clean_archive_name(self, pattern, og_name):
        new_name = re.sub(pattern, '', og_name)
        return new_name


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    main_logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(
        description="A tool to recursively extract nested archives and delete the originals.",
        epilog="Example: python extractor.py --archive /path/to/archive.tar.gz --destination /path/to/output"
    )

    parser.add_argument(
        "-a", "--archive",
        required=True,
        help="Path to the main archive file to be extracted."
    )

    parser.add_argument(
        "-d", "--destination",
        required=True,
        help="The directory where the content will be extracted."
    )

    args = parser.parse_args()

    # Fixed: passed the logger to the class initialization
    extractor = ArchiveExtractor(destination_root=args.destination, logger=main_logger)
    extractor.run(initial_archive_path=args.archive)
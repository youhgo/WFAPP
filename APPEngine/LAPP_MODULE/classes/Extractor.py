import os
import shutil
import argparse
import zipfile
import tarfile
import gzip
import lzma
import logging

# Configure basic logging to see the progress
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ArchiveExtractor:
    """
    A class to recursively extract archives of various formats.

    It supports nested archives and cleans up by deleting the original
    archive file after a successful extraction.
    """

    def __init__(self, destination_root):
        """
        Initializes the extractor.

        Args:
            destination_root (str): The root directory where archives will be extracted.
        """
        self.destination_root = destination_root
        if not os.path.isdir(self.destination_root):
            logging.info(f"Creating destination directory: {self.destination_root}")
            os.makedirs(self.destination_root, exist_ok=True)

        # Map file extensions to their handler methods.
        # The order can matter for getting the handler, so we list longest first.
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
        # For creating output paths, we need a sorted list of extensions
        self.known_extensions = sorted(self.handlers.keys(), key=len, reverse=True)

    def _get_handler(self, file_path):
        """Finds the correct handler based on the file extension."""
        filename = os.path.basename(file_path).lower()
        for ext, handler in self.handlers.items():
            if filename.endswith(ext):
                return handler
        return None

    # --- MODIFIED SECTION ---
    # This method is now more robust for compound extensions.
    def _get_output_path(self, file_path):
        """
        Generates the output directory name from the archive name, correctly
        handling compound extensions like .tar.gz.
        """
        base_name = os.path.basename(file_path)

        # Check against a sorted list of extensions (longest first)
        for ext in self.known_extensions:
            if base_name.lower().endswith(ext):
                # Remove the longest matching extension
                output_dir_name = base_name[:-len(ext)]
                # For single-file compression like .gz, the output path is a directory
                # named after the file.
                return os.path.join(os.path.dirname(file_path), output_dir_name)

        # Fallback if no known handler extension is found
        return os.path.join(os.path.dirname(file_path), os.path.splitext(base_name)[0])

    # --- END MODIFIED SECTION ---

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
        # The output filename is the archive name without .gz
        output_filename = os.path.basename(self._get_output_path(file_path))
        full_output_path = os.path.join(output_path, output_filename)
        with gzip.open(file_path, 'rb') as f_in:
            with open(full_output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

    def _extract_xz(self, file_path, output_path):
        """Decompresses an .xz file."""
        output_filename = os.path.basename(self._get_output_path(file_path))
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

        # The new _get_output_path doesn't need the extension passed to it.
        output_path = self._get_output_path(file_path)

        logging.info(f"Found archive: {file_path}")
        logging.info(f"Attempting to extract to: {output_path}")

        try:
            if not os.path.exists(output_path):
                os.makedirs(output_path, exist_ok=True)

            handler(file_path, output_path)
            logging.info(f"Successfully extracted {os.path.basename(file_path)}")

            os.remove(file_path)
            logging.info(f"Deleted original archive: {file_path}")

            self.extract_recursively(output_path)

        except (zipfile.BadZipFile, tarfile.TarError, Exception) as e:
            logging.error(f"Failed to extract {file_path}: {e}")
            logging.error("Leaving corrupted or problematic archive in place.")

    def run(self, initial_archive_path):
        """
        Starts the extraction process from a main archive file.

        Args:
            initial_archive_path (str): The path to the first archive to extract.
        """
        if not os.path.exists(initial_archive_path):
            logging.error(f"Initial archive not found: {initial_archive_path}")
            return

        logging.info(f"Starting process for: {initial_archive_path}")
        initial_dest_path = os.path.join(self.destination_root, os.path.basename(initial_archive_path))
        shutil.copy(initial_archive_path, initial_dest_path)

        self.extract_recursively(self.destination_root)
        logging.info("Extraction process finished.")


if __name__ == "__main__":
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

    extractor = ArchiveExtractor(destination_root=args.destination)
    extractor.run(initial_archive_path=args.archive)
#!/usr/bin/python3
import os
import csv
import shutil
import traceback
import zipfile
import hashlib
import re
import subprocess
from pathlib import Path

def _clean_long_filename(base_name: str) -> str:
    """
    Cleans overly long filenames during extraction (prevents OS errors OSError 206/207).
    Uses the same robust Regex logic as OrcRenamer.
    """
    # Do not apply this logic if the name is already valid (< 255 bytes)
    # We preserve the full name so that the GetThis.csv mapping works
    if len(base_name.encode('utf-8')) <= 255:
        return base_name

    # 1. Clean ORC suffix ({GUID}.data)
    filename_clean = re.sub(r'_\{[a-fA-F0-9\-]+\}(?:\.data)?$', '', base_name)
    filename_clean = re.sub(r'\_data$', '', filename_clean)

    # 2. Clean ORC prefixes (3 or 4 hex/num blocks separated by _)
    filename_clean = re.sub(r'^([A-Fa-f0-9]{5,20}_){2,4}(?:[A-Fa-f0-9]+_)?', '', filename_clean)

    # Safety: if the regex accidentally emptied the name, generate a name based on the hash
    if not filename_clean:
        file_hash = hashlib.md5(base_name.encode('utf-8')).hexdigest()[:8]
        file_ext = "".join(Path(base_name).suffixes)
        filename_clean = f"RENAMED_EMPTY_{file_hash}{file_ext}"

    # Ultimate safety: if the name is *still* too long, brutally truncate it
    if len(filename_clean.encode('utf-8')) > 255:
        name, ext = os.path.splitext(filename_clean)
        # Keep room for the extension
        filename_clean = name[:200] + ext

    return filename_clean


try:
    import py7zr

    original_get_sanitized_output_path = py7zr.py7zr.get_sanitized_output_path
    
    def safe_get_sanitized_output_path(arcname, path):
        import os
        dirname, basename = os.path.split(arcname)
        clean_basename = _clean_long_filename(basename)
        clean_arcname = os.path.join(dirname, clean_basename)
        return original_get_sanitized_output_path(clean_arcname, path)

    py7zr.py7zr.get_sanitized_output_path = safe_get_sanitized_output_path

    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False


class OrcExtractor:
    """
    Class managing the (recursive) extraction of DFIR-ORC archives (.zip, .7z).
    """

    def __init__(self, logger, password=None):
        self.logger = logger
        self.password = password

    def extract_recursively(self, archive_ext, archive_path, dest_dir):
        """
        Extracts the main archive, then searches and extracts all nested archives.
        """
        self.logger.info(f"[EXTRACTOR] Start main extraction of {archive_path}", header="START")

        # 1. Root archive extraction
        success = self._extract_archive(archive_ext, archive_path, dest_dir)
        if not success:
            return False

        # 2. Loop for recursive extraction of nested archives (created by ORC)
        archives_to_extract = True
        while archives_to_extract:
            archives_to_extract = False
            for root, dirs, files in os.walk(dest_dir):
                for file in files:
                    if file.endswith('.zip') or file.endswith('.7z'):
                        nested_archive_path = os.path.join(root, file)
                        nested_ext = os.path.splitext(file)[1]

                        self.logger.info(f"[EXTRACTOR] Extraction of nested archive: {file}", header="INFO",
                                         indentation=1)

                        if self._extract_archive(nested_ext, nested_archive_path, root):
                            try:
                                os.remove(nested_archive_path)  # Cleanup after successful extraction
                            except OSError:
                                pass
                            archives_to_extract = True  # Keep searching in case the extracted archive contained others

        self.logger.info("[EXTRACTOR] Recursive extraction completed", header="FINISHED")
        return True

    def _extract_archive(self, ext, archive_path, dest_dir):
        """Internal method managing 7z and Zip extraction logic."""
        Path(dest_dir).mkdir(parents=True, exist_ok=True)

        try:
            if ext == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    if self.password:
                        zip_ref.setpassword(self.password.encode('utf-8'))

                    for member in zip_ref.infolist():
                        # Use the long filename cleaning function
                        clean_name = _clean_long_filename(os.path.basename(member.filename))
                        member.filename = os.path.join(os.path.dirname(member.filename), clean_name)
                        zip_ref.extract(member, path=dest_dir)
                return True

            elif ext == '.7z':
                if PY7ZR_AVAILABLE:
                    with py7zr.SevenZipFile(archive_path, mode='r', password=self.password) as z:
                        z.extractall(path=dest_dir)
                    return True
                else:
                    # Fallback using system 7za executable if py7zr is not installed
                    self.logger.warning("[EXTRACTOR] py7zr unavailable, fallback to 7za (system binary)",
                                        indentation=1)
                    cmd = ['7za', 'x', archive_path, f'-o{dest_dir}', '-y']
                    if self.password:
                        cmd.append(f'-p{self.password}')
                    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                    return True
        except Exception as e:
            self.logger.error(f"[EXTRACTOR] Extraction failed for {archive_path} : {e}", header="ERROR", indentation=1)
            return False


class ArtefactRestorer:
    """
    If the user requests tree restoration (--restore),
    this class rebuilds original folders (e.g., C:/Windows/System32/...)
    from GetThis log files.
    """

    def __init__(self, extracted_dir: str, restored_dir: str, logger):
        self.extracted_dir = Path(extracted_dir)
        self.restored_dir = Path(restored_dir)
        self.logger = logger
        self.mapping = {}

    def build_mapping(self):
        """
        Same as OrcRenamer: reads all GetThis.csv files to map
        the name generated by ORC to the full path (FullName).
        """
        getthis_files = [f for f in self.extracted_dir.rglob("*.csv") if "GetThis" in f.name]

        for csv_file in getthis_files:
            try:
                with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        sample_name = row.get("SampleName")
                        full_name = row.get("FullName")

                        if sample_name and full_name:
                            # Secure cross-platform extraction
                            ugly_basename = sample_name.replace('\\', '/').split('/')[-1]

                            # Clean FullName to make it a proper relative path
                            # Transforms "C:\Windows\..." to "C/Windows/..." to avoid bugs
                            clean_path = full_name.replace('\\', '/').lstrip('/')
                            clean_path = clean_path.replace(':', '')

                            self.mapping[ugly_basename] = clean_path
            except Exception as e:
                self.logger.error(f"[RESTORER] Error reading {csv_file.name}: {e}", header="ERROR", indentation=1)

    def run(self):
        self.logger.info("[RESTORER] Starting tree restoration (Virtual FileSystem)",
                         header="START")
        self.build_mapping()

        restored_count = 0
        orphans_count = 0

        for file_path in self.extracted_dir.rglob("*"):
            if not file_path.is_file():
                continue

            original_name = file_path.name

            # Do not move inventory files
            if original_name.endswith(".csv") and "GetThis" in original_name:
                continue

            if original_name in self.mapping:
                # Retrieve original path (e.g., C/Windows/System32/winevt/Logs/Security.evtx)
                relative_target = self.mapping[original_name]
                target_path = self.restored_dir / relative_target

                # Create parent folders automatically
                target_path.parent.mkdir(parents=True, exist_ok=True)

                # Anti-overwrite management
                counter = 1
                base_target = target_path
                while target_path.exists():
                    target_path = base_target.parent / f"{base_target.stem}_{counter}{base_target.suffix}"
                    counter += 1

                try:
                    # Move file to its place in the restored tree
                    shutil.move(str(file_path), str(target_path))
                    restored_count += 1
                except Exception as e:
                    self.logger.warning(f"[RESTORER] Failed to move {original_name}: {e}", header="WARNING",
                                        indentation=2)
            else:
                # Files not appearing in GetThis (Orphans, ORC metadata, logs...)
                target_path = self.restored_dir / "ORC_Metadata_Orphans" / original_name
                target_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.move(str(file_path), str(target_path))
                    orphans_count += 1
                except:
                    pass

        # Cleanup the original extraction folder which should be empty
        try:
            shutil.rmtree(self.extracted_dir)
        except OSError:
            pass

        self.logger.info(
            f"[RESTORER] Completed. {restored_count} files moved and {orphans_count} metadata saved.",
            header="FINISHED")
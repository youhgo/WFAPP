import os
import sqlite3
import shutil
import traceback
from pathlib import Path
from typing import Generator, Dict, Any, Tuple

from ...classes.BaseParser import BaseParser

class ActivitiesCacheParser(BaseParser):
    """
    Classe pour parser le fichier ActivitiesCache.db (Windows Activity Timeline).
    Extrait les activités des utilisateurs et les informations sur les packages.
    """

    def parse(self, input_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        if self.logger:
            self.logger.info(f"[PARSING][ACTIVITIESCACHE] Début du traitement de {input_path}", header="START", indentation=2)

        if not input_path.exists():
            if self.logger:
                self.logger.error(f"[PARSING][ACTIVITIESCACHE] Fichier non trouvé : {input_path}", header="ERROR", indentation=2)
            return

        db_copy = f"{input_path}_temp.db"
        try:
            shutil.copy2(str(input_path), db_copy)
            conn = sqlite3.connect(db_copy)
            cursor = conn.cursor()

            # Extraction de la table Activity
            yield from self._yield_activities(cursor)
            
            # Extraction de la table Activity_PackageId
            yield from self._yield_package_ids(cursor)

            if self.logger:
                self.logger.info("[PARSING][ACTIVITIESCACHE] Parsing terminé avec succès", header="FINISHED", indentation=2)

        except Exception as e:
            if self.logger:
                self.logger.error(f"[PARSING][ACTIVITIESCACHE] Erreur critique : {traceback.format_exc()}", header="ERROR", indentation=2)
        finally:
            if 'conn' in locals() and conn:
                conn.close()
            if os.path.exists(db_copy):
                try:
                    os.remove(db_copy)
                except Exception:
                    pass

    def _yield_activities(self, cursor) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        query = '''
                SELECT datetime(Activity.LastModifiedTime, 'unixepoch') as LastModifiedTime,
                       datetime(Activity.ExpirationTime, 'unixepoch') as ExpirationTime,
                       datetime(Activity.LastModifiedOnClient, 'unixepoch') as LastModifiedOnClient,
                       datetime(Activity.StartTime, 'unixepoch') as StartTime,
                       CASE WHEN Activity.CreatedInCloud == 0 THEN 'No' ELSE 'Yes' END as CreatedInCloud,
                       Activity.AppId,
                       Activity.AppActivityId,
                       Activity.ActivityType,
                       Activity.Tag,
                       Activity.Group,
                       Activity.Priority
                FROM Activity
                '''
        try:
            cursor.execute(query)
            columns = [column[0] for column in cursor.description]
            for row in cursor:
                record = dict(zip(columns, row))
                # Map exactly to original headers
                formatted_record = {
                    'Last Modified Time': record.get('LastModifiedTime', ''),
                    'Expiration Time': record.get('ExpirationTime', ''),
                    'Last Modification Time on Client': record.get('LastModifiedOnClient', ''),
                    'Start Time': record.get('StartTime', ''),
                    'Created In Cloud': record.get('CreatedInCloud', ''),
                    'App ID': record.get('AppId', ''),
                    'App Activity ID': record.get('AppActivityId', ''),
                    'Activity Type': record.get('ActivityType', ''),
                    'Tag': record.get('Tag', ''),
                    'Group': record.get('Group', ''),
                    'Priority': record.get('Priority', '')
                }
                yield "ActivityCache_Activities", formatted_record
        except sqlite3.OperationalError:
            pass # Table might not exist

    def _yield_package_ids(self, cursor) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        query = '''
                SELECT ActivityId,
                       Platform,
                       PackageFullName,
                       datetime(ExpirationTime, 'unixepoch') as ExpirationTime
                FROM Activity_PackageId
                '''
        try:
            cursor.execute(query)
            columns = [column[0] for column in cursor.description]
            for row in cursor:
                record = dict(zip(columns, row))
                formatted_record = {
                    'Activity ID': record.get('ActivityId', ''),
                    'Platform': record.get('Platform', ''),
                    'Package Name': record.get('PackageFullName', ''),
                    'Expiration Time': record.get('ExpirationTime', '')
                }
                yield "ActivityCache_PackageID", formatted_record
        except sqlite3.OperationalError:
            pass # Table might not exist
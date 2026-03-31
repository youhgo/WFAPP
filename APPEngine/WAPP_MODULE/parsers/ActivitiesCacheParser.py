#!/usr/bin/python3
import os
import sqlite3
import csv
import traceback
import argparse
import sys
from pathlib import Path


class ActivitiesCacheParser:
    """
    Classe pour parser le fichier ActivitiesCache.db (Windows Activity Timeline).
    Extrait les activités des utilisateurs et les informations sur les packages.
    """

    def __init__(self, logger, separator="|") -> None:
        """
        Constructeur pour la classe ActivitiesCacheParser.

        Args:
            logger: L'instance du logger pour le suivi de l'exécution.
            separator: Le séparateur à utiliser pour les fichiers CSV en sortie.
        """
        self.logger_run = logger
        self.separator = separator

    def parse_activities_cache(self, input_file_path: str, output_dir: str):
        """
        Point d'entrée principal pour le parsing du fichier ActivitiesCache.db.

        Args:
            input_file_path: Chemin complet vers le fichier ActivitiesCache.db.
            output_dir: Dossier de destination pour les rapports CSV.
        """
        self.logger_run.info(f"[PARSING][ACTIVITIESCACHE] Début du traitement de {input_file_path}", header="START",
                             indentation=2)

        if not os.path.exists(input_file_path):
            self.logger_run.error(f"[PARSING][ACTIVITIESCACHE] Fichier non trouvé : {input_file_path}", header="ERROR",
                                  indentation=2)
            return

        db_copy = f"{input_file_path}_temp.db"
        try:
            # Création d'une copie temporaire pour éviter les verrous SQLite
            import shutil
            shutil.copy2(input_file_path, db_copy)

            conn = sqlite3.connect(db_copy)
            cursor = conn.cursor()

            # Extraction des deux tables principales
            activities = self._get_activity(cursor)
            packages = self._get_package_id(cursor)

            # Génération des rapports
            self._write_results(activities, os.path.join(output_dir, "ActivityCache_Activities.csv"),
                                ['Last Modified Time', 'Expiration Time', 'Last Modification Time on Client',
                                 'Start Time', 'Created In Cloud', 'App ID', 'App Activity ID',
                                 'Activity Type', 'Tag', 'Group', 'Priority'])

            self._write_results(packages, os.path.join(output_dir, "ActivityCache_PackageID.csv"),
                                ['Activity ID', 'Platform', 'Package Name', 'Expiration Time'])

            self.logger_run.info("[PARSING][ACTIVITIESCACHE] Parsing terminé avec succès", header="FINISHED",
                                 indentation=2)

        except Exception as e:
            self.logger_run.error(f"[PARSING][ACTIVITIESCACHE] Erreur critique : {traceback.format_exc()}",
                                  header="ERROR", indentation=2)
        finally:
            if 'conn' in locals():
                conn.close()
            if os.path.exists(db_copy):
                os.remove(db_copy)

    def _get_activity(self, cursor):
        """Extrait les données de la table Activity."""
        query = '''
                SELECT datetime(Activity.LastModifiedTime, 'unixepoch'), \
                       datetime(Activity.ExpirationTime, 'unixepoch'), \
                       datetime(Activity.LastModifiedOnClient, 'unixepoch'), \
                       datetime(Activity.StartTime, 'unixepoch'), \
                       CASE WHEN Activity.CreatedInCloud == 0 THEN 'No' ELSE 'Yes' END, \
                       Activity.AppId, \
                       Activity.AppActivityId, \
                       Activity.ActivityType, \
                       Activity.Tag, \
                       Activity.Group, \
                       Activity.Priority
                FROM Activity \
                '''
        cursor.execute(query)
        return cursor.fetchall()

    def _get_package_id(self, cursor):
        """Extrait les données de la table Activity_PackageId."""
        query = '''
                SELECT ActivityId, \
                       Platform, \
                       PackageFullName, \
                       datetime(ExpirationTime, 'unixepoch')
                FROM Activity_PackageId \
                '''
        cursor.execute(query)
        return cursor.fetchall()

    def _write_results(self, data, output_file, headers):
        """Écrit les résultats dans un fichier CSV avec le séparateur défini."""
        if not data:
            return

        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter=self.separator)
                writer.writerow(headers)
                writer.writerows(data)
        except Exception as e:
            self.logger_run.error(f"[PARSING][ACTIVITIESCACHE] Erreur d'écriture dans {output_file} : {e}")


def parse_args():
    """Configure les arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(description='Parser pour Windows Activity Timeline (ActivitiesCache.db)')
    parser.add_argument('-i', '--input', required=True, help='Chemin vers le fichier ActivitiesCache.db')
    parser.add_argument('-o', '--output', required=True, help='Dossier de destination pour les fichiers CSV')
    parser.add_argument('-s', '--separator', default='|', help='Séparateur CSV (défaut: |)')
    return parser.parse_args()


if __name__ == '__main__':
    # Logger minimaliste pour l'exécution autonome
    class DummyLogger:
        def info(self, msg, header="", indentation=0):
            prefix = f"[{header}] " if header else ""
            indent = "  " * indentation
            print(f"{indent}{prefix}{msg}")

        def error(self, msg, header="", indentation=0):
            prefix = f"[{header}] " if header else ""
            indent = "  " * indentation
            print(f"{indent}{prefix}ERROR: {msg}", file=sys.stderr)

        def warning(self, msg, header="", indentation=0):
            prefix = f"[{header}] " if header else ""
            indent = "  " * indentation
            print(f"{indent}{prefix}WARNING: {msg}")


    args = parse_args()

    # Vérification du dossier de sortie
    if not os.path.exists(args.output):
        os.makedirs(args.output, exist_ok=True)

    # Initialisation et exécution
    ac_parser = ActivitiesCacheParser(DummyLogger(), separator=args.separator)
    ac_parser.parse_activities_cache(args.input, args.output)
import csv
from datetime import datetime
import os
import argparse


class BodyfileParser:
    """
    Parseur dédié aux fichiers format bodyfile.
    Convertit chaque entrée en 3 événements de timeline distincts (MAC) et trie par date.
    """

    def __init__(self, logger, separator):
        self.logger_run = logger
        self.separator = separator

    def convert_timestamp(self, ts):
        """
        Convertit un timestamp UNIX en date lisible (UTC).
        """
        try:
            return datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            # Fallback en cas de timestamp corrompu
            return "1970-01-01 00:00:00"

    def sort_csv_by_date(self, output_file, separator="|"):
        """
        Trie le fichier CSV final chronologiquement en se basant sur la colonne DATE.
        """
        print("[INFO] Début du tri chronologique pour le fichier : {}".format(output_file))
        try:
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f, delimiter=separator)
                header = next(reader)
                rows = list(reader)

            # Tri des lignes basé sur la première colonne (DATE)
            # Le format YYYY-MM-DD HH:MM:SS permet un tri de chaînes de caractères direct
            rows.sort(key=lambda x: x[0])

            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f, delimiter=separator)
                writer.writerow(header)
                writer.writerows(rows)

            print("[INFO] Tri chronologique terminé avec succès.")

        except Exception as e:
            print("[ERROR] Une erreur est survenue lors du tri : {}".format(e))

    def parse_bodyfile(self, input_file, output_file, separator='|'):
        print("[INFO] Début du parsing du bodyfile : {}".format(input_file))

        try:
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as infile, \
                    open(output_file, 'w', newline='', encoding='utf-8') as outfile:

                writer = csv.writer(outfile, delimiter=separator)

                # Écriture de l'en-tête (Header)
                header = ['DATE', 'DateType', 'Filename', 'inode', 'mode', 'uid', 'gid', 'size']
                writer.writerow(header)

                line_count = 0
                for line in infile:
                    line = line.strip()
                    # Ignorer les lignes vides ou les commentaires potentiels
                    if not line or line.startswith('#'):
                        continue

                    parts = line.split('|')

                    # Un bodyfile classique possède 11 colonnes (index 0 à 10)
                    if len(parts) >= 10:
                        filename = parts[1]
                        inode = parts[2]
                        mode = parts[3]
                        uid = parts[4]
                        gid = parts[5]
                        size = parts[6]
                        atime = parts[7]
                        mtime = parts[8]
                        ctime = parts[9]

                        # On prépare la base commune aux 3 événements
                        base_info = [filename, inode, mode, uid, gid, size]

                        # Génération des 3 lignes (Access, Modified, Change)
                        writer.writerow([self.convert_timestamp(atime), 'Access'] + base_info)
                        writer.writerow([self.convert_timestamp(mtime), 'Modified'] + base_info)
                        writer.writerow([self.convert_timestamp(ctime), 'Change'] + base_info)

                        line_count += 1

            print("[INFO] Parsing terminé. {} fichiers traités, {} lignes de timeline générées dans {}".format(
                line_count, line_count * 3, output_file))

            # Appel de la fonction de tri une fois le fichier généré
            self.sort_csv_by_date(output_file, separator)

        except Exception as e:
            print("[ERROR] Une erreur est survenue lors du parsing : {}".format(e))


def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Solution to parse a mft to more redable format'))

    argument_parser.add_argument('-b', '--bodyfile', action="store",
                                 required=True, dest="bodyfile", default=False,
                                 help="path to the bodyfile file")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=True, dest="output_dir", default=False,
                                 help="dest where the result will be written")
    return argument_parser


if __name__ == '__main__':
    arg_parser = parse_args()
    args = arg_parser.parse_args()

    disk_parser = BodyfileParser(args.bodyfile, args.output_dir)
    if args.bodyfile:
        disk_parser.parse_bodyfile(args.bodyfile, args.output_dir)
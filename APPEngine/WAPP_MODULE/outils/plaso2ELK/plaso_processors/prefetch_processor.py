#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .base_processor import BaseEventProcessor


class PlasoPrefetchProcessor(BaseEventProcessor):
    """
    Processeur Plaso pour les événements Prefetch (windows:prefetch:execution).
    MODIFIÉ: Dénormalise la liste 'mapped_files' en créant un document par fichier chargé.
    """

    def __init__(self):
        print("  [*] Initialisation du processeur Prefetch")

    def process_event(self, event: dict):  # -> (dict, str) ou Generator
        """
        Traite un événement Prefetch de Plaso.
        Retourne un générateur de documents (dict, str) si des fichiers mappés sont présents.
        """
        try:
            # 1. Gestion du Timestamp (FILETIME)
            # Le champ 'date_time' (FILETIME) représente le 'Previous Last Time Executed'
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            if dt_filetime:
                es_timestamp = self._format_dt_to_es(dt_filetime)
            else:
                # Fallback sur le timestamp plaso
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                es_timestamp = self._format_dt_to_es(dt_plaso)

            # 2. Renommer le descripteur de timestamp
            timestamp_type = event.pop("timestamp_desc", None)

            # 3. Préparation du document de base
            # On conserve tous les champs contextuels importants
            base_doc = {
                "estimestamp": es_timestamp,
                "prefetch_timestamp_type": timestamp_type,
                "executable": event.get("executable"),
                "run_count": event.get("run_count"),
                "prefetch_hash": event.get("prefetch_hash"),
                "version": event.get("version"),
                "path_hints": event.get("path_hints"),  # On garde la liste des hints telle quelle
                "volume_serial_numbers": event.get("volume_serial_numbers"),
                "volume_device_paths": event.get("volume_device_paths"),
                "filename": event.get("filename"),
                "parser": event.get("parser"),
                "data_type": event.get("data_type"),
                # On garde le message global pour le contexte
                "message": event.get("message")
            }

            mapped_files = event.get("mapped_files")

            # 4. Cas de Dénormalisation (Liste de fichiers mappés)
            if isinstance(mapped_files, list) and len(mapped_files) > 0:

                # On retire la liste originale pour ne pas indexer un gros tableau
                event.pop("mapped_files", None)

                for mapped_file in mapped_files:
                    if not isinstance(mapped_file, str):
                        continue

                    processed_doc = base_doc.copy()

                    # On stocke la chaîne complète (Chemin + [MFT Ref] si présent)
                    # Conformément à votre demande, on ne découpe plus cette chaîne.
                    processed_doc["mapped_file"] = mapped_file

                    # Nettoyage final
                    self.drop_useless_fields(processed_doc)
                    yield processed_doc, "prefetch"

                return  # Fin du traitement dénormalisé

            # 5. Cas Standard (Pas de fichiers mappés ou liste vide)
            # On renvoie l'événement tel quel (le 'run' principal)

            # On garde mapped_files s'il est vide ou absent (peu probable mais possible)
            event.update(base_doc)
            self.drop_useless_fields(event)

            return event, "prefetch"

        except Exception as e:
            # En cas d'erreur, on renvoie un doc d'erreur
            error_doc = {
                "message": f"Prefetch parsing failed: {e}",
                "raw_event_line": event.get("event_raw_string")
            }
            return error_doc, "prefetch"
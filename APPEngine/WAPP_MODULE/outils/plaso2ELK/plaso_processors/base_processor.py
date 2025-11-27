#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta, timezone
import re


class BaseEventProcessor:
    """Classe de base abstraite pour tous les processeurs d'événements Plaso."""

    # Époque pour les OLE Automation Timestamps (30/12/1899)
    _OLE_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)

    def process_event(self, event: dict) -> (dict, str):
        """Méthode de traitement principale pour un événement Plaso."""
        raise NotImplementedError("La méthode process_event doit être implémentée par la sous-classe.")

    @staticmethod
    def drop_useless_fields(event: dict):
        """
        Supprime les champs Plaso "verbeux" et redondants pour nettoyer le document final.
        Modifie l'événement sur place.
        """

        l_field_to_drop = [
            "__container_type__",
            "__type__",
            "date_time",
            "_event_values_hash",
            "display_name",
            "inode",
            "pathspec",
            "strings",
            "xml_string",
            "event_version",
            "message_identifier",
            "offset",
            "provider_identifier",
            "recovered",
            "timestamp"
        ]

        for field in l_field_to_drop:
            event.pop(field, None)
        return event

    @staticmethod
    def _parse_filetime_to_dt(filetime_int):
        """
        Convertit un Windows FILETIME (intervalles de 100 ns depuis 1601)
        en objet datetime UTC.
        """
        if not isinstance(filetime_int, int): return None
        try:
            # Époque FILETIME (1601-01-01 UTC)
            _FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
            # Convertir les intervalles de 100 ns en microsecondes
            microseconds = filetime_int / 10
            return _FILETIME_EPOCH + timedelta(microseconds=microseconds)
        except Exception:
            return None

    @staticmethod
    def _parse_unix_micro_to_dt(unix_micro):
        """
        Convertit un timestamp Unix (microsecondes) en objet datetime UTC.
        """
        if not isinstance(unix_micro, int): return None
        try:
            # Convertir les microsecondes en secondes
            return datetime.fromtimestamp(unix_micro / 1e6, tz=timezone.utc)
        except Exception:
            return None

    @staticmethod
    def _parse_iso_string_to_dt(iso_string):
        """
        Convertit une chaîne ISO 8601 (comme celle d'EVTX) en objet datetime UTC.
        """
        if not iso_string: return None
        try:
            # Tronque les nanosecondes (9 chiffres) en microsecondes (6 chiffres)
            iso_string = re.sub(r'(\.\d{6})\d+Z$', r'\1Z', iso_string)
            return datetime.strptime(iso_string, '%Y-%m-%dT%H:%M:%S.%f%z')
        except ValueError:
            try:
                return datetime.strptime(iso_string, '%Y-%m-%dT%H:%M:%S%z')
            except Exception:
                return None  # Échec de l'analyse
        except Exception:
            return None

    @classmethod
    def _parse_ole_automation_date_to_dt(cls, ole_float):
        """
        Convertit un OLE Automation Date (float) en objet datetime UTC.
        """
        if not isinstance(ole_float, (float, int)):
            return None
        try:
            # L'époque est 30/12/1899
            return cls._OLE_EPOCH + timedelta(days=ole_float)
        except Exception:
            return None

    @staticmethod
    def _format_dt_to_es(dt_obj):
        """
        Formate un objet datetime en une chaîne ISO compatible avec Elasticsearch.
        """
        if not isinstance(dt_obj, datetime): return None
        # S'assurer qu'il est UTC
        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        # Formater en ISO 8601 avec 'Z'
        return dt_obj.isoformat(timespec='microseconds').replace('+00:00', 'Z')

    @staticmethod
    def _parse_time_elements_to_dt(time_tuple):
        """
        Convertit un tuple (Y, M, D, H, m, s) en objet datetime UTC.
        Utilisé par Amcache.
        """
        if not isinstance(time_tuple, list) or len(time_tuple) < 6:
            return None
        try:
            # (Année, Mois, Jour, Heure, Minute, Seconde)
            return datetime(
                time_tuple[0], time_tuple[1], time_tuple[2],
                time_tuple[3], time_tuple[4], time_tuple[5],
                tzinfo=timezone.utc
            )
        except Exception:
            return None
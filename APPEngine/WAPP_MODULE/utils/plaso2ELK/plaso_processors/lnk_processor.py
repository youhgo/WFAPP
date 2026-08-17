#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from .base_processor import BaseEventProcessor


class PlasoLnkProcessor(BaseEventProcessor):
    """
    Processeur Plaso pour les événements LNK (windows:lnk:link) et JumpLists.
    Consolide les multiples champs de chemin en un champ unique 'lnk_path'.
    """

    def __init__(self):
        print("  [*] Initialisation du processeur LNK")
        # Regex pour nettoyer les artifacts de shell items (ex: "<My Computer> C:\...")
        self.shell_item_cleaner = re.compile(r'^<[^>]+>\s*')

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement LNK de Plaso."""
        try:
            timestamp_desc = event.get("timestamp_desc", "")

            # 1. Gestion du Timestamp
            # Priorité au FATDateTime si présent (typique des LNK), sinon timestamp standard
            if timestamp_desc == "Not a time" or event.get("timestamp") == 0:
                dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                event["estimestamp"] = self._format_dt_to_es(dt_plaso)
            else:
                # C'est un vrai timestamp (Creation, Modif, etc.)
                dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
                if dt_filetime:
                    event["estimestamp"] = self._format_dt_to_es(dt_filetime)
                else:
                    # Fallback pour FATDateTime ou autre
                    dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
                    event["estimestamp"] = self._format_dt_to_es(dt_plaso)

            # 2. Renommer le descripteur
            if "timestamp_desc" in event:
                event["lnk_timestamp_type"] = event.pop("timestamp_desc")

            # 3. Consolidation du Chemin (La partie importante)
            # On cherche le chemin le plus complet dans l'ordre de préférence

            final_path = None

            # Candidats possibles
            local_path = event.get("local_path")
            network_path = event.get("network_target")
            link_target = event.get("link_target")
            shell_item_path = event.get("shell_item_path")
            # Parfois le chemin est dans 'message' sous forme "Local path: ..." ou "Shell item path: ..."

            if local_path:
                final_path = local_path
            elif network_path:
                final_path = network_path
            elif link_target:
                # link_target contient souvent "<My Computer> C:\..."
                final_path = self.shell_item_cleaner.sub('', link_target)
            elif shell_item_path:
                final_path = self.shell_item_cleaner.sub('', shell_item_path)

            # Nettoyage final des double backslashes si nécessaire (souvent doublés dans le JSON)
            if final_path:
                # On normalise les slashes
                final_path = final_path.replace('\\\\', '\\')
                event["lnk_path"] = final_path

            # 4. Nettoyage
            # On garde les champs originaux s'ils sont utiles, mais on peut supprimer les redondances
            # si on est sûr de 'lnk_path'. Ici, je les garde pour référence.
            self.drop_useless_fields(event)

            # 5. Clé d'index
            return event, "lnk"

        except Exception as e:
            # print(f"[ERREUR] Échec de process_lnk_event: {e}")
            return self.drop_useless_fields(event), "lnk"
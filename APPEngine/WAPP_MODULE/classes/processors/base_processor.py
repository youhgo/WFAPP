#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class BaseFileProcessor:
    """Classe de base abstraite pour tous les processeurs de fichiers."""
    def process_file(self, filepath: str, **kwargs):
        raise NotImplementedError("La méthode process_file doit être implémentée par la sous-classe.")

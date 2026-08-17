import re

class BaseFileProcessor:
    """Classe de base abstraite pour tous les processeurs de fichiers."""
    
    DEFAULT_PATTERNS = {}

    def __init__(self, case_name="unknown", machine_name="unknown"):
        self.case_name = case_name
        self.machine_name = machine_name
        
    @classmethod
    def get_dataset_for_file(cls, filename: str) -> str:
        """Retourne le dataset correspondant si le nom de fichier matche un pattern."""
        for pattern, dataset in cls.DEFAULT_PATTERNS.items():
            if re.match(pattern, filename, re.IGNORECASE):
                return dataset
        return None

    def process_file(self, filepath: str, **kwargs):
        raise NotImplementedError("La méthode process_file doit être implémentée par la sous-classe.")

    def inject_wapp_info(self, log_data: dict) -> dict:
        """Méthode utilitaire pour injecter les métadonnées dans chaque log."""
        # Utilisation de getattr pour sécuriser la lecture des variables
        log_data['wapp_info'] = {
            'case_name': getattr(self, 'case_name', 'unknown'),
            'machine_name': getattr(self, 'machine_name', 'unknown')
        }
        return log_data
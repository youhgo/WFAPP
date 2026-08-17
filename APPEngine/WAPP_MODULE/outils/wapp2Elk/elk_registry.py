from typing import Type, Dict, List, Any

# Registre global des processeurs ELK
ELK_PROCESSORS_REGISTRY: Dict[str, List[Type[Any]]] = {}

def register_elk_processor(name: str):
    """
    Décorateur pour enregistrer automatiquement un processeur ELK.
    
    :param name: Le nom de la catégorie / l'index cible (ex: 'evtx', 'registry', 'processes').
    """
    def decorator(cls):
        if name not in ELK_PROCESSORS_REGISTRY:
            ELK_PROCESSORS_REGISTRY[name] = []
        cls.__processor_name__ = name
        ELK_PROCESSORS_REGISTRY[name].append(cls)
        return cls
    return decorator

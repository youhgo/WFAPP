from typing import Type, Dict, Any

# Registre global des pipelines
PIPELINE_REGISTRY: Dict[str, Type[Any]] = {}


def register_pipeline(name: str):
    """
    Décorateur pour enregistrer automatiquement un pipeline.
    
    :param name: Le nom de configuration du pipeline (ex: 'evtx', 'mft').
                 Ceci doit correspondre à la clé utilisée dans main_config.json.
    """
    def decorator(cls):
        if name in PIPELINE_REGISTRY:
            raise ValueError(f"Un pipeline avec le nom '{name}' est déjà enregistré ({PIPELINE_REGISTRY[name]}).")
        cls.__pipeline_name__ = name
        PIPELINE_REGISTRY[name] = cls
        return cls
    return decorator

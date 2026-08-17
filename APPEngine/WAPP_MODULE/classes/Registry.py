from typing import Type, Dict, Any

# Registres globaux pour l'auto-découverte
PIPELINE_REGISTRY: Dict[str, Type['BaseArtefactPipeline']] = {}
POSTPROCESSOR_REGISTRY: Dict[str, Type['BasePostProcessor']] = {}
PREPROCESSOR_REGISTRY: Dict[str, Type['BasePreProcessor']] = {}


def register_pipeline(name: str):
    """
    Decorator to automatically register a pipeline.
    
    :param name: The pipeline configuration name (e.g., 'evtx', 'mft').
                 This must match the key used in main_config.json.
    """
    def decorator(cls):
        if name in PIPELINE_REGISTRY:
            raise ValueError(f"A pipeline with the name '{name}' is already registered ({PIPELINE_REGISTRY[name]}).")
        cls.__pipeline_name__ = name
        PIPELINE_REGISTRY[name] = cls
        return cls
    return decorator

def register_postprocessor(name: str):
    """
    Decorator to automatically register a post-processor.
    
    :param name: The post-processor configuration name (e.g., 'plaso', 'elk').
    """
    def decorator(cls):
        if name in POSTPROCESSOR_REGISTRY:
            raise ValueError(f"A post-processor with the name '{name}' is already registered ({POSTPROCESSOR_REGISTRY[name]}).")
        cls.__postprocessor_name__ = name
        POSTPROCESSOR_REGISTRY[name] = cls
        return cls
    return decorator

def register_preprocessor(name: str):
    """
    Decorator to automatically register a pre-processor.
    """
    def decorator(cls):
        if name in PREPROCESSOR_REGISTRY:
            raise ValueError(f"A pre-processor with the name '{name}' is already registered.")
        cls.__preprocessor_name__ = name
        PREPROCESSOR_REGISTRY[name] = cls
        return cls
    return decorator

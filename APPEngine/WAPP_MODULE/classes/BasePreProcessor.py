from abc import ABC, abstractmethod
from typing import List
from .WappContext import WappContext

class BasePreProcessor(ABC):
    """
    Base class for all pre-processing plugins (extraction, renaming, restoration, etc.).
    """
    
    # Execution priority. The lower the number, the earlier the plugin executes.
    # Ex: ExtractPreProcessor=0, RestorePreProcessor=10, RenamePreProcessor=20
    priority: int = 100
    
    # List of configuration keys of pre-processors that MUST execute before this one.
    requires: List[str] = []
    
    # Defines if the plugin is recommended for general use.
    recommended: bool = True
    
    # Defines if the plugin is enabled by default, even if not mentioned in the config.
    default_enabled: bool = False

    def __init__(self, context: WappContext):
        self.context = context
        self.logger = context.logger

    @abstractmethod
    def run(self) -> None:
        """
        Main method to override. Contains the pre-processor execution logic.
        """
        pass

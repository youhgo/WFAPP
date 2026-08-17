from abc import ABC, abstractmethod
from typing import List

from .WappContext import WappContext


class BasePostProcessor(ABC):
    """
    Base class for all post-processors and exports (Plaso, ELK, Wazuh, etc.).
    """
    
    # Execution order: the lower the number, the earlier the post-processor executes.
    priority: int = 100
    
    # List of configuration keys of post-processors that MUST execute before this one.
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
        Main method to implement to execute post-processing.
        """
        pass

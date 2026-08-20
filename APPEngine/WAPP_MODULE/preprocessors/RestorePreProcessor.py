from ..classes.BasePreProcessor import BasePreProcessor
from ..classes.Registry import register_preprocessor
from ..classes.OrcExtractor import ArtefactRestorer

@register_preprocessor('restore')
class RestorePreProcessor(BasePreProcessor):
    """
    Rebuilds the complete tree (Virtual FS) instead of a flat folder.
    Takes time if there are many files.
    """
    recommended = False
    importance = "Optional"
    speed = "Fast"
    priority = 10
    requires = ['extract']
    default_enabled = False

    def run(self) -> None:
        # If the "restore" configuration is not requested, or if not on an ORC, we skip.
        # The dispatcher checks is_enabled via config, so if it's here, it means it's enabled.
        restorer = ArtefactRestorer(str(self.context.extracted_dir), str(self.context.restored_path), self.logger)
        restorer.run()

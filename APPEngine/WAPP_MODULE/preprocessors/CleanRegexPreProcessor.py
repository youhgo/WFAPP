from ..classes.BasePreProcessor import BasePreProcessor
from ..classes.Registry import register_preprocessor
from ..classes.OrcRenamer import OrcRenamer

class CleanRegexPreProcessor(BasePreProcessor):
    """
    Fast Regex renaming (Fallback).
    Executed automatically in the background (without GUI).
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"
    priority = 30
    requires = ['extract']
    default_enabled = True

    def run(self) -> None:
        renamer = OrcRenamer(self.context)
        renamer.rename_with_regex(self.context.extracted_dir)

# Manual registration to hide it from GUI's ast_parser
register_preprocessor('clean_regex')(CleanRegexPreProcessor)

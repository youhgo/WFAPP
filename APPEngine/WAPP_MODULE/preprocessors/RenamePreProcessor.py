from ..classes.BasePreProcessor import BasePreProcessor
from ..classes.Registry import register_preprocessor
from ..classes.OrcRenamer import OrcRenamer

@register_preprocessor('rename_from_orc')
class RenamePreProcessor(BasePreProcessor):
    """
    Renames files extracted by DFIR-ORC using GetThis.csv file mappings.
    (Slow, so disabled by default. Must be checked by the user if desired).
    """
    recommended = False
    importance = "Optionnal"
    speed = "Slow"
    priority = 20
    requires = ['extract']
    default_enabled = False

    def run(self) -> None:
        renamer = OrcRenamer(self.context)
        renamer.rename_with_getthis(self.context.extracted_dir)

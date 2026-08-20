import traceback
from ..classes.BasePostProcessor import BasePostProcessor
from ..classes.Registry import register_postprocessor
from ..parsers import MaximumPlasoParserJson

@register_postprocessor('mpp')
class MppPostProcessor(BasePostProcessor):
    """
    Maximum Plaso Parser. 
    Converts Plaso JSON events into a sorted CSV file tree.
    Allows quick viewing of the most interesting artifacts like connection, mft, etc.
    format : DATETIME|TYPE|ENTRIE|ETC|ETC
    """
    recommended = True
    importance = "Highly recommended"
    speed = "Fast"

    priority = 20
    requires = ['plaso']

    def run(self) -> None:
        """
        Launch Maximum plaso parser, a parser for json plaso timeline that convert a timeline to lot of differents
        artefacts files formated in human friendly format : DATE|TIME|ETC|ETC
        """
        timeline_json_path = self.context.timeline_dir / "timeline.json"
        try:
            self.logger.info("[MAXIMUMPLASOPARSER]", header="START", indentation=1)
            parser = MaximumPlasoParserJson.MaximumPlasoParser(
                path_to_timeline=str(timeline_json_path),
                output_directory=str(self.context.parsed_dir),
                separator=self.context.separator,
                machine_name=self.context.machine_name
            )
            parser.parse_timeline()
            self.logger.info("[MAXIMUMPLASOPARSER]", header="FINISHED", indentation=1)
        except Exception as e:
            self.logger.error("[MAXIMUMPLASOPARSER] {}".format(traceback.format_exc()), header="ERROR", indentation=1)

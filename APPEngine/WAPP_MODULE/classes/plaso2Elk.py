from pathlib import Path
import argparse
from datetime import datetime
import json
from lxml import etree
import traceback
import re
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk, streaming_bulk  # Added import for the bulk helper
import warnings
from urllib3.exceptions import InsecureRequestWarning
import os

warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class PlasoToELK:
    """
       Class MaximumPlasoParser
       MPP or MaximumPlasoParser is a python script that will parse a plaso - Log2Timeline json timeline file.
       The goal is to provide easily readable and straight forward files for the Forensic analyst.
       MPP will create a file for each artefact.
       Attributes :
       None
    """

    def __init__(self, path_to_timeline, case_name=None, machine_name=None, is_flat=False, elk_host="localhost",
                 elk_port="9200", elk_user="elastic", elk_password="changeme") -> None:
        """
        Constructor for classes Plaso to ELK

         Args:
             path_to_timeline (str): path to the timeline to send
             case_name (str): Name of the case, will be inside the index.
             machine_name (str): Name of the machine, will be inside the index.
             is_flat (str): Set to true to flatten all the json field to top level, better for Kibana Vue but can explode index field and slow down searchs
             elk_host (str): elastic ip addr
             elk_port (str): elastic port
             elk_user (str): user for elk
             elk_password (str): password for user for elk

         Returns:
             type: (PlasoToELK)
         """

        if not os.environ.get('ELK_HOST'): self.elk_host = elk_host
        else : self.elk_host = os.environ.get('ELK_HOST')

        if not os.environ.get('ELK_PORT'): self.elk_port = elk_port
        else: self.elk_port = os.environ.get('ELK_PORT')

        if not os.environ.get('ELK_USER'): self.elk_user = elk_user
        else: self.elk_user = os.environ.get('ELK_USER')

        if not os.environ.get('ELK_PASSWD'): self.elk_password = elk_password
        else: self.elk_password = os.environ.get('ELK_PASSWD')

        # Initialize the Elasticsearch client using the environment variables
        self.elk_client = Elasticsearch(
            f"https://{self.elk_host}:{ self.elk_port}",
            basic_auth=(self.elk_user, self.elk_password),
            ca_certs=False,
            verify_certs=False
        )

        self.path_to_timeline = path_to_timeline
        self.case_name = case_name
        self.machine_name = machine_name


        self.is_flat = is_flat
        self.id = 1
        self.index = "{}_{}".format(self.case_name, self.machine_name)
        self.mapping = {}
        self.settings = {}

    def test_connection(self):
        """
        Tests the connection to the Elasticsearch cluster.

        Returns:
            bool: True if the connection is successful, False otherwise.
        """
        try:
            if self.elk_client.ping():
                print("Successfully connected to Elasticsearch.")
                return True
            else:
                print("Could not connect to Elasticsearch. The server might be down or unreachable.")
                return False
        except Exception as e:
            print(f"An error occurred while trying to connect to Elasticsearch: {e}")
            return False

    def initialise_elk_client(self):

        if not self.elk_client.indices.exists(index=self.index):
            settings = {
                "index": {
                    "mapping": {
                        "total_fields": {
                            "limit": 10000
                        }
                    }
                }
            }
            es_mapping = {
                "dynamic_templates": [
                    {
                        "nombres_entiers_en_keyword": {
                            "match_mapping_type": "long",
                            "mapping": {
                                "type": "keyword"
                            }
                        }
                    },
                    {
                        "nombres_flottants_en_keyword": {
                            "match_mapping_type": "double",
                            "mapping": {
                                "type": "keyword"
                            }
                        }
                    },
                    {
                        "booleens_en_keyword": {
                            "match_mapping_type": "boolean",
                            "mapping": {
                                "type": "keyword"
                            }
                        }
                    }
                ],
                "properties": {
                    "message": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    },
                    "EventFromData": {
                        "type": "object",
                        "dynamic": True
                    },
                    "estimestamp": {
                        "type": "date",
                        "format": "strict_date_optional_time||epoch_millis"
                    }
                }
            }


            self.elk_client.indices.create(index=self.index, body={
                "mappings": es_mapping,
                "settings": settings
            })
            print(f"Index '{self.index}' created successfully with custom nested mapping.")
        else:
            print(f"Index '{self.index}' already exists. Skipping creation.")

    def identify_type_artefact_by_parser(self, line):
        """
        Function to indentify an artefact type depending on the plaso parser used
        :param line: (dict) dict containing one line of the plaso timeline,
        :return: (dict(key))|(str) the key containing the name of the artefact associated with the parser
        """
        d_regex_type_artefact = {
            "evtx": re.compile(r'winevtx'),
            "hive": re.compile(r'winreg'),
            "db": re.compile(r'(sqlite)|(esedb)'),
            "lnk": re.compile(r'lnk'),
            "prefetch": re.compile(r'prefetch'),
            "winFile": re.compile(r'(lnk)|(text)|(prefetch)'),
            "mft": re.compile(r'(filestat)|(usnjrnl)|(mft)')
        }
        for key, value in d_regex_type_artefact.items():
            if re.search(value, line.get("parser")):
                return key

    def parse_xml_to_flat_json(self, event):
        """
        Lit une clé "xml_string", parse le XML et le transforme en un dictionnaire
        Python parfaitement plat, optimisé pour les logs d'événements Windows.
        """
        l_field_to_drop = ["__container_type__", "__type__", "date_time", "_event_values_hash",
                           "display_name", "inode", "is_allocated", "pathspec", "strings", "file_reference",
                           "event_level", "event_version", "message", "message_identifier", "offset", "record_number",
                           "recovered", "provider_identifier", "xml_string"]

        xml_string = event.get("xml_string")
        if not xml_string:
            return {}

        flat_dict = {}

        def _flatten_recursive(element, prefix=''):
            """
            Fonction récursive qui utilise l'attribut 'Name' pour créer des clés uniques.
            """
            tag = element.tag.split('}')[-1]

            children = list(element)
            if children:
                for child in children:
                    child_tag = child.tag.split('}')[-1]

                    name_attr = child.attrib.get('Name')
                    if name_attr:
                        new_key = f"{prefix}{tag}.{name_attr}"
                        value = ''.join(child.itertext()).strip()
                        if value:
                            flat_dict[new_key] = value
                    else:
                        _flatten_recursive(child, prefix=f"{prefix}{tag}.")

            # Traitement du texte de l'élément courant s'il n'a pas d'enfants
            elif element.text:
                text = element.text.strip()
                if text:
                    key_for_text = f"{prefix.rstrip('.')}.Value"
                    flat_dict[key_for_text] = text

            for attr_name, attr_value in element.attrib.items():
                if attr_name != 'Name':
                    attr_key = f"{prefix}{tag}@{attr_name}"
                    flat_dict[attr_key] = attr_value

        try:
            parser = etree.XMLParser(recover=True, encoding='utf-8')
            root = etree.fromstring(xml_string.encode('utf-8'), parser=parser)

            _flatten_recursive(root)

            root_tag = root.tag.split('}')[-1]
            final_flat_dict = {k.replace(f"{root_tag}.", '', 1): v for k, v in flat_dict.items()}

        except etree.XMLSyntaxError as e:
            print(f"Erreur de syntaxe XML : {e}")
            return {}

        event["filename"] = self.format_filename_to_es(event.get("filename"))
        event["estimestamp"] = self.format_ts_to_es(event.get("timestamp"))
        event["EventFromData"] = final_flat_dict
        for field in l_field_to_drop:
            event.pop(field, None)

        return event

    def drop_useless_fields(self, event):
        try:
            l_field_to_drop = ["__container_type__", "__type__", "date_time", "_event_values_hash",
                               "display_name", "inode", "is_allocated", "pathspec", "strings", "file_reference"]

            event["filename"] = self.format_filename_to_es(event.get("filename"))
            event["estimestamp"] = self.format_ts_to_es(event.get("timestamp"))

            for field in l_field_to_drop:
                event.pop(field, None)

            return event
        except:
            print(traceback.format_exc())
            return None

    def generate_documents(self):
        """
        Generator function to read the timeline file line by line
        and yield formatted documents for bulk ingestion.
        """
        it = 0
        with open(self.path_to_timeline) as timeline:
            for line in timeline:
                try:
                    # os.system('cls' if os.name=='nt' else 'clear')
                    it += 1
                    # print("processing line : {}".format(it))
                    if it % 20000 == 0:
                        print("processing line : {}".format(it))

                    d_line = json.loads(line)
                    artefact_type = self.identify_type_artefact_by_parser(d_line)
                    if artefact_type == "evtx":
                        formatted_event = self.parse_xml_to_flat_json(d_line)
                    else:
                        formatted_event = self.drop_useless_fields(d_line)

                    if formatted_event:
                        # Yield the document in the format required by the bulk helper
                        yield {
                            "_index": self.index,
                            "_source": formatted_event
                        }
                except json.JSONDecodeError:
                    print(f"Could not load json line, skipping: {line.strip()}")
                    continue
                except Exception as e:
                    print(f"An error occurred while processing line: {e}")
                    print(traceback.format_exc())
                    continue

    def send_to_elk_in_bulk(self):
        """
        Bulk ingestion with immediate error reporting.
        """
        if not self.test_connection():
            return

        print("Starting bulk ingestion...")
        self.initialise_elk_client()

        docs_generator = self.generate_documents()

        success_count = 0
        fail_count = 0

        try:
            for ok, result in streaming_bulk(
                    self.elk_client,
                    docs_generator,
                    chunk_size=20000,
                    raise_on_error=False,
                    raise_on_exception=False
            ):
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    # Print the error immediately
                    print("\nFailed document:")
                    print(json.dumps(result, indent=2))

            print("\nIngestion complete.")
            print(f"Successfully indexed {success_count} documents.")
            print(f"Failed to index {fail_count} documents.")

        except Exception as e:
            print("⚠️ Bulk ingestion crashed with exception:")
            print(e)

    def format_ts_to_es(self, timestamp_ms):
        date_object = datetime.fromtimestamp(timestamp_ms / 1e6)
        iso_format = date_object.isoformat() + "Z"
        return iso_format

    def format_filename_to_es(self, file_name):
        p = Path(file_name)
        return f"{p.parent.name}/{p.name}"

def parse_args():
    """
        Function to parse args
    """

    argument_parser = argparse.ArgumentParser(description=(
        'Solution to parse a json plaso timeline'))

    argument_parser.add_argument('-t', '--timeline', action="store",
                                 required=True, dest="timeline", default=False,
                                 help="path to the timeline , must be json timeline")

    argument_parser.add_argument("-o", "--output", action="store",
                                 required=False, dest="output_dir", default=False,
                                 help="dest where the result will be written")

    argument_parser.add_argument("-c", "--casename", action="store",
                                 required=True, dest="case_name", default=None,
                                 help="name of the case u working on")

    argument_parser.add_argument("-m", "--machine_name", action="store",
                                 required=True, dest="machine_name",
                                 metavar="name of the machine",
                                 help="name of the machine")

    argument_parser.add_argument("--ip", action="store",
                                 required=False, dest="elk_ip", default="localhost",
                                 metavar="address of elastic",
                                 help="address of elasticsearch")

    argument_parser.add_argument("--port", action="store",
                                 required=False, dest="elk_port", default="9200",
                                 metavar="port of elastic",
                                 help="port of elasticsearch")

    argument_parser.add_argument("--flat", action="store_true",
                                 required=False, dest="is_flat",
                                 help="Set to True to flatten json before sending")

    return argument_parser


if __name__ == '__main__':
    parser = parse_args()
    args = parser.parse_args()
    plaso_to_elk = PlasoToELK(path_to_timeline=args.timeline,
                              case_name=args.case_name,
                              machine_name=args.machine_name,
                              is_flat=args.is_flat,
                              elk_ip=args.elk_ip,
                              elk_port=args.elk_port)
    plaso_to_elk.send_to_elk_in_bulk()



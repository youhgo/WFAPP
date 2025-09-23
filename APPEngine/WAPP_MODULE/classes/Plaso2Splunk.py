import json
import re
import traceback
import argparse
import requests
from pathlib import Path
from datetime import datetime
from lxml import etree
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3 needed for self-signed certs
warnings.filterwarnings('ignore', category=InsecureRequestWarning)


class PlasoToSplunk:
    """
    Parses a Plaso JSON timeline file and sends the events to a Splunk instance
    via the HTTP Event Collector (HEC).
    """

    def __init__(self, path_to_timeline, splunk_host, splunk_token, splunk_index,
                 machine_name=None, splunk_port=8088, is_flat=False) -> None:
        """
        Constructor for the PlasoToSplunk classes.

        Args:
            path_to_timeline (str): Path to the Plaso JSON timeline.
            splunk_host (str): Hostname or IP of the Splunk instance.
            splunk_token (str): Splunk HTTP Event Collector (HEC) token.
            splunk_index (str): Splunk index to send data to.
            machine_name (str, optional): Name of the source machine for the 'host' field. Defaults to None.
            splunk_port (int, optional): Splunk HEC port. Defaults to 8088.
            is_flat (bool, optional): Flattens XML data if True. Defaults to False.
        """
        self.path_to_timeline = path_to_timeline
        self.splunk_hec_url = f"https://{splunk_host}:{splunk_port}/services/collector"
        self.splunk_token = splunk_token
        self.splunk_index = splunk_index
        self.machine_name = machine_name
        self.is_flat = is_flat
        self.headers = {'Authorization': f'Splunk {self.splunk_token}'}

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
            if re.search(value, line.get("parser", "")):
                return key
        return "unknown"  # Return a default sourcetype

    def parse_xml_to_flat_json(self, event):
        """
        Reads a "xml_string" key, parses the XML, and transforms it into a
        flat Python dictionary, optimized for Windows event logs.
        """
        l_field_to_drop = ["__container_type__", "__type__", "date_time", "_event_values_hash",
                           "display_name", "inode", "is_allocated", "pathspec", "strings", "file_reference",
                           "event_level", "event_version", "message", "message_identifier", "offset", "record_number",
                           "recovered", "provider_identifier", "xml_string"]

        xml_string = event.get("xml_string")
        if not xml_string:
            return event

        flat_dict = {}

        def _flatten_recursive(element, prefix=''):
            tag = element.tag.split('}')[-1]
            children = list(element)
            if children:
                for child in children:
                    name_attr = child.attrib.get('Name')
                    if name_attr:
                        new_key = f"{prefix}{tag}.{name_attr}"
                        value = ''.join(child.itertext()).strip()
                        if value:
                            flat_dict[new_key] = value
                    else:
                        _flatten_recursive(child, prefix=f"{prefix}{tag}.")
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
            print(f"XML syntax error: {e}")
            return event

        event["EventFromData"] = final_flat_dict
        for field in l_field_to_drop:
            event.pop(field, None)
        return event

    def drop_useless_fields(self, event):
        """Removes common, noisy fields from a Plaso event."""
        l_field_to_drop = ["__container_type__", "__type__", "date_time", "_event_values_hash",
                           "display_name", "inode", "is_allocated", "pathspec", "strings", "file_reference"]
        for field in l_field_to_drop:
            event.pop(field, None)
        return event

    def format_ts_to_splunk_epoch(self, timestamp_us):
        """Converts Plaso microsecond timestamp to Splunk-compatible epoch time (seconds)."""
        return timestamp_us / 1e6

    def _send_batch(self, batch):
        """Helper function to send a batch of events to HEC."""
        if not batch:
            return True
        payload = "".join(batch)
        try:
            response = requests.post(self.splunk_hec_url, headers=self.headers, data=payload.encode('utf-8'),
                                     verify=False)
            response.raise_for_status()  # Raises an exception for bad status codes (4xx or 5xx)
            if response.json().get("code") != 0:
                print(f"❌ Splunk HEC Error: {response.text}")
                return False
            return True
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to send batch to Splunk: {e}")
            return False

    def send_to_splunk(self, chunk_size=1000):
        """
        Reads the timeline, processes events, and sends them to Splunk HEC in batches.
        """
        print(f"Starting ingestion to Splunk index '{self.splunk_index}'...")
        batch = []
        it = 0
        success_count = 0

        with open(self.path_to_timeline, 'r', encoding='utf-8') as timeline:
            for line in timeline:
                it += 1
                if it % 20000 == 0:
                    print(f"Processing line: {it}")
                try:
                    event_data = json.loads(line)
                    artefact_type = self.identify_type_artefact_by_parser(event_data)

                    # Process the event based on its type
                    if artefact_type == "evtx" and self.is_flat:
                        processed_event = self.parse_xml_to_flat_json(event_data)
                    else:
                        processed_event = self.drop_useless_fields(event_data)

                    # Construct the HEC payload for this event
                    hec_event = {
                        "time": self.format_ts_to_splunk_epoch(processed_event.pop("timestamp")),
                        "host": self.machine_name or processed_event.get("hostname", "unknown_host"),
                        "index": self.splunk_index,
                        "sourcetype": f"plaso:{artefact_type}",
                        "source": processed_event.get("filename", self.path_to_timeline),
                        "event": processed_event
                    }
                    batch.append(json.dumps(hec_event))

                    # Send the batch if it reaches the chunk size
                    if len(batch) >= chunk_size:
                        if self._send_batch(batch):
                            success_count += len(batch)
                            print(f"✅ Sent {success_count} events...")
                        else:
                            print("Stopping due to send failure.")
                            return
                        batch = []  # Reset batch

                except json.JSONDecodeError:
                    print(f"Could not load json line, skipping: {line.strip()}")
                except Exception:
                    print(f"An error occurred while processing line {it}:")
                    print(traceback.format_exc())

        # Send any remaining events in the last batch
        if self._send_batch(batch):
            success_count += len(batch)

        print("\nIngestion complete.")
        print(f"✅ Total events successfully sent: {success_count}")


def parse_args():
    """Function to parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Parse a Plaso JSON timeline and send it to Splunk HEC.')
    parser.add_argument('-t', '--timeline', required=True, dest="timeline",
                        help="Path to the Plaso JSON timeline file.")
    parser.add_argument("-m", "--machine_name", required=True, dest="machine_name",
                        help="Name of the machine (will be the 'host' field in Splunk).")
    parser.add_argument("--shost", required=True, dest="splunk_host", help="Address of Splunk HEC.")
    parser.add_argument("--stoken", required=True, dest="splunk_token", help="Splunk HEC token.")
    parser.add_argument("--sindex", required=True, dest="splunk_index", help="Splunk index for the data.")
    parser.add_argument("--sport", dest="splunk_port", default=8088, type=int,
                        help="Port of Splunk HEC (default: 8088).")
    parser.add_argument("--flat", action="store_true", dest="is_flat",
                        help="Set to True to flatten XML in events before sending.")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    plaso_to_splunk = PlasoToSplunk(
        path_to_timeline=args.timeline,
        splunk_host=args.splunk_host,
        splunk_port=args.splunk_port,
        splunk_token=args.splunk_token,
        splunk_index=args.splunk_index,
        machine_name=args.machine_name,
        is_flat=args.is_flat
    )
    plaso_to_splunk.send_to_splunk()

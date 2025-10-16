#!/usr/bin/python3
import argparse
import json
import os
import re
import csv
import sys
from pathlib import Path


class EventParser:
    """
    Classe pour parser des fichiers journaux d'événements (EVTX) au format JSON
    vers un format CSV lisible par l'homme. Cette version est refactorisée pour
    utiliser une logique modulaire, la rendant plus évolutive et maintenable.
    """

    def __init__(self, events_json_directory, output_directory, separator="|"):
        """
        Constructeur pour la classe EventParser.
        """
        self.work_dir = events_json_directory
        self.output_directory = output_directory
        self.separator = separator

        # --- En-têtes CSV centralisés ---
        self.csv_headers = {
            "4624": ["Date", "Time", "event_code", "subject_user_name", "target_user_name", "ip_address", "ip_port",
                     "logon_type"],
            "4625": ["Date", "Time", "event_code", "logon_type", "subject_user_name", "target_user_name", "ip_address",
                     "ip_port", "failure_reason"],
            "4672": ["Date", "Time", "event_code", "logon_type", "subject_user_name", "target_user_name", "ip_address",
                     "ip_port"],
            "4648": ["Date", "Time", "event_code", "logon_type", "subject_user_name", "target_user_name", "ip_address",
                     "ip_port"],
            "4688": ["Date", "Time", "event_code", "subject_user_name", "target_user_name", "parent_process_name",
                     "new_process_name", "command_line"],
            "tscheduler": ["Date", "Time", "event_code", "name", "task_name", "instance_id", "action_name",
                           "result_code", "user_name", "user_context"],
            "remote_rdp": ["Date", "Time", "event_code", "user_name", "ip_addr"],
            "local_rdp": ["Date", "Time", "event_code", "user_name", "ip_addr", "session_id", "source",
                          "target_session", "reason_n", "reason"],
            "bits": ["Date", "Time", "event_code", "id", "job_id", "job_title", "job_owner", "user", "bytes_total",
                     "bytes_transferred", "file_count", "file_length", "file_Time", "name", "url", "process_path"],
            "7045": ["Date", "Time", "event_code", "account_name", "img_path", "service_name", "start_type"],
            "script_powershell": ["Date", "Time", "event_code", "path_to_script", "script_block_text"],
            "powershell": ["Date", "Time", "event_code", "cmd"],
            "wmi": ["Date", "Time", "event_code", "operation_name", "user", "namespace", "consumer", "cause", "query"],
            "wmi_failure": ["Date", "Time", "event_code", "operation_name", "user", "namespace", "consumer", "cause",
                            "operation"],
            "windefender": ["Date", "Time", "Event", "ThreatName", "Severity", "User", "ProcessName", "Path", "Action"],
            "user_modification": ["Date", "Time", "event_code", "info", "TargetUserName", "SubjectUserName",
                                  "TargetDomainName", "TargetSid", "SamAccountName", "PasswordLastSet"],
        }

        # --- Gestionnaires de fichiers et writers CSV centralisés ---
        self.file_handlers = {}
        self.csv_writers = {}
        os.makedirs(self.output_directory, exist_ok=True)

        # --- Mapping central des fichiers journaux vers les parsers ---
        self.log_file_map = {
            "security": {
                "pattern": re.compile(r'(^|_)Security\.evtx\.json$'),
                "parser": self.parse_generic_evtx_file
            },
            "system": {
                "pattern": re.compile(r'^System\.evtx\.json$'),
                "parser": self.parse_generic_evtx_file
            },
            "task_scheduler": {
                "pattern": re.compile(r'Microsoft-Windows-TaskScheduler%4Operational\.evtx\.json$'),
                "parser": self.parse_generic_evtx_file
            },
            "rdp_remote": {
                "pattern": re.compile(
                    r'Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational\.evtx\.json$'),
                "parser": self.parse_generic_evtx_file
            },
            "rdp_local": {
                "pattern": re.compile(r'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational\.evtx\.json$'),
                "parser": self.parse_generic_evtx_file
            },
            "bits": {
                "pattern": re.compile(r'Microsoft-Windows-Bits-Client%4Operational\.evtx\.json$'),
                "parser": self.parse_generic_evtx_file
            },
            "powershell_operational": {
                "pattern": re.compile(r'Microsoft-Windows-PowerShell%4Operational\\.evtx.json$'),
                "parser": self.parse_generic_evtx_file
            },
            "windows_powershell": {
                "pattern": re.compile(r'Windows PowerShell\.evtx\.json$'),
                "parser": self.parse_generic_evtx_file
            },
            "wmi": {
                "pattern": re.compile(r'Microsoft-Windows-WMI-Activity%4Operational\.evtx\.json$'),
                "parser": self.parse_generic_evtx_file
            },
            "windefender": {
                "pattern": re.compile(r'Microsoft-Windows-Windows Defender%4Operational\.evtx\.json$'),
                "parser": self.parse_generic_evtx_file
            }
        }

    def get_csv_writer(self, artifact_type):
        if artifact_type not in self.csv_writers:
            try:
                filepath = os.path.join(self.output_directory, f'{artifact_type}.csv')
                file_handler = open(filepath, 'a', newline='', encoding='utf-8')
                self.file_handlers[artifact_type] = file_handler
                writer = csv.writer(file_handler, delimiter=self.separator)

                if file_handler.tell() == 0:
                    headers = self.csv_headers.get(artifact_type, [])
                    if headers:
                        writer.writerow(headers)

                self.csv_writers[artifact_type] = writer
            except IOError as e:
                print(f"ERREUR: Impossible d'ouvrir le fichier pour l'artefact {artifact_type}: {e}", file=sys.stderr)
                return None
        return self.csv_writers[artifact_type]

    def _write_csv_row(self, artifact_key, data_dict):
        """Fonction utilitaire pour écrire un dictionnaire de données dans le bon fichier CSV."""
        writer = self.get_csv_writer(artifact_key)
        if writer:
            headers = self.csv_headers.get(artifact_key, [])
            row_data = [data_dict.get(h, "-") for h in headers]
            writer.writerow(row_data)

    def close_files(self):
        """Ferme tous les gestionnaires de fichiers ouverts dynamiquement."""
        print("Fermeture de tous les fichiers ouverts...")
        for handler in self.file_handlers.values():
            try:
                handler.close()
            except Exception as e:
                print(f"Avertissement: impossible de fermer un fichier. Erreur: {e}")

    def format_system_time(self, evt_timestamp):
        if not isinstance(evt_timestamp, str):
            return "-", "-"
        try:
            parts = evt_timestamp.split("T")
            if len(parts) == 2:
                ts_date = parts[0]
                ts_time = parts[1].split(".")[0]
                return ts_date, ts_time
        except Exception:
            pass
        return evt_timestamp, "-"

    # --- PARSER GÉNÉRIQUE ET RÉPARTITEUR D'ÉVÉNEMENTS ---

    def parse_generic_evtx_file(self, file_path):
        """
        Parser générique qui lit un fichier EVTX JSON ligne par ligne et répartit
        chaque événement vers le parser spécialisé approprié en fonction de son ID d'événement.
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                system_info = event.get("Event", {}).get("System", {})
                event_code = system_info.get("EventID")

                if isinstance(event_code, dict):
                    event_code = event_code.get("Value")

                if not event_code:
                    continue

                event_code_str = str(event_code)

                # Répartition vers la fonction de parsing correcte
                if event_code_str == "4624":
                    self.parse_logon(event, event_code_str)
                elif event_code_str == "4625":
                    self.parse_failed_logon(event, event_code_str)
                elif event_code_str == "4672":
                    self.parse_spe_logon(event, event_code_str)
                elif event_code_str == "4648":
                    self.parse_exp_logon(event, event_code_str)
                elif event_code_str == "4688":
                    self.parse_new_proc(event, event_code_str)
                elif event_code_str in ["4720", "4722", "4723", "4724", "4725", "4726", "4738"]:
                    self.parse_user_modification(event, event_code_str)
                elif event_code_str in ["106", "107", "140", "141", "200", "201"]:
                    self.parse_task_scheduler(event, event_code_str)
                elif event_code_str == "1149":
                    self.parse_rdp_remote(event, event_code_str)
                elif event_code_str in ["21", "24", "25", "39", "40"]:
                    self.parse_rdp_local(event, event_code_str)
                elif event_code_str in ["3", "4", "59", "60", "61"]:
                    self.parse_bits(event, event_code_str)
                elif event_code_str == "7045":
                    self.parse_service(event, event_code_str)
                elif event_code_str == "4104":
                    self.parse_powershell_script(event, event_code_str)
                elif event_code_str in ["400", "600"]:
                    self.parse_powershell_cmd(event, event_code_str)
                elif event_code_str in ["5860", "5861"]:
                    self.parse_wmi(event, event_code_str)
                elif event_code_str == "5858":
                    self.parse_wmi_failure(event, event_code_str)
                elif event_code_str == "1116":
                    self.parse_windef_detection(event, event_code_str)
                elif event_code_str in ["1117", "1118", "1119"]:
                    self.parse_windef_action(event, event_code_str)

    # --- PARSERS D'ÉVÉNEMENTS SPÉCIALISÉS ---

    def _get_event_base_data(self, event, event_code):
        ts_date, ts_time = self.format_system_time(
            event.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("SystemTime"))
        return {"Date": ts_date, "Time": ts_time, "event_code": event_code}

    def parse_logon(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({
            "subject_user_name": data.get("SubjectUserName"), "target_user_name": data.get("TargetUserName"),
            "ip_address": data.get("IpAddress"), "ip_port": data.get("IpPort"), "logon_type": data.get("LogonType")
        })
        self._write_csv_row(code, data_dict)

    def parse_failed_logon(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({
            "subject_user_name": data.get("SubjectUserName"), "target_user_name": data.get("TargetUserName"),
            "ip_address": data.get("IpAddress"), "ip_port": data.get("IpPort"), "logon_type": data.get("LogonType"),
            "failure_reason": data.get("Status")
        })
        self._write_csv_row(code, data_dict)

    def parse_spe_logon(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({
            "subject_user_name": data.get("SubjectUserName"), "target_user_name": data.get("TargetUserName"),
            "ip_address": data.get("IpAddress", "-"), "ip_port": data.get("IpPort", "-"),
            "logon_type": data.get("LogonType")
        })
        self._write_csv_row(code, data_dict)

    def parse_exp_logon(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({
            "subject_user_name": data.get("SubjectUserName"), "target_user_name": data.get("TargetUserName"),
            "ip_address": data.get("IpAddress"), "ip_port": data.get("IpPort", "-"),
            "logon_type": data.get("LogonType", "-")
        })
        self._write_csv_row(code, data_dict)

    def parse_new_proc(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({
            "subject_user_name": data.get("SubjectUserName"), "target_user_name": data.get("TargetUserName"),
            "parent_process_name": data.get("ParentProcessName"), "new_process_name": data.get("NewProcessName"),
            "command_line": data.get("CommandLine")
        })
        self._write_csv_row(code, data_dict)

    def parse_user_modification(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("EventData", {})

        info_map = {
            "4720": "User Account Created",
            "4722": "User Account Enabled",
            "4723": "Password Change Attempt",
            "4724": "Password Reset Attempt",
            "4725": "User Account Disabled",
            "4726": "User Account Deleted",
            "4738": "User Account Changed"
        }

        data_dict.update({
            "info": info_map.get(code, "Unknown User Modification"),
            "TargetUserName": data.get("TargetUserName"),
            "SubjectUserName": data.get("SubjectUserName"),
            "TargetDomainName": data.get("TargetDomainName"),
            "TargetSid": data.get("TargetSid"),
            "SamAccountName": data.get("SamAccountName"),
            "PasswordLastSet": data.get("PasswordLastSet"),
        })
        self._write_csv_row("user_modification", data_dict)

    def parse_task_scheduler(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({
            "name": data.get("Name"), "task_name": data.get("TaskName"), "instance_id": data.get("InstanceId"),
            "action_name": data.get("ActionName"), "result_code": data.get("ResultCode"),
            "user_name": data.get("UserName"), "user_context": data.get("UserContext")
        })
        self._write_csv_row("tscheduler", data_dict)

    def parse_rdp_remote(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("UserData", {}).get("EventXML", {})
        data_dict.update({"user_name": data.get("Param1"), "ip_addr": data.get("Param3")})
        self._write_csv_row("remote_rdp", data_dict)

    def parse_rdp_local(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("UserData", {}).get("EventXML", {})
        reason_map = {"21": "AuthSuccess", "24": "UserDisconnected", "25": "UserReconnected",
                      "39": "UserHasBeenDisconnected", "40": "UserHasBeenDisconnected"}
        data_dict.update({
            "user_name": data.get("User"), "ip_addr": data.get("Address"), "session_id": data.get("SessionID"),
            "source": data.get("Source"), "target_session": data.get("TargetSession"),
            "reason_n": data.get("Reason"), "reason": reason_map.get(code, "-")
        })
        self._write_csv_row("local_rdp", data_dict)

    def parse_service(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({
            "account_name": data.get("AccountName"), "img_path": data.get("ImagePath"),
            "service_name": data.get("ServiceName"), "start_type": data.get("StartType")
        })
        self._write_csv_row(code, data_dict)

    def parse_powershell_script(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({"path_to_script": data.get("Path"), "script_block_text": data.get("ScriptBlockText")})
        self._write_csv_row("script_powershell", data_dict)

    def parse_powershell_cmd(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        cmd = "-"
        evt_data = event.get("Event", {}).get("EventData", {}).get("Data")
        if isinstance(evt_data, list):
            for line in evt_data:
                if "HostApplication=" in line:
                    for part in line.split("\n"):
                        if "HostApplication" in part:
                            cmd = part.split("HostApplication=")[1].strip()
                            break
        data_dict["cmd"] = cmd
        self._write_csv_row("powershell", data_dict)

    def parse_wmi(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        user_data = event.get("Event", {}).get("UserData", {})
        if user_data:
            op_name = next(iter(user_data), None)
            op_dict = user_data.get(op_name, {})
            data_dict.update({
                "operation_name": op_name, "user": op_dict.get("User"), "namespace": op_dict.get("NamespaceName"),
                "consumer": op_dict.get("CONSUMER"), "cause": op_dict.get("PossibleCause", "").replace("\n", " "),
                "query": op_dict.get("Query", "").replace("\n", " ")
            })
        self._write_csv_row("wmi", data_dict)

    def parse_wmi_failure(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        user_data = event.get("Event", {}).get("UserData", {})
        if user_data:
            op_name = next(iter(user_data), None)
            op_dict = user_data.get(op_name, {})
            data_dict.update({
                "operation_name": op_name, "user": op_dict.get("User"), "namespace": op_dict.get("NamespaceName"),
                "consumer": op_dict.get("CONSUMER"), "cause": op_dict.get("PossibleCause", "").replace("\n", " "),
                "operation": op_dict.get("Operation", "").replace("\n", " ")
            })
        self._write_csv_row("wmi_failure", data_dict)

    def parse_bits(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({
            "id": data.get("Id"), "job_id": data.get("jobId"), "job_title": data.get("jobTitle"),
            "job_owner": data.get("jobOwner"), "user": data.get("User"), "bytes_total": data.get("bytesTotal"),
            "bytes_transferred": data.get("bytesTransferred"), "file_count": data.get("fileCount"),
            "file_length": data.get("fileLength"), "file_Time": data.get("fileTime"), "name": data.get("name"),
            "url": data.get("url"), "process_path": data.get("processPath")
        })
        self._write_csv_row("bits", data_dict)

    def parse_windef_detection(self, event, code):
        data_dict = self._get_event_base_data(event, f"{code} - Detection")
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({
            "ThreatName": data.get("Threat Name"), "Severity": data.get("Severity Name"),
            "User": data.get("Detection User"), "ProcessName": data.get("Process Name"),
            "Path": data.get("Path"), "Action": data.get("Action Name")
        })
        self._write_csv_row("windefender", data_dict)

    def parse_windef_action(self, event, code):
        data_dict = self._get_event_base_data(event, f"{code} - Action")
        data = event.get("Event", {}).get("EventData", {})
        data_dict.update({
            "ThreatName": data.get("Threat Name"), "Severity": data.get("Severity Name"),
            "User": data.get("Detection User"), "ProcessName": data.get("Process Name"),
            "Path": data.get("Path"), "Action": data.get("Action Name")
        })
        self._write_csv_row("windefender", data_dict)

    # --- LOGIQUE D'EXÉCUTION PRINCIPALE ---

    def parse_all(self):
        """
        Fonction principale pour trouver et parser tous les fichiers EVTX JSON pertinents
        en se basant sur la carte `log_file_map`.
        """
        print(f"Recherche des fichiers journaux dans : {self.work_dir}")

        found_files = {key: [] for key in self.log_file_map.keys()}
        for f in os.listdir(self.work_dir):
            for key, value in self.log_file_map.items():
                if value["pattern"].search(f):
                    found_files[key].append(os.path.join(self.work_dir, f))

        for key, files in found_files.items():
            if not files:
                print(f"  - Aucun fichier trouvé pour le type de journal : {key}")
                continue

            print(f"  + Trouvé {len(files)} fichier(s) pour le type de journal : {key}. Parsing en cours...")
            parser_func = self.log_file_map[key]["parser"]
            for file_path in files:
                try:
                    parser_func(file_path)
                except Exception as e:
                    print(f"ERREUR: Échec du parsing de {file_path}. Raison: {e}", file=sys.stderr)

        self.close_files()
        print("Parsing terminé.")


def parse_args():
    parser = argparse.ArgumentParser(description='Parser pour les fichiers EVTX formatés en JSON.')
    parser.add_argument('-i', '--input', required=True, dest="input_dir",
                        help="Chemin vers le répertoire d'entrée contenant les fichiers EVTX JSON.")
    parser.add_argument("-o", "--output", required=True, dest="output_dir",
                        help="Répertoire de destination où les résultats CSV seront écrits.")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"ERREUR: Répertoire d'entrée non trouvé à '{args.input_dir}'", file=sys.stderr)
        sys.exit(1)

    evt_parser = EventParser(args.input_dir, args.output_dir)
    evt_parser.parse_all()


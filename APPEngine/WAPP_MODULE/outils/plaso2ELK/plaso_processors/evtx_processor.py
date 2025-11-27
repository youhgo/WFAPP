#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import xmltodict
from datetime import datetime
from .base_processor import BaseEventProcessor


# --- DÉBUT DE LA CLASSE EVTXHANDLER (IMPORTÉE DE evtx_processor.py) ---
# (Intégrée ici pour garder le fichier autonome)
class EvtxHandler:
    """
    Contient la logique de parsing pour les différents Event ID des logs EVTX.
    """

    def __init__(self):
        self.SECURITY_EVENT_HANDLERS = {
            4624: self.handle_security_logon, 4625: self.handle_security_logon_fail,
            4648: self.handle_security_logon, 4672: self.handle_4672_special_privileges,
            4688: self.handle_security_process_created,
            4698: self.handle_security_task_created,
            4720: self.handle_user_modification,
            4723: self.handle_user_modification, 4724: self.handle_user_modification,
            4726: self.handle_user_modification
        }
        self.POWERSHELL_EVENT_HANDLERS = {
            400: self.handle_ps_engine_state,
            600: self.handle_ps_provider_lifecycle,  # NOUVEAU: Gestion de l'event 600
            4103: self.handle_ps_module_logging, 4104: self.handle_ps_script_block,
        }
        self.SYSTEM_EVENT_HANDLERS = {7045: self.handle_system_service_install}

        self.WMI_EVENT_HANDLERS = {
            5858: self.handle_wmi_failure,
            5860: self.handle_wmi_activity,
            5861: self.handle_wmi_consumer_binding
        }

        self.WINDEFENDER_EVENT_HANDLERS = {1116: self.handle_windefender, 1117: self.handle_windefender,
                                           1118: self.handle_windefender, 1119: self.handle_windefender}
        self.TASKSCHEDULER_EVENT_HANDLERS = {106: self.handle_task_scheduler, 107: self.handle_task_scheduler,
                                             140: self.handle_task_scheduler, 141: self.handle_task_scheduler,
                                             200: self.handle_task_scheduler, 201: self.handle_task_scheduler}
        self.RDP_REMOTE_EVENT_HANDLERS = {1149: self.handle_rdp_remote_success}
        self.RDP_LOCAL_EVENT_HANDLERS = {21: self.handle_rdp_local_session, 24: self.handle_rdp_local_session,
                                         25: self.handle_rdp_local_session, 39: self.handle_rdp_local_session,
                                         40: self.handle_rdp_local_session}
        self.BITS_EVENT_HANDLERS = {3: self.handle_bits_client, 4: self.handle_bits_client, 59: self.handle_bits_client,
                                    60: self.handle_bits_client, 61: self.handle_bits_client}

    def _get_system_data(self, raw_log: dict) -> dict:
        return raw_log.get("Event", {}).get("System", {})

    def _get_event_data(self, raw_log: dict) -> dict:
        event_data = raw_log.get("Event", {}).get("EventData")
        if event_data is None: return {}
        if not isinstance(event_data, dict): return {}
        if "Data" not in event_data: return event_data

        parsed_output = {}
        data_items = event_data.get("Data")
        if not data_items:
            for key, value in event_data.items():
                if key != 'Data': parsed_output[key] = value
            return parsed_output

        if not isinstance(data_items, list): data_items = [data_items]

        # --- FIX: Always include raw Data list for unnamed parameters (like PowerShell 400/600) ---
        parsed_output["Data"] = data_items

        for item in data_items:
            if isinstance(item, dict) and '@Name' in item:
                parsed_output[item['@Name']] = item.get('#text')

        for key, value in event_data.items():
            if key != 'Data': parsed_output[key] = value
        return parsed_output

    def _get_user_data(self, raw_log: dict) -> dict:
        return raw_log.get("Event", {}).get("UserData", {})

    def _format_timestamp(self, time_str: str) -> str:
        if not time_str: return datetime.utcnow().isoformat() + "Z"
        if '.' in time_str and len(time_str.split('.')[1]) > 7: time_str = time_str[:-2] + 'Z'
        try:
            return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%f%z").isoformat()
        except ValueError:
            try:
                return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ").isoformat()
            except Exception:
                return datetime.utcnow().isoformat() + "Z"

    def _create_base_document(self, raw_log: dict) -> dict:
        system_data = self._get_system_data(raw_log)
        time_created = system_data.get("TimeCreated", {}).get("SystemTime")
        event_id_value = system_data.get("EventID", 0)
        final_event_id = 0
        if isinstance(event_id_value, dict):
            id_val = event_id_value.get("Value") or event_id_value.get("#text")
            try:
                final_event_id = int(id_val)
            except (ValueError, TypeError):
                pass
        else:
            try:
                final_event_id = int(event_id_value)
            except (ValueError, TypeError):
                pass

        return {"@timestamp": self._format_timestamp(time_created),
                "host": {"name": system_data.get("Computer")},
                "winlog": {"provider_name": system_data.get("Provider", {}).get("Name"), "event_id": final_event_id,
                           "channel": system_data.get("Channel")},
                "event": {"kind": "event", "category": "host", "original": json.dumps(raw_log)}}

    def handle_generic_evtx(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        doc["winlog"]["event_data_str"] = json.dumps(self._get_event_data(raw_log))
        return doc

    def handle_security_logon(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        try:
            port = int(data.get("IpPort")) if data.get("IpPort") not in ["-", "0"] else None
        except (ValueError, TypeError):
            port = None
        doc.update({"event": {**doc["event"], "action": "logon", "type": "start", "outcome": "success"},
                    "source": {"user": {"name": data.get("SubjectUserName")},
                               "ip": data.get("IpAddress") if data.get("IpAddress") != "-" else None, "port": port},
                    "user": {"name": data.get("TargetUserName"), "domain": data.get("TargetDomainName")},
                    "winlog": {**doc["winlog"], "logon": {"type": data.get("LogonType")}}})
        return doc

    def handle_security_logon_fail(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        failure_reasons = {
            "0xc000006A": "STATUS_WRONG_PASSWORD",
            "0xc0000072": "STATUS_ACCOUNT_DISABLED",
            "0xC000006A": "STATUS_WRONG_PASSWORD",
            "0xC0000064": "STATUS_NO_SUCH_USER",
            "0xC0000234": "STATUS_ACCOUNT_LOCKED_OUT",
            "0xC000006F": "STATUS_ACCOUNT_RESTRICTION",
            "0xC0000133": "STATUS_TIME_DIFFERENCE_TOO_LARGE",
            "0xC000019C": "STATUS_LOGON_TYPE_NOT_GRANTED",
            "0xC0000071": "STATUS_PASSWORD_EXPIRED",
            "0xC00000E5": "STATUS_UNKNOWN_LOGON_SESSION",
            "0xC000006E": "STATUS_ACCOUNT_RESTRICTION",
            "0xC000006D": "STATUS_LOGON_FAILURE"
        }
        status_code = data.get("Status", "")
        failure_text = failure_reasons.get(status_code, status_code)
        try:
            port = int(data.get("IpPort")) if data.get("IpPort") not in ["-", "0"] else None
        except (ValueError, TypeError):
            port = None
        doc.update({"event": {**doc["event"], "action": "logon", "type": "start", "outcome": "failure"},
                    "source": {"user": {"name": data.get("SubjectUserName")},
                               "ip": data.get("IpAddress") if data.get("IpAddress") != "-" else None, "port": port},
                    "user": {"name": data.get("TargetUserName")},
                    "winlog": {**doc["winlog"], "logon": {"type": data.get("LogonType")}},
                    "error": {"code": status_code, "message": failure_text}})
        return doc

    def handle_security_process_created(self, raw_log: dict) -> dict:
        doc, data = self._create_base_document(raw_log), self._get_event_data(raw_log)
        try:
            pid = int(data.get('ProcessId', '0x0'), 16)
        except (ValueError, TypeError):
            pid = 0
        try:
            parent_pid = int(data.get('CreatorProcessId', '0x0'), 16)
        except (ValueError, TypeError):
            parent_pid = 0
        doc.update({"event": {**doc["event"], "action": "process_started", "type": "start"},
                    "process": {"executable": data.get("NewProcessName"),
                                "name": os.path.basename(data.get("NewProcessName", "")),
                                "pid": pid,
                                "command_line": data.get("CommandLine"),
                                "parent": {"pid": parent_pid,
                                           "ParentProcessName": data.get("ParentProcessName")
                                           }
                                }
                    })
        return doc

    def handle_security_task_created(self, raw_log: dict) -> dict:
        """
        Gère l'événement 4698: A scheduled task was created.
        Parse le XML de la tâche pour extraire la commande exécutée.
        """
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)

        task_name = data.get("TaskName")
        task_content = data.get("TaskContent")  # XML Brut de la tâche

        doc.update({
            "event": {**doc["event"], "action": "scheduled_task_created", "category": "persistence"},
            "task": {"name": task_name},
            "user": {"name": data.get("SubjectUserName"), "domain": data.get("SubjectDomainName")}
        })

        # Parsing du XML de la tâche pour extraire l'action (Command/Arguments)
        if task_content:
            try:
                # Le XML peut être échappé ou inclus directement, xmltodict gère bien les structures
                # Il faut parfois nettoyer le XML s'il est brut dans une string
                if task_content.startswith("<?xml"):
                    task_xml = xmltodict.parse(task_content)

                    # Navigation dans la structure XML de la tâche (Task > Actions > Exec)
                    # Note: La structure peut varier légèrement
                    actions = task_xml.get("Task", {}).get("Actions", {}).get("Exec", {})

                    # Exec peut être une liste si plusieurs actions
                    if isinstance(actions, list):
                        cmds = []
                        args_list = []
                        for action in actions:
                            cmds.append(action.get("Command"))
                            args_list.append(action.get("Arguments"))
                        doc["task"]["command"] = cmds
                        doc["task"]["arguments"] = args_list
                    elif isinstance(actions, dict):
                        doc["task"]["command"] = actions.get("Command")
                        doc["task"]["arguments"] = actions.get("Arguments")

                    # Extraction du Trigger (si possible)
                    triggers = task_xml.get("Task", {}).get("Triggers", {})
                    doc["task"]["triggers_raw"] = json.dumps(triggers)

            except Exception as e:
                # En cas d'échec de parsing XML, on garde le contenu brut
                doc["task"]["xml_parsing_error"] = str(e)
                doc["task"]["content_raw"] = task_content

        return doc

    def handle_user_modification(self, raw_log: dict) -> dict:
        doc, data = self._create_base_document(raw_log), self._get_event_data(raw_log)
        actions = {4720: "user_created", 4726: "user_deleted", 4723: "password_changed", 4724: "password_reset"}
        doc.update({"event": {**doc["event"], "action": actions.get(doc["winlog"]["event_id"], "user_modified")},
                    "user": {"name": data.get("TargetUserName"), "id": data.get("TargetSid")},
                    "source_user": {"name": data.get("SubjectUserName")}})
        return doc

    def handle_system_service_install(self, raw_log: dict) -> dict:
        doc, data = self._create_base_document(raw_log), self._get_event_data(raw_log)
        doc.update({"event": {**doc["event"], "action": "service_installed"},
                    "service": {"name": data.get("ServiceName"), "path": data.get("ImagePath"),
                                "start_type": data.get("StartType"), "account": data.get("AccountName")}})
        return doc

    def handle_4672_special_privileges(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        doc.update({"event": {**doc["event"], "action": "special_privileges_assigned"},
                    "user": {"name": data.get("SubjectUserName"), "domain": data.get("SubjectDomainName")},
                    "winlog": {**doc["winlog"], "event_data": {"privileges": data.get("PrivilegeList")}}})
        return doc

    def handle_ps_script_block(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        doc.update({"event": {**doc["event"], "action": "powershell_script_block_execution"},
                    "process": {"pid": data.get("HostId"), "name": data.get("HostName")},
                    "powershell": {"script_block_id": data.get("ScriptBlockId"),
                                   "script_block_text": data.get("ScriptBlockText"), "path": data.get("Path")}})
        return doc

    def handle_ps_module_logging(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        doc.update({"event": {**doc["event"], "action": "powershell_module_pipeline_execution"},
                    "powershell": {"context": data.get("Context"), "payload": data.get("Payload")}})
        return doc

    def handle_ps_engine_state(self, raw_log: dict) -> dict:
        """
        Gère l'événement 400 (Engine State Changed) de PowerShell.
        Parse le bloc de données textuel pour extraire les détails comme HostApplication, NewEngineState, etc.
        """
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)

        ps_details = {}
        # data['Data'] est maintenant disponible grâce au correctif dans _get_event_data
        data_block = data.get("Data")

        if data_block:
            # Dans l'Event 400, le dernier élément contient souvent les détails clé=valeur
            # data_block peut être une liste de strings (ex: ['Available', 'None', '...details...']) ou une string unique
            text_block = data_block[-1] if isinstance(data_block, list) else data_block

            if isinstance(text_block, str):
                for line in text_block.splitlines():
                    if '=' in line:
                        # Split sur le premier '=' uniquement
                        key, val = line.split('=', 1)
                        ps_details[key.strip()] = val.strip()

        doc.update({
            "event": {**doc["event"], "action": "powershell_engine_state_change"},
            "powershell": {
                "engine_state": ps_details.get("NewEngineState"),
                "previous_engine_state": ps_details.get("PreviousEngineState"),
                "sequence_number": ps_details.get("SequenceNumber"),
                "host": {
                    "name": ps_details.get("HostName"),
                    "version": ps_details.get("HostVersion"),
                    "id": ps_details.get("HostId")
                },
                "runspace_id": ps_details.get("RunspaceId"),
                "pipeline_id": ps_details.get("PipelineId"),
                "engine_version": ps_details.get("EngineVersion"),
                "command": {
                    "name": ps_details.get("CommandName"),
                    "type": ps_details.get("CommandType"),
                    "path": ps_details.get("CommandPath"),
                    "line": ps_details.get("CommandLine")
                },
                "script_name": ps_details.get("ScriptName")
            },
            "process": {"command_line": ps_details.get("HostApplication")}
        })
        return doc

    def handle_ps_provider_lifecycle(self, raw_log: dict) -> dict:
        """
        Gère l'événement 600 (Provider Lifecycle) de PowerShell.
        Ex: "Provider 'Alias' is Started."
        Parse les détails similaires à l'événement 400.
        """
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)

        ps_details = {}
        data_block = data.get("Data")

        if data_block:
            # Comme pour 400, le dernier élément contient les détails
            text_block = data_block[-1] if isinstance(data_block, list) else data_block

            if isinstance(text_block, str):
                for line in text_block.splitlines():
                    if '=' in line:
                        key, val = line.split('=', 1)
                        ps_details[key.strip()] = val.strip()

        doc.update({
            "event": {**doc["event"], "action": "powershell_provider_lifecycle"},
            "powershell": {
                "provider": {
                    "name": ps_details.get("ProviderName"),
                    "new_state": ps_details.get("NewProviderState"),
                },
                "sequence_number": ps_details.get("SequenceNumber"),
                "host": {
                    "name": ps_details.get("HostName"),
                    "version": ps_details.get("HostVersion"),
                    "id": ps_details.get("HostId")
                },
                "runspace_id": ps_details.get("RunspaceId"),
                "pipeline_id": ps_details.get("PipelineId"),
                "command": {
                    "name": ps_details.get("CommandName"),
                    "type": ps_details.get("CommandType"),
                    "path": ps_details.get("CommandPath"),
                    "line": ps_details.get("CommandLine")
                },
                "script_name": ps_details.get("ScriptName")
            },
            "process": {"command_line": ps_details.get("HostApplication")}
        })
        return doc

    def handle_wmi_activity(self, raw_log: dict) -> dict:
        """Gère les événements d'activité WMI standards (5860)."""
        doc = self._create_base_document(raw_log)
        user_data = self._get_user_data(raw_log)
        op_data = user_data.get("Operation_TemporaryEssStarted") or user_data.get("Operation_EssStarted")
        if op_data:
            doc.update({
                "event": {**doc["event"], "action": "wmi_activity", "outcome": "success"},
                "wmi": {"namespace": op_data.get("NamespaceName"), "query": op_data.get("Query"),
                        "operation": op_data.get("Operation", "EssStarted")},
                "source": {"process": {"pid": op_data.get("Processid")}}, "user": {"name": op_data.get("User")}
            })
        else:
            data = self._get_event_data(raw_log)
            doc.update({"event": {**doc["event"], "action": "wmi_activity", "outcome": "success"},
                        "wmi": {"operation": data.get("Operation"), "query": data.get("Query"),
                                "consumer": data.get("Consumer")}, "user": {"name": data.get("User")}})
        return doc

    def handle_wmi_consumer_binding(self, raw_log: dict) -> dict:
        """
        Gère l'événement 5861 : WMI FilterToConsumerBinding (Indicateur fort de persistance).
        Parse le champ 'UserData' spécifique à cet événement.
        """
        doc = self._create_base_document(raw_log)
        user_data = self._get_user_data(raw_log)
        # Structure XML spécifique pour 5861
        binding_data = user_data.get("Operation_ESStoConsumerBinding", {})

        if not binding_data:
            # Fallback si la structure attendue n'est pas trouvée
            return self.handle_generic_evtx(raw_log)

        doc.update({
            "event": {**doc["event"], "action": "wmi_consumer_binding", "category": "persistence"},
            "wmi": {
                "namespace": binding_data.get("Namespace"),
                "filter_name": binding_data.get("ESS"),  # ESS = Event Source Subscription (le nom du filtre)
                "consumer_name": binding_data.get("CONSUMER"),
                "binding_xml_raw": binding_data.get("PossibleCause")  # Contient souvent la définition MOF brute
            }
        })

        # Tentative d'extraction avancée depuis 'PossibleCause' qui contient souvent la requête WQL
        possible_cause = binding_data.get("PossibleCause", "")
        if possible_cause:
            # Extraction de la requête WQL
            query_match = re.search(r'Query\s*=\s*"([^"]+)"', possible_cause, re.IGNORECASE)
            if query_match:
                doc["wmi"]["query"] = query_match.group(1)

            # Extraction du langage (ex: WQL)
            ql_match = re.search(r'QueryLanguage\s*=\s*"([^"]+)"', possible_cause, re.IGNORECASE)
            if ql_match:
                doc["wmi"]["query_language"] = ql_match.group(1)

        return doc

    def handle_wmi_failure(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        user_data = self._get_user_data(raw_log)
        failure_data = user_data.get("Operation_ClientFailure", {})
        doc.update({
            "event": {**doc["event"], "action": "wmi_activity", "outcome": "failure"},
            "source": {"domain": failure_data.get("ClientMachine"),
                       "process": {"pid": failure_data.get("ClientProcessId")}},
            "wmi": {"operation": failure_data.get("Operation"), "component": failure_data.get("Component")},
            "user": {"name": failure_data.get("User")},
            "error": {"code": failure_data.get("ResultCode"), "message": failure_data.get("PossibleCause")}
        })
        return doc

    def handle_windefender(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        actions = {1116: "threat_detected", 1117: "threat_action_taken", 1118: "threat_action_failed",
                   1119: "history_deleted"}
        doc.update({"event": {**doc["event"], "action": actions.get(doc["winlog"]["event_id"], "defender_activity"),
                              "provider": "Windows Defender"},
                    "threat": {"name": data.get("Threat Name"), "severity": data.get("Severity Name"),
                               "path": data.get("Path")}, "user": {"name": data.get("Detection User")}})
        return doc

    def handle_task_scheduler(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        doc.update({"event": {**doc["event"], "action": "scheduled_task_activity"},
                    "task": {"name": data.get("TaskName"), "action": data.get("ActionName"),
                             "result_code": data.get("ResultCode")}, "user": {"name": data.get("UserContext")}})
        return doc

    def handle_rdp_remote_success(self, raw_log: dict) -> dict:
        """
        Handle Event ID 1149: Remote Desktop Services: User authentication succeeded.
        Updates to map Param1 (User), Param2 (Domain), and Param3 (Source IP) from UserData > EventXML.
        """
        doc = self._create_base_document(raw_log)

        # Default extraction using _get_event_data (sometimes works, but UserData is safer for 1149)
        data = self._get_event_data(raw_log)

        # Try to extract specifically from UserData > EventXML as shown in your example
        user_data = self._get_user_data(raw_log)
        event_xml = user_data.get("EventXML", {})

        # Extract params from EventXML or fall back to EventData
        # Param1: User Name
        # Param2: Domain
        # Param3: Source IP
        user_name = event_xml.get("Param1") or data.get("User") or data.get("Param1")
        domain = event_xml.get("Param2") or data.get("Domain") or data.get("Param2")
        source_ip = event_xml.get("Param3") or data.get("ClientAddress") or data.get("Param3")

        doc.update({
            "event": {**doc["event"], "action": "rdp_login", "outcome": "success"},
            "user": {"name": user_name, "domain": domain},
            "source": {"ip": source_ip}
        })
        return doc

    def handle_rdp_local_session(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        user_data = self._get_user_data(raw_log)
        event_xml_data = user_data.get("EventXML", {})
        actions = {21: "session_logon", 24: "session_disconnected", 25: "session_reconnected",
                   39: "session_disconnected_by_other", 40: "session_disconnected_by_other"}
        doc.update({
            "event": {**doc["event"], "action": actions.get(doc["winlog"]["event_id"], "rdp_session_activity")},
            "user": {"name": event_xml_data.get("User")},
            "source": {"ip": event_xml_data.get("Address")},
            "winlog": {**doc["winlog"], "session_id": event_xml_data.get("SessionID")}
        })
        return doc

    def handle_bits_client(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        actions = {
            3: "bits_job_creation", 4: "bits_job_transferred", 59: "bits_job_modified",
            60: "bits_job_error", 61: "bits_job_cancelled"
        }
        doc.update({
            "event": {**doc["event"], "action": actions.get(doc["winlog"]["event_id"], "bits_job_activity")},
            "bits": {"job_id": data.get("Id") or data.get("jobId"),
                     "job_title": data.get("name") or data.get("jobTitle"),
                     "transfer_id": data.get("transferId"), "owner": data.get("owner")},
            "file": {
                "name": os.path.basename(data.get("url", "").split('?')[0]) if data.get("url") else data.get("name"),
                "size": data.get("fileLength"), "mtime": data.get("fileTime")},
            "network": {"bytes_Transfered": data.get("bytesTransferred"), "total_bytes": data.get("bytesTotal")},
            "url": {"original": data.get("url")}
        })
        return doc


# --- FIN DE LA CLASSE EVTXHANDLER ---


class PlasoEvtxProcessor(BaseEventProcessor):
    """Processeur Plaso pour les événements EVTX (winevtx)."""

    def __init__(self):
        print("  [*] Initialisation du processeur EVTX")
        self.evtx_handler = EvtxHandler()

        # Copié de plaso_2_siem.py
        self.LOG_FILE_MAP = {
            r'Security\.evtx': "security",
            r'System\.evtx': "system",
            r'Microsoft-Windows-TaskScheduler.*Operational\.evtx': "taskScheduler",
            r'Microsoft-Windows-TerminalServices-RemoteConnectionManager.*Operational\.evtx': "rdp_remote",
            r'Microsoft-Windows-TerminalServices-LocalSessionManager.*Operational\.evtx': "rdp_local",
            r'Microsoft-Windows-Bits-Client.*Operational\.evtx': "bits",
            r'Microsoft-Windows-PowerShell.*Operational\.evtx': "powershell_operational",
            r'Windows PowerShell\.evtx': "windows_powershell",
            r'Microsoft-Windows-WMI-Activity.*Operational\.evtx': "wmi",
            r'Microsoft-Windows-Windows Defender.*Operational\.evtx': "windefender",
        }

        # Copié de plaso_2_siem.py
        self.EVTX_HANDLER_MAP = {
            "security": self.evtx_handler.SECURITY_EVENT_HANDLERS,
            "powershell_operational": self.evtx_handler.POWERSHELL_EVENT_HANDLERS,
            "windows_powershell": self.evtx_handler.POWERSHELL_EVENT_HANDLERS,
            "system": self.evtx_handler.SYSTEM_EVENT_HANDLERS,
            "wmi": self.evtx_handler.WMI_EVENT_HANDLERS,
            "windefender": self.evtx_handler.WINDEFENDER_EVENT_HANDLERS,
            "taskScheduler": self.evtx_handler.TASKSCHEDULER_EVENT_HANDLERS,
            "rdp_remote": self.evtx_handler.RDP_REMOTE_EVENT_HANDLERS,
            "rdp_local": self.evtx_handler.RDP_LOCAL_EVENT_HANDLERS,
            "bits": self.evtx_handler.BITS_EVENT_HANDLERS,
        }

    def get_specific_evtx_type(self, original_filename):
        if not original_filename: return None
        for pattern, log_type in self.LOG_FILE_MAP.items():
            if re.search(pattern, original_filename, re.IGNORECASE):
                return log_type
        return None

    def process_event(self, event: dict) -> (dict, str):
        """Traite un événement EVTX de Plaso."""
        try:
            xml_string = event.get("xml_string")
            if not xml_string:
                # S'il n'y a pas de XML, on ne peut pas faire grand chose
                return self.drop_useless_fields(event), "evtx"

            xml_as_json = xmltodict.parse(xml_string)

            # MODIFIÉ: Stocker en tant que chaîne JSON pour éviter les conflits de mapping
            event["Data_json_string"] = json.dumps(xml_as_json)

            # --- Logique de Timestamp ---
            dt_plaso = self._parse_unix_micro_to_dt(event.get("timestamp"))
            dt_filetime = self._parse_filetime_to_dt(event.get("date_time", {}).get("timestamp"))
            dt_xml = self._parse_iso_string_to_dt(
                xml_as_json.get("Event", {}).get("System", {}).get("TimeCreated", {}).get("@SystemTime")
            )
            valid_dts = [dt for dt in [dt_plaso, dt_filetime, dt_xml] if dt]
            final_dt = max(valid_dts) if valid_dts else None

            event["estimestamp"] = self._format_dt_to_es(final_dt)

            # --- Logique de Parsing Spécifique (EvtxHandler) ---
            filename = event.get("filename", "")
            specific_type = self.get_specific_evtx_type(filename)

            if specific_type:
                event["evtx_type"] = specific_type

            event_id = 0
            try:
                event_id = int(event.get("event_identifier", 0))
            except (ValueError, TypeError):
                event_id = 0  # Fallback

            processed_data = None
            handler_func = None

            if specific_type:
                handler_map = self.EVTX_HANDLER_MAP.get(specific_type)
                if handler_map:
                    handler_func = handler_map.get(event_id)

            if handler_func:
                try:
                    # Le handler a toujours besoin de l'objet, pas de la chaîne
                    processed_data = handler_func(xml_as_json)
                except Exception as e:
                    # print(f"[WARN] Handler {handler_func.__name__} échec pour EventID {event_id}: {e}")
                    processed_data = self.evtx_handler.handle_generic_evtx(xml_as_json)
            else:
                processed_data = self.evtx_handler.handle_generic_evtx(xml_as_json)

            if processed_data:
                processed_data.pop("@timestamp", None)
                processed_data.pop("host", None)
                if "event" in processed_data:
                    processed_data["event"].pop("original", None)
                event["winlog_parsed"] = processed_data

            # --- Nettoyage et Finalisation ---
            self.drop_useless_fields(event)

            index_key = "evtx"

            return event, index_key

        except Exception as e:
            # print(f"[ERREUR] Échec de process_evtx_event: {e}")
            return self.drop_useless_fields(event), "evtx"
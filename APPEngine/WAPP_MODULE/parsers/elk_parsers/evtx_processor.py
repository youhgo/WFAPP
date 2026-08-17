#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from datetime import datetime
import os
import re
from .base_processor import BaseFileProcessor
import sys

class EvtxHandler:
    """
    Contient la logique de parsing pour les différents Event ID des logs EVTX.
    """

    def __init__(self):
        # Dispatcher pour les logs de Sécurité
        self.SECURITY_EVENT_HANDLERS = {
            4624: self.handle_security_logon, 4625: self.handle_security_logon_fail,
            4648: self.handle_security_logon, 4672: self.handle_4672_special_privileges,
            4688: self.handle_security_process_created, 4720: self.handle_user_modification,
            4722: self.handle_user_modification, 4723: self.handle_user_modification,
            4724: self.handle_user_modification, 4725: self.handle_user_modification,
            4726: self.handle_user_modification, 4738: self.handle_user_modification,
        }
        # Dispatcher pour les logs PowerShell
        self.POWERSHELL_EVENT_HANDLERS = {
            400: self.handle_ps_engine_state, 600: self.handle_ps_engine_state,
            4103: self.handle_ps_module_logging, 4104: self.handle_ps_script_block,
        }
        # Dispatcher pour les logs Système
        self.SYSTEM_EVENT_HANDLERS = {7045: self.handle_system_service_install}
        # Dispatcher pour les logs WMI
        self.WMI_EVENT_HANDLERS = {5858: self.handle_wmi_failure, 5860: self.handle_wmi_activity,
                                   5861: self.handle_wmi_activity}
        # Dispatcher pour les logs Windows Defender
        self.WINDEFENDER_EVENT_HANDLERS = {1116: self.handle_windefender, 1117: self.handle_windefender,
                                           1118: self.handle_windefender, 1119: self.handle_windefender}
        # Dispatcher pour les Tâches Planifiées
        self.TASKSCHEDULER_EVENT_HANDLERS = {106: self.handle_task_scheduler, 107: self.handle_task_scheduler,
                                             140: self.handle_task_scheduler, 141: self.handle_task_scheduler,
                                             200: self.handle_task_scheduler, 201: self.handle_task_scheduler}
        # Dispatcher pour RDP Remote
        self.RDP_REMOTE_EVENT_HANDLERS = {1149: self.handle_rdp_remote_success}
        # Dispatcher pour RDP Local
        self.RDP_LOCAL_EVENT_HANDLERS = {21: self.handle_rdp_local_session, 24: self.handle_rdp_local_session,
                                         25: self.handle_rdp_local_session, 39: self.handle_rdp_local_session,
                                         40: self.handle_rdp_local_session}
        # Dispatcher pour BITS Client
        self.BITS_EVENT_HANDLERS = {3: self.handle_bits_client, 4: self.handle_bits_client, 59: self.handle_bits_client,
                                    60: self.handle_bits_client, 61: self.handle_bits_client}

        self.APP_EXP_EVENT_HANDLERS = {
            504: self.handle_app_experience,
            505: self.handle_app_experience
        }

    def _get_system_data(self, raw_log: dict) -> dict:
        return raw_log.get("Event", {}).get("System", {})

    def _get_event_data(self, raw_log: dict) -> dict:
        return raw_log.get("Event", {}).get("EventData", {})

    def _get_user_data(self, raw_log: dict) -> dict:
        return raw_log.get("Event", {}).get("UserData", {})

    def _format_timestamp(self, time_str: str) -> str:
        if not time_str: return datetime.utcnow().isoformat() + "Z"
        if '.' in time_str and len(time_str.split('.')[1]) > 7: time_str = time_str[:-2] + 'Z'
        try:
            return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%f%z").isoformat()
        except ValueError:
            return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ").isoformat()

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
        base_doc = {"@timestamp": self._format_timestamp(time_created),
                    "host": {"name": system_data.get("Computer")},
                    "winlog": {"provider_name": system_data.get("Provider", {}).get("Name"),
                               "event_id": final_event_id,
                               "channel": system_data.get("Channel")},
                    "event": {"kind": "event",
                              "dataset": "evtx",
                              "category": "host",
                              "original": json.dumps(raw_log)}
                    }
        if hasattr(self, 'inject_wapp_info'):
            doc = self.inject_wapp_info(base_doc)
            return doc
        else:
            return base_doc

    def handle_generic_evtx(self, raw_log: dict) -> dict:
        """Handler générique pour les EventID non spécifiquement traités."""
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
        failure_reasons = {"0xc000006a": "Incorrect password", "0xc0000072": "Account disabled"}
        status_code = data.get("Status", "").lower()
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
                                "name": os.path.basename(data.get("NewProcessName", "")), "pid": pid,
                                "command_line": data.get("CommandLine"), "parent": {"pid": parent_pid}}})
        return doc

    def handle_user_modification(self, raw_log: dict) -> dict:
        doc, data = self._create_base_document(raw_log), self._get_event_data(raw_log)
        actions = {4720: "user_created", 4722: "User_Account_Enabled",4723: "password_changed", 4724: "password_reset",
                   4725: "User_Account_Disabled", 4726: "user_deleted", 4738: "User_Account_Changed"}
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
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)

        ps_details = {}
        data_block = data.get("Data")

        # Recherche robuste des paires clé=valeur dans tous les éléments de Data
        if isinstance(data_block, list):
            for block in data_block:
                # On cherche le bloc qui contient les paramètres séparés par des retours à la ligne
                if isinstance(block, str) and "=" in block and "\n" in block:
                    for line in block.splitlines():
                        line = line.strip()  # Enlève les \t et espaces
                        if '=' in line:
                            key, val = line.split('=', 1)
                            if val.strip():  # On ne stocke que si la valeur n'est pas vide
                                ps_details[key.strip()] = val.strip()

        # HostApplication contient le binaire appelant (powershell.exe -Bypass ...),
        # CommandLine ou CommandName peuvent contenir le script directement
        cmd_line = ps_details.get("HostApplication") or ps_details.get("CommandLine")

        # Structuration des détails PowerShell
        ps_enrichment = {
            "engine_state": ps_details.get("NewEngineState"),
            "previous_engine_state": ps_details.get("PreviousEngineState"),
            "host": {
                "name": ps_details.get("HostName"),
                "version": ps_details.get("HostVersion"),
                "id": ps_details.get("HostId"),
                "application": ps_details.get("HostApplication")
            },
            "runspace_id": ps_details.get("RunspaceId"),
            "pipeline_id": ps_details.get("PipelineId"),
            "sequence_number": ps_details.get("SequenceNumber"),
            "command": {
                "name": ps_details.get("CommandName"),
                "type": ps_details.get("CommandType"),
                "path": ps_details.get("CommandPath"),
                "line": ps_details.get("CommandLine")
            },
            "script": {
                "name": ps_details.get("ScriptName")
            }
        }

        # Nettoyage des dictionnaires pour retirer les sous-groupes vides
        ps_enrichment["host"] = {k: v for k, v in ps_enrichment["host"].items() if v}
        ps_enrichment["command"] = {k: v for k, v in ps_enrichment["command"].items() if v}
        ps_enrichment["script"] = {k: v for k, v in ps_enrichment["script"].items() if v}
        ps_enrichment = {k: v for k, v in ps_enrichment.items() if v}

        doc.update({
            "event": {**doc["event"], "action": "powershell_engine_state_change"},
            "powershell": ps_enrichment,
        })

        # On garde process.command_line pour un mapping ECS standardisé sur Wazuh
        if cmd_line:
            doc["process"] = {"command_line": cmd_line}
        return doc

    def handle_wmi_activity(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        user_data = self._get_user_data(raw_log)

        op_data = user_data.get("Operation_TemporaryEssStarted") or user_data.get("Operation_EssStarted")

        if op_data:
            doc.update({
                "event": {**doc["event"], "action": "wmi_activity", "outcome": "success"},
                "wmi": {"namespace": op_data.get("NamespaceName"), "query": op_data.get("Query"),
                        "operation": op_data.get("Operation", "EssStarted")},
                "source": {"process": {"pid": op_data.get("Processid")}},
                "user": {"name": op_data.get("User")}
            })
        else:
            # Fallback for other WMI success events using EventData
            data = self._get_event_data(raw_log)
            doc.update({"event": {**doc["event"], "action": "wmi_activity", "outcome": "success"},
                        "wmi": {"operation": data.get("Operation"), "query": data.get("Query"),
                                "consumer": data.get("Consumer")}, "user": {"name": data.get("User")}})
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
        doc = self._create_base_document(raw_log)
        data = self._get_event_data(raw_log)
        doc.update(
            {"event": {**doc["event"], "action": "rdp_login", "outcome": "success"}, "user": {"name": data.get("User")},
             "source": {"ip": data.get("ClientAddress")}})
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
            3: "bits_job_creation",
            4: "bits_job_transferred",
            59: "bits_job_modified",
            60: "bits_job_error",
            61: "bits_job_cancelled"
        }

        doc.update({
            "event": {**doc["event"], "action": actions.get(doc["winlog"]["event_id"], "bits_job_activity")},
            "bits": {
                "job_id": data.get("Id") or data.get("jobId"),
                "job_title": data.get("name") or data.get("jobTitle"),
                "transfer_id": data.get("transferId"),
                "owner": data.get("owner")
            },
            "file": {
                "name": os.path.basename(data.get("url", "").split('?')[0]) if data.get("url") else data.get("name"),
                "size": data.get("fileLength"),
                "mtime": data.get("fileTime")
            },
            "network": {
                "bytes_Transfered": data.get("bytesTransferred"),
                "total_bytes": data.get("bytesTotal")
            },
            "url": {"original": data.get("url")}
        })
        return doc

    def handle_app_experience(self, raw_log: dict) -> dict:
        doc = self._create_base_document(raw_log)
        user_data = self._get_user_data(raw_log)
        sys_data = self._get_system_data(raw_log)

        # Les évènements 504/505 utilisent souvent CompatibilityFixEvent
        event_details = user_data.get("CompatibilityFixEvent") or user_data.get("CompatibilityAppraiserEvent") or {}

        exe_path = event_details.get("ExePath", "")

        # Le SID utilisateur est crucial en forensic, on le récupère dans System -> Security
        user_sid = sys_data.get("Security", {}).get("UserID")

        process_info = {
            "executable": exe_path,
            "name": os.path.basename(exe_path.replace("\\", "/")) if exe_path else None,
        }

        if "ProcessId" in event_details:
            try:
                process_info["pid"] = int(event_details["ProcessId"])
            except (ValueError, TypeError):
                pass

        doc.update({
            "event": {**doc["event"], "action": "application_execution", "category": "process"},
            "process": process_info,
            "user": {"id": user_sid},
            "windows_telemetry": {
                "fix_name": event_details.get("FixName"),
                "fix_id": event_details.get("FixID"),
                "flags": event_details.get("Flags")
            }
        })

        # Nettoyage des dictionnaires pour retirer les clés vides
        doc["process"] = {k: v for k, v in doc["process"].items() if v}
        doc["windows_telemetry"] = {k: v for k, v in doc["windows_telemetry"].items() if v}
        if not doc["windows_telemetry"]:
            del doc["windows_telemetry"]
        if not user_sid:
            del doc["user"]

        return doc

from ...classes.elk_registry import register_elk_processor

@register_elk_processor("evtx")
class EvtxJsonProcessor(BaseFileProcessor):
    DEFAULT_PATTERNS = {
        r'.*\.evtx\.jsonl$': "evtx"
    }

    def __init__(self, case_name="unknown", machine_name="unknown"):
        super().__init__(case_name=case_name, machine_name=machine_name)
        self.handler = EvtxHandler()
        self.LOG_TYPE_PROCESSORS = {
            'security': self._process_security_log,
            'system': self._process_system_log,
            'powershell_operational': self._process_powershell_log,
            'windows_powershell': self._process_powershell_log,
            'wmi': self._process_wmi_log,
            'windefender': self._process_windefender_log,
            'taskScheduler': self._process_taskscheduler_log,
            'rdp_remote': self._process_rdp_remote_log,
            'rdp_local': self._process_rdp_local_log,
            'bits': self._process_bits_log,
            'app_experience': self._process_app_exp_log
        }
        self.LOG_FILE_MAP = {
            r'(\d+_)?Security\.evtx\.json?': "security",
            r'(\d+_)?System\.evtx\.json?': "system",
            r'^Security\.evtx\.json?': "security",
            r'^System\.evtx\.json?': "system",
            r'.*Microsoft-Windows-TaskScheduler.*Operational\.evtx\.json?': "taskScheduler",
            r'.*Microsoft-Windows-TerminalServices-RemoteConnectionManager.*Operational\.evtx\.json?': "rdp_remote",
            r'.*Microsoft-Windows-TerminalServices-LocalSessionManager.*Operational\.evtx\.json': "rdp_local",
            r'.*Microsoft-Windows-Bits-Client.*Operational\.evtx\.json': "bits",
            r'.*Microsoft-Windows-PowerShell.*Operational\.evtx\.json': "powershell_operational",
            r'.*Windows PowerShell\.evtx\.json?': "windows_powershell",
            r'.*Microsoft-Windows-WMI-Activity.*Operational\.evtx\.json': "wmi",
            r'.*Microsoft-Windows-Windows.Defender.*Operational\.evtx\.json?': "windefender",
            r'.*Microsoft-Windows-Application-Experience.*\.evtx\.json?': "app_experience"
        }

    def _get_event_id(self, raw_log: dict) -> int:
        event_id_value = raw_log.get("Event", {}).get("System", {}).get("EventID", 0)
        try:
            if isinstance(event_id_value, dict):
                id_val = event_id_value.get("Value") or event_id_value.get("#text")
                return int(id_val)
            else:
                return int(event_id_value)
        except (ValueError, TypeError):
            return 0

    def _process_security_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.SECURITY_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_powershell_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.POWERSHELL_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_system_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.SYSTEM_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_wmi_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.WMI_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_windefender_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.WINDEFENDER_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_taskscheduler_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.TASKSCHEDULER_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_rdp_remote_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.RDP_REMOTE_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_rdp_local_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.RDP_LOCAL_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_bits_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.BITS_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_app_exp_log(self, raw_log: dict) -> dict:
        event_id = self._get_event_id(raw_log)
        handler_method = self.handler.APP_EXP_EVENT_HANDLERS.get(event_id, self.handler.handle_generic_evtx)
        return handler_method(raw_log)

    def _process_generic_evtx(self, raw_log: dict) -> dict:
        return self.handler.handle_generic_evtx(raw_log)

    def _yield_from_records(self, records: list, processor_method):
        """Helper to process a list of records."""
        for i, record in enumerate(records):
            try:
                if "Event" in record:
                    processed_log = processor_method(record)
                    yield processed_log, "evtx"
            except Exception as e:
                print(f"\n[Attention] Impossible de traiter l'enregistrement EVTX #{i + 1}. Erreur: {e}\n")

    def process_file(self, filepath: str, **kwargs):
        filename = os.path.basename(filepath)
        print(f"  -> Lecture du fichier EVTX : {filename}")

        processor_method = self._process_generic_evtx
        log_type = "generic"
        for pattern, type_name in self.LOG_FILE_MAP.items():
            if re.search(pattern, filename, re.IGNORECASE):
                log_type = type_name
                processor_method = self.LOG_TYPE_PROCESSORS.get(log_type, self._process_generic_evtx)
                break

        print(f"    -> Type de log détecté : {log_type}. Utilisation du processeur : {processor_method.__name__}")

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                # Essayer de lire comme un JSON complet d'abord
                all_data = json.load(f)
                records = all_data if isinstance(all_data, list) else [all_data]
                print(f"    -> Fichier détecté comme JSON complet.")
                yield from self._yield_from_records(records, processor_method)
            except json.JSONDecodeError:
                # Si ça échoue, on suppose que c'est du JSON Lines
                print(f"    -> Fichier détecté comme JSON Lines.")
                f.seek(0)
                for line_num, line in enumerate(f, 1):
                    stripped_line = line.strip()
                    if not stripped_line: continue
                    try:
                        raw_log_data = json.loads(stripped_line)
                        if "Event" in raw_log_data:
                            processed_log = processor_method(raw_log_data)
                            yield processed_log, "evtx"
                    except Exception as e:
                        print(
                            f"\n[Attention] Impossible de traiter la ligne {line_num}. Erreur: {e}\nLigne: {stripped_line}\n")


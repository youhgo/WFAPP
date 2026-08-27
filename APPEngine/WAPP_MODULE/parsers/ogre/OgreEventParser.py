#!/usr/bin/python3
import json
from pathlib import Path
from typing import Generator, Dict, Any, Tuple

from ...classes.BaseParser import BaseParser

class OgreEventParser(BaseParser):
    """
    Parser for Ogre windows_events files, adapting Ogre JSON structure 
    to match the legacy EventParser CSV output.
    """

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

    def parse(self, input_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                system_info = event.get("data", {}).get("system", {})
                event_code = system_info.get("event_id")

                if not event_code:
                    continue

                event_code_str = str(event_code)

                if event_code_str == "4624":
                    yield self.parse_logon(event, event_code_str)
                elif event_code_str == "4625":
                    yield self.parse_failed_logon(event, event_code_str)
                elif event_code_str == "4672":
                    yield self.parse_spe_logon(event, event_code_str)
                elif event_code_str == "4648":
                    yield self.parse_exp_logon(event, event_code_str)
                elif event_code_str == "4688":
                    yield self.parse_new_proc(event, event_code_str)
                elif event_code_str in ["4720", "4722", "4723", "4724", "4725", "4726", "4738"]:
                    yield self.parse_user_modification(event, event_code_str)
                elif event_code_str in ["106", "107", "140", "141", "200", "201"]:
                    yield self.parse_task_scheduler(event, event_code_str)
                elif event_code_str == "1149":
                    yield self.parse_rdp_remote(event, event_code_str)
                elif event_code_str in ["21", "24", "25", "39", "40"]:
                    yield self.parse_rdp_local(event, event_code_str)
                elif event_code_str in ["3", "4", "59", "60", "61"]:
                    yield self.parse_bits(event, event_code_str)
                elif event_code_str == "7045":
                    yield self.parse_service(event, event_code_str)
                elif event_code_str == "4104":
                    yield self.parse_powershell_script(event, event_code_str)
                elif event_code_str in ["400", "600"]:
                    yield self.parse_powershell_cmd(event, event_code_str)
                elif event_code_str in ["5860", "5861"]:
                    yield self.parse_wmi(event, event_code_str)
                elif event_code_str == "5858":
                    yield self.parse_wmi_failure(event, event_code_str)
                elif event_code_str == "1116":
                    yield self.parse_windef_detection(event, event_code_str)
                elif event_code_str in ["1117", "1118", "1119"]:
                    yield self.parse_windef_action(event, event_code_str)
                elif event_code_str == "1122":
                    yield self.parse_windef_1122(event, event_code_str)
                else:
                    # Generic fallback for unhandled events
                    pass


    def _get_event_base_data(self, event, event_code):
        time_str = event.get("data", {}).get("system", {}).get("time_created", {}).get("system_time")
        if not time_str:
            time_str = event.get("timestamp")
        ts_date, ts_time = self.format_system_time(time_str)
        return {"Date": ts_date, "Time": ts_time, "event_code": event_code}

    def parse_logon(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        data_dict.update({
            "subject_user_name": data.get("subject_user_name"), "target_user_name": data.get("target_user_name"),
            "ip_address": data.get("ip_address"), "ip_port": data.get("ip_port"), "logon_type": data.get("logon_type")
        })
        return code, data_dict

    def parse_failed_logon(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        data_dict.update({
            "subject_user_name": data.get("subject_user_name"), "target_user_name": data.get("target_user_name"),
            "ip_address": data.get("ip_address"), "ip_port": data.get("ip_port"), "logon_type": data.get("logon_type"),
            "failure_reason": data.get("status")
        })
        return code, data_dict

    def parse_spe_logon(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        data_dict.update({
            "subject_user_name": data.get("subject_user_name"), "target_user_name": data.get("target_user_name"),
            "ip_address": data.get("ip_address", "-"), "ip_port": data.get("ip_port", "-"),
            "logon_type": data.get("logon_type")
        })
        return code, data_dict

    def parse_exp_logon(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        data_dict.update({
            "subject_user_name": data.get("subject_user_name"), "target_user_name": data.get("target_user_name"),
            "ip_address": data.get("ip_address"), "ip_port": data.get("ip_port", "-"),
            "logon_type": data.get("logon_type", "-")
        })
        return code, data_dict

    def parse_new_proc(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        data_dict.update({
            "subject_user_name": data.get("subject_user_name"), "target_user_name": data.get("target_user_name"),
            "parent_process_name": data.get("parent_process_name"), "new_process_name": data.get("new_process_name"),
            "command_line": data.get("command_line")
        })
        return code, data_dict

    def parse_user_modification(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        info_map = {
            "4720": "User Account Created", "4722": "User Account Enabled", "4723": "Password Change Attempt",
            "4724": "Password Reset Attempt", "4725": "User Account Disabled", "4726": "User Account Deleted",
            "4738": "User Account Changed"
        }
        data_dict.update({
            "info": info_map.get(code, "Unknown User Modification"), "TargetUserName": data.get("target_user_name"),
            "SubjectUserName": data.get("subject_user_name"), "TargetDomainName": data.get("target_domain_name"),
            "TargetSid": data.get("target_sid"), "SamAccountName": data.get("sam_account_name"),
            "PasswordLastSet": data.get("password_last_set"),
        })
        return "user_modification", data_dict

    def parse_task_scheduler(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        attr = event.get("data", {}).get("event_data_attributes", {})
        
        instance_id = data.get("instance_id") or data.get("task_instance_id")
        
        data_dict.update({
            "event_name": attr.get("name"),
            "task_name": data.get("task_name"), 
            "instance_id": instance_id,
            "action_name": data.get("action_name"), 
            "result_code": data.get("result_code"),
            "user_name": data.get("user_name"), 
            "user_context": data.get("user_context"),
            "engine_pid": data.get("engine_pid")
        })
        return "tscheduler", data_dict

    def parse_rdp_remote(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        # Ogre parsing of UserData/EventXML
        data = event.get("data", {}).get("user_data", {}).get("event_xml", {})
        data_dict.update({"user_name": data.get("param1"), "ip_addr": data.get("param3")})
        return "remote_rdp", data_dict

    def parse_rdp_local(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("user_data", {}).get("event_xml", {})
        reason_map = {"21": "AuthSuccess", "24": "UserDisconnected", "25": "UserReconnected",
                      "39": "UserHasBeenDisconnected", "40": "UserHasBeenDisconnected"}
        data_dict.update({
            "user_name": data.get("user"), "ip_addr": data.get("address"), "session_id": data.get("session_id"),
            "source": data.get("source"), "target_session": data.get("target_session"),
            "reason_n": data.get("reason"), "reason": reason_map.get(code, "UnknownReason")
        })
        return "local_rdp", data_dict

    def parse_bits(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("user_data", {}).get("event_xml", {})
        if not data:
            data = event.get("data", {}).get("event_data", {})
        
        # Fallback to additional_description parsing if data is empty or missing key fields
        if not data and "additional_description" in event:
            import re
            matches = re.findall(r"'([^']+)':\s*'([^']*)'", event["additional_description"])
            data = {k: v for k, v in matches}
            
        def get_val(*keys):
            for k in keys:
                if k in data:
                    return data[k]
            return None

        data_dict.update({
            "id": get_val("id", "Id"), 
            "job_id": get_val("job_id", "jobId", "JobId"), 
            "job_title": get_val("job_title", "jobTitle", "JobTitle"),
            "job_owner": get_val("job_owner", "jobOwner", "JobOwner"), 
            "user": get_val("user", "User", "userId"), 
            "bytes_total": get_val("bytes_total", "bytesTotal", "BytesTotal"),
            "bytes_transferred": get_val("bytes_transferred", "bytesTransferred", "BytesTransferred"),
            "bytes_transferred_from_peer": get_val("bytes_transferred_from_peer", "bytesTransferredFromPeer", "BytesTransferredFromPeer"), 
            "file_count": get_val("file_count", "fileCount", "FileCount"),
            "file_length": get_val("file_length", "fileLength", "FileLength"), 
            "file_time": get_val("file_time", "fileTime", "FileTime", "file_Time"), 
            "name": get_val("name", "Name"),
            "url": get_val("url", "Url", "URL"), 
            "process_path": get_val("process_path", "processPath", "ProcessPath"),
            "process_id": get_val("process_id", "processId", "ProcessId"), 
            "client_process_start_key": get_val("client_process_start_key", "clientProcessStartKey", "ClientProcessStartKey"),
            "transfer_id": get_val("transfer_id", "transferId", "TransferId"), 
            "peer": get_val("peer", "Peer"), 
            "proxy": get_val("proxy", "Proxy"),
            "hr": get_val("hr", "Hr", "HR"), 
            "additional_info_hr": get_val("additional_info_hr", "additionalInfoHr", "AdditionalInfoHr"),
            "peer_protocol_flags": get_val("peer_protocol_flags", "peerProtocolFlags", "PeerProtocolFlags"), 
            "peer_context_info": get_val("peer_context_info", "peerContextInfo", "PeerContextInfo"),
            "bandwidth_limit": get_val("bandwidth_limit", "bandwidthLimit", "BandwidthLimit"), 
            "ignore_bandwidth_limits_on_lan": get_val("ignore_bandwidth_limits_on_lan", "ignoreBandwidthLimitsOnLan", "IgnoreBandwidthLimitsOnLan"),
            "state": get_val("state", "State"), 
            "error_code": get_val("error_code", "errorCode", "ErrorCode")
        })
        return "bits", data_dict

    def parse_service(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        data_dict.update({
            "account_name": data.get("account_name"), "img_path": data.get("image_path"),
            "service_name": data.get("service_name"), "start_type": data.get("start_type")
        })
        return "7045", data_dict

    def parse_powershell_script(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        data_dict.update({
            "path_to_script": data.get("path"), 
            "script_block_text": data.get("script_block_text"),
            "script_block_id": data.get("script_block_id"),
            "message_number": data.get("message_number"),
            "message_total": data.get("message_total")
        })
        return "script_powershell", data_dict

    def parse_powershell_cmd(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        event_data = event.get("data", {}).get("event_data", {})
        
        extracted_data = {}
        text_data = event_data.get("data", {}).get("#text", [])
        if isinstance(text_data, list):
            for item in text_data:
                if isinstance(item, str) and ("HostApplication=" in item or "CommandLine=" in item):
                    for line in item.split("\n"):
                        line = line.strip()
                        if "=" in line:
                            parts = line.split("=", 1)
                            key = parts[0].strip()
                            val = parts[1].strip()
                            extracted_data[key] = val
                            
        cmd = extracted_data.get("HostApplication") or event_data.get("host_application")
        script_name = extracted_data.get("ScriptName") or event_data.get("script_name")
        command_line = extracted_data.get("CommandLine") or event_data.get("command_line")
        
        data_dict.update({
            "cmd": cmd,
            "script_name": script_name,
            "command_line": command_line,
            "host_version": extracted_data.get("HostVersion"),
            "runspace_id": extracted_data.get("RunspaceId")
        })
        return "powershell", data_dict

    def parse_wmi(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        user_data = event.get("data", {}).get("user_data", {})
        data = {}
        for k, v in user_data.items():
            if isinstance(v, dict) and not k.endswith("_attributes"):
                data = v
                break

        data_dict.update({
            "operation_name": data.get("operation"), "user": data.get("user"),
            "namespace": data.get("namespace_name") or data.get("namespace"), "consumer": data.get("consumer"),
            "cause": data.get("possible_cause"), "query": data.get("query"),
            "process_id": data.get("processid") or data.get("client_process_id"),
            "client_machine": data.get("client_machine"), "ess": data.get("ess")
        })
        return "wmi", data_dict

    def parse_wmi_failure(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        user_data = event.get("data", {}).get("user_data", {})
        data = {}
        for k, v in user_data.items():
            if isinstance(v, dict) and not k.endswith("_attributes"):
                data = v
                break

        data_dict.update({
            "operation_name": data.get("operation"), "user": data.get("user"),
            "namespace": data.get("namespace_name") or data.get("namespace"), "consumer": data.get("consumer"),
            "cause": data.get("possible_cause"), "process_id": data.get("processid") or data.get("client_process_id"),
            "client_machine": data.get("client_machine"), "result_code": data.get("result_code"),
            "component": data.get("component")
        })
        return "wmi_failure", data_dict

    def parse_windef_detection(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        data_dict.update({
            "ThreatName": data.get("threat_name"), "Severity": data.get("severity_id"),
            "User": data.get("user"), "ProcessName": data.get("process_name"),
            "Path": data.get("path")
        })
        return f"windefender_{code}", data_dict

    def parse_windef_action(self, event, code):
        data_dict = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        data_dict.update({
            "ThreatName": data.get("threat_name"), "Severity": data.get("severity_id"),
            "User": data.get("user"), "ProcessName": data.get("process_name"),
            "Path": data.get("path"), "Action": data.get("action_id")
        })
        return f"windefender_{code}", data_dict

    def parse_windef_1122(self, event, code):
        base_data = self._get_event_base_data(event, code)
        data = event.get("data", {}).get("event_data", {})
        
        data_dict = {
            "DATE": base_data.get("Date", ""),
            "TIME": base_data.get("Time", ""),
            "detection_time": data.get("detection_time"),
            "user": data.get("user"),
            "process_name": data.get("process_name"),
            "parent_commandline": data.get("parent_commandline"),
            "target_commandline": data.get("target_commandline"),
            "path": data.get("path"),
            "involved_file": data.get("involved_file")
        }
        return "windefender_1122", data_dict

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from datetime import datetime
from .base_processor import BaseFileProcessor


from ..elk_registry import register_elk_processor

@register_elk_processor("network")
class NetworkProcessor(BaseFileProcessor):
    """Processeur pour les fichiers texte contenant la sortie de 'netstat', 'tcpvcon', 'arp -a', ou des enregistrements DNS."""
    DEFAULT_PATTERNS = {
        r'^netstat\.txt$': "netstat",
        r'^tcpvcon\.txt$': "tcpvcon",
        r'^arp_cache\.txt$': "arp",
        r'^DNS_records\.txt$': "dns"
    }

    def __init__(self, case_name="unknown", machine_name="unknown"):
        super().__init__(case_name, machine_name)

    def _parse_address(self, address_str: str):
        try:
            ip, port = address_str.rsplit(':', 1)
            return ip, int(port)
        except (ValueError, AttributeError):
            return address_str, None

    def _process_netstat_line(self, line: str, machine_name: str, dataset) -> dict:
        parts = re.split(r'\s+', line.strip())
        if len(parts) < 4: return None
        proto, local_addr, foreign_addr, state, *pid_parts = parts
        pid = pid_parts[0] if pid_parts else None
        local_ip, local_port = self._parse_address(local_addr)
        foreign_ip, foreign_port = self._parse_address(foreign_addr)
        return {"@timestamp": datetime.utcnow().isoformat() + "Z", "host": {"name": machine_name},
                "event": {"kind": "event", "category": "network", "dataset": dataset, "original": line.strip()},
                "source": {"ip": local_ip, "port": local_port}, "destination": {"ip": foreign_ip, "port": foreign_port},
                "network": {"transport": proto.lower(), "state": state}, "process": {"pid": pid}}

    def _process_tcpvcon_line(self, line: str, machine_name: str, dataset) -> dict:
        parts = [p.strip() for p in line.strip().split(',')]
        if len(parts) < 6: return None
        proto, process_name, pid, state, local_addr, foreign_addr = parts
        local_ip, local_port = self._parse_address(local_addr)
        foreign_ip, foreign_port = self._parse_address(foreign_addr)
        return {"@timestamp": datetime.utcnow().isoformat() + "Z", "host": {"name": machine_name},
                "event": {"kind": "event", "category": "network", "dataset": dataset, "original": line.strip()},
                "source": {"ip": local_ip, "port": local_port}, "destination": {"ip": foreign_ip, "port": foreign_port},
                "network": {"transport": proto.lower(), "state": state}, "process": {"pid": pid, "name": process_name}}

    def _process_arp_line(self, line: str, machine_name: str, interface_ip: str, dataset) -> dict:
        parts = re.split(r'\s+', line.strip())
        if len(parts) < 3: return None
        ip_address, mac_address, arp_type = parts[0], parts[1], parts[2]
        return {"@timestamp": datetime.utcnow().isoformat() + "Z", "host": {"name": machine_name},
                "event": {"kind": "event", "category": "network", "dataset": dataset, "original": line.strip()},
                "source": {"ip": ip_address, "mac": mac_address.lower().replace('-', ':')},
                "network": {"type": arp_type.lower(), "interface": {"ip": interface_ip}}}

    def _parse_dns_timestamp(self, timestamp_str: str) -> str:
        if not timestamp_str or timestamp_str.strip() == '0':
            return datetime.utcnow().isoformat() + "Z"
        try:
            dt_object = datetime.strptime(timestamp_str.strip(), '%m/%d/%Y %I:%M:%S %p')
            return dt_object.isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"

    def _process_dns_line(self, line: str, zone: str, machine_name: str, dataset) -> dict:
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) != 6: return None
        hostname, record_type, _, timestamp, ttl, record_data = parts
        return {"@timestamp": self._parse_dns_timestamp(timestamp), "host": {"name": machine_name},
                "event": {"kind": "event", "category": "network", "dataset": dataset, "original": line.strip()},
                "dns": {"question": {"name": hostname, "type": record_type}, "zone": zone,
                        "answers": {"data": record_data, "ttl": ttl, "type": record_type}}}

    def _process_netstat_file(self, lines: list, machine_name: str, dataset):
        header_found = False
        for line_num, line in enumerate(lines, 1):
            if not header_found:
                if "Active Connections" in line: header_found = True
                continue
            if line.strip() and (line.strip().lower().startswith('tcp') or line.strip().lower().startswith('udp')):
                try:
                    doc = self._process_netstat_line(line, machine_name, dataset)
                    if hasattr(self, 'inject_wapp_info'):
                        doc = self.inject_wapp_info(doc)

                    if doc: yield doc, "network"
                except Exception as e:
                    print(f"\n[Attention] Impossible de traiter la ligne Netstat #{line_num}. Erreur: {e}\n")

    def _process_tcpvcon_file(self, lines: list, machine_name: str, dataset):
        for line_num, line in enumerate(lines, 1):
            if line.strip() and (line.strip().lower().startswith('tcp') or line.strip().lower().startswith('udp')):
                try:
                    doc = self._process_tcpvcon_line(line, machine_name, dataset)
                    if hasattr(self, 'inject_wapp_info'):
                        doc = self.inject_wapp_info(doc)
                    if doc: yield doc, "network"
                except Exception as e:
                    print(f"\n[Attention] Impossible de traiter la ligne Tcpvcon #{line_num}. Erreur: {e}\n")

    def _process_arp_file(self, lines: list, machine_name: str, dataset):
        current_interface = None
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.lower().startswith('internet address'): continue
            if line.lower().startswith('interface:'):
                current_interface = line.split('---')[0].replace('Interface:', '').strip()
                continue
            try:
                if len(re.split(r'\s+', line)) >= 3:
                    doc = self._process_arp_line(line, machine_name, current_interface, dataset)
                    if hasattr(self, 'inject_wapp_info'):
                        doc = self.inject_wapp_info(doc)
                    if doc: yield doc, "network"
            except Exception as e:
                print(f"\n[Attention] Impossible de traiter la ligne ARP #{line_num}. Erreur: {e}\n")

    def _process_dns_file(self, lines: list, machine_name: str, dataset):
        current_zone = "unknown"
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('---') or line.lower().startswith('hostname'): continue
            if line.startswith('***'):
                current_zone = line.strip().strip(' *')
                continue
            try:
                doc = self._process_dns_line(line, current_zone, machine_name, dataset)
                if hasattr(self, 'inject_wapp_info'):
                    doc = self.inject_wapp_info(doc)
                if doc: yield doc, "network"
            except Exception as e:
                print(f"\n[Attention] Impossible de traiter la ligne DNS #{line_num}. Erreur: {e}\n")

    def _parse_bits_timestamp(self, ts_str: str) -> str:
        """Parse les dates BITS (ex: 30/03/2026 09:37:27)"""
        if not ts_str or ts_str == "UNKNOWN":
            return datetime.utcnow().isoformat() + "Z"
        try:
            dt = datetime.strptime(ts_str.strip(), "%d/%m/%Y %H:%M:%S")
            return dt.isoformat() + "Z"
        except ValueError:
            return datetime.utcnow().isoformat() + "Z"

    def _process_routes_file(self,lines, machine_name_val, dataset):
        pass

    def _process_bits_jobs_file(self, lines: list, machine_name: str, dataset: str):
        print(f"  -> Lecture du fichier BITS Jobs : {dataset}")

        current_job = {}

        def yield_job(job):
            if "guid" not in job: return None

            timestamp = self._parse_bits_timestamp(job.get("creation_time"))
            owner = job.get("owner", "")

            doc = {
                "@timestamp": timestamp,
                "host": {"name": machine_name},
                "event": {
                    "kind": "state",
                    "category": "network",
                    "dataset": dataset
                },
                "user": {"name": owner.split('\\')[-1] if '\\' in owner else owner},
                "bits": job
            }
            return doc

        for line_num, line in enumerate(lines, 1):
            clean_line = line.strip()

            # Ignorer en-têtes et pieds de page
            if not clean_line or clean_line.startswith("BITSADMIN") or clean_line.startswith(
                    "(C)") or clean_line.startswith("Listed"):
                continue

            # Nouveau Job détecté
            if line.startswith("GUID:"):
                if current_job:
                    doc = yield_job(current_job)
                    if hasattr(self, 'inject_wapp_info'):
                        doc = self.inject_wapp_info(doc)
                    if doc: yield doc, "network"

                current_job = {}
                # Extraction du GUID et du DISPLAY via regex simple
                m = re.search(r"GUID:\s*(\{.*?\})\s*DISPLAY:\s*'(.*?)'", line)
                if m:
                    current_job["guid"] = m.group(1)
                    current_job["display_name"] = m.group(2)
                continue

            if not current_job:
                continue

            # --- Parsing des blocs de données ---
            try:
                if line.startswith("TYPE:"):
                    m = re.search(r"TYPE:\s*(.*?)\s+STATE:\s*(.*?)\s+OWNER:\s*(.*)", line)
                    if m: current_job["type"], current_job["state"], current_job["owner"] = [g.strip() for g in
                                                                                             m.groups()]

                elif line.startswith("PRIORITY:"):
                    m = re.search(r"PRIORITY:\s*(.*?)\s+FILES:\s*(.*?)\s+BYTES:\s*(.*)", line)
                    if m: current_job["priority"], current_job["files"], current_job["bytes"] = [g.strip() for g in
                                                                                                 m.groups()]

                elif line.startswith("CREATION TIME:"):
                    m = re.search(r"CREATION TIME:\s*(.*?)\s+MODIFICATION TIME:\s*(.*)", line)
                    if m: current_job["creation_time"], current_job["modification_time"] = [g.strip() for g in
                                                                                            m.groups()]

                elif line.startswith("ERROR CODE:"):
                    current_job["error_code"] = line.split("ERROR CODE:")[1].strip()

                elif line.startswith("ERROR CONTEXT:"):
                    current_job["error_context"] = line.split("ERROR CONTEXT:")[1].strip()

                elif line.startswith("owner MIC integrity level:"):
                    current_job["integrity_level"] = line.split("owner MIC integrity level:")[1].strip()

                # Détection des lignes de fichiers (qui contiennent " -> ")
                elif " -> " in line:
                    parts = line.split(" -> ", 1)
                    url_part = parts[0].strip()
                    path_part = parts[1].strip()

                    # On nettoie tout ce qui est avant l'URL (statuts BITS: WORKING, ERROR FILE, SUSPENDED, etc.)
                    prefixes_to_strip = ["WORKING", "ERROR FILE:", "TRANSIENT_ERROR", "SUSPENDED", "ACKNOWLEDGED",
                                         "TRANSFERRED"]
                    for prefix in prefixes_to_strip:
                        if prefix in url_part:
                            url_part = url_part.split(prefix)[-1].strip()
                            break

                    # S'assure que job_files est une liste pour gérer les multi-téléchargements
                    current_job.setdefault("job_files", []).append({
                        "url": url_part,
                        "target_path": path_part
                    })

            except Exception as e:
                print(f"\n[Attention] Erreur de parsing BITS ligne #{line_num}: {e}\n")

        # Sauvegarde du dernier Job du fichier
        if current_job:
            doc = yield_job(current_job)
            if doc: yield doc, "network"

    def process_file(self, filepath: str, **kwargs):
        dataset = kwargs.get("dataset")

        # Lecture sécurisée : on essaie de lire self.machine_name, sinon on lit kwargs, sinon on met "unknown"
        machine_name_val = getattr(self, 'machine_name', None)
        if not machine_name_val or machine_name_val == "unknown":
            machine_name_val = kwargs.get("machine_name", "unknown")

        print(f"  -> Traitement du fichier Réseau : {filepath} (dataset: {dataset})")

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        ds_lower = dataset.lower()

        if ds_lower in ["netstat", "network_netstat"]:
            yield from self._process_netstat_file(lines, machine_name_val, dataset)
        elif ds_lower in ["tcpvcon", "network_tcpvcon"]:
            yield from self._process_tcpvcon_file(lines, machine_name_val, dataset)
        elif ds_lower in ["arp", "network_arp_cache"]:
            yield from self._process_arp_file(lines, machine_name_val, dataset)
        elif ds_lower in ["dns", "network_dns_cache"]:
            yield from self._process_dns_file(lines, machine_name_val, dataset)
        elif ds_lower in ["routes", "network_routes"]:
            yield from self._process_routes_file(lines, machine_name_val, dataset)
        elif ds_lower in ["bits_jobs", "network_bits_jobs"]:
            yield from self._process_bits_jobs_file(lines, machine_name_val, dataset)
        # Datasets restants à développer
        elif ds_lower in ["network_services", "network_lmhosts", "network_hosts", "network_networks",
                          "network_protocol"]:
            print(f"  [Info] Un parseur spécifique doit être développé pour : {dataset}")

        else:
            print(f"  [Attention] Dataset réseau non supporté '{dataset}'. Fichier ignoré.")


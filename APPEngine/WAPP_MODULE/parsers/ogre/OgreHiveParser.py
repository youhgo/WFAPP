import json
from pathlib import Path
from typing import Generator, Dict, Any, Tuple
from ...classes.BaseParser import BaseParser

class OgreHiveParser(BaseParser):
    """
    Parses DFIR-Ogre hive and registry JSONL output files into structured dictionaries.
    Handles specific event types like amcache_file.
    """

    def parse(self, input_path: Path) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    data_type = event.get("data_type", "")
                    
                    if data_type == "amcache_file":
                        yield self.parse_amcache_file(event)
                    elif data_type == "app_compat_cache":
                        yield self.parse_app_compat_cache(event)
                    elif data_type == "bam_dam":
                        yield self.parse_bam_dam(event)
                    elif data_type == "clsid":
                        yield self.parse_clsid(event)
                    elif data_type == "mass_storage":
                        yield self.parse_mass_storage(event)
                    elif data_type == "mui_cache":
                        yield self.parse_mui_cache(event)
                    elif data_type == "reg_autoruns":
                        yield from self.parse_reg_autoruns(event)
                    elif data_type == "scheduled_tasks":
                        yield self.parse_scheduled_tasks(event)
                    elif data_type == "services_control_set":
                        yield self.parse_services_control_set(event)
                    elif data_type == "shellbags":
                        yield self.parse_shellbags(event)
                    elif data_type == "user_assist":
                        yield self.parse_user_assist(event)
                    elif data_type == "user_profile":
                        yield self.parse_user_profile(event)
                    else:
                        # Fallback générique pour les autres types non implémentés spécifiquement
                        yield self.parse_generic(event, data_type)
                        
                except json.JSONDecodeError:
                    if self.logger:
                        self.logger.warning(f"[PARSING][OGRE_HIVE] Error decoding JSON line: {line}", header="WARNING")
                    continue
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"[PARSING][OGRE_HIVE] Unexpected error: {e}", header="ERROR")
                    continue

    def _get_base_data(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extrait les métadonnées communes à tous les événements hive."""
        return {
            "timestamp": event.get("timestamp"),
            "timestamp_meaning": event.get("timestamp_meaning"),
            "data_type": event.get("data_type"),
            "related_user": event.get("related_user"),
            "computer": event.get("metadata", {}).get("computer"),
            "orc_id": event.get("metadata", {}).get("orc_id"),
        }

    def parse_amcache_file(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées amcache_file."""
        data = event.get("data", {})
        
        # Split timestamp into DATE and TIME
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
                
        data_dict = {
            "DATE": date_part,
            "TIME": time_part
        }
        
        # Extraction sécurisée des champs de data
        def get_val(*keys):
            for k in keys:
                if k in data:
                    return data[k]
            return None
            
        data_dict.update({
            "name": get_val("name", "Name"),
            "path": get_val("path", "Path"),
            "sha1": get_val("sha1", "SHA1")
        })
        
        # Extraction du SID de l'owner si disponible dans key_security
        key_security = get_val("key_security", "keySecurity") or {}
        data_dict["owner_sid"] = key_security.get("owner_sid")
        
        return "ogre_amcache_file", data_dict

    def parse_app_compat_cache(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées app_compat_cache."""
        data = event.get("data", {})
        
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
        
        def get_val(*keys):
            for k in keys:
                if k in data:
                    return data[k]
            return None
            
        data_dict = {
            "DATE": date_part,
            "TIME": time_part,
            "key_modif_time": get_val("key_modif_time", "keyModifTime"),
            "path": get_val("path", "Path")
        }
        
        return "ogre_app_compat_cache", data_dict

    def parse_bam_dam(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées bam_dam."""
        data = event.get("data", {})
        
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
        
        def get_val(*keys):
            for k in keys:
                if k in data:
                    return data[k]
            return None
            
        data_dict = {
            "DATE": date_part,
            "TIME": time_part,
            "EXECTIME": get_val("exec_time", "execTime", "ExecTime"),
            "exec_path": get_val("exec_path", "execPath", "ExecPath")
        }
        
        return "ogre_bam_dam", data_dict

    def parse_clsid(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées clsid."""
        data = event.get("data", {})
        
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
        
        def get_val(*keys):
            for k in keys:
                if k in data:
                    return data[k]
            return None
            
        data_dict = {
            "date": date_part,
            "time": time_part,
            "related_user": event.get("related_user", ""),
            "executable": get_val("executable", "Executable")
        }
        
        return "ogre_clsid", data_dict

    def parse_mass_storage(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées mass_storage."""
        data = event.get("data", {})
        
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
        
        def get_val(*keys):
            for k in keys:
                if k in data:
                    return data[k]
            return None
            
        friendly_names = get_val("friendly_names", "FriendlyNames") or []
        users = get_val("users", "Users") or []
        registry_path = get_val("registry_path", "RegistryPath") or []
            
        data_dict = {
            "date": date_part,
            "time": time_part,
            "vendor_id": get_val("vendor_id", "VendorId") or "",
            "product_id": get_val("product_id", "ProductId") or "",
            "instance_id": get_val("instance_id", "InstanceId") or "",
            "friendly_names": ", ".join(friendly_names) if isinstance(friendly_names, list) else str(friendly_names),
            "users": ", ".join(users) if isinstance(users, list) else str(users),
            "registry_path": ", ".join(registry_path) if isinstance(registry_path, list) else str(registry_path),
            "volume_guid": get_val("volume_guid") or "",
            "type": get_val("type") or "",
            "vendor": get_val("vendor") or "",
            "product": get_val("product") or "",
            "usbstor_first_install": get_val("usbstor_first_install") or "",
            "usbstor_install": get_val("usbstor_install") or "",
            "usbstor_last_arrival": get_val("usbstor_last_arrival") or "",
            "usbstor_last_removal": get_val("usbstor_last_removal") or "",
            "usbstor_last_modified": get_val("usbstor_last_modified") or ""
        }
        
        return "ogre_mass_storage", data_dict

    def parse_mui_cache(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées mui_cache."""
        data = event.get("data", {})
        
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
        
        def get_val(*keys):
            for k in keys:
                if k in data:
                    return data[k]
            return None
            
        data_dict = {
            "date": date_part,
            "time": time_part,
            "executable": get_val("executable", "Executable") or ""
        }
        
        return "ogre_mui_cache", data_dict

    def parse_reg_autoruns(self, event: Dict[str, Any]) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Parse spécifiquement les entrées reg_autoruns (générateur pour valeurs multiples)."""
        data = event.get("data", {})
        
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
                
        entry_type = data.get("type", "")
        values = data.get("values", [])
        
        if not values:
            yield "ogre_reg_autoruns", {
                "date": date_part,
                "time": time_part,
                "type": entry_type,
                "name": "",
                "data": ""
            }
        else:
            for val in values:
                if isinstance(val, dict):
                    yield "ogre_reg_autoruns", {
                        "date": date_part,
                        "time": time_part,
                        "type": entry_type,
                        "name": val.get("name", ""),
                        "data": val.get("data", "")
                    }
                else:
                    yield "ogre_reg_autoruns", {
                        "date": date_part,
                        "time": time_part,
                        "type": entry_type,
                        "name": "Unknown",
                        "data": str(val)
                    }

    def parse_scheduled_tasks(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées scheduled_tasks."""
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
                
        data_dict = {
            "date": date_part,
            "time": time_part,
            "timestamp_meaning": event.get("timestamp_meaning", ""),
            "description": event.get("description", ""),
            "additional_description": event.get("additional_description", "")
        }
        
        return "ogre_scheduled_tasks", data_dict

    def parse_services_control_set(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées services_control_set."""
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
                
        data_dict = {
            "date": date_part,
            "time": time_part,
            "description": event.get("description", "")
        }
        
        return "ogre_services_control_set", data_dict

    def parse_shellbags(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées shellbags."""
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
                
        data_dict = {
            "date": date_part,
            "time": time_part,
            "timestamp_meaning": event.get("timestamp_meaning", ""),
            "description": event.get("description", ""),
            "additional_description": event.get("additional_description", "")
        }
        
        return "ogre_shellbags", data_dict

    def parse_user_assist(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées user_assist."""
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
                
        data_dict = {
            "date": date_part,
            "time": time_part,
            "description": event.get("description", ""),
            "additional_description": event.get("additional_description", "")
        }
        
        return "ogre_user_assist", data_dict

    def parse_user_profile(self, event: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Parse spécifiquement les entrées user_profile."""
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
                
        data_dict = {
            "date": date_part,
            "time": time_part,
            "description": event.get("description", ""),
            "additional_description": event.get("additional_description", "")
        }
        
        return "ogre_user_profile", data_dict

    def parse_generic(self, event: Dict[str, Any], data_type: str) -> Tuple[str, Dict[str, Any]]:
        """Fallback pour n'importe quel event non spécifique."""
        timestamp_raw = event.get("timestamp", "")
        date_part, time_part = "", ""
        if "T" in timestamp_raw:
            date_part, time_part = timestamp_raw.split("T", 1)
            if "+" in time_part:
                time_part = time_part.split("+")[0]
            elif "-" in time_part:
                time_part = time_part.split("-")[0]
            elif "Z" in time_part:
                time_part = time_part.replace("Z", "")
                
        data_dict = {
            "date": date_part,
            "time": time_part,
            "description": event.get("description", ""),
            "additional_description": event.get("additional_description", "")
        }
                
        # Le nom du tag sera basé sur le data_type (ex: ogre_shim_db)
        tag = f"ogre_{data_type}" if data_type else "ogre_hive_generic"
        return tag, data_dict

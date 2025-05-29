#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte d'artefacts à partir de disques durs physiques.

Ce module permet d'analyser directement des disques durs physiques
pour collecter des artefacts forensiques.
"""

import os
import sys
import logging
import platform
import subprocess
import json
from datetime import datetime
from pathlib import Path

# Ajout du répertoire parent au path pour les imports absolus
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # src/
root_dir = os.path.dirname(parent_dir)     # racine du projet
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from utils.logger import get_logger
# No fallback logger needed, if utils.logger is not found, it's a critical error.

class DiskCollector:
    """
    Collecteur d'artefacts à partir de disques durs physiques.
    
    Cette classe permet d'analyser directement des disques durs physiques
    pour collecter des artefacts forensiques.
    """
    
    def __init__(self, config=None):
        """
        Initialise le collecteur de disques durs.
        
        Args:
            config (dict): Configuration du collecteur
        """
        self.config = config or {}
        self.logger = get_logger("forensichunter.collectors.disk") # Get logger instance here
        self.artifacts = []
    
    def list_physical_disks(self):
        """
        Liste les disques durs physiques disponibles sur le système.
        
        Returns:
            list: Liste des disques durs physiques
        """
        disks = []
        
        try:
            if platform.system() == "Windows":
                # Utilisation de wmic pour lister les disques physiques sur Windows
                cmd = "wmic diskdrive list brief /format:csv"
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
                except Exception as e:
                    self.logger.error(f"Failed to execute '{cmd}'. Exception: {str(e)}")
                    result = None # Ensure result is defined

                if result and result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:  # Au moins une ligne d'en-tête et une ligne de données
                        headers = lines[0].strip().split(',')
                        
                        # Trouver les indices des colonnes qui nous intéressent
                        device_id_idx = headers.index("DeviceID") if "DeviceID" in headers else -1
                        model_idx = headers.index("Model") if "Model" in headers else -1
                        size_idx = headers.index("Size") if "Size" in headers else -1
                        
                        for i in range(1, len(lines)):
                            if not lines[i].strip():
                                continue
                                
                            values = lines[i].strip().split(',')
                            
                            if device_id_idx >= 0 and model_idx >= 0 and size_idx >= 0 and len(values) > max(device_id_idx, model_idx, size_idx):
                                device_id = values[device_id_idx]
                                model = values[model_idx]
                                size = int(values[size_idx]) if values[size_idx].isdigit() else 0
                                size_gb = round(size / (1024**3), 2)
                                
                                disks.append({
                                    "device_id": device_id,
                                    "model": model,
                                    "size_bytes": size,
                                    "size_gb": size_gb,
                                    "friendly_name": f"{model} ({size_gb} GB)"
                                })
                elif result:
                    self.logger.error(f"Error executing '{cmd}'. Return code: {result.returncode}. Stderr: {result.stderr.strip()}. Stdout: {result.stdout.strip()}")
                
                # Ajouter également les volumes logiques
                cmd_logical = "wmic logicaldisk get deviceid, volumename, size, filesystem /format:csv"
                try:
                    result_logical = subprocess.run(cmd_logical, shell=True, capture_output=True, text=True, check=False)
                except Exception as e:
                    self.logger.error(f"Failed to execute '{cmd_logical}'. Exception: {str(e)}")
                    result_logical = None

                if result_logical and result_logical.returncode == 0:
                    lines = result_logical.stdout.strip().split('\n')
                    if len(lines) > 1:
                        headers = lines[0].strip().split(',')
                        
                        device_id_idx = headers.index("DeviceID") if "DeviceID" in headers else -1
                        volume_name_idx = headers.index("VolumeName") if "VolumeName" in headers else -1
                        size_idx = headers.index("Size") if "Size" in headers else -1
                        filesystem_idx = headers.index("FileSystem") if "FileSystem" in headers else -1
                        
                        for i in range(1, len(lines)):
                            if not lines[i].strip():
                                continue
                                
                            values = lines[i].strip().split(',')
                            
                            if device_id_idx >= 0 and len(values) > device_id_idx:
                                device_id = values[device_id_idx]
                                volume_name = values[volume_name_idx] if volume_name_idx >= 0 and len(values) > volume_name_idx else ""
                                size = int(values[size_idx]) if size_idx >= 0 and len(values) > size_idx and values[size_idx].isdigit() else 0
                                filesystem = values[filesystem_idx] if filesystem_idx >= 0 and len(values) > filesystem_idx else ""
                                
                                size_gb = round(size / (1024**3), 2)
                                
                                disks.append({
                                    "device_id": device_id,
                                    "model": f"Volume {device_id}",
                                    "volume_name": volume_name,
                                    "filesystem": filesystem,
                                    "size_bytes": size,
                                    "size_gb": size_gb,
                                    "friendly_name": f"{device_id} - {volume_name} ({size_gb} GB, {filesystem})",
                                    "is_volume": True
                                })
                elif result_logical:
                    self.logger.error(f"Error executing '{cmd_logical}'. Return code: {result_logical.returncode}. Stderr: {result_logical.stderr.strip()}. Stdout: {result_logical.stdout.strip()}")
            
            elif platform.system() == "Linux":
                # Utilisation de lsblk pour lister les disques physiques sur Linux
                cmd_lsblk = "lsblk -J -o NAME,MODEL,SIZE,TYPE"
                try:
                    result_lsblk = subprocess.run(cmd_lsblk, shell=True, capture_output=True, text=True, check=False)
                except Exception as e:
                    self.logger.error(f"Failed to execute '{cmd_lsblk}'. Exception: {str(e)}")
                    result_lsblk = None
                
                if result_lsblk and result_lsblk.returncode == 0:
                    try:
                        data = json.loads(result_lsblk.stdout)
                        for device in data.get("blockdevices", []):
                            if device.get("type") == "disk":
                                name = device.get("name", "")
                                model = device.get("model", "")
                                size = device.get("size", "")
                                
                                disks.append({
                                    "device_id": f"/dev/{name}",
                                    "model": model,
                                    "size_bytes": 0,  # Pas facilement disponible dans ce format
                                    "size_gb": size,
                                    "friendly_name": f"{model} {size}"
                                })
                    except json.JSONDecodeError as je:
                        self.logger.error(f"Failed to decode JSON output from '{cmd_lsblk}'. Error: {str(je)}. Output: {result_lsblk.stdout}")
                elif result_lsblk:
                    self.logger.error(f"Error executing '{cmd_lsblk}'. Return code: {result_lsblk.returncode}. Stderr: {result_lsblk.stderr.strip()}. Stdout: {result_lsblk.stdout.strip()}")
            
            else:
                self.logger.warning(f"Système d'exploitation non pris en charge pour la liste des disques: {platform.system()}")
        
        except Exception as e:
            self.logger.error(f"Exception in list_physical_disks: {str(e)}")
        
        return disks
    
    def collect(self, disk_ids=None):
        """
        Collecte des artefacts à partir des disques durs spécifiés.
        
        Args:
            disk_ids (list): Liste des identifiants de disques à analyser
            
        Returns:
            list: Liste des artefacts collectés
        """
        self.artifacts = []
        
        if not disk_ids:
            self.logger.warning("Aucun disque spécifié pour la collecte")
            return self.artifacts
        
        self.logger.info(f"Début de la collecte sur {len(disk_ids)} disque(s)")
        
        for disk_id in disk_ids:
            try:
                self.logger.info(f"Analyse du disque: {disk_id}")
                
                # Vérifier si le disque existe
                if not os.path.exists(disk_id) and not disk_id.startswith("\\\\.\\"):
                    # Sur Windows, essayer avec le préfixe \\.\
                    if platform.system() == "Windows" and not disk_id.startswith("\\\\.\\"):
                        disk_id = f"\\\\.\\{disk_id}"
                    
                    if not os.path.exists(disk_id):
                        self.logger.warning(f"Le disque {disk_id} n'existe pas")
                        continue
                
                # Collecter les informations de base sur le disque
                disk_info = self._get_disk_info(disk_id)
                
                if disk_info:
                    self.artifacts.append({
                        "type": "disk",
                        "source": disk_id,
                        "timestamp": datetime.now().isoformat(),
                        "data": disk_info
                    })
                
                # Collecter les partitions
                partitions = self._get_disk_partitions(disk_id)
                
                for partition in partitions:
                    self.artifacts.append({
                        "type": "partition",
                        "source": disk_id,
                        "partition": partition.get("device_id", ""),
                        "timestamp": datetime.now().isoformat(),
                        "data": partition
                    })
                
                # Si c'est un volume logique, collecter les fichiers importants
                if disk_id.endswith(":") and platform.system() == "Windows":
                    self._collect_important_files(disk_id)
                
                self.logger.info(f"Collecte terminée pour le disque: {disk_id}")
            
            except Exception as e:
                self.logger.error(f"Error during collection for disk {disk_id}: {str(e)}") # Changed to English
        
        self.logger.info(f"Collecte terminée: {len(self.artifacts)} artefacts collectés")
        return self.artifacts
    
    def _get_disk_info(self, disk_id):
        """
        Obtient des informations sur un disque dur.
        
        Args:
            disk_id (str): Identifiant du disque
            
        Returns:
            dict: Informations sur le disque
        """
        disk_info = {
            "device_id": disk_id,
            "model": "",
            "size_bytes": 0,
            "size_gb": 0,
            "serial": "",
            "firmware": ""
        }
        
        try:
            if platform.system() == "Windows":
                # Utiliser wmic pour obtenir des informations détaillées sur le disque
                if disk_id.endswith(":"):
                    # C'est un volume logique
                    cmd_logical_info = f'wmic logicaldisk where "DeviceID=\'{disk_id}\'" get size, filesystem, volumename /format:csv'
                    try:
                        result_logical_info = subprocess.run(cmd_logical_info, shell=True, capture_output=True, text=True, check=False)
                    except Exception as e:
                        self.logger.error(f"Failed to execute '{cmd_logical_info}'. Exception: {str(e)}")
                        result_logical_info = None

                    if result_logical_info and result_logical_info.returncode == 0:
                        lines = result_logical_info.stdout.strip().split('\n')
                        if len(lines) > 1:
                            headers = lines[0].strip().split(',')
                            values = lines[1].strip().split(',')
                            
                            size_idx = headers.index("Size") if "Size" in headers else -1
                            filesystem_idx = headers.index("FileSystem") if "FileSystem" in headers else -1
                            volumename_idx = headers.index("VolumeName") if "VolumeName" in headers else -1
                            
                            if size_idx >= 0 and len(values) > size_idx:
                                size = int(values[size_idx]) if values[size_idx].isdigit() else 0
                                disk_info["size_bytes"] = size
                                disk_info["size_gb"] = round(size / (1024**3), 2)
                            
                            if filesystem_idx >= 0 and len(values) > filesystem_idx:
                                disk_info["filesystem"] = values[filesystem_idx]
                            
                            if volumename_idx >= 0 and len(values) > volumename_idx:
                                disk_info["volume_name"] = values[volumename_idx]
                                disk_info["model"] = f"Volume {disk_id} - {values[volumename_idx]}"
                    elif result_logical_info:
                        self.logger.error(f"Error executing '{cmd_logical_info}'. Return code: {result_logical_info.returncode}. Stderr: {result_logical_info.stderr.strip()}. Stdout: {result_logical_info.stdout.strip()}")
                else:
                    # C'est un disque physique
                    # Extraire le numéro de disque à partir de l'ID (ex: \\.\PhysicalDrive0 -> 0)
                    disk_num_str = disk_id.split("PhysicalDrive")[-1]
                    if not disk_num_str.isdigit():
                        self.logger.error(f"Could not extract a valid disk number from PhysicalDrive ID: {disk_id}")
                        return disk_info # Return basic info
                    
                    cmd_physical_info = f'wmic diskdrive where "Index={disk_num_str}" get model, size, serialnumber, firmwarerevision /format:csv'
                    try:
                        result_physical_info = subprocess.run(cmd_physical_info, shell=True, capture_output=True, text=True, check=False)
                    except Exception as e:
                        self.logger.error(f"Failed to execute '{cmd_physical_info}'. Exception: {str(e)}")
                        result_physical_info = None
                        
                    if result_physical_info and result_physical_info.returncode == 0:
                        lines = result_physical_info.stdout.strip().split('\n')
                        if len(lines) > 1:
                            headers = lines[0].strip().split(',')
                            values = lines[1].strip().split(',')
                            
                            model_idx = headers.index("Model") if "Model" in headers else -1
                            size_idx = headers.index("Size") if "Size" in headers else -1
                            serial_idx = headers.index("SerialNumber") if "SerialNumber" in headers else -1
                            firmware_idx = headers.index("FirmwareRevision") if "FirmwareRevision" in headers else -1
                            
                            if model_idx >= 0 and len(values) > model_idx:
                                disk_info["model"] = values[model_idx]
                            
                            if size_idx >= 0 and len(values) > size_idx:
                                size = int(values[size_idx]) if values[size_idx].isdigit() else 0
                                disk_info["size_bytes"] = size
                                disk_info["size_gb"] = round(size / (1024**3), 2)
                            
                            if serial_idx >= 0 and len(values) > serial_idx:
                                disk_info["serial"] = values[serial_idx]
                            
                            if firmware_idx >= 0 and len(values) > firmware_idx:
                                disk_info["firmware"] = values[firmware_idx]
                    elif result_physical_info:
                        self.logger.error(f"Error executing '{cmd_physical_info}'. Return code: {result_physical_info.returncode}. Stderr: {result_physical_info.stderr.strip()}. Stdout: {result_physical_info.stdout.strip()}")
            
            elif platform.system() == "Linux":
                # Utiliser lsblk et hdparm pour obtenir des informations détaillées sur le disque
                disk_name = os.path.basename(disk_id)
                
                # Obtenir la taille et le modèle
                cmd_lsblk_info = f"lsblk -J -o NAME,MODEL,SIZE,TYPE,SERIAL {disk_id}"
                try:
                    result_lsblk_info = subprocess.run(cmd_lsblk_info, shell=True, capture_output=True, text=True, check=False)
                except Exception as e:
                    self.logger.error(f"Failed to execute '{cmd_lsblk_info}'. Exception: {str(e)}")
                    result_lsblk_info = None

                if result_lsblk_info and result_lsblk_info.returncode == 0:
                    try:
                        data = json.loads(result_lsblk_info.stdout)
                        for device in data.get("blockdevices", []):
                            if device.get("name") == disk_name:
                                disk_info["model"] = device.get("model", "")
                                disk_info["size_gb"] = device.get("size", "") # This is a string like "10G"
                                disk_info["serial"] = device.get("serial", "")
                                break
                    except json.JSONDecodeError as je:
                        self.logger.error(f"Failed to decode JSON output from '{cmd_lsblk_info}'. Error: {str(je)}. Output: {result_lsblk_info.stdout}")
                elif result_lsblk_info:
                    self.logger.error(f"Error executing '{cmd_lsblk_info}'. Return code: {result_lsblk_info.returncode}. Stderr: {result_lsblk_info.stderr.strip()}. Stdout: {result_lsblk_info.stdout.strip()}")
                
                # Obtenir le firmware avec hdparm
                cmd_hdparm = f"hdparm -I {disk_id}" # Grep can hide errors, so get full output first
                try:
                    result_hdparm = subprocess.run(cmd_hdparm, shell=True, capture_output=True, text=True, check=False)
                except Exception as e:
                    self.logger.error(f"Failed to execute '{cmd_hdparm}'. Exception: {str(e)}")
                    result_hdparm = None

                if result_hdparm and result_hdparm.returncode == 0:
                    # Search for 'Firmware Revision' in output
                    for line in result_hdparm.stdout.splitlines():
                        if 'Firmware Revision' in line:
                            firmware_line = line.strip()
                            if ":" in firmware_line:
                                disk_info["firmware"] = firmware_line.split(":", 1)[1].strip()
                            break # Found it
                elif result_hdparm: # Log error only if hdparm command itself failed
                    # Not finding 'Firmware Revision' isn't necessarily an error for all devices
                    if "not supported" not in result_hdparm.stderr.lower() and "no such file or directory" not in result_hdparm.stderr.lower() :
                         self.logger.warning(f"Command '{cmd_hdparm}' executed with code {result_hdparm.returncode}. Stderr: {result_hdparm.stderr.strip()}. Stdout: {result_hdparm.stdout.strip()}")
        
        except Exception as e:
            self.logger.error(f"Exception in _get_disk_info for disk {disk_id}: {str(e)}")
        
        return disk_info
    
    def _get_disk_partitions(self, disk_id):
        """
        Obtient la liste des partitions d'un disque dur.
        
        Args:
            disk_id (str): Identifiant du disque
            
        Returns:
            list: Liste des partitions
        """
        partitions = []
        
        try:
            if platform.system() == "Windows":
                if disk_id.endswith(":"):
                    # C'est déjà un volume logique, pas besoin de chercher des partitions
                    return partitions
                
                # Extraire le numéro de disque à partir de l'ID (ex: \\.\PhysicalDrive0 -> 0)
                disk_num_str = disk_id.split("PhysicalDrive")[-1]
                if not disk_num_str.isdigit():
                    self.logger.error(f"Could not extract a valid disk number from PhysicalDrive ID for diskpart: {disk_id}")
                    return partitions # Return empty list

                # Utiliser diskpart pour lister les partitions
                # Créer un script diskpart temporaire
                temp_dir = os.environ.get("TEMP", "C:\\Windows\\Temp")
                script_path = os.path.join(temp_dir, f"diskpart_script_{disk_num_str}.txt")
                
                try:
                    with open(script_path, "w") as f:
                        f.write(f"select disk {disk_num_str}\nlist partition\nexit\n")
                except IOError as e:
                    self.logger.error(f"Failed to create diskpart script at {script_path}: {str(e)}")
                    return partitions # Return empty list

                # Exécuter diskpart avec le script
                cmd_diskpart = f"diskpart /s {script_path}"
                try:
                    result_diskpart = subprocess.run(cmd_diskpart, shell=True, capture_output=True, text=True, check=False)
                except Exception as e:
                    self.logger.error(f"Failed to execute '{cmd_diskpart}'. Exception: {str(e)}")
                    result_diskpart = None # Ensure result_diskpart is defined
                
                if result_diskpart and result_diskpart.returncode == 0:
                    # Analyser la sortie pour extraire les informations sur les partitions
                    lines = result_diskpart.stdout.strip().split('\n')
                    partition_section = False
                    
                    for line in lines:
                        line = line.strip()
                        
                        if "Partition" in line and "###" in line and "Type" in line and "Size" in line:
                            partition_section = True
                            continue
                        
                        if partition_section and line and line[0].isdigit():
                            parts = line.split()
                            if len(parts) >= 4:
                                partition_num = parts[0]
                                partition_type = parts[1]
                                size_mb = float(parts[2])
                                
                                partitions.append({
                                    "device_id": f"{disk_id} Partition {partition_num}",
                                    "partition_number": partition_num,
                                    "type": partition_type,
                                    "size_mb": size_mb,
                                    "size_gb": round(size_mb / 1024, 2)
                                })
                elif result_diskpart:
                    self.logger.error(f"Error executing '{cmd_diskpart}'. Return code: {result_diskpart.returncode}. Stderr: {result_diskpart.stderr.strip()}. Stdout: {result_diskpart.stdout.strip()}")
                
                # Supprimer le script temporaire
                try:
                    if os.path.exists(script_path): # Check if script was created before trying to remove
                        os.remove(script_path)
                except OSError as e:
                    self.logger.warning(f"Failed to remove temporary diskpart script {script_path}: {str(e)}")
            
            elif platform.system() == "Linux":
                # Utiliser lsblk pour lister les partitions
                disk_name = os.path.basename(disk_id)
                cmd_lsblk_part = f"lsblk -J -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT {disk_id}"
                try:
                    result_lsblk_part = subprocess.run(cmd_lsblk_part, shell=True, capture_output=True, text=True, check=False)
                except Exception as e:
                    self.logger.error(f"Failed to execute '{cmd_lsblk_part}'. Exception: {str(e)}")
                    result_lsblk_part = None

                if result_lsblk_part and result_lsblk_part.returncode == 0:
                    try:
                        data = json.loads(result_lsblk_part.stdout)
                        for device in data.get("blockdevices", []):
                            if device.get("name") == disk_name:
                                for child in device.get("children", []):
                                    if child.get("type") == "part":
                                        name = child.get("name", "")
                                        size = child.get("size", "")
                                        fstype = child.get("fstype", "")
                                        mountpoint = child.get("mountpoint", "")
                                        
                                        partitions.append({
                                            "device_id": f"/dev/{name}",
                                            "partition_number": name.replace(disk_name, ""),
                                            "type": fstype,
                                            "size_gb": size,
                                            "mountpoint": mountpoint
                                        })
                    except json.JSONDecodeError as je:
                        self.logger.error(f"Failed to decode JSON output from '{cmd_lsblk_part}'. Error: {str(je)}. Output: {result_lsblk_part.stdout}")
                elif result_lsblk_part:
                    self.logger.error(f"Error executing '{cmd_lsblk_part}'. Return code: {result_lsblk_part.returncode}. Stderr: {result_lsblk_part.stderr.strip()}. Stdout: {result_lsblk_part.stdout.strip()}")
        
        except Exception as e:
            self.logger.error(f"Exception in _get_disk_partitions for disk {disk_id}: {str(e)}")
        
        return partitions
    
    def _collect_important_files(self, volume_id):
        """
        Collecte des fichiers importants à partir d'un volume.
        
        Args:
            volume_id (str): Identifiant du volume (ex: C:)
        """
        important_paths = [
            # Journaux d'événements Windows
            f"{volume_id}\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            f"{volume_id}\\Windows\\System32\\winevt\\Logs\\System.evtx",
            f"{volume_id}\\Windows\\System32\\winevt\\Logs\\Application.evtx",
            
            # Fichiers de registre
            f"{volume_id}\\Windows\\System32\\config\\SYSTEM",
            f"{volume_id}\\Windows\\System32\\config\\SOFTWARE",
            f"{volume_id}\\Windows\\System32\\config\\SAM",
            
            # Fichiers de démarrage
            f"{volume_id}\\Windows\\System32\\drivers\\etc\\hosts",
            f"{volume_id}\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            
            # Fichiers utilisateur
            f"{volume_id}\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            f"{volume_id}\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
            f"{volume_id}\\Users\\*\\AppData\\Local\\Temp",
            
            # Navigateurs
            f"{volume_id}\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
            f"{volume_id}\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History",
            f"{volume_id}\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite"
        ]
        
        # Wrap the main loop for path patterns in a try-except block
        for path_pattern in important_paths:
            try: # This try is for the processing of a single path_pattern
                # Gérer les chemins avec des caractères génériques
                if "*" in path_pattern:
                    # This part needs careful error handling for os.walk and os.path.exists
                    try:
                        # Expand the initial part of the pattern that does not contain wildcards
                        # to ensure os.walk has a valid starting directory.
                        # For example, "C:\\Users\\*\\AppData" -> "C:\\Users"
                        base_dir_pattern = path_pattern.split("*", 1)[0]
                        # Resolve the base directory if it contains environment variables like %SystemDrive%
                        expanded_base_dir = os.path.expandvars(base_dir_pattern)
                        
                        # Make sure the base directory part before any wildcard actually exists
                        # Example: C:\Users\* - base_dir_to_check would be C:\Users
                        # Example: C:\Windows\System32\Tasks\*\Microsoft - base_dir_to_check would be C:\Windows\System32\Tasks
                        
                        # Let's find the last path component that is static before a wildcard
                        # This is tricky if the wildcard is not in the last component of the path.
                        # For now, using the part before the first wildcard as the base for os.walk.
                        # This might need more refinement for complex patterns.
                        
                        # If expanded_base_dir ends with a path separator, os.walk might not behave as expected.
                        # Usually, it's better to walk a directory like "C:\Users" rather than "C:\Users\*".
                        # The pattern matching will handle the wildcard part.
                        
                        # We need to find a valid existing directory to start os.walk from.
                        # If path_pattern is "C:\\Users\\*\\AppData\\Local", base_for_walk should be "C:\\Users"
                        
                        # Let's take the directory part of the expanded_base_dir
                        walk_start_dir = os.path.dirname(expanded_base_dir)
                        if not os.path.isdir(walk_start_dir):
                             # If the directory of the base pattern does not exist, try the expanded base_dir itself
                             walk_start_dir = expanded_base_dir
                             if not os.path.isdir(walk_start_dir):
                                self.logger.debug(f"Base directory '{walk_start_dir}' for pattern '{path_pattern}' does not exist or is not a directory. Skipping.")
                                continue # Skip this pattern

                        for root, dirs, files in os.walk(walk_start_dir, topdown=True):
                            # Prune directories that cannot possibly match the pattern to optimize the walk
                            # This is a basic optimization; more complex patterns might need more sophisticated pruning.
                            dirs[:] = [d for d in dirs if self._directory_might_contain_match(os.path.join(root,d), path_pattern)]

                            for item_name in dirs + files: # Check both directories and files
                                full_path = os.path.join(root, item_name)
                                # Normalize paths for consistent matching
                                normalized_full_path = os.path.normpath(full_path)
                                normalized_path_pattern = os.path.normpath(os.path.expandvars(path_pattern))
                                
                                if self._match_pattern(normalized_full_path, normalized_path_pattern):
                                    self._collect_file_info(normalized_full_path)
                    except Exception as walk_e:
                        self.logger.error(f"Error processing wildcard pattern '{path_pattern}': {str(walk_e)}")
                else:
                    # Chemin direct
                    expanded_path = os.path.expandvars(path_pattern) # Expand environment variables
                    if os.path.exists(expanded_path):
                        self._collect_file_info(expanded_path)
                    else:
                        self.logger.debug(f"Path {expanded_path} (from pattern {path_pattern}) does not exist.")
            except Exception as e: # Catch errors for a single path_pattern
                self.logger.error(f"Unhandled error while processing path pattern '{path_pattern}': {str(e)}")
    
    def _directory_might_contain_match(self, dir_path, pattern):
        """
        Checks if a directory path could potentially lead to a match for the pattern.
        This is a basic pruning helper for os.walk.
        Example: pattern C:\Users\*\AppData, dir_path C:\Windows -> False
                 pattern C:\Users\*\AppData, dir_path C:\Users\TestUser -> True
        """
        # Normalize both paths
        dir_path_norm = os.path.normpath(dir_path)
        pattern_norm = os.path.normpath(os.path.expandvars(pattern))

        # Get parts of the paths
        dir_parts = dir_path_norm.split(os.sep)
        pattern_parts = pattern_norm.split(os.sep)

        # If pattern is shorter or equal, and dir_path starts with pattern (up to wildcard)
        # This is a simplified check. A more robust solution would involve comparing parts
        # and respecting wildcards at each level.
        
        # Check if the current directory path is "a prefix" of the pattern,
        # or if the pattern (up to a wildcard) is a prefix of the directory path.
        
        len_min = min(len(dir_parts), len(pattern_parts))
        for i in range(len_min):
            if pattern_parts[i] == "*": # Wildcard in pattern, can match anything at this level
                return True 
            if dir_parts[i].lower() != pattern_parts[i].lower(): # Mismatch before any wildcard in pattern
                return False # This directory cannot lead to a match
        
        # If we've exhausted dir_parts and all matched so far, it's a potential match.
        # Or if we've exhausted pattern_parts (and it didn't end in wildcard), and all matched.
        return True


    def _match_pattern(self, path, pattern):
        """
        Vérifie si un chemin correspond à un modèle avec des caractères génériques.
        
        Args:
            path (str): Chemin à vérifier
            pattern (str): Modèle avec des caractères génériques
            
        Returns:
            bool: True si le chemin correspond au modèle, False sinon
        """
        import fnmatch
        return fnmatch.fnmatch(path, pattern)
    
    def _collect_file_info(self, file_path):
        """
        Collecte des informations sur un fichier.
        
        Args:
            file_path (str): Chemin du fichier
        """
        try:
            # Ensure we are dealing with a file, not a directory that might have matched a pattern
            if not os.path.isfile(file_path):
                self.logger.debug(f"Path {file_path} is a directory or not a regular file. Skipping file info collection.")
                return

            file_stat = os.stat(file_path)
            
            file_info = {
                "path": file_path,
                "size": file_stat.st_size,
                "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(file_stat.st_atime).isoformat()
            }
            
            self.artifacts.append({
                "type": "file",
                "source": file_path, # Source is the file itself
                "timestamp": datetime.now().isoformat(),
                "data": file_info
            })
            
            self.logger.debug(f"Collected file info: {file_path}")
        except OSError as oe: # Catch OS-level errors like permission denied more specifically
            self.logger.error(f"OS error collecting info for file {file_path}: {str(oe)}")
        except Exception as e: # Catch any other unexpected errors
            self.logger.error(f"Unexpected error collecting info for file {file_path}: {str(e)}")


# Test du module si exécuté directement
if __name__ == "__main__":
    collector = DiskCollector()
    disks = collector.list_physical_disks()
    
    print(f"Disques physiques détectés: {len(disks)}")
    for disk in disks:
        print(f"- {disk['friendly_name']} ({disk['device_id']})")
    
    if disks:
        print("\nCollecte d'artefacts sur le premier disque...")
        artifacts = collector.collect([disks[0]["device_id"]])
        print(f"Artefacts collectés: {len(artifacts)}")

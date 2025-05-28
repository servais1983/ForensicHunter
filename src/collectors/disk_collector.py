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

try:
    from utils.logger import get_logger
except ImportError:
    # Définition d'une fonction de remplacement si le module n'est pas disponible
    def get_logger(name="forensichunter"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

# Obtention du logger
logger = get_logger("forensichunter.collectors.disk")


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
        self.logger = logger
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
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
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
                
                # Ajouter également les volumes logiques
                cmd = "wmic logicaldisk get deviceid, volumename, size, filesystem /format:csv"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
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
            
            elif platform.system() == "Linux":
                # Utilisation de lsblk pour lister les disques physiques sur Linux
                cmd = "lsblk -J -o NAME,MODEL,SIZE,TYPE"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    try:
                        data = json.loads(result.stdout)
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
                    except json.JSONDecodeError:
                        self.logger.error("Erreur lors du décodage JSON de la sortie lsblk")
            
            else:
                self.logger.warning(f"Système d'exploitation non pris en charge: {platform.system()}")
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la liste des disques physiques: {str(e)}")
        
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
                self.logger.error(f"Erreur lors de la collecte sur le disque {disk_id}: {str(e)}")
        
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
                    cmd = f'wmic logicaldisk where "DeviceID=\'{disk_id}\'" get size, filesystem, volumename /format:csv'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
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
                else:
                    # C'est un disque physique
                    # Extraire le numéro de disque à partir de l'ID (ex: \\.\PhysicalDrive0 -> 0)
                    disk_num = disk_id.split("PhysicalDrive")[-1]
                    cmd = f'wmic diskdrive where "Index={disk_num}" get model, size, serialnumber, firmwarerevision /format:csv'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
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
            
            elif platform.system() == "Linux":
                # Utiliser lsblk et hdparm pour obtenir des informations détaillées sur le disque
                disk_name = os.path.basename(disk_id)
                
                # Obtenir la taille et le modèle
                cmd = f"lsblk -J -o NAME,MODEL,SIZE,TYPE,SERIAL {disk_id}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    try:
                        data = json.loads(result.stdout)
                        for device in data.get("blockdevices", []):
                            if device.get("name") == disk_name:
                                disk_info["model"] = device.get("model", "")
                                disk_info["size_gb"] = device.get("size", "")
                                disk_info["serial"] = device.get("serial", "")
                                break
                    except json.JSONDecodeError:
                        self.logger.error("Erreur lors du décodage JSON de la sortie lsblk")
                
                # Obtenir le firmware avec hdparm
                cmd = f"hdparm -I {disk_id} | grep 'Firmware Revision'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    firmware_line = result.stdout.strip()
                    if ":" in firmware_line:
                        disk_info["firmware"] = firmware_line.split(":", 1)[1].strip()
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'obtention des informations sur le disque {disk_id}: {str(e)}")
        
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
                disk_num = disk_id.split("PhysicalDrive")[-1]
                
                # Utiliser diskpart pour lister les partitions
                # Créer un script diskpart temporaire
                script_path = os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"), "diskpart_script.txt")
                with open(script_path, "w") as f:
                    f.write(f"select disk {disk_num}\nlist partition\nexit\n")
                
                # Exécuter diskpart avec le script
                cmd = f"diskpart /s {script_path}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    # Analyser la sortie pour extraire les informations sur les partitions
                    lines = result.stdout.strip().split('\n')
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
                
                # Supprimer le script temporaire
                try:
                    os.remove(script_path)
                except:
                    pass
            
            elif platform.system() == "Linux":
                # Utiliser lsblk pour lister les partitions
                disk_name = os.path.basename(disk_id)
                cmd = f"lsblk -J -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT {disk_id}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    try:
                        data = json.loads(result.stdout)
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
                    except json.JSONDecodeError:
                        self.logger.error("Erreur lors du décodage JSON de la sortie lsblk")
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'obtention des partitions du disque {disk_id}: {str(e)}")
        
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
        
        for path_pattern in important_paths:
            try:
                # Gérer les chemins avec des caractères génériques
                if "*" in path_pattern:
                    base_path = path_pattern.split("*")[0]
                    if os.path.exists(base_path):
                        for root, dirs, files in os.walk(base_path):
                            for item in dirs + files:
                                full_path = os.path.join(root, item)
                                if self._match_pattern(full_path, path_pattern):
                                    self._collect_file_info(full_path)
                else:
                    # Chemin direct
                    if os.path.exists(path_pattern):
                        self._collect_file_info(path_pattern)
            except Exception as e:
                self.logger.error(f"Erreur lors de la collecte du fichier {path_pattern}: {str(e)}")
    
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
            if os.path.isfile(file_path):
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
                    "source": file_path,
                    "timestamp": datetime.now().isoformat(),
                    "data": file_info
                })
                
                self.logger.debug(f"Collecté: {file_path}")
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte du fichier {file_path}: {str(e)}")


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

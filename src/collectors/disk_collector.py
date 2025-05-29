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
import fnmatch
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
        self.logger = get_logger("forensichunter.collectors.disk")
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
                cmd = "wmic diskdrive list brief /format:csv"
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
                except Exception as e:
                    self.logger.error(f"Failed to execute '{cmd}'. Exception: {str(e)}")
                    result = None

                if result and result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        headers = lines[0].strip().split(',')
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
                
                cmd_logical = "wmic logicaldisk get deviceid, volumename, size, filesystem /format:csv"
                try:
                    result_logical = subprocess.run(cmd_logical, shell=True, capture_output=True, text=True, check=False)
                    if result_logical and result_logical.returncode == 0:
                        lines = result_logical.stdout.strip().split('\n')
                        if len(lines) > 1:
                            headers = lines[0].strip().split(',')
                            for i in range(1, len(lines)):
                                if not lines[i].strip():
                                    continue
                                values = lines[i].strip().split(',')
                                device_id_idx = headers.index("DeviceID") if "DeviceID" in headers else -1
                                
                                if device_id_idx >= 0 and len(values) > device_id_idx:
                                    device_id = values[device_id_idx]
                                    volume_name = values[1] if len(values) > 1 else ""
                                    size = int(values[2]) if len(values) > 2 and values[2].isdigit() else 0
                                    filesystem = values[3] if len(values) > 3 else ""
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
                except Exception as e:
                    self.logger.error(f"Failed to execute logical disk command: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Exception in list_physical_disks: {str(e)}")
        
        return disks
    
    def collect(self, disk_ids=None):
        """
        Collecte des artefacts à partir des disques durs spécifiés.
        """
        self.artifacts = []
        
        if not disk_ids:
            self.logger.warning("Aucun disque spécifié pour la collecte")
            return self.artifacts
        
        self.logger.info(f"Début de la collecte sur {len(disk_ids)} disque(s)")
        
        for disk_id in disk_ids:
            try:
                self.logger.info(f"Analyse du disque: {disk_id}")
                
                if disk_id.endswith(":") and platform.system() == "Windows":
                    self._collect_important_files(disk_id)
                
                self.logger.info(f"Collecte terminée pour le disque: {disk_id}")
            
            except Exception as e:
                self.logger.error(f"Error during collection for disk {disk_id}: {str(e)}")
        
        self.logger.info(f"Collecte terminée: {len(self.artifacts)} artefacts collectés")
        return self.artifacts
    
    def _collect_important_files(self, volume_id):
        """
        Collecte des fichiers importants à partir d'un volume.
        """
        important_paths = [
            fr"{volume_id}\Windows\System32\winevt\Logs\Security.evtx",
            fr"{volume_id}\Windows\System32\winevt\Logs\System.evtx",
            fr"{volume_id}\Windows\System32\winevt\Logs\Application.evtx",
            fr"{volume_id}\Windows\System32\config\SYSTEM",
            fr"{volume_id}\Windows\System32\config\SOFTWARE",
            fr"{volume_id}\Windows\System32\config\SAM",
            fr"{volume_id}\Windows\System32\drivers\etc\hosts",
            fr"{volume_id}\Users\*\AppData\Local\Google\Chrome\User Data\Default\History",
            fr"{volume_id}\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History",
            fr"{volume_id}\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite"
        ]
        
        for path_pattern in important_paths:
            try:
                if "*" in path_pattern:
                    try:
                        base_dir_pattern = path_pattern.split("*", 1)[0]
                        expanded_base_dir = os.path.expandvars(base_dir_pattern)
                        walk_start_dir = os.path.dirname(expanded_base_dir)
                        
                        if os.path.isdir(walk_start_dir):
                            for root, dirs, files in os.walk(walk_start_dir, topdown=True):
                                for item_name in dirs + files:
                                    full_path = os.path.join(root, item_name)
                                    normalized_full_path = os.path.normpath(full_path)
                                    normalized_path_pattern = os.path.normpath(os.path.expandvars(path_pattern))
                                    
                                    if fnmatch.fnmatch(normalized_full_path, normalized_path_pattern):
                                        self._collect_file_info(normalized_full_path)
                    except Exception as walk_e:
                        self.logger.error(f"Error processing wildcard pattern '{path_pattern}': {str(walk_e)}")
                else:
                    expanded_path = os.path.expandvars(path_pattern)
                    if os.path.exists(expanded_path):
                        self._collect_file_info(expanded_path)
                        
            except Exception as e:
                self.logger.error(f"Unhandled error while processing path pattern '{path_pattern}': {str(e)}")
    
    def _collect_file_info(self, file_path):
        """
        Collecte des informations sur un fichier.
        """
        try:
            if not os.path.isfile(file_path):
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
                "source": file_path,
                "timestamp": datetime.now().isoformat(),
                "data": file_info
            })
            
            self.logger.debug(f"Collected file info: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error collecting info for file {file_path}: {str(e)}")


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

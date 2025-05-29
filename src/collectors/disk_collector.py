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

from .base_collector import BaseCollector, Artifact

# Configuration du logger
logger = logging.getLogger("forensichunter.collectors.disk")

class DiskCollector(BaseCollector):
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
        super().__init__(config)
        self.timeout = self.config.get("timeout", 60)
        self.max_files = self.config.get("max_files", 1000)
    
    def get_name(self):
        """
        Retourne le nom du collecteur.
        
        Returns:
            str: Nom du collecteur
        """
        return "DiskCollector"
    
    def get_description(self):
        """
        Retourne la description du collecteur.
        
        Returns:
            str: Description du collecteur
        """
        return "Collecteur d'artefacts à partir de disques durs physiques"
    
    def _safe_subprocess_run(self, cmd, timeout=None):
        """
        Exécute une commande subprocess avec gestion d'encodage sécurisée.
        
        Args:
            cmd (str/list): Commande à exécuter
            timeout (int, optional): Timeout en secondes
            
        Returns:
            tuple: (stdout, stderr, returncode)
        """
        if timeout is None:
            timeout = self.timeout
            
        try:
            # Essayer avec UTF-8 d'abord
            result = subprocess.run(
                cmd, 
                shell=True if isinstance(cmd, str) else False,
                capture_output=True, 
                text=True,
                encoding='utf-8',
                errors='replace',  # Remplacer les caractères invalides
                timeout=timeout
            )
            
            return result.stdout, result.stderr, result.returncode
                
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout lors de l'exécution de la commande: {cmd}")
            return "", f"Timeout après {timeout} secondes", 1
            
        except UnicodeDecodeError:
            # Fallback avec encodage système
            try:
                result = subprocess.run(
                    cmd, 
                    shell=True if isinstance(cmd, str) else False,
                    capture_output=True, 
                    text=True,
                    encoding='cp1252',  # Encodage Windows par défaut
                    errors='replace',
                    timeout=timeout
                )
                
                return result.stdout, result.stderr, result.returncode
                
            except Exception as e:
                logger.error(f"Erreur d'encodage même avec fallback: {str(e)}")
                return "", str(e), 1
        
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de la commande: {str(e)}")
            return "", str(e), 1
    
    def list_physical_disks(self):
        """
        Liste les disques durs physiques disponibles sur le système.
        
        Returns:
            list: Liste des disques durs physiques
        """
        disks = []
        
        try:
            if platform.system() == "Windows":
                # Lister les disques physiques
                cmd = "wmic diskdrive list brief /format:csv"
                stdout, stderr, returncode = self._safe_subprocess_run(cmd)
                
                if returncode == 0 and stdout:
                    lines = stdout.strip().split('\n')
                    if len(lines) > 1:
                        headers = [h.strip() for h in lines[0].split(',')]
                        
                        # Trouver les index des colonnes
                        device_id_idx = -1
                        model_idx = -1
                        size_idx = -1
                        
                        for i, header in enumerate(headers):
                            if 'DeviceID' in header:
                                device_id_idx = i
                            elif 'Model' in header:
                                model_idx = i
                            elif 'Size' in header:
                                size_idx = i
                        
                        for i in range(1, len(lines)):
                            line = lines[i].strip()
                            if not line:
                                continue
                                
                            values = [v.strip() for v in line.split(',')]
                            
                            if (device_id_idx >= 0 and model_idx >= 0 and size_idx >= 0 and 
                                len(values) > max(device_id_idx, model_idx, size_idx)):
                                
                                device_id = values[device_id_idx] if device_id_idx < len(values) else ""
                                model = values[model_idx] if model_idx < len(values) else ""
                                size_str = values[size_idx] if size_idx < len(values) else "0"
                                
                                try:
                                    size = int(size_str) if size_str.isdigit() else 0
                                    size_gb = round(size / (1024**3), 2) if size > 0 else 0
                                    
                                    if device_id and model:
                                        disks.append({
                                            "device_id": device_id,
                                            "model": model,
                                            "size_bytes": size,
                                            "size_gb": size_gb,
                                            "friendly_name": f"{model} ({size_gb} GB)",
                                            "is_physical": True
                                        })
                                except (ValueError, TypeError) as e:
                                    logger.debug(f"Erreur lors du parsing de la taille: {size_str} - {str(e)}")
                                    continue
                
                # Lister les volumes logiques
                cmd_logical = "wmic logicaldisk get deviceid,volumename,size,filesystem /format:csv"
                stdout, stderr, returncode = self._safe_subprocess_run(cmd_logical)
                
                if returncode == 0 and stdout:
                    lines = stdout.strip().split('\n')
                    if len(lines) > 1:
                        headers = [h.strip() for h in lines[0].split(',')]
                        
                        # Trouver les index des colonnes
                        device_id_idx = -1
                        volume_name_idx = -1  
                        size_idx = -1
                        filesystem_idx = -1
                        
                        for i, header in enumerate(headers):
                            if 'DeviceID' in header:
                                device_id_idx = i
                            elif 'VolumeName' in header:
                                volume_name_idx = i
                            elif 'Size' in header:
                                size_idx = i
                            elif 'FileSystem' in header:
                                filesystem_idx = i
                        
                        for i in range(1, len(lines)):
                            line = lines[i].strip()
                            if not line:
                                continue
                                
                            values = [v.strip() for v in line.split(',')]
                            
                            if device_id_idx >= 0 and len(values) > device_id_idx:
                                device_id = values[device_id_idx] if device_id_idx < len(values) else ""
                                volume_name = values[volume_name_idx] if volume_name_idx >= 0 and volume_name_idx < len(values) else ""
                                size_str = values[size_idx] if size_idx >= 0 and size_idx < len(values) else "0"
                                filesystem = values[filesystem_idx] if filesystem_idx >= 0 and filesystem_idx < len(values) else ""
                                
                                try:
                                    size = int(size_str) if size_str.isdigit() else 0
                                    size_gb = round(size / (1024**3), 2) if size > 0 else 0
                                    
                                    if device_id:
                                        friendly_name = f"{device_id}"
                                        if volume_name:
                                            friendly_name += f" - {volume_name}"
                                        if size_gb > 0:
                                            friendly_name += f" ({size_gb} GB"
                                            if filesystem:
                                                friendly_name += f", {filesystem}"
                                            friendly_name += ")"
                                        
                                        disks.append({
                                            "device_id": device_id,
                                            "model": f"Volume {device_id}",
                                            "volume_name": volume_name,
                                            "filesystem": filesystem,
                                            "size_bytes": size,
                                            "size_gb": size_gb,
                                            "friendly_name": friendly_name,
                                            "is_volume": True
                                        })
                                except (ValueError, TypeError) as e:
                                    logger.debug(f"Erreur lors du parsing de la taille logique: {size_str} - {str(e)}")
                                    continue
                
            else:
                # Support pour Linux/Mac (à implémenter si nécessaire)
                logger.warning("Liste des disques non supportée sur ce système d'exploitation")
                
        except Exception as e:
            logger.error(f"Erreur lors de la liste des disques physiques: {str(e)}")
        
        logger.info(f"{len(disks)} disques détectés")
        return disks
    
    def collect(self, disk_ids=None):
        """
        Collecte des artefacts à partir des disques durs spécifiés.
        
        Args:
            disk_ids (list): Liste des IDs de disques à analyser
            
        Returns:
            list: Liste d'objets Artifact collectés
        """
        self.clear_artifacts()
        
        if not disk_ids:
            logger.warning("Aucun disque spécifié pour la collecte")
            return self.artifacts
        
        logger.info(f"Début de la collecte sur {len(disk_ids)} disque(s)")
        
        for disk_id in disk_ids:
            try:
                logger.info(f"Analyse du disque: {disk_id}")
                
                if disk_id.endswith(":") and platform.system() == "Windows":
                    self._collect_important_files(disk_id)
                elif disk_id.startswith("\\\\.\\") and platform.system() == "Windows":
                    # Disque physique
                    self._collect_physical_disk_info(disk_id)
                else:
                    logger.warning(f"Type de disque non supporté: {disk_id}")
                
                logger.info(f"Collecte terminée pour le disque: {disk_id}")
            
            except Exception as e:
                logger.error(f"Erreur lors de la collecte pour le disque {disk_id}: {str(e)}")
                continue
        
        logger.info(f"Collecte terminée: {len(self.artifacts)} artefacts collectés")
        return self.artifacts
    
    def _collect_physical_disk_info(self, disk_id):
        """
        Collecte des informations sur un disque physique.
        
        Args:
            disk_id (str): ID du disque physique
        """
        try:
            # Collecter les informations de base du disque
            cmd = f'wmic diskdrive where "DeviceID=\\"{disk_id}\\"" get Model,Size,MediaType /format:csv'
            stdout, stderr, returncode = self._safe_subprocess_run(cmd)
            
            if returncode == 0 and stdout:
                lines = stdout.strip().split('\n')
                if len(lines) > 1:
                    for line in lines[1:]:
                        if line.strip():
                            values = [v.strip() for v in line.split(',')]
                            if len(values) >= 4:  # Node, MediaType, Model, Size
                                media_type = values[1] if len(values) > 1 else ""
                                model = values[2] if len(values) > 2 else ""
                                size = values[3] if len(values) > 3 else "0"
                                
                                metadata = {
                                    "disk_id": disk_id,
                                    "model": model,
                                    "media_type": media_type,
                                    "size_bytes": size,
                                    "collection_method": "wmic_diskdrive"
                                }
                                
                                self.add_artifact(
                                    artifact_type="disk_info",
                                    source=f"physical_disk_{disk_id}",
                                    data={
                                        "disk_info": {
                                            "device_id": disk_id,
                                            "model": model,
                                            "media_type": media_type,
                                            "size": size
                                        }
                                    },
                                    metadata=metadata
                                )
        
        except Exception as e:
            logger.error(f"Erreur lors de la collecte d'informations du disque physique {disk_id}: {str(e)}")
    
    def _collect_important_files(self, volume_id):
        """
        Collecte des fichiers importants à partir d'un volume.
        
        Args:
            volume_id (str): ID du volume (ex: C:)
        """
        important_paths = [
            # Journaux d'événements
            fr"{volume_id}\Windows\System32\winevt\Logs\Security.evtx",
            fr"{volume_id}\Windows\System32\winevt\Logs\System.evtx",
            fr"{volume_id}\Windows\System32\winevt\Logs\Application.evtx",
            
            # Registre
            fr"{volume_id}\Windows\System32\config\SYSTEM",
            fr"{volume_id}\Windows\System32\config\SOFTWARE",
            fr"{volume_id}\Windows\System32\config\SAM",
            
            # Fichiers système
            fr"{volume_id}\Windows\System32\drivers\etc\hosts",
            fr"{volume_id}\Windows\System32\Tasks",
            
            # Historiques navigateurs (patterns avec wildcard)
            fr"{volume_id}\Users\*\AppData\Local\Google\Chrome\User Data\Default\History",
            fr"{volume_id}\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History",
            fr"{volume_id}\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite",
            
            # Fichiers de démarrage
            fr"{volume_id}\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            fr"{volume_id}\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        ]
        
        files_collected = 0
        
        for path_pattern in important_paths:
            if files_collected >= self.max_files:
                logger.warning(f"Limite de {self.max_files} fichiers atteinte")
                break
                
            try:
                if "*" in path_pattern:
                    # Gérer les patterns avec wildcards
                    self._collect_wildcard_files(path_pattern)
                else:
                    # Fichier ou dossier spécifique
                    expanded_path = os.path.expandvars(path_pattern)
                    if os.path.exists(expanded_path):
                        if os.path.isfile(expanded_path):
                            self._collect_file_info(expanded_path)
                            files_collected += 1
                        elif os.path.isdir(expanded_path):
                            # Lister les fichiers du dossier
                            try:
                                for item in os.listdir(expanded_path):
                                    if files_collected >= self.max_files:
                                        break
                                    item_path = os.path.join(expanded_path, item)
                                    if os.path.isfile(item_path):
                                        self._collect_file_info(item_path)
                                        files_collected += 1
                            except (PermissionError, OSError) as e:
                                logger.debug(f"Accès refusé au dossier {expanded_path}: {str(e)}")
                                continue
                        
            except Exception as e:
                logger.error(f"Erreur lors du traitement du pattern '{path_pattern}': {str(e)}")
                continue
    
    def _collect_wildcard_files(self, path_pattern):
        """
        Collecte des fichiers correspondant à un pattern avec wildcards.
        
        Args:
            path_pattern (str): Pattern de chemin avec wildcards
        """
        try:
            # Séparer le pattern en parties
            parts = path_pattern.split("*")
            if len(parts) < 2:
                return
            
            base_path = parts[0]
            if not os.path.exists(base_path):
                return
            
            # Utiliser os.walk pour parcourir les dossiers
            for root, dirs, files in os.walk(base_path):
                # Limiter la profondeur pour éviter les parcours trop longs
                depth = root.replace(base_path, '').count(os.sep)
                if depth > 3:  # Limiter à 3 niveaux de profondeur
                    continue
                
                for item_name in dirs + files:
                    full_path = os.path.join(root, item_name)
                    normalized_full_path = os.path.normpath(full_path)
                    normalized_path_pattern = os.path.normpath(path_pattern)
                    
                    # Vérifier si le chemin correspond au pattern
                    if fnmatch.fnmatch(normalized_full_path, normalized_path_pattern):
                        if os.path.isfile(normalized_full_path):
                            self._collect_file_info(normalized_full_path)
                        
        except Exception as e:
            logger.error(f"Erreur lors du traitement du pattern wildcard '{path_pattern}': {str(e)}")
    
    def _collect_file_info(self, file_path):
        """
        Collecte des informations sur un fichier.
        
        Args:
            file_path (str): Chemin du fichier
        """
        try:
            if not os.path.isfile(file_path):
                return
                
            file_stat = os.stat(file_path)
            
            # Calculer le hash du fichier pour les petits fichiers
            file_hash = None
            if file_stat.st_size < 1024 * 1024:  # 1 MB
                try:
                    import hashlib
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
                except (PermissionError, OSError):
                    pass  # Ignorer si on ne peut pas lire le fichier
            
            file_info = {
                "path": file_path,
                "name": os.path.basename(file_path),
                "size": file_stat.st_size,
                "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(file_stat.st_atime).isoformat(),
                "hash_md5": file_hash
            }
            
            metadata = {
                "file_path": file_path,
                "file_size": file_stat.st_size,
                "collection_method": "file_system_walk"
            }
            
            self.add_artifact(
                artifact_type="file_info",
                source=f"disk_file_{file_path}",
                data=file_info,
                metadata=metadata
            )
            
            logger.debug(f"Informations collectées pour le fichier: {file_path}")
            
        except (PermissionError, OSError) as e:
            logger.debug(f"Accès refusé au fichier {file_path}: {str(e)}")
        except Exception as e:
            logger.error(f"Erreur lors de la collecte d'informations pour le fichier {file_path}: {str(e)}")


# Test du module si exécuté directement
if __name__ == "__main__":
    # Configuration du logging pour les tests
    logging.basicConfig(level=logging.INFO)
    
    collector = DiskCollector()
    disks = collector.list_physical_disks()
    
    print(f"Disques physiques détectés: {len(disks)}")
    for disk in disks:
        print(f"- {disk['friendly_name']} ({disk['device_id']})")
    
    if disks:
        print("\nCollecte d'artefacts sur le premier disque...")
        artifacts = collector.collect([disks[0]["device_id"]])
        print(f"Artefacts collectés: {len(artifacts)}")
        
        # Afficher quelques artefacts
        for artifact in artifacts[:5]:
            print(f"  - {artifact.type}: {artifact.source}")

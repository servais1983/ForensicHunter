#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des artefacts à partir de fichiers VMDK.

Ce module permet de monter et d'analyser des fichiers VMDK
pour en extraire des artefacts forensiques.
"""

import os
import logging
import datetime
import json
import subprocess
import tempfile
import shutil
from pathlib import Path

from .base_collector import BaseCollector, Artifact
from .filesystem_collector import FileSystemCollector

# Configuration du logger
logger = logging.getLogger("forensichunter.collectors.vmdk")

class VMDKCollector(BaseCollector):
    """Collecteur d'artefacts à partir de fichiers VMDK."""
    
    def __init__(self, config=None):
        """
        Initialise un nouveau collecteur de fichiers VMDK.
        
        Args:
            config (dict, optional): Configuration du collecteur
        """
        super().__init__(config)
        self.vmdk_path = self.config.get("vmdk_path", "")
        self.mount_point = self.config.get("mount_point", "")
        self.auto_mount = self.config.get("auto_mount", True)
        self.auto_unmount = self.config.get("auto_unmount", True)
        self.use_vmdktools = self.config.get("use_vmdktools", True)
        self.use_libguestfs = self.config.get("use_libguestfs", True)
        self.use_7zip = self.config.get("use_7zip", True)
        self.collect_registry = self.config.get("collect_registry", True)
        self.collect_eventlogs = self.config.get("collect_eventlogs", True)
        self.collect_filesystem = self.config.get("collect_filesystem", True)
        self.filesystem_paths = self.config.get("filesystem_paths", [
            r"Windows\System32\config",
            r"Windows\System32\winevt\Logs",
            r"Windows\System32\drivers\etc\hosts",
            r"Users\*\AppData\Local\Temp",
            r"Users\*\AppData\Local\Google\Chrome\User Data\Default\History",
            r"Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        ])
        self.temp_dir = None
    
    def get_name(self):
        """
        Retourne le nom du collecteur.
        
        Returns:
            str: Nom du collecteur
        """
        return "VMDKCollector"
    
    def get_description(self):
        """
        Retourne la description du collecteur.
        
        Returns:
            str: Description du collecteur
        """
        return "Collecteur d'artefacts à partir de fichiers VMDK (disques virtuels VMware)"
    
    def collect(self):
        """
        Collecte les artefacts à partir d'un fichier VMDK.
        
        Returns:
            list: Liste d'objets Artifact collectés
        """
        self.clear_artifacts()
        
        # Vérifier si un chemin VMDK a été spécifié
        if not self.vmdk_path:
            logger.error("Aucun chemin VMDK spécifié")
            return self.artifacts
        
        # Vérifier si le fichier VMDK existe
        if not os.path.exists(self.vmdk_path):
            logger.error(f"Le fichier VMDK {self.vmdk_path} n'existe pas")
            return self.artifacts
        
        # Créer un répertoire temporaire
        self.temp_dir = tempfile.mkdtemp(prefix="forensichunter_vmdk_")
        logger.info(f"Répertoire temporaire créé: {self.temp_dir}")
        
        try:
            # Monter le VMDK
            if self.auto_mount:
                mount_success = False
                
                if self.use_vmdktools and self._mount_with_vmdktools():
                    mount_success = True
                    logger.info("Montage avec vmdktools réussi")
                elif self.use_libguestfs and self._mount_with_libguestfs():
                    mount_success = True
                    logger.info("Montage avec libguestfs réussi")
                elif self.use_7zip and self._extract_with_7zip():
                    mount_success = True
                    logger.info("Extraction avec 7-Zip réussie")
                
                if not mount_success:
                    logger.error("Toutes les méthodes de montage ont échoué")
                    return self.artifacts
            
            # Collecter les artefacts
            self._collect_vmdk_artifacts()
            
            # Démonter le VMDK
            if self.auto_mount and self.auto_unmount:
                self._unmount_vmdk()
            
            return self.artifacts
            
        finally:
            # Nettoyer le répertoire temporaire
            if self.temp_dir and os.path.exists(self.temp_dir):
                try:
                    shutil.rmtree(self.temp_dir)
                    logger.info(f"Répertoire temporaire supprimé: {self.temp_dir}")
                except Exception as e:
                    logger.error(f"Erreur lors de la suppression du répertoire temporaire: {str(e)}")
    
    def _mount_with_vmdktools(self):
        """
        Monte le fichier VMDK avec vmdktools.
        
        Returns:
            bool: True si le montage a réussi, False sinon
        """
        try:
            # Vérifier si vmdkmount est disponible
            try:
                subprocess.run(["vmdkmount", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.warning("vmdkmount n'est pas disponible")
                return False
            
            # Créer un point de montage
            if not self.mount_point:
                self.mount_point = os.path.join(self.temp_dir, "mount")
                os.makedirs(self.mount_point, exist_ok=True)
            
            # Monter le VMDK
            cmd = ["vmdkmount", self.vmdk_path, self.mount_point]
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            
            if process.returncode != 0:
                logger.error(f"Erreur lors du montage avec vmdkmount: {process.stderr}")
                return False
            
            logger.info(f"VMDK monté avec succès sur {self.mount_point}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors du montage avec vmdktools: {str(e)}")
            return False
    
    def _mount_with_libguestfs(self):
        """
        Monte le fichier VMDK avec libguestfs.
        
        Returns:
            bool: True si le montage a réussi, False sinon
        """
        try:
            # Vérifier si guestmount est disponible
            try:
                subprocess.run(["guestmount", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.warning("guestmount n'est pas disponible")
                return False
            
            # Créer un point de montage
            if not self.mount_point:
                self.mount_point = os.path.join(self.temp_dir, "mount")
                os.makedirs(self.mount_point, exist_ok=True)
            
            # Monter le VMDK
            cmd = ["guestmount", "-a", self.vmdk_path, "-i", "--ro", self.mount_point]
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            
            if process.returncode != 0:
                logger.error(f"Erreur lors du montage avec guestmount: {process.stderr}")
                return False
            
            logger.info(f"VMDK monté avec succès sur {self.mount_point}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors du montage avec libguestfs: {str(e)}")
            return False
    
    def _extract_with_7zip(self):
        """
        Extrait le contenu du fichier VMDK avec 7-Zip.
        
        Returns:
            bool: True si l'extraction a réussi, False sinon
        """
        try:
            # Vérifier si 7z est disponible
            try:
                subprocess.run(["7z", "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.warning("7-Zip n'est pas disponible")
                return False
            
            # Créer un répertoire d'extraction
            if not self.mount_point:
                self.mount_point = os.path.join(self.temp_dir, "extract")
                os.makedirs(self.mount_point, exist_ok=True)
            
            # Extraire le VMDK
            cmd = ["7z", "x", self.vmdk_path, f"-o{self.mount_point}"]
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            
            if process.returncode != 0:
                logger.error(f"Erreur lors de l'extraction avec 7-Zip: {process.stderr}")
                return False
            
            logger.info(f"VMDK extrait avec succès dans {self.mount_point}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction avec 7-Zip: {str(e)}")
            return False
    
    def _unmount_vmdk(self):
        """
        Démonte le fichier VMDK.
        
        Returns:
            bool: True si le démontage a réussi, False sinon
        """
        try:
            if self.use_vmdktools:
                try:
                    cmd = ["vmdkumount", self.mount_point]
                    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                    
                    if process.returncode == 0:
                        logger.info(f"VMDK démonté avec succès de {self.mount_point}")
                        return True
                except:
                    pass
            
            if self.use_libguestfs:
                try:
                    cmd = ["fusermount", "-u", self.mount_point]
                    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                    
                    if process.returncode == 0:
                        logger.info(f"VMDK démonté avec succès de {self.mount_point}")
                        return True
                except:
                    pass
            
            logger.warning(f"Impossible de démonter proprement le VMDK de {self.mount_point}")
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors du démontage du VMDK: {str(e)}")
            return False
    
    def _collect_vmdk_artifacts(self):
        """
        Collecte les artefacts à partir du VMDK monté.
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            # Vérifier si le point de montage existe
            if not os.path.exists(self.mount_point):
                logger.error(f"Le point de montage {self.mount_point} n'existe pas")
                return False
            
            # Collecter les artefacts du système de fichiers
            if self.collect_filesystem:
                logger.info("Collecte des artefacts du système de fichiers...")
                
                # Créer une configuration pour le collecteur de système de fichiers
                fs_config = {
                    "paths": [os.path.join(self.mount_point, path) for path in self.filesystem_paths],
                    "max_file_size": self.config.get("max_file_size", 10 * 1024 * 1024),
                    "hash_algorithms": self.config.get("hash_algorithms", ["md5", "sha256"]),
                    "collect_metadata": True,
                    "collect_content": True,
                    "follow_symlinks": False,
                    "max_files": self.config.get("max_files", 1000)
                }
                
                # Créer et exécuter le collecteur
                fs_collector = FileSystemCollector(fs_config)
                fs_artifacts = fs_collector.collect()
                
                # Ajouter les artefacts collectés
                for artifact in fs_artifacts:
                    # Modifier les métadonnées pour indiquer la source VMDK
                    if artifact.metadata:
                        artifact.metadata["vmdk_source"] = self.vmdk_path
                    
                    self.artifacts.append(artifact)
                
                logger.info(f"{len(fs_artifacts)} artefacts du système de fichiers collectés")
            
            # Collecter les artefacts du registre
            if self.collect_registry:
                logger.info("Collecte des artefacts du registre...")
                
                # Chercher les ruches de registre
                registry_paths = [
                    os.path.join(self.mount_point, "Windows", "System32", "config", "SYSTEM"),
                    os.path.join(self.mount_point, "Windows", "System32", "config", "SOFTWARE"),
                    os.path.join(self.mount_point, "Windows", "System32", "config", "SAM"),
                    os.path.join(self.mount_point, "Windows", "System32", "config", "SECURITY")
                ]
                
                for reg_path in registry_paths:
                    if os.path.exists(reg_path):
                        # Créer un artefact pour la ruche de registre
                        metadata = {
                            "registry_hive": os.path.basename(reg_path),
                            "vmdk_source": self.vmdk_path,
                            "size": os.path.getsize(reg_path),
                            "path": reg_path
                        }
                        
                        self.add_artifact(
                            artifact_type="registry_hive",
                            source=reg_path,
                            data={"type": "registry_hive", "path": reg_path},
                            metadata=metadata
                        )
                        
                        logger.info(f"Ruche de registre collectée: {reg_path}")
            
            # Collecter les journaux d'événements
            if self.collect_eventlogs:
                logger.info("Collecte des journaux d'événements...")
                
                # Chercher les journaux d'événements
                eventlog_path = os.path.join(self.mount_point, "Windows", "System32", "winevt", "Logs")
                
                if os.path.exists(eventlog_path) and os.path.isdir(eventlog_path):
                    for log_file in os.listdir(eventlog_path):
                        if log_file.endswith(".evtx"):
                            log_path = os.path.join(eventlog_path, log_file)
                            
                            # Créer un artefact pour le journal d'événements
                            metadata = {
                                "event_log": log_file,
                                "vmdk_source": self.vmdk_path,
                                "size": os.path.getsize(log_path),
                                "path": log_path
                            }
                            
                            self.add_artifact(
                                artifact_type="event_log_file",
                                source=log_path,
                                data={"type": "event_log_file", "path": log_path},
                                metadata=metadata
                            )
                            
                            logger.info(f"Journal d'événements collecté: {log_path}")
            
            logger.info(f"{len(self.artifacts)} artefacts collectés au total à partir du VMDK")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des artefacts du VMDK: {str(e)}")
            return False

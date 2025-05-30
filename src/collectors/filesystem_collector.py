#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des artefacts du système de fichiers Windows.

Ce module permet de collecter les fichiers et dossiers importants
du système de fichiers Windows pour analyse forensique.
"""

import os
import logging
from datetime import datetime
import json
import subprocess
import hashlib
import stat
import glob
from pathlib import Path
from typing import Dict, List, Optional

# Tentative d'import de win32security
HAS_WIN32SECURITY = False
try:
    import win32security
    HAS_WIN32SECURITY = True
except ImportError:
    logging.warning("Module win32security non disponible. La récupération des propriétaires de fichiers sera limitée.")

from .base_collector import BaseCollector, Artifact

# Configuration du logger
logger = logging.getLogger("forensichunter.collectors.filesystem")

class FileSystemCollector(BaseCollector):
    """Collecteur d'artefacts du système de fichiers Windows."""
    
    def __init__(self, config=None):
        """
        Initialise un nouveau collecteur d'artefacts du système de fichiers.
        
        Args:
            config (dict, optional): Configuration du collecteur
        """
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.paths = self.config.get("paths", [
            # Fichiers système importants
            r"C:\Windows\System32\config",
            r"C:\Windows\System32\winevt\Logs",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\Tasks",
            r"C:\Windows\System32\wbem\Repository",
            r"C:\Windows\System32\drivers",
            r"C:\Windows\System32\LogFiles",
            r"C:\Windows\System32\config\systemprofile",
            r"C:\Windows\System32\config\RegBack",
            
            # Fichiers temporaires et cache
            r"C:\Windows\Temp\*",
            r"C:\Users\*\AppData\Local\Temp\*",
            r"C:\Windows\Prefetch\*",
            r"C:\Windows\SoftwareDistribution\Download\*",
            r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\*",
            r"C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\*",
            
            # Historique des navigateurs
            r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\*",
            r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Local State",
            r"C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\*",
            r"C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\*",
            r"C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\*",
            r"C:\Users\*\AppData\Local\Microsoft\Windows\History\*",
            r"C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*",
            r"C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\*",
            
            # Fichiers de démarrage
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*",
            r"C:\Windows\Tasks\*",
            r"C:\Windows\System32\Tasks\*",
            r"C:\Windows\System32\GroupPolicy\Machine\Scripts\*",
            r"C:\Windows\System32\GroupPolicy\User\Scripts\*",
            
            # Fichiers récents
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*",
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*",
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*",
            
            # Fichiers PowerShell
            r"C:\Users\*\Documents\WindowsPowerShell\*",
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\*",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules\*",
            
            # Fichiers de journalisation
            r"C:\Windows\debug\*",
            r"C:\Windows\Logs\*",
            r"C:\Windows\System32\winevt\Logs\*",
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\WER\*",
            r"C:\ProgramData\Microsoft\Windows\WER\*",
            
            # Dossiers utilisateurs importants
            r"C:\Users\*\Desktop\*",
            r"C:\Users\*\Documents\*",
            r"C:\Users\*\Downloads\*",
            r"C:\Users\*\Pictures\*",
            r"C:\Users\*\Videos\*",
            r"C:\Users\*\Music\*",
            r"C:\Users\*\AppData\Roaming\*",
            r"C:\Users\*\AppData\Local\*",
            r"C:\Users\*\AppData\LocalLow\*",
            r"C:\Users\*\Favorites\*",
            r"C:\Users\*\Contacts\*",
            r"C:\Users\*\Links\*",
            r"C:\Users\*\Saved Games\*",
            r"C:\Users\*\Searches\*",
            
            # Fichiers système supplémentaires
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SECURITY",
            r"C:\Windows\System32\config\SOFTWARE",
            r"C:\Windows\System32\config\SYSTEM",
            r"C:\Windows\System32\config\DEFAULT",
            r"C:\Windows\System32\config\RegBack\*",
            r"C:\Windows\System32\config\systemprofile\*",
            
            # Fichiers de mise à jour
            r"C:\Windows\SoftwareDistribution\*",
            r"C:\Windows\WindowsUpdate.log",
            r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-WindowsUpdateClient%4Operational.evtx",
            
            # Fichiers de configuration réseau
            r"C:\Windows\System32\drivers\etc\*",
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Network\*",
            r"C:\Users\*\AppData\Local\Microsoft\Windows\Network\*",
            
            # Journaux d'événements Windows
            r"C:\Windows\System32\winevt\Logs\*.evtx",
            
            # Logs d'accès à distance
            r"C:\Users\*\AppData\Roaming\TeamViewer\*",
            r"C:\Users\*\AppData\Roaming\AnyDesk\*",
            r"C:\ProgramData\AnyDesk\*",
            r"C:\ProgramData\TeamViewer\*",
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\RDP Connections.lnk",
            r"C:\Users\*\Documents\*.rdp",
            r"C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\*",
            
            # Fichiers de sécurité supplémentaires
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Explorer\*",
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\History\*",
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache\*",
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCookies\*",
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetHistory\*",
            
            # Fichiers de configuration d'application
            r"C:\Users\*\AppData\Local\Microsoft\Windows\Explorer\*",
            r"C:\Users\*\AppData\Local\Microsoft\Windows\History\*",
            r"C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\*",
            r"C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies\*",
            r"C:\Users\*\AppData\Local\Microsoft\Windows\INetHistory\*",
            
            # Fichiers de configuration système
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Explorer\*",
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\History\*",
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache\*",
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetCookies\*",
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\INetHistory\*"
        ])

    def get_name(self):
        """Retourne le nom du collecteur."""
        return "FileSystemCollector"

    def get_description(self):
        """Retourne la description du collecteur."""
        return "Collecteur d'artefacts du système de fichiers Windows."

    def collect(self, paths=None):
        """
        Collecte les artefacts du système de fichiers.
        
        Args:
            paths (list, optional): Liste des chemins à collecter. Si non spécifié, utilise les chemins par défaut.
            
        Returns:
            dict: Dictionnaire contenant les artefacts collectés
        """
        try:
            if paths is None:
                paths = self.paths
                
            artifacts = {}
            
            for path in paths:
                try:
                    # Gestion des wildcards dans les chemins
                    if '*' in path:
                        # Séparation du chemin en parties
                        parts = path.split('*')
                        base_path = parts[0]
                        
                        # Si le chemin de base n'existe pas, on passe au suivant
                        if not os.path.exists(base_path):
                            continue
                            
                        # Recherche récursive des fichiers correspondants
                        for root, dirs, files in os.walk(base_path):
                            for file in files:
                                full_path = os.path.join(root, file)
                                try:
                                    if self._should_collect_file(full_path):
                                        artifacts[full_path] = self._collect_file_info(full_path)
                                except Exception as e:
                                    self.logger.error(f"Erreur lors de la collecte du fichier {full_path}: {str(e)}")
                    else:
                        # Chemin sans wildcard
                        if os.path.exists(path):
                            if os.path.isfile(path):
                                if self._should_collect_file(path):
                                    artifacts[path] = self._collect_file_info(path)
                            elif os.path.isdir(path):
                                for root, dirs, files in os.walk(path):
                                    for file in files:
                                        full_path = os.path.join(root, file)
                                        try:
                                            if self._should_collect_file(full_path):
                                                artifacts[full_path] = self._collect_file_info(full_path)
                                        except Exception as e:
                                            self.logger.error(f"Erreur lors de la collecte du fichier {full_path}: {str(e)}")
                except Exception as e:
                    self.logger.error(f"Erreur lors du traitement du chemin {path}: {str(e)}")
                    continue
                    
            return artifacts
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des artefacts: {str(e)}")
            return {}
            
    def _should_collect_file(self, file_path):
        """
        Détermine si un fichier doit être collecté en fonction de sa taille et de son type.
        
        Args:
            file_path (str): Chemin du fichier à vérifier
            
        Returns:
            bool: True si le fichier doit être collecté, False sinon
        """
        try:
            # Vérification de la taille du fichier
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024:  # 100 MB
                return False
                
            # Vérification du type de fichier
            _, ext = os.path.splitext(file_path)
            excluded_extensions = ['.exe', '.dll', '.sys', '.bin']
            if ext.lower() in excluded_extensions:
                return False
                
            return True
            
        except Exception:
            return False
            
    def _collect_file_info(self, file_path):
        """
        Collecte les informations sur un fichier.
        
        Args:
            file_path (str): Chemin du fichier
            
        Returns:
            dict: Informations sur le fichier
        """
        try:
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'created': stat.st_ctime,
                'modified': stat.st_mtime,
                'accessed': stat.st_atime,
                'permissions': stat.st_mode,
                'owner': self._get_file_owner(file_path)
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des informations du fichier {file_path}: {str(e)}")
            return {}
            
    def _get_file_owner(self, file_path):
        """
        Récupère le propriétaire d'un fichier.
        
        Args:
            file_path (str): Chemin du fichier
            
        Returns:
            str: Nom du propriétaire
        """
        if not HAS_WIN32SECURITY:
            return "Unknown (win32security non disponible)"
            
        try:
            sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner()
            name, domain, type = win32security.LookupAccountSid("", owner_sid)
            return f"{domain}\\{name}"
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération du propriétaire du fichier {file_path}: {str(e)}")
            return "Unknown"
        
        
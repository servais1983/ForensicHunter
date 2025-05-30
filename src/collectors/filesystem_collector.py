#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des artefacts du système de fichiers Windows.

Ce module permet de collecter les fichiers et dossiers importants
du système de fichiers Windows pour analyse forensique.
"""

import os
import logging
import datetime
import json
import subprocess
import hashlib
import stat
import glob
from pathlib import Path

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
            
            # Artéfacts de sécurité
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows Defender",
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Firewall",
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Network",
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Security",
            
            # Artéfacts réseau
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Network",
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Network",
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            r"C:\Windows\System32\config\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            
            # Fichiers temporaires
            r"C:\Windows\Temp",
            r"C:\Users\*\AppData\Local\Temp",
            r"C:\Windows\Prefetch",
            r"C:\Windows\SoftwareDistribution\Download",
            
            # Historique des navigateurs
            r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History",
            r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\places.sqlite",
            r"C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\cookies.sqlite",
            r"C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History",
            r"C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Cookies",
            r"C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
            r"C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat",
            
            # Fichiers de démarrage
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            r"C:\Windows\Tasks",
            r"C:\Windows\System32\Tasks",
            
            # Fichiers récents
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent",
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations",
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations",
            
            # Fichiers PowerShell
            r"C:\Users\*\Documents\WindowsPowerShell\*.ps1",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            
            # Fichiers de journalisation
            r"C:\Windows\debug\*.log",
            r"C:\Windows\Logs\*",
            r"C:\Windows\System32\winevt\Logs\*.evtx",
            
            # Dossiers utilisateurs importants
            r"C:\Users\*\Desktop",
            r"C:\Users\*\Documents",
            r"C:\Users\*\Downloads",
            r"C:\Users\*\Pictures",
            r"C:\Users\*\Videos",
            r"C:\Users\*\Music",
            r"C:\Users\*\AppData\Roaming",
            r"C:\Users\*\AppData\Local",
            r"C:\Users\*\AppData\LocalLow",
            r"C:\Users\*\Favorites",
            r"C:\Users\*\Contacts",
            r"C:\Users\*\Links",
            r"C:\Users\*\Saved Games",
            r"C:\Users\*\Searches",
            
            # Fichiers système supplémentaires
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SECURITY",
            r"C:\Windows\System32\config\SOFTWARE",
            r"C:\Windows\System32\config\SYSTEM",
            r"C:\Windows\System32\config\DEFAULT",
            r"C:\Windows\System32\config\RegBack\*",
            
            # Fichiers de mise à jour
            r"C:\Windows\SoftwareDistribution\ReportingEvents.log",
            r"C:\Windows\WindowsUpdate.log",
            
            # Fichiers de configuration réseau
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\drivers\etc\networks",
            r"C:\Windows\System32\drivers\etc\protocol",
            r"C:\Windows\System32\drivers\etc\services",
            
            # Journaux d'événements Windows
            r"C:\Windows\System32\winevt\Logs\Security.evtx",
            r"C:\Windows\System32\winevt\Logs\Application.evtx",
            r"C:\Windows\System32\winevt\Logs\System.evtx",
            r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
            r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
            r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
            r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
            r"C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx",
            r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
            r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx",
            r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
            
            # Logs d'accès à distance
            r"C:\Users\*\AppData\Roaming\TeamViewer\*.log",
            r"C:\Users\*\AppData\Roaming\AnyDesk\*.log",
            r"C:\ProgramData\AnyDesk\*.log",
            r"C:\ProgramData\TeamViewer\*.log",
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\RDP Connections.lnk",
            r"C:\Users\*\Documents\*.rdp",
            r"C:\Users\*\AppData\Local\Microsoft\Terminal Server Client\*.rdp"
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
            paths (list, optional): Liste des chemins à collecter. Si None, utilise self.paths.
        
        Returns:
            list: Liste des artefacts collectés
        """
        artifacts = []
        
        # Utilise les chemins fournis en argument ou ceux par défaut
        paths_to_collect = paths if paths is not None else self.paths
        
        for path_pattern in paths_to_collect:
            try:
                # Gestion des chemins avec wildcards
                if '*' in path_pattern:
                    matching_paths = glob.glob(path_pattern)
                else:
                    matching_paths = [path_pattern]
                
                for path in matching_paths:
                    if os.path.exists(path):
                        # Collecte des métadonnées du fichier
                        stat_info = os.stat(path)
                        
                        # Création de l'artefact
                        artifact = Artifact(
                            name=os.path.basename(path),
                            path=path,
                            type="file" if os.path.isfile(path) else "directory",
                            size=stat_info.st_size if os.path.isfile(path) else 0,
                            created=datetime.datetime.fromtimestamp(stat_info.st_ctime),
                            modified=datetime.datetime.fromtimestamp(stat_info.st_mtime),
                            accessed=datetime.datetime.fromtimestamp(stat_info.st_atime),
                            metadata={
                                "permissions": oct(stat_info.st_mode)[-3:],
                                "owner": stat_info.st_uid,
                                "group": stat_info.st_gid
                            }
                        )
                        
                        # Calcul du hash pour les fichiers
                        if os.path.isfile(path):
                            try:
                                with open(path, 'rb') as f:
                                    file_hash = hashlib.sha256(f.read()).hexdigest()
                                    artifact.metadata["sha256"] = file_hash
                            except Exception as e:
                                logger.warning(f"Impossible de calculer le hash pour {path}: {str(e)}")
                        
                        artifacts.append(artifact)
                        
            except Exception as e:
                logger.error(f"Erreur lors de la collecte de {path_pattern}: {str(e)}")
                continue
        
        return artifacts
        
        
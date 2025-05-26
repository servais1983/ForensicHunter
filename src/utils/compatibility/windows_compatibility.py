#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de compatibilité Windows pour ForensicHunter.

Ce module fournit des fonctions et classes pour garantir la compatibilité
avec toutes les versions de Windows, des plus anciennes (Windows XP) aux
plus récentes (Windows 11), ainsi que toutes les versions de Windows Server.
"""

import os
import sys
import ctypes
import logging
import platform
import winreg
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger("forensichunter")


class WindowsCompatibilityManager:
    """Gestionnaire de compatibilité Windows pour ForensicHunter."""

    # Mapping des versions de Windows
    WINDOWS_VERSIONS = {
        "5.0": "Windows 2000",
        "5.1": "Windows XP",
        "5.2": "Windows Server 2003/XP x64",
        "6.0": "Windows Vista/Server 2008",
        "6.1": "Windows 7/Server 2008 R2",
        "6.2": "Windows 8/Server 2012",
        "6.3": "Windows 8.1/Server 2012 R2",
        "10.0": "Windows 10/11/Server 2016/2019/2022"
    }

    def __init__(self):
        """Initialise le gestionnaire de compatibilité Windows."""
        self.windows_info = self._get_windows_info()
        self.compatibility_issues = []
        self.compatibility_fixes = []
        
        # Vérification de la compatibilité
        self._check_compatibility()
    
    def _get_windows_info(self) -> Dict[str, Any]:
        """
        Récupère les informations détaillées sur la version de Windows.
        
        Returns:
            Dictionnaire contenant les informations sur la version de Windows
        """
        windows_info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "win32_edition": "",
            "product_type": "",
            "is_server": False,
            "is_workstation": False,
            "is_domain_controller": False,
            "major_version": 0,
            "minor_version": 0,
            "build_number": 0,
            "service_pack": "",
            "friendly_name": "Unknown Windows Version"
        }
        
        # Vérification du système d'exploitation
        if windows_info["system"] != "Windows":
            logger.warning("Système d'exploitation non Windows détecté")
            return windows_info
        
        try:
            # Extraction des informations de version
            version_parts = windows_info["version"].split(".")
            windows_info["major_version"] = int(version_parts[0]) if len(version_parts) > 0 else 0
            windows_info["minor_version"] = int(version_parts[1]) if len(version_parts) > 1 else 0
            windows_info["build_number"] = int(version_parts[2]) if len(version_parts) > 2 else 0
            
            # Détermination du nom convivial
            version_key = f"{windows_info['major_version']}.{windows_info['minor_version']}"
            windows_info["friendly_name"] = self.WINDOWS_VERSIONS.get(version_key, "Unknown Windows Version")
            
            # Détermination du type de produit (Workstation, Server, Domain Controller)
            if sys.platform == "win32":
                try:
                    import win32api
                    import win32con
                    
                    windows_info["product_type"] = win32api.GetVersionEx(1)[8]
                    windows_info["is_workstation"] = (windows_info["product_type"] == win32con.VER_NT_WORKSTATION)
                    windows_info["is_server"] = (windows_info["product_type"] == win32con.VER_NT_SERVER)
                    windows_info["is_domain_controller"] = (windows_info["product_type"] == win32con.VER_NT_DOMAIN_CONTROLLER)
                except ImportError:
                    # Fallback si pywin32 n'est pas disponible
                    windows_info["is_server"] = "Server" in platform.win32_edition() if hasattr(platform, "win32_edition") else False
                    windows_info["is_workstation"] = not windows_info["is_server"]
            
            # Récupération du Service Pack
            try:
                windows_info["service_pack"] = sys.getwindowsversion().service_pack
            except:
                pass
            
            # Récupération de l'édition Windows
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                    windows_info["win32_edition"] = winreg.QueryValueEx(key, "EditionID")[0]
            except:
                pass
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des informations Windows: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
        
        return windows_info
    
    def _check_compatibility(self):
        """Vérifie la compatibilité avec la version de Windows actuelle."""
        # Vérification du système d'exploitation
        if self.windows_info["system"] != "Windows":
            self.compatibility_issues.append("Système d'exploitation non Windows")
            return
        
        # Vérification de la version de Windows
        major_version = self.windows_info["major_version"]
        minor_version = self.windows_info["minor_version"]
        
        if major_version < 5:
            self.compatibility_issues.append("Version de Windows trop ancienne (antérieure à Windows 2000)")
        elif major_version == 5 and minor_version == 0:
            self.compatibility_issues.append("Windows 2000 détecté - support limité")
            self.compatibility_fixes.append("Utilisation de méthodes de collecte alternatives pour Windows 2000")
        elif major_version == 5 and minor_version == 1:
            self.compatibility_issues.append("Windows XP détecté - certaines fonctionnalités peuvent être limitées")
            self.compatibility_fixes.append("Utilisation de méthodes de collecte alternatives pour Windows XP")
        
        # Vérification de l'architecture
        if self.windows_info["architecture"] == "x86":
            self.compatibility_issues.append("Architecture 32 bits détectée - certaines fonctionnalités de mémoire peuvent être limitées")
            self.compatibility_fixes.append("Adaptation des méthodes de collecte mémoire pour l'architecture 32 bits")
        
        # Journalisation des résultats
        if self.compatibility_issues:
            logger.warning(f"Problèmes de compatibilité détectés: {', '.join(self.compatibility_issues)}")
            logger.info(f"Correctifs de compatibilité appliqués: {', '.join(self.compatibility_fixes)}")
        else:
            logger.info(f"Aucun problème de compatibilité détecté avec {self.windows_info['friendly_name']}")
    
    def is_compatible(self) -> bool:
        """
        Vérifie si la version de Windows est compatible.
        
        Returns:
            True si la version est compatible, False sinon
        """
        # Toutes les versions sont techniquement compatibles avec des limitations
        return self.windows_info["system"] == "Windows"
    
    def get_compatibility_status(self) -> Dict[str, Any]:
        """
        Récupère le statut de compatibilité.
        
        Returns:
            Dictionnaire contenant le statut de compatibilité
        """
        return {
            "compatible": self.is_compatible(),
            "windows_info": self.windows_info,
            "issues": self.compatibility_issues,
            "fixes": self.compatibility_fixes
        }
    
    def adapt_collector_for_windows_version(self, collector_name: str) -> Dict[str, Any]:
        """
        Adapte un collecteur pour la version de Windows actuelle.
        
        Args:
            collector_name: Nom du collecteur à adapter
            
        Returns:
            Dictionnaire contenant les adaptations effectuées
        """
        adaptations = {
            "collector": collector_name,
            "windows_version": self.windows_info["friendly_name"],
            "adaptations_applied": []
        }
        
        # Adaptations spécifiques pour EventLogCollector
        if collector_name == "EventLogCollector":
            if self.windows_info["major_version"] <= 5:
                # Windows XP/2000/2003 utilisent l'ancienne API d'événements
                adaptations["adaptations_applied"].append("Utilisation de l'API d'événements legacy")
            elif self.windows_info["major_version"] == 6 and self.windows_info["minor_version"] == 0:
                # Windows Vista/2008 ont une API d'événements intermédiaire
                adaptations["adaptations_applied"].append("Utilisation de l'API d'événements Vista")
        
        # Adaptations spécifiques pour RegistryCollector
        elif collector_name == "RegistryCollector":
            if self.windows_info["major_version"] <= 5:
                # Windows XP/2000/2003 ont des ruches de registre différentes
                adaptations["adaptations_applied"].append("Adaptation des chemins de ruches de registre pour Windows XP/2000/2003")
        
        # Adaptations spécifiques pour ProcessCollector
        elif collector_name == "ProcessCollector":
            if self.windows_info["major_version"] <= 5:
                # Windows XP/2000/2003 nécessitent des méthodes alternatives pour certaines informations de processus
                adaptations["adaptations_applied"].append("Utilisation de méthodes alternatives pour la collecte de processus")
        
        # Adaptations spécifiques pour MemoryCollector
        elif collector_name == "MemoryCollector":
            if self.windows_info["major_version"] <= 5:
                # Windows XP/2000/2003 nécessitent des méthodes alternatives pour la capture mémoire
                adaptations["adaptations_applied"].append("Utilisation de méthodes alternatives pour la capture mémoire")
            
            if self.windows_info["architecture"] == "x86":
                # Adaptation pour l'architecture 32 bits
                adaptations["adaptations_applied"].append("Adaptation des méthodes de capture mémoire pour l'architecture 32 bits")
        
        # Journalisation des adaptations
        if adaptations["adaptations_applied"]:
            logger.info(f"Adaptations appliquées pour {collector_name} sur {self.windows_info['friendly_name']}: {', '.join(adaptations['adaptations_applied'])}")
        else:
            logger.debug(f"Aucune adaptation nécessaire pour {collector_name} sur {self.windows_info['friendly_name']}")
        
        return adaptations
    
    def get_available_event_logs(self) -> List[str]:
        """
        Récupère la liste des journaux d'événements disponibles selon la version de Windows.
        
        Returns:
            Liste des journaux d'événements disponibles
        """
        # Journaux d'événements de base disponibles sur toutes les versions
        event_logs = ["Application", "System", "Security"]
        
        # Journaux supplémentaires disponibles sur les versions plus récentes
        if self.windows_info["major_version"] >= 6:
            event_logs.extend([
                "Setup",
                "ForwardedEvents"
            ])
            
            # Windows 7 et supérieur
            if self.windows_info["major_version"] > 6 or (self.windows_info["major_version"] == 6 and self.windows_info["minor_version"] >= 1):
                event_logs.extend([
                    "Microsoft-Windows-PowerShell/Operational",
                    "Microsoft-Windows-TaskScheduler/Operational",
                    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                    "Microsoft-Windows-Windows Defender/Operational"
                ])
            
            # Windows 8 et supérieur
            if self.windows_info["major_version"] > 6 or (self.windows_info["major_version"] == 6 and self.windows_info["minor_version"] >= 2):
                event_logs.extend([
                    "Microsoft-Windows-AppLocker/EXE and DLL",
                    "Microsoft-Windows-AppLocker/MSI and Script",
                    "Microsoft-Windows-AppLocker/Packaged app-Execution"
                ])
            
            # Windows 10 et supérieur
            if self.windows_info["major_version"] >= 10:
                event_logs.extend([
                    "Microsoft-Windows-Sysmon/Operational",
                    "Microsoft-Windows-PowerShell/Operational"
                ])
        
        # Journaux spécifiques aux serveurs
        if self.windows_info["is_server"]:
            event_logs.extend([
                "Directory Service",
                "DNS Server",
                "File Replication Service"
            ])
            
            # Windows Server 2008 et supérieur
            if self.windows_info["major_version"] >= 6:
                event_logs.extend([
                    "Microsoft-Windows-DHCP-Server/Operational",
                    "Microsoft-Windows-DNSServer/Operational"
                ])
            
            # Windows Server 2012 et supérieur
            if self.windows_info["major_version"] > 6 or (self.windows_info["major_version"] == 6 and self.windows_info["minor_version"] >= 2):
                event_logs.extend([
                    "Microsoft-Windows-NTLM/Operational",
                    "Microsoft-Windows-Kerberos/Operational"
                ])
        
        return event_logs
    
    def get_registry_paths(self) -> Dict[str, str]:
        """
        Récupère les chemins des ruches de registre selon la version de Windows.
        
        Returns:
            Dictionnaire contenant les chemins des ruches de registre
        """
        # Chemins de base pour toutes les versions
        registry_paths = {
            "SYSTEM": r"%SystemRoot%\System32\config\SYSTEM",
            "SOFTWARE": r"%SystemRoot%\System32\config\SOFTWARE",
            "SECURITY": r"%SystemRoot%\System32\config\SECURITY",
            "SAM": r"%SystemRoot%\System32\config\SAM"
        }
        
        # Adaptations pour les anciennes versions
        if self.windows_info["major_version"] <= 5:
            # Windows XP/2000/2003 peuvent avoir des chemins légèrement différents
            pass
        
        # Ajout des ruches utilisateur
        registry_paths["NTUSER.DAT"] = r"%UserProfile%\NTUSER.DAT"
        
        # Windows Vista et supérieur
        if self.windows_info["major_version"] >= 6:
            registry_paths["UsrClass.dat"] = r"%UserProfile%\AppData\Local\Microsoft\Windows\UsrClass.dat"
        else:
            # Windows XP
            registry_paths["UsrClass.dat"] = r"%UserProfile%\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat"
        
        # Résolution des variables d'environnement
        for key, path in registry_paths.items():
            registry_paths[key] = os.path.expandvars(path)
        
        return registry_paths
    
    def get_browser_paths(self) -> Dict[str, Dict[str, str]]:
        """
        Récupère les chemins des données de navigateurs selon la version de Windows.
        
        Returns:
            Dictionnaire contenant les chemins des données de navigateurs
        """
        browser_paths = {}
        
        # Internet Explorer (toutes versions)
        ie_paths = {}
        if self.windows_info["major_version"] >= 6:
            # Vista et supérieur
            ie_paths["history"] = r"%UserProfile%\AppData\Local\Microsoft\Windows\History"
            ie_paths["cookies"] = r"%UserProfile%\AppData\Roaming\Microsoft\Windows\Cookies"
            ie_paths["cache"] = r"%UserProfile%\AppData\Local\Microsoft\Windows\Temporary Internet Files"
        else:
            # XP et antérieur
            ie_paths["history"] = r"%UserProfile%\Local Settings\History"
            ie_paths["cookies"] = r"%UserProfile%\Cookies"
            ie_paths["cache"] = r"%UserProfile%\Local Settings\Temporary Internet Files"
        
        browser_paths["Internet Explorer"] = ie_paths
        
        # Edge (Windows 10 et supérieur)
        if self.windows_info["major_version"] >= 10:
            edge_paths = {
                "history": r"%UserProfile%\AppData\Local\Microsoft\Edge\User Data\Default\History",
                "cookies": r"%UserProfile%\AppData\Local\Microsoft\Edge\User Data\Default\Cookies",
                "cache": r"%UserProfile%\AppData\Local\Microsoft\Edge\User Data\Default\Cache",
                "bookmarks": r"%UserProfile%\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
            }
            browser_paths["Edge"] = edge_paths
        
        # Chrome (toutes versions, mais les chemins peuvent varier)
        chrome_paths = {
            "history": r"%UserProfile%\AppData\Local\Google\Chrome\User Data\Default\History",
            "cookies": r"%UserProfile%\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            "cache": r"%UserProfile%\AppData\Local\Google\Chrome\User Data\Default\Cache",
            "bookmarks": r"%UserProfile%\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
        }
        
        # Adaptation pour XP
        if self.windows_info["major_version"] <= 5:
            chrome_paths["history"] = r"%UserProfile%\Local Settings\Application Data\Google\Chrome\User Data\Default\History"
            chrome_paths["cookies"] = r"%UserProfile%\Local Settings\Application Data\Google\Chrome\User Data\Default\Cookies"
            chrome_paths["cache"] = r"%UserProfile%\Local Settings\Application Data\Google\Chrome\User Data\Default\Cache"
            chrome_paths["bookmarks"] = r"%UserProfile%\Local Settings\Application Data\Google\Chrome\User Data\Default\Bookmarks"
        
        browser_paths["Chrome"] = chrome_paths
        
        # Firefox (toutes versions, mais les chemins peuvent varier)
        firefox_paths = {}
        
        if self.windows_info["major_version"] >= 6:
            # Vista et supérieur
            firefox_paths["profile"] = r"%UserProfile%\AppData\Roaming\Mozilla\Firefox\Profiles"
        else:
            # XP et antérieur
            firefox_paths["profile"] = r"%UserProfile%\Application Data\Mozilla\Firefox\Profiles"
        
        browser_paths["Firefox"] = firefox_paths
        
        # Résolution des variables d'environnement
        for browser, paths in browser_paths.items():
            for key, path in paths.items():
                browser_paths[browser][key] = os.path.expandvars(path)
        
        return browser_paths
    
    def get_memory_acquisition_method(self) -> str:
        """
        Détermine la méthode d'acquisition mémoire à utiliser selon la version de Windows.
        
        Returns:
            Nom de la méthode d'acquisition mémoire à utiliser
        """
        # Windows 10 et supérieur
        if self.windows_info["major_version"] >= 10:
            return "winpmem"
        
        # Windows 7/8/8.1
        elif self.windows_info["major_version"] == 6 and self.windows_info["minor_version"] >= 1:
            return "winpmem"
        
        # Windows Vista
        elif self.windows_info["major_version"] == 6 and self.windows_info["minor_version"] == 0:
            return "win32dd"
        
        # Windows XP/2003
        elif self.windows_info["major_version"] == 5 and self.windows_info["minor_version"] >= 1:
            return "win32dd"
        
        # Windows 2000
        elif self.windows_info["major_version"] == 5 and self.windows_info["minor_version"] == 0:
            return "mdd"
        
        # Méthode par défaut
        return "winpmem"
    
    def is_admin(self) -> bool:
        """
        Vérifie si le processus actuel dispose des privilèges administrateur.
        
        Returns:
            True si le processus dispose des privilèges administrateur, False sinon
        """
        try:
            if sys.platform == "win32":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return os.geteuid() == 0
        except:
            return False
    
    def get_prefetch_path(self) -> str:
        """
        Récupère le chemin du répertoire Prefetch selon la version de Windows.
        
        Returns:
            Chemin du répertoire Prefetch
        """
        # Chemin par défaut
        prefetch_path = r"%SystemRoot%\Prefetch"
        
        # Résolution des variables d'environnement
        return os.path.expandvars(prefetch_path)
    
    def get_event_log_path(self) -> str:
        """
        Récupère le chemin du répertoire des journaux d'événements selon la version de Windows.
        
        Returns:
            Chemin du répertoire des journaux d'événements
        """
        # Windows Vista et supérieur
        if self.windows_info["major_version"] >= 6:
            event_log_path = r"%SystemRoot%\System32\winevt\Logs"
        else:
            # Windows XP et antérieur
            event_log_path = r"%SystemRoot%\System32\config"
        
        # Résolution des variables d'environnement
        return os.path.expandvars(event_log_path)
    
    def get_user_profile_paths(self) -> List[str]:
        """
        Récupère les chemins des profils utilisateur selon la version de Windows.
        
        Returns:
            Liste des chemins des profils utilisateur
        """
        user_profile_paths = []
        
        try:
            # Chemin de base des profils utilisateur
            if self.windows_info["major_version"] >= 6:
                # Vista et supérieur
                users_dir = os.path.expandvars(r"%SystemDrive%\Users")
            else:
                # XP et antérieur
                users_dir = os.path.expandvars(r"%SystemDrive%\Documents and Settings")
            
            # Récupération des répertoires utilisateur
            if os.path.exists(users_dir):
                for user_dir in os.listdir(users_dir):
                    user_path = os.path.join(users_dir, user_dir)
                    if os.path.isdir(user_path) and user_dir not in ["All Users", "Default User", "Public", "Default"]:
                        user_profile_paths.append(user_path)
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des profils utilisateur: {str(e)}")
        
        return user_profile_paths
    
    def get_usb_registry_keys(self) -> List[str]:
        """
        Récupère les clés de registre USB selon la version de Windows.
        
        Returns:
            Liste des clés de registre USB
        """
        # Clés de base pour toutes les versions
        usb_keys = [
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB"
        ]
        
        # Windows Vista et supérieur
        if self.windows_info["major_version"] >= 6:
            usb_keys.extend([
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Portable Devices\Devices"
            ])
        
        # Windows 7 et supérieur
        if self.windows_info["major_version"] > 6 or (self.windows_info["major_version"] == 6 and self.windows_info["minor_version"] >= 1):
            usb_keys.extend([
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM"
            ])
        
        return usb_keys

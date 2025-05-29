#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion des listes blanches pour réduire les faux positifs.

Ce module permet de gérer les listes blanches utilisées par les analyseurs
pour éviter les faux positifs sur des éléments légitimes.
"""

import os
import json
import logging
import re
from pathlib import Path

# Configuration du logger
logger = logging.getLogger("forensichunter.analyzers.whitelist_manager")

class WhitelistManager:
    """Gestionnaire de listes blanches pour réduire les faux positifs."""
    
    def __init__(self, config=None):
        """
        Initialise un nouveau gestionnaire de listes blanches.
        
        Args:
            config (dict, optional): Configuration du gestionnaire
        """
        self.config = config or {}
        self.whitelists = {}
        
        # Charger les listes blanches par défaut
        self._load_default_whitelists()
        
        # Charger les listes blanches personnalisées
        custom_whitelist_path = self.config.get("custom_whitelist_path")
        if custom_whitelist_path and os.path.exists(custom_whitelist_path):
            self._load_custom_whitelists(custom_whitelist_path)
    
    def _load_default_whitelists(self):
        """Charge les listes blanches par défaut."""
        # Liste blanche pour les clés de registre Windows légitimes
        self.whitelists["registry_keys"] = [
            # Clés Run et RunOnce légitimes
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"HKCU\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"HKCU\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            
            # Clés système légitimes
            r"HKLM\\SYSTEM\\CurrentControlSet\\Services",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            
            # Clés de configuration légitimes
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows Defender",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows Defender",
            r"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
            r"HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Reliability",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Reliability",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PreviewHandlers",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PreviewHandlers",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PropertySystem",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PropertySystem",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UFH",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\UFH",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Winlogon",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Winlogon",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN",
            r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer",
            r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer",
            r"HKLM\\SOFTWARE\\Microsoft\\WBEM\\CIMOM",
            r"HKCU\\SOFTWARE\\Microsoft\\WBEM\\CIMOM"
        ]
        
        # Liste blanche pour les processus Windows légitimes
        self.whitelists["processes"] = [
            r"svchost\.exe",
            r"explorer\.exe",
            r"lsass\.exe",
            r"services\.exe",
            r"winlogon\.exe",
            r"csrss\.exe",
            r"smss\.exe",
            r"spoolsv\.exe",
            r"wininit\.exe",
            r"taskmgr\.exe",
            r"msiexec\.exe",
            r"dllhost\.exe",
            r"conhost\.exe",
            r"dwm\.exe",
            r"taskhost\.exe",
            r"rundll32\.exe",
            r"regsvr32\.exe",
            r"wmiprvse\.exe",
            r"wuauclt\.exe",
            r"ctfmon\.exe",
            r"searchindexer\.exe",
            r"searchprotocolhost\.exe",
            r"searchfilterhost\.exe",
            r"winlogon\.exe",
            r"wininit\.exe",
            r"lsm\.exe",
            r"audiodg\.exe",
            r"wlanext\.exe",
            r"consent\.exe",
            r"taskeng\.exe",
            r"taskhostw\.exe",
            r"runtimebroker\.exe",
            r"smartscreen\.exe",
            r"sihost\.exe",
            r"fontdrvhost\.exe",
            r"backgroundtaskhost\.exe",
            r"shellexperiencehost\.exe",
            r"applicationframehost\.exe",
            r"systemsettings\.exe",
            r"winstore\.app\.exe",
            r"microsoftedge\.exe",
            r"microsoftedgecp\.exe",
            r"microsoftedgesh\.exe",
            r"runtimebroker\.exe",
            r"securityhealthservice\.exe",
            r"securityhealthsystray\.exe",
            r"mrt\.exe",
            r"msmpeng\.exe",
            r"nissrv\.exe",
            r"msseces\.exe",
            r"msascui\.exe",
            r"msascuil\.exe",
            r"msmpeng\.exe",
            r"mpcmdrun\.exe",
            r"mssense\.exe",
            r"sense\.exe",
            r"securityhealthhost\.exe",
            r"securityhealthservice\.exe",
            r"securityhealthsystray\.exe",
            r"windowsdefender\.exe",
            r"smartscreen\.exe",
            r"wscsvc\.exe",
            r"wscntfy\.exe",
            r"wuauclt\.exe",
            r"wuauserv\.exe",
            r"musnotifyicon\.exe",
            r"usoclient\.exe",
            r"usocoreworker\.exe",
            r"usoservice\.exe",
            r"wuapihost\.exe",
            r"wuauclt\.exe"
        ]
        
        # Liste blanche pour les domaines légitimes
        self.whitelists["domains"] = [
            r"\.microsoft\.com$",
            r"\.windows\.com$",
            r"\.windowsupdate\.com$",
            r"\.office\.com$",
            r"\.office365\.com$",
            r"\.live\.com$",
            r"\.msn\.com$",
            r"\.bing\.com$",
            r"\.google\.com$",
            r"\.googleapis\.com$",
            r"\.gstatic\.com$",
            r"\.amazon\.com$",
            r"\.amazonaws\.com$",
            r"\.apple\.com$",
            r"\.icloud\.com$",
            r"\.adobe\.com$",
            r"\.akamai\.net$",
            r"\.cloudfront\.net$",
            r"\.cloudflare\.com$",
            r"\.github\.com$",
            r"\.githubusercontent\.com$",
            r"\.digicert\.com$",
            r"\.verisign\.com$",
            r"\.symantec\.com$",
            r"\.mcafee\.com$",
            r"\.norton\.com$",
            r"\.kaspersky\.com$",
            r"\.avast\.com$",
            r"\.avg\.com$",
            r"\.bitdefender\.com$",
            r"\.eset\.com$",
            r"\.trendmicro\.com$",
            r"\.sophos\.com$"
        ]
        
        # Liste blanche pour les adresses IP légitimes
        self.whitelists["ips"] = [
            r"^127\.0\.0\.1$",
            r"^0\.0\.0\.0$",
            r"^255\.255\.255\.255$",
            r"^192\.168\.\d{1,3}\.\d{1,3}$",
            r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$",
            r"^169\.254\.\d{1,3}\.\d{1,3}$",
            r"^224\.0\.0\.\d{1,3}$",
            r"^239\.255\.255\.250$",
            r"^255\.255\.255\.255$"
        ]
        
        logger.info(f"Listes blanches par défaut chargées: {', '.join(self.whitelists.keys())}")
    
    def _load_custom_whitelists(self, custom_whitelist_path):
        """
        Charge les listes blanches personnalisées depuis un fichier JSON.
        
        Args:
            custom_whitelist_path (str): Chemin vers le fichier JSON contenant les listes blanches personnalisées
        """
        try:
            with open(custom_whitelist_path, 'r', encoding='utf-8') as f:
                custom_whitelists = json.load(f)
            
            # Fusionner les listes blanches personnalisées avec les listes blanches par défaut
            for category, entries in custom_whitelists.items():
                if category in self.whitelists:
                    self.whitelists[category].extend(entries)
                else:
                    self.whitelists[category] = entries
            
            logger.info(f"Listes blanches personnalisées chargées depuis {custom_whitelist_path}")
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement des listes blanches personnalisées: {str(e)}")
    
    def is_whitelisted(self, value, category=None):
        """
        Vérifie si une valeur est dans une liste blanche.
        
        Args:
            value (str): Valeur à vérifier
            category (str, optional): Catégorie de liste blanche à vérifier.
                Si None, toutes les catégories sont vérifiées.
                
        Returns:
            bool: True si la valeur est dans la liste blanche, False sinon
        """
        # Si une catégorie est spécifiée, ne vérifier que cette catégorie
        if category and category in self.whitelists:
            for pattern in self.whitelists[category]:
                if re.search(pattern, value, re.IGNORECASE):
                    logger.debug(f"Valeur ignorée (liste blanche {category}): {value}")
                    return True
            return False
        
        # Sinon, vérifier toutes les catégories
        for category, patterns in self.whitelists.items():
            for pattern in patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    logger.debug(f"Valeur ignorée (liste blanche {category}): {value}")
                    return True
        
        return False
    
    def add_whitelist_entry(self, category, pattern):
        """
        Ajoute une entrée à une liste blanche.
        
        Args:
            category (str): Catégorie de liste blanche
            pattern (str): Pattern à ajouter
            
        Returns:
            bool: True si l'ajout a réussi, False sinon
        """
        try:
            if category not in self.whitelists:
                self.whitelists[category] = []
            
            if pattern not in self.whitelists[category]:
                self.whitelists[category].append(pattern)
                logger.info(f"Entrée ajoutée à la liste blanche {category}: {pattern}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout d'une entrée à la liste blanche: {str(e)}")
            return False
    
    def remove_whitelist_entry(self, category, pattern):
        """
        Supprime une entrée d'une liste blanche.
        
        Args:
            category (str): Catégorie de liste blanche
            pattern (str): Pattern à supprimer
            
        Returns:
            bool: True si la suppression a réussi, False sinon
        """
        try:
            if category in self.whitelists and pattern in self.whitelists[category]:
                self.whitelists[category].remove(pattern)
                logger.info(f"Entrée supprimée de la liste blanche {category}: {pattern}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la suppression d'une entrée de la liste blanche: {str(e)}")
            return False
    
    def save_whitelists(self, output_path):
        """
        Sauvegarde les listes blanches dans un fichier JSON.
        
        Args:
            output_path (str): Chemin vers le fichier JSON de sortie
            
        Returns:
            bool: True si la sauvegarde a réussi, False sinon
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.whitelists, f, indent=2)
            
            logger.info(f"Listes blanches sauvegardées dans {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des listes blanches: {str(e)}")
            return False
    
    def get_whitelist(self, category=None):
        """
        Retourne une liste blanche.
        
        Args:
            category (str, optional): Catégorie de liste blanche à retourner.
                Si None, toutes les listes blanches sont retournées.
                
        Returns:
            dict or list: Liste blanche demandée
        """
        if category:
            return self.whitelists.get(category, [])
        return self.whitelists

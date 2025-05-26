#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des données de registre Windows.

Ce module est responsable de la collecte et de l'extraction des ruches de registre
Windows pour analyse forensique.
"""

import os
import logging
import datetime
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional

from Registry import Registry

logger = logging.getLogger("forensichunter")

# Ruches de registre importantes pour l'analyse forensique
REGISTRY_HIVES = {
    "SYSTEM": r"%SystemRoot%\System32\config\SYSTEM",
    "SOFTWARE": r"%SystemRoot%\System32\config\SOFTWARE",
    "SECURITY": r"%SystemRoot%\System32\config\SECURITY",
    "SAM": r"%SystemRoot%\System32\config\SAM",
    "DEFAULT": r"%SystemRoot%\System32\config\DEFAULT",
    "NTUSER.DAT": r"%UserProfile%\NTUSER.DAT",
    "UsrClass.dat": r"%LocalAppData%\Microsoft\Windows\UsrClass.dat"
}

# Clés de registre d'intérêt pour l'analyse forensique
REGISTRY_KEYS_OF_INTEREST = {
    "SYSTEM": [
        r"ControlSet001\Control\ComputerName\ComputerName",
        r"ControlSet001\Services\Tcpip\Parameters\Interfaces",
        r"ControlSet001\Control\TimeZoneInformation",
        r"ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters",
        r"ControlSet001\Services",
        r"Setup\Upgrade",
        r"ControlSet001\Control\Windows\ShutdownTime"
    ],
    "SOFTWARE": [
        r"Microsoft\Windows\CurrentVersion\Run",
        r"Microsoft\Windows\CurrentVersion\RunOnce",
        r"Microsoft\Windows\CurrentVersion\Uninstall",
        r"Microsoft\Windows NT\CurrentVersion",
        r"Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        r"Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        r"Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
        r"Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        r"Microsoft\Windows\CurrentVersion\Policies",
        r"Microsoft\Windows\CurrentVersion\WindowsUpdate"
    ],
    "NTUSER.DAT": [
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Internet Explorer\TypedURLs",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
    ]
}


class RegistryCollector:
    """Collecteur de données de registre Windows."""

    def __init__(self, config):
        """
        Initialise le collecteur de données de registre.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "registry")
        self.image_path = None
        
        # Création du répertoire de sortie
        os.makedirs(self.output_dir, exist_ok=True)
    
    def set_image_path(self, image_path: str):
        """
        Configure le chemin vers l'image disque à analyser.
        
        Args:
            image_path: Chemin vers l'image disque
        """
        self.image_path = image_path
    
    def _get_registry_path(self, hive_path: str) -> str:
        """
        Détermine le chemin complet vers une ruche de registre.
        
        Args:
            hive_path: Chemin relatif de la ruche
            
        Returns:
            Chemin complet vers la ruche de registre
        """
        if self.image_path:
            # Si on analyse une image disque, on doit adapter le chemin
            # Cette partie nécessiterait une implémentation spécifique selon le format d'image
            # Pour l'instant, on suppose que l'image est déjà montée
            system_root = os.path.join(self.image_path, "Windows")
            user_profile = os.path.join(self.image_path, "Users", "Default")  # À adapter selon le profil à analyser
            local_app_data = os.path.join(user_profile, "AppData", "Local")
        else:
            # Sur un système Windows en direct
            system_root = os.environ.get("SystemRoot", "C:\\Windows")
            user_profile = os.environ.get("UserProfile", "")
            local_app_data = os.environ.get("LocalAppData", "")
        
        # Remplacement des variables d'environnement
        path = hive_path.replace("%SystemRoot%", system_root)
        path = path.replace("%UserProfile%", user_profile)
        path = path.replace("%LocalAppData%", local_app_data)
        
        return path
    
    def _extract_registry_key(self, reg, key_path: str) -> Dict[str, Any]:
        """
        Extrait les données d'une clé de registre.
        
        Args:
            reg: Objet Registry ouvert
            key_path: Chemin de la clé à extraire
            
        Returns:
            Dictionnaire contenant les données de la clé
        """
        try:
            key = reg.open(key_path)
            result = {
                "path": key_path,
                "last_modified": key.timestamp().isoformat() if key.timestamp() else None,
                "values": {},
                "subkeys": []
            }
            
            # Extraction des valeurs
            for value in key.values():
                try:
                    result["values"][value.name()] = {
                        "type": value.value_type_str(),
                        "data": str(value.value())
                    }
                except Exception as e:
                    result["values"][value.name()] = {
                        "type": value.value_type_str(),
                        "data": f"[Erreur d'extraction: {str(e)}]"
                    }
            
            # Extraction des sous-clés
            for subkey in key.subkeys():
                result["subkeys"].append({
                    "name": subkey.name(),
                    "last_modified": subkey.timestamp().isoformat() if subkey.timestamp() else None
                })
            
            return result
            
        except Registry.RegistryKeyNotFoundException:
            return {
                "path": key_path,
                "error": "Clé non trouvée"
            }
        except Exception as e:
            logger.debug(f"Erreur lors de l'extraction de la clé {key_path}: {str(e)}")
            return {
                "path": key_path,
                "error": str(e)
            }
    
    def collect(self) -> Dict[str, Any]:
        """
        Collecte les données de registre Windows.
        
        Returns:
            Dictionnaire contenant les données de registre collectées
        """
        logger.info("Collecte des données de registre Windows...")
        
        collected_registry = {}
        
        # Parcours des ruches de registre importantes
        for hive_name, hive_path in REGISTRY_HIVES.items():
            full_path = self._get_registry_path(hive_path)
            
            if not os.path.exists(full_path):
                logger.warning(f"Ruche de registre non trouvée: {full_path}")
                continue
            
            try:
                logger.info(f"Analyse de la ruche: {hive_name}")
                
                # Copie de la ruche pour analyse
                output_path = os.path.join(self.output_dir, f"{hive_name}")
                
                # Pour les ruches système en cours d'utilisation, on utilise une approche spéciale
                if hive_name in ["SYSTEM", "SOFTWARE", "SECURITY", "SAM"]:
                    # Sur un système en direct, on doit utiliser reg.exe pour exporter
                    if not self.image_path:
                        temp_path = os.path.join(tempfile.gettempdir(), f"{hive_name}")
                        os.system(f'reg save HKLM\\{hive_name} "{temp_path}" /y')
                        if os.path.exists(temp_path):
                            shutil.copy2(temp_path, output_path)
                            os.remove(temp_path)
                        else:
                            # Fallback: copie directe (peut échouer si les fichiers sont verrouillés)
                            shutil.copy2(full_path, output_path)
                    else:
                        # Pour une image disque, copie directe
                        shutil.copy2(full_path, output_path)
                else:
                    # Pour les autres ruches, copie directe
                    shutil.copy2(full_path, output_path)
                
                # Analyse de la ruche
                reg = Registry.Registry(output_path)
                
                # Extraction des clés d'intérêt
                keys_data = {}
                if hive_name in REGISTRY_KEYS_OF_INTEREST:
                    for key_path in REGISTRY_KEYS_OF_INTEREST[hive_name]:
                        keys_data[key_path] = self._extract_registry_key(reg, key_path)
                
                collected_registry[hive_name] = {
                    "path": full_path,
                    "keys": keys_data
                }
                
                logger.info(f"Collecté {len(keys_data)} clés depuis {hive_name}")
                
            except Exception as e:
                logger.error(f"Erreur lors de la collecte de la ruche {hive_name}: {str(e)}")
                logger.debug("Détails de l'erreur:", exc_info=True)
                collected_registry[hive_name] = {"error": str(e)}
        
        return collected_registry

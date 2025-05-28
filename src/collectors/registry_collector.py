#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des entrées de registre Windows.

Ce module permet de collecter les entrées de registre Windows
pour analyse forensique.
"""

import os
import logging
import datetime
import json
import subprocess
from pathlib import Path

from .base_collector import BaseCollector, Artifact

# Configuration du logger
logger = logging.getLogger("forensichunter.collectors.registry")

class RegistryCollector(BaseCollector):
    """Collecteur d'entrées de registre Windows."""
    
    def __init__(self, config=None):
        """
        Initialise un nouveau collecteur d'entrées de registre.
        
        Args:
            config (dict, optional): Configuration du collecteur
        """
        super().__init__(config)
        self.registry_keys = self.config.get("registry_keys", [
            # Clés de démarrage automatique
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            # Services
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            # Informations système
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            # Programmes installés
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            # Historique USB
            r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
            # Persistance WMI
            r"HKLM\SOFTWARE\Microsoft\WBEM\CIMOM",
            # Historique des commandes PowerShell
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PowerShell\PSReadLine"
        ])
        self.use_powershell = self.config.get("use_powershell", True)
        self.use_reg = self.config.get("use_reg", True)
        self.use_python_winreg = self.config.get("use_python_winreg", True)
        self.recursive = self.config.get("recursive", True)
        self.max_depth = self.config.get("max_depth", 3)
    
    def get_name(self):
        """
        Retourne le nom du collecteur.
        
        Returns:
            str: Nom du collecteur
        """
        return "RegistryCollector"
    
    def get_description(self):
        """
        Retourne la description du collecteur.
        
        Returns:
            str: Description du collecteur
        """
        return "Collecteur d'entrées de registre Windows (Run, Services, USB, etc.)"
    
    def collect(self):
        """
        Collecte les entrées de registre Windows.
        
        Returns:
            list: Liste d'objets Artifact collectés
        """
        self.clear_artifacts()
        
        # Vérifier si nous sommes sur Windows
        if os.name != "nt":
            logger.warning("Ce collecteur ne fonctionne que sur Windows. Aucun artefact collecté.")
            return self.artifacts
        
        # Essayer différentes méthodes de collecte
        if self.use_powershell and self._collect_with_powershell():
            logger.info("Collecte avec PowerShell réussie")
        elif self.use_reg and self._collect_with_reg():
            logger.info("Collecte avec reg.exe réussie")
        elif self.use_python_winreg and self._collect_with_winreg():
            logger.info("Collecte avec winreg réussie")
        else:
            logger.error("Toutes les méthodes de collecte ont échoué")
        
        return self.artifacts
    
    def _collect_with_powershell(self):
        """
        Collecte les entrées de registre avec PowerShell.
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            for key in self.registry_keys:
                logger.info(f"Collecte des entrées de registre {key} avec PowerShell...")
                
                # Construire la commande PowerShell
                if self.recursive:
                    cmd = [
                        "powershell",
                        "-Command",
                        f"Get-ItemProperty -Path 'Registry::{key}' -ErrorAction SilentlyContinue | ConvertTo-Json; "
                        f"Get-ChildItem -Path 'Registry::{key}' -Recurse -Depth {self.max_depth} -ErrorAction SilentlyContinue | "
                        f"Get-ItemProperty -ErrorAction SilentlyContinue | ConvertTo-Json"
                    ]
                else:
                    cmd = [
                        "powershell",
                        "-Command",
                        f"Get-ItemProperty -Path 'Registry::{key}' -ErrorAction SilentlyContinue | ConvertTo-Json"
                    ]
                
                # Exécuter la commande
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()
                
                if process.returncode != 0:
                    logger.error(f"Erreur lors de l'exécution de PowerShell: {stderr}")
                    continue
                
                # Traiter les résultats
                try:
                    # Séparer les résultats (peut contenir plusieurs objets JSON)
                    json_parts = stdout.split("\n\n")
                    
                    for json_part in json_parts:
                        if not json_part.strip():
                            continue
                        
                        try:
                            registry_data = json.loads(json_part)
                            
                            # Si un seul objet est retourné, le convertir en liste
                            if isinstance(registry_data, dict):
                                registry_data = [registry_data]
                            
                            for entry in registry_data:
                                # Extraire le chemin de la clé
                                pspath = entry.get("PSPath", "")
                                if "Registry::" in pspath:
                                    reg_key = pspath.split("Registry::")[1]
                                else:
                                    reg_key = key
                                
                                # Supprimer les propriétés PowerShell
                                ps_properties = ["PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider"]
                                for prop in ps_properties:
                                    if prop in entry:
                                        del entry[prop]
                                
                                # Créer un artefact
                                metadata = {
                                    "registry_key": reg_key,
                                    "collection_method": "powershell"
                                }
                                
                                self.add_artifact(
                                    artifact_type="registry",
                                    source=f"powershell_{reg_key}",
                                    data=entry,
                                    metadata=metadata
                                )
                        
                        except json.JSONDecodeError:
                            logger.warning(f"Partie JSON invalide ignorée pour {key}")
                            continue
                    
                    logger.info(f"Entrées de registre collectées pour {key}")
                    
                except Exception as e:
                    logger.error(f"Erreur lors du traitement des données pour {key}: {str(e)}")
                    continue
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec PowerShell: {str(e)}")
            return False
    
    def _collect_with_reg(self):
        """
        Collecte les entrées de registre avec reg.exe.
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            for key in self.registry_keys:
                logger.info(f"Collecte des entrées de registre {key} avec reg.exe...")
                
                # Construire la commande reg
                if self.recursive:
                    cmd = ["reg", "query", key, "/s"]
                else:
                    cmd = ["reg", "query", key]
                
                # Exécuter la commande
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()
                
                if process.returncode != 0:
                    logger.error(f"Erreur lors de l'exécution de reg.exe: {stderr}")
                    continue
                
                # Traiter les résultats
                lines = stdout.splitlines()
                current_key = key
                registry_data = {}
                
                for line in lines:
                    line = line.strip()
                    
                    if not line:
                        continue
                    
                    # Nouvelle clé
                    if line.startswith("HKEY_") or line.startswith("HK"):
                        if registry_data and current_key:
                            # Sauvegarder la clé précédente
                            metadata = {
                                "registry_key": current_key,
                                "collection_method": "reg.exe"
                            }
                            
                            self.add_artifact(
                                artifact_type="registry",
                                source=f"reg_{current_key}",
                                data=registry_data,
                                metadata=metadata
                            )
                            
                            registry_data = {}
                        
                        current_key = line
                    
                    # Valeur de clé
                    elif "    " in line:
                        parts = line.split("    ")
                        parts = [p for p in parts if p]
                        
                        if len(parts) >= 3:
                            name = parts[0].strip()
                            type_reg = parts[1].strip()
                            value = parts[2].strip()
                            
                            registry_data[name] = {
                                "type": type_reg,
                                "value": value
                            }
                
                # Sauvegarder la dernière clé
                if registry_data and current_key:
                    metadata = {
                        "registry_key": current_key,
                        "collection_method": "reg.exe"
                    }
                    
                    self.add_artifact(
                        artifact_type="registry",
                        source=f"reg_{current_key}",
                        data=registry_data,
                        metadata=metadata
                    )
                
                logger.info(f"Entrées de registre collectées pour {key}")
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec reg.exe: {str(e)}")
            return False
    
    def _collect_with_winreg(self):
        """
        Collecte les entrées de registre avec winreg.
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            # Importer winreg
            try:
                import winreg
            except ImportError:
                logger.error("Module winreg non disponible")
                return False
            
            # Mapper les noms de ruches
            hive_map = {
                "HKLM": winreg.HKEY_LOCAL_MACHINE,
                "HKCU": winreg.HKEY_CURRENT_USER,
                "HKCR": winreg.HKEY_CLASSES_ROOT,
                "HKU": winreg.HKEY_USERS,
                "HKCC": winreg.HKEY_CURRENT_CONFIG,
                "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
                "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
                "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
                "HKEY_USERS": winreg.HKEY_USERS,
                "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG
            }
            
            for key in self.registry_keys:
                logger.info(f"Collecte des entrées de registre {key} avec winreg...")
                
                # Séparer la ruche et le chemin
                parts = key.split("\\", 1)
                
                if len(parts) != 2:
                    logger.error(f"Format de clé invalide: {key}")
                    continue
                
                hive_name, subkey = parts
                
                if hive_name not in hive_map:
                    logger.error(f"Ruche inconnue: {hive_name}")
                    continue
                
                hive = hive_map[hive_name]
                
                try:
                    # Ouvrir la clé
                    registry_key = winreg.OpenKey(hive, subkey)
                    
                    # Lire les valeurs
                    registry_data = {}
                    
                    try:
                        i = 0
                        while True:
                            name, value, type_reg = winreg.EnumValue(registry_key, i)
                            registry_data[name] = {
                                "type": type_reg,
                                "value": str(value)
                            }
                            i += 1
                    except WindowsError:
                        # Fin de l'énumération
                        pass
                    
                    # Créer un artefact
                    metadata = {
                        "registry_key": key,
                        "collection_method": "winreg"
                    }
                    
                    self.add_artifact(
                        artifact_type="registry",
                        source=f"winreg_{key}",
                        data=registry_data,
                        metadata=metadata
                    )
                    
                    # Si récursif, énumérer les sous-clés
                    if self.recursive:
                        self._collect_subkeys_recursive(hive, subkey, key, 0)
                    
                    logger.info(f"Entrées de registre collectées pour {key}")
                    
                except WindowsError as e:
                    logger.error(f"Erreur lors de l'ouverture de la clé {key}: {str(e)}")
                    continue
                
                finally:
                    try:
                        winreg.CloseKey(registry_key)
                    except:
                        pass
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec winreg: {str(e)}")
            return False
    
    def _collect_subkeys_recursive(self, hive, subkey, full_key, depth):
        """
        Collecte récursivement les sous-clés de registre.
        
        Args:
            hive: Ruche de registre
            subkey (str): Sous-clé à collecter
            full_key (str): Clé complète (pour l'affichage)
            depth (int): Profondeur actuelle
            
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        import winreg
        
        if depth >= self.max_depth:
            return True
        
        try:
            # Ouvrir la clé
            registry_key = winreg.OpenKey(hive, subkey)
            
            try:
                # Énumérer les sous-clés
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(registry_key, i)
                        subkey_path = f"{subkey}\\{subkey_name}"
                        full_subkey = f"{full_key}\\{subkey_name}"
                        
                        # Collecter la sous-clé
                        try:
                            subkey_handle = winreg.OpenKey(hive, subkey_path)
                            
                            # Lire les valeurs
                            registry_data = {}
                            
                            try:
                                j = 0
                                while True:
                                    name, value, type_reg = winreg.EnumValue(subkey_handle, j)
                                    registry_data[name] = {
                                        "type": type_reg,
                                        "value": str(value)
                                    }
                                    j += 1
                            except WindowsError:
                                # Fin de l'énumération
                                pass
                            
                            # Créer un artefact
                            metadata = {
                                "registry_key": full_subkey,
                                "collection_method": "winreg",
                                "depth": depth + 1
                            }
                            
                            self.add_artifact(
                                artifact_type="registry",
                                source=f"winreg_{full_subkey}",
                                data=registry_data,
                                metadata=metadata
                            )
                            
                            # Récursion
                            self._collect_subkeys_recursive(hive, subkey_path, full_subkey, depth + 1)
                            
                        except WindowsError as e:
                            logger.error(f"Erreur lors de l'ouverture de la sous-clé {full_subkey}: {str(e)}")
                        
                        finally:
                            try:
                                winreg.CloseKey(subkey_handle)
                            except:
                                pass
                        
                        i += 1
                        
                    except WindowsError:
                        # Fin de l'énumération
                        break
                
                return True
                
            finally:
                winreg.CloseKey(registry_key)
                
        except WindowsError as e:
            logger.error(f"Erreur lors de l'ouverture de la clé {full_key}: {str(e)}")
            return False

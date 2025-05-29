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
        self.recursive = self.config.get("recursive", False)  # Désactivé par défaut pour éviter les erreurs
        self.max_depth = self.config.get("max_depth", 2)  # Réduit pour éviter les timeouts
        self.timeout = self.config.get("timeout", 60)  # Timeout augmenté
    
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
        success = False
        
        if self.use_python_winreg:
            try:
                if self._collect_with_winreg():
                    logger.info("Collecte avec winreg réussie")
                    success = True
            except Exception as e:
                logger.error(f"Erreur lors de la collecte winreg: {str(e)}")
        
        if not success and self.use_powershell:
            try:
                if self._collect_with_powershell():
                    logger.info("Collecte avec PowerShell réussie")
                    success = True
            except Exception as e:
                logger.error(f"Erreur lors de la collecte PowerShell: {str(e)}")
        
        if not success and self.use_reg:
            try:
                if self._collect_with_reg():
                    logger.info("Collecte avec reg.exe réussie")
                    success = True
            except Exception as e:
                logger.error(f"Erreur lors de la collecte reg.exe: {str(e)}")
        
        if not success:
            logger.error("Toutes les méthodes de collecte ont échoué")
        
        return self.artifacts
    
    def _safe_subprocess_run(self, cmd, timeout=None):
        """
        Exécute une commande subprocess avec gestion d'encodage sécurisée.
        
        Args:
            cmd (list): Commande à exécuter
            timeout (int, optional): Timeout en secondes
            
        Returns:
            tuple: (stdout, stderr, returncode)
        """
        if timeout is None:
            timeout = self.timeout
            
        try:
            # Essayer avec UTF-8 d'abord
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                encoding='utf-8',
                errors='replace'  # Remplacer les caractères invalides
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return stdout, stderr, process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                logger.error(f"Timeout lors de l'exécution de la commande: {' '.join(cmd[:5])}")
                return "", f"Timeout après {timeout} secondes", 1
                
        except UnicodeDecodeError:
            # Fallback avec encodage système
            try:
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True,
                    encoding='cp1252',  # Encodage Windows par défaut
                    errors='replace'
                )
                
                stdout, stderr = process.communicate(timeout=timeout)
                return stdout, stderr, process.returncode
                
            except Exception as e:
                logger.error(f"Erreur d'encodage même avec fallback: {str(e)}")
                return "", str(e), 1
        
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de la commande: {str(e)}")
            return "", str(e), 1
    
    def _safe_json_loads(self, json_str):
        """
        Charge JSON de manière sécurisée avec nettoyage.
        
        Args:
            json_str (str): Chaîne JSON à parser
            
        Returns:
            dict/list ou None: Données JSON ou None en cas d'erreur
        """
        if not json_str or not json_str.strip():
            return None
            
        try:
            # Nettoyer la chaîne JSON
            json_str = json_str.strip()
            
            # Enlever les caractères de contrôle problématiques
            json_str = ''.join(char for char in json_str if ord(char) >= 32 or char in '\n\r\t')
            
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.error(f"Erreur JSON: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Erreur lors du parsing JSON: {str(e)}")
            return None
    
    def _collect_with_powershell(self):
        """
        Collecte les entrées de registre avec PowerShell.
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            for key in self.registry_keys:
                logger.info(f"Collecte des entrées de registre {key} avec PowerShell...")
                
                # Échapper les backslashes pour PowerShell
                escaped_key = key.replace('\\', '\\\\')
                
                # Construire la commande PowerShell simplifiée et robuste
                if self.recursive:
                    cmd = [
                        "powershell.exe",
                        "-NoProfile",
                        "-ExecutionPolicy", "Bypass",
                        "-Command",
                        f"""
                        try {{
                            $regPath = 'Registry::{escaped_key}'
                            if (Test-Path $regPath) {{
                                $items = @()
                                
                                # Obtenir les propriétés de la clé principale
                                try {{
                                    $mainItem = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                                    if ($mainItem) {{
                                        $items += $mainItem
                                    }}
                                }} catch {{}}
                                
                                # Obtenir les sous-clés si récursif
                                try {{
                                    $childItems = Get-ChildItem -Path $regPath -Recurse -Depth {self.max_depth} -ErrorAction SilentlyContinue | 
                                                 ForEach-Object {{ Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue }} |
                                                 Where-Object {{ $_ -ne $null }}
                                    if ($childItems) {{
                                        $items += $childItems
                                    }}
                                }} catch {{}}
                                
                                if ($items.Count -gt 0) {{
                                    $items | ConvertTo-Json -Depth 3 -Compress
                                }} else {{
                                    '[]'
                                }}
                            }} else {{
                                '[]'
                            }}
                        }} catch {{
                            Write-Error "Erreur: $($_.Exception.Message)"
                            '[]'
                        }}
                        """
                    ]
                else:
                    cmd = [
                        "powershell.exe",
                        "-NoProfile",
                        "-ExecutionPolicy", "Bypass",
                        "-Command",
                        f"""
                        try {{
                            $regPath = 'Registry::{escaped_key}'
                            if (Test-Path $regPath) {{
                                $item = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                                if ($item) {{
                                    $item | ConvertTo-Json -Depth 2 -Compress
                                }} else {{
                                    '{{}}'
                                }}
                            }} else {{
                                '{{}}'
                            }}
                        }} catch {{
                            Write-Error "Erreur: $($_.Exception.Message)"
                            '{{}}'
                        }}
                        """
                    ]
                
                # Exécuter la commande
                stdout, stderr, returncode = self._safe_subprocess_run(cmd, timeout=self.timeout)
                
                if returncode != 0:
                    logger.error(f"Erreur lors de l'exécution de PowerShell pour {key}: {stderr}")
                    continue
                
                if not stdout or stdout.strip() in ["", "[]", "{}"]:
                    logger.warning(f"Aucune entrée trouvée pour {key}")
                    continue
                
                # Traiter les résultats JSON
                registry_data = self._safe_json_loads(stdout)
                
                if registry_data is None:
                    logger.error(f"Impossible de parser le JSON pour {key}")
                    continue
                
                # Si un seul objet est retourné, le convertir en liste
                if isinstance(registry_data, dict):
                    registry_data = [registry_data]
                elif not isinstance(registry_data, list):
                    continue
                
                for entry in registry_data:
                    if not isinstance(entry, dict):
                        continue
                    
                    try:
                        # Extraire le chemin de la clé
                        pspath = entry.get("PSPath", "")
                        if "Registry::" in pspath:
                            reg_key = pspath.split("Registry::")[1]
                        else:
                            reg_key = key
                        
                        # Supprimer les propriétés PowerShell spéciales
                        ps_properties = ["PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider"]
                        clean_entry = {k: v for k, v in entry.items() if k not in ps_properties}
                        
                        # Créer un artefact seulement si on a des données utiles
                        if clean_entry:
                            metadata = {
                                "registry_key": reg_key,
                                "collection_method": "powershell",
                                "timestamp": datetime.datetime.now().isoformat()
                            }
                            
                            self.add_artifact(
                                artifact_type="registry",
                                source=f"powershell_{reg_key}",
                                data=clean_entry,
                                metadata=metadata
                            )
                    
                    except Exception as e:
                        logger.error(f"Erreur lors du traitement d'une entrée pour {key}: {str(e)}")
                        continue
                
                logger.info(f"Entrées de registre collectées pour {key}")
            
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
                    cmd = ["reg.exe", "query", key, "/s"]
                else:
                    cmd = ["reg.exe", "query", key]
                
                # Exécuter la commande
                stdout, stderr, returncode = self._safe_subprocess_run(cmd, timeout=self.timeout)
                
                if returncode != 0:
                    logger.error(f"Erreur lors de l'exécution de reg.exe pour {key}: {stderr}")
                    continue
                
                if not stdout:
                    logger.warning(f"Aucune sortie pour {key}")
                    continue
                
                # Traiter les résultats
                self._parse_reg_output(stdout, key)
                logger.info(f"Entrées de registre collectées pour {key}")
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec reg.exe: {str(e)}")
            return False
    
    def _parse_reg_output(self, output, base_key):
        """
        Parse la sortie de reg.exe.
        
        Args:
            output (str): Sortie de reg.exe
            base_key (str): Clé de base
        """
        try:
            lines = output.splitlines()
            current_key = base_key
            registry_data = {}
            
            for line in lines:
                line = line.strip()
                
                if not line:
                    continue
                
                # Nouvelle clé de registre
                if line.startswith("HKEY_") or line.startswith("HK"):
                    # Sauvegarder la clé précédente si elle a des données
                    if registry_data and current_key:
                        self._create_reg_artifact(current_key, registry_data)
                        registry_data = {}
                    
                    current_key = line
                
                # Valeur de registre (ligne avec espaces en début)
                elif line.startswith("    ") and "    " in line:
                    try:
                        # Parser la ligne de valeur
                        parts = [p.strip() for p in line.split("    ") if p.strip()]
                        
                        if len(parts) >= 3:
                            name = parts[0]
                            type_reg = parts[1]
                            value = "    ".join(parts[2:])  # Reconstituer la valeur
                            
                            registry_data[name] = {
                                "type": type_reg,
                                "value": value
                            }
                    except Exception as e:
                        logger.debug(f"Erreur lors du parsing d'une ligne: {line} - {str(e)}")
                        continue
            
            # Sauvegarder la dernière clé
            if registry_data and current_key:
                self._create_reg_artifact(current_key, registry_data)
        
        except Exception as e:
            logger.error(f"Erreur lors du parsing de la sortie reg.exe: {str(e)}")
    
    def _create_reg_artifact(self, reg_key, data):
        """
        Crée un artefact de registre.
        
        Args:
            reg_key (str): Clé de registre
            data (dict): Données de la clé
        """
        try:
            if not data:
                return
                
            metadata = {
                "registry_key": reg_key,
                "collection_method": "reg.exe",
                "timestamp": datetime.datetime.now().isoformat()
            }
            
            self.add_artifact(
                artifact_type="registry",
                source=f"reg_{reg_key}",
                data=data,
                metadata=metadata
            )
        except Exception as e:
            logger.error(f"Erreur lors de la création d'artefact: {str(e)}")
    
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
                    # Collecter la clé principale
                    self._collect_winreg_key(hive, subkey, key)
                    
                    # Si récursif, énumérer les sous-clés
                    if self.recursive:
                        self._collect_subkeys_recursive(hive, subkey, key, 0)
                    
                    logger.info(f"Entrées de registre collectées pour {key}")
                    
                except OSError as e:
                    logger.error(f"Erreur lors de l'ouverture de la clé {key}: {str(e)}")
                    continue
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec winreg: {str(e)}")
            return False
    
    def _collect_winreg_key(self, hive, subkey, full_key):
        """
        Collecte une clé de registre spécifique avec winreg.
        
        Args:
            hive: Ruche de registre
            subkey (str): Sous-clé
            full_key (str): Clé complète
        """
        import winreg
        
        try:
            # Ouvrir la clé
            registry_key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            
            try:
                # Lire les valeurs
                registry_data = {}
                
                try:
                    i = 0
                    while True:
                        try:
                            name, value, type_reg = winreg.EnumValue(registry_key, i)
                            
                            # Convertir la valeur en chaîne de manière sécurisée
                            try:
                                if isinstance(value, bytes):
                                    value_str = value.decode('utf-8', errors='replace')
                                else:
                                    value_str = str(value)
                            except Exception:
                                value_str = f"<Valeur non lisible: type {type(value)}>"
                            
                            registry_data[name if name else "(Default)"] = {
                                "type": type_reg,
                                "value": value_str
                            }
                            i += 1
                        except OSError:
                            # Fin de l'énumération
                            break
                except Exception as e:
                    logger.error(f"Erreur lors de l'énumération des valeurs pour {full_key}: {str(e)}")
                
                # Créer un artefact seulement si on a des données
                if registry_data:
                    metadata = {
                        "registry_key": full_key,
                        "collection_method": "winreg",
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                    
                    self.add_artifact(
                        artifact_type="registry",
                        source=f"winreg_{full_key}",
                        data=registry_data,
                        metadata=metadata
                    )
            
            finally:
                winreg.CloseKey(registry_key)
                
        except OSError as e:
            logger.error(f"Erreur lors de l'ouverture de la clé {full_key}: {str(e)}")
    
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
            registry_key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            
            try:
                # Énumérer les sous-clés
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(registry_key, i)
                        subkey_path = f"{subkey}\\{subkey_name}"
                        full_subkey = f"{full_key}\\{subkey_name}"
                        
                        # Collecter la sous-clé
                        self._collect_winreg_key(hive, subkey_path, full_subkey)
                        
                        # Récursion
                        self._collect_subkeys_recursive(hive, subkey_path, full_subkey, depth + 1)
                        
                        i += 1
                        
                    except OSError:
                        # Fin de l'énumération
                        break
                
                return True
                
            finally:
                winreg.CloseKey(registry_key)
                
        except OSError as e:
            logger.error(f"Erreur lors de l'ouverture de la clé {full_key}: {str(e)}")
            return False

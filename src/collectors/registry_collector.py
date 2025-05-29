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
        # Clés de registre sécurisées qui existent généralement
        self.registry_keys = self.config.get("registry_keys", [
            # Clés de démarrage automatique (communes)
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            # Services (toujours présent)
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            # Informations système (toujours présent)
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            # Programmes installés (toujours présent)
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            # Clés optionnelles (peuvent ne pas exister)
            # r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",  # Commenté car souvent absent
            # r"HKLM\SOFTWARE\Microsoft\WBEM\CIMOM",  # Commenté car peut être absent
            # r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PowerShell\PSReadLine"  # Commenté car optionnel
        ])
        
        # Liste des clés optionnelles à tester séparément
        self.optional_registry_keys = self.config.get("optional_registry_keys", [
            r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
            r"HKLM\SOFTWARE\Microsoft\WBEM\CIMOM", 
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PowerShell\PSReadLine",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
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
    
    def _key_exists(self, key_path):
        """
        Vérifie si une clé de registre existe avant de tenter d'y accéder.
        
        Args:
            key_path (str): Chemin de la clé de registre
            
        Returns:
            bool: True si la clé existe, False sinon
        """
        try:
            # Utiliser PowerShell pour tester l'existence de la clé
            escaped_key = key_path.replace('\\', '\\\\')
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command",
                f"Test-Path 'Registry::{escaped_key}'"
            ]
            
            stdout, stderr, returncode = self._safe_subprocess_run(cmd, timeout=10)
            
            if returncode == 0 and stdout.strip().lower() == "true":
                return True
            else:
                logger.debug(f"Clé de registre inexistante ou inaccessible: {key_path}")
                return False
                
        except Exception as e:
            logger.debug(f"Erreur lors de la vérification de la clé {key_path}: {str(e)}")
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
            
            # Collecter les clés obligatoires
            all_keys = self.registry_keys + self.optional_registry_keys
            
            for key in all_keys:
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
                    
                    logger.info(f"Entrées de registre collectées pour {key}")
                    
                except OSError as e:
                    # Cette erreur est normale pour les clés optionnelles
                    if key in self.optional_registry_keys:
                        logger.debug(f"Clé optionnelle inexistante (normal): {key}")
                    else:
                        logger.warning(f"Clé obligatoire inaccessible: {key} - {str(e)}")
                    continue
                except Exception as e:
                    logger.error(f"Erreur inattendue pour la clé {key}: {str(e)}")
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
                else:
                    logger.debug(f"Clé vide (normal): {full_key}")
            
            finally:
                winreg.CloseKey(registry_key)
                
        except OSError as e:
            # Ne pas logger comme une erreur pour les clés optionnelles
            raise e
    
    def _collect_with_powershell(self):
        """
        Collecte les entrées de registre avec PowerShell.
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            all_keys = self.registry_keys + self.optional_registry_keys
            
            for key in all_keys:
                logger.info(f"Collecte des entrées de registre {key} avec PowerShell...")
                
                # Vérifier d'abord si la clé existe
                if not self._key_exists(key):
                    if key in self.optional_registry_keys:
                        logger.debug(f"Clé optionnelle inexistante (normal): {key}")
                    else:
                        logger.warning(f"Clé obligatoire inexistante: {key}")
                    continue
                
                # Échapper les backslashes pour PowerShell
                escaped_key = key.replace('\\', '\\\\')
                
                # Construire la commande PowerShell simplifiée et robuste
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
                                # Supprimer les propriétés PowerShell
                                $cleanItem = @{{}}
                                $item.PSObject.Properties | Where-Object {{ $_.Name -notlike 'PS*' }} | ForEach-Object {{
                                    $cleanItem[$_.Name] = $_.Value
                                }}
                                if ($cleanItem.Count -gt 0) {{
                                    $cleanItem | ConvertTo-Json -Depth 2 -Compress
                                }} else {{
                                    '{{}}'
                                }}
                            }} else {{
                                '{{}}'
                            }}
                        }} else {{
                            Write-Error "Clé inexistante: {escaped_key}"
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
                    if key in self.optional_registry_keys:
                        logger.debug(f"Erreur PowerShell pour clé optionnelle {key}: {stderr}")
                    else:
                        logger.error(f"Erreur PowerShell pour clé obligatoire {key}: {stderr}")
                    continue
                
                if not stdout or stdout.strip() in ["", "{}"]:
                    logger.debug(f"Aucune entrée trouvée pour {key}")
                    continue
                
                # Traiter les résultats JSON
                try:
                    # Nettoyer la chaîne JSON
                    json_data = stdout.strip()
                    if not json_data or json_data == "{}":
                        continue
                    
                    # Enlever les caractères de contrôle problématiques
                    json_data = ''.join(char for char in json_data if ord(char) >= 32 or char in '\n\r\t')
                    
                    registry_data = json.loads(json_data)
                    
                    if registry_data and isinstance(registry_data, dict):
                        metadata = {
                            "registry_key": key,
                            "collection_method": "powershell",
                            "timestamp": datetime.datetime.now().isoformat()
                        }
                        
                        self.add_artifact(
                            artifact_type="registry",
                            source=f"powershell_{key}",
                            data=registry_data,
                            metadata=metadata
                        )
                        
                        logger.info(f"Entrées de registre collectées pour {key}")
                
                except json.JSONDecodeError as e:
                    logger.error(f"Erreur JSON pour {key}: {str(e)}")
                    logger.debug(f"JSON problématique: {stdout[:200]}...")
                    continue
                except Exception as e:
                    logger.error(f"Erreur lors du traitement pour {key}: {str(e)}")
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
            all_keys = self.registry_keys + self.optional_registry_keys
            
            for key in all_keys:
                logger.info(f"Collecte des entrées de registre {key} avec reg.exe...")
                
                # Construire la commande reg
                cmd = ["reg.exe", "query", key]
                
                # Exécuter la commande
                stdout, stderr, returncode = self._safe_subprocess_run(cmd, timeout=self.timeout)
                
                if returncode != 0:
                    if key in self.optional_registry_keys:
                        logger.debug(f"Clé optionnelle inaccessible avec reg.exe: {key}")
                    else:
                        logger.error(f"Erreur reg.exe pour clé obligatoire {key}: {stderr}")
                    continue
                
                if not stdout:
                    logger.debug(f"Aucune sortie pour {key}")
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

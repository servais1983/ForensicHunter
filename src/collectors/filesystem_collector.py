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
            # Fichiers temporaires
            r"C:\Windows\Temp",
            r"C:\Users\*\AppData\Local\Temp",
            # Historique des navigateurs
            r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History",
            r"C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\places.sqlite",
            r"C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History",
            # Fichiers de démarrage
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            # Fichiers de préfetch
            r"C:\Windows\Prefetch\*.pf",
            # Fichiers récents
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent",
            # Fichiers PowerShell
            r"C:\Users\*\Documents\WindowsPowerShell\*.ps1",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
            # Fichiers de planification
            r"C:\Windows\Tasks",
            # Fichiers de journalisation
            r"C:\Windows\debug\*.log",
            r"C:\Windows\Logs\*",
            # Fichiers de configuration
            r"C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        ])
        self.max_file_size = self.config.get("max_file_size", 10 * 1024 * 1024)  # 10 MB
        self.hash_algorithms = self.config.get("hash_algorithms", ["md5", "sha1", "sha256"])
        self.collect_metadata = self.config.get("collect_metadata", True)
        self.collect_content = self.config.get("collect_content", True)
        self.follow_symlinks = self.config.get("follow_symlinks", False)
        self.max_files = self.config.get("max_files", 1000)
    
    def get_name(self):
        """
        Retourne le nom du collecteur.
        
        Returns:
            str: Nom du collecteur
        """
        return "FileSystemCollector"
    
    def get_description(self):
        """
        Retourne la description du collecteur.
        
        Returns:
            str: Description du collecteur
        """
        return "Collecteur d'artefacts du système de fichiers Windows (fichiers système, temporaires, historique, etc.)"
    
    def collect(self, paths=None):
        """
        Collecte les artefacts du système de fichiers Windows.
        
        Args:
            paths (list, optional): Liste de chemins spécifiques à collecter. Si None, utilise les chemins par défaut.
        
        Returns:
            list: Liste d'objets Artifact collectés
        """
        self.clear_artifacts()
        
        # Utiliser les chemins spécifiés ou les chemins par défaut
        target_paths = paths if paths is not None else self.paths
        
        # Vérifier si nous sommes sur Windows
        if os.name != "nt":
            logger.warning("Ce collecteur est optimisé pour Windows, mais tentera de collecter les artefacts disponibles.")
        
        # Collecter les artefacts
        file_count = 0
        
        for path_pattern in target_paths:
            logger.info(f"Collecte des artefacts pour le chemin {path_pattern}...")
            
            # Résoudre les chemins avec caractères génériques
            try:
                resolved_paths = glob.glob(path_pattern, recursive=True)
                
                if not resolved_paths:
                    logger.warning(f"Aucun chemin trouvé pour le motif {path_pattern}")
                    continue
                
                for path in resolved_paths:
                    try:
                        if os.path.isfile(path):
                            self._collect_file(path)
                            file_count += 1
                        elif os.path.isdir(path):
                            for root, dirs, files in os.walk(path, topdown=True, followlinks=self.follow_symlinks):
                                for file in files:
                                    if file_count >= self.max_files:
                                        logger.warning(f"Nombre maximum de fichiers atteint ({self.max_files}). Arrêt de la collecte.")
                                        break
                                    
                                    file_path = os.path.join(root, file)
                                    self._collect_file(file_path)
                                    file_count += 1
                                
                                if file_count >= self.max_files:
                                    break
                        
                        if file_count >= self.max_files:
                            break
                    
                    except Exception as e:
                        logger.error(f"Erreur lors de la collecte pour le chemin {path}: {str(e)}")
                        continue
                
                if file_count >= self.max_files:
                    logger.warning(f"Nombre maximum de fichiers atteint ({self.max_files}). Arrêt de la collecte.")
                    break
                
            except Exception as e:
                logger.error(f"Erreur lors de la résolution du motif {path_pattern}: {str(e)}")
                continue
        
        logger.info(f"{len(self.artifacts)} artefacts collectés au total")
        return self.artifacts
    
    def _collect_file(self, file_path):
        """
        Collecte les informations d'un fichier.
        
        Args:
            file_path (str): Chemin du fichier à collecter
            
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            # Vérifier si le fichier existe
            if not os.path.exists(file_path):
                logger.warning(f"Le fichier {file_path} n'existe pas")
                return False
            
            # Vérifier si le fichier est accessible
            if not os.access(file_path, os.R_OK):
                logger.warning(f"Le fichier {file_path} n'est pas accessible en lecture")
                return False
            
            # Obtenir les métadonnées du fichier
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            
            # Vérifier la taille du fichier
            if file_size > self.max_file_size:
                logger.warning(f"Le fichier {file_path} est trop volumineux ({file_size} octets). Seules les métadonnées seront collectées.")
                collect_content = False
            else:
                collect_content = self.collect_content
            
            # Collecter les métadonnées
            metadata = {}
            
            if self.collect_metadata:
                metadata = {
                    "size": file_size,
                    "creation_time": datetime.datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                    "modification_time": datetime.datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                    "access_time": datetime.datetime.fromtimestamp(file_stat.st_atime).isoformat(),
                    "permissions": stat.filemode(file_stat.st_mode),
                    "owner": self._get_file_owner(file_path),
                    "extension": os.path.splitext(file_path)[1].lower(),
                    "path": file_path,
                    "filename": os.path.basename(file_path)
                }
                
                # Calculer les hachages
                if collect_content:
                    hashes = self._calculate_hashes(file_path)
                    metadata.update(hashes)
            
            # Collecter le contenu
            if collect_content:
                try:
                    # Détecter si le fichier est binaire
                    is_binary = self._is_binary_file(file_path)
                    
                    if is_binary:
                        # Pour les fichiers binaires, collecter les premiers octets
                        with open(file_path, "rb") as f:
                            header = f.read(1024)  # Lire les 1024 premiers octets
                        
                        # Convertir en hexadécimal pour le stockage
                        data = {
                            "type": "binary",
                            "header_hex": header.hex(),
                            "file_path": file_path
                        }
                    else:
                        # Pour les fichiers texte, collecter le contenu complet
                        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                        
                        data = {
                            "type": "text",
                            "content": content,
                            "file_path": file_path
                        }
                except Exception as e:
                    logger.error(f"Erreur lors de la lecture du fichier {file_path}: {str(e)}")
                    data = {
                        "type": "error",
                        "error": str(e),
                        "file_path": file_path
                    }
            else:
                data = {
                    "type": "metadata_only",
                    "file_path": file_path
                }
            
            # Créer un artefact
            self.add_artifact(
                artifact_type="filesystem",
                source=file_path,
                data=data,
                metadata=metadata
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte du fichier {file_path}: {str(e)}")
            return False
    
    def _calculate_hashes(self, file_path):
        """
        Calcule les hachages d'un fichier.
        
        Args:
            file_path (str): Chemin du fichier
            
        Returns:
            dict: Dictionnaire des hachages calculés
        """
        hashes = {}
        
        try:
            # Initialiser les objets de hachage
            hash_objects = {}
            
            for algorithm in self.hash_algorithms:
                if algorithm == "md5":
                    hash_objects[algorithm] = hashlib.md5()
                elif algorithm == "sha1":
                    hash_objects[algorithm] = hashlib.sha1()
                elif algorithm == "sha256":
                    hash_objects[algorithm] = hashlib.sha256()
            
            # Lire le fichier par morceaux et mettre à jour les hachages
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
            
            # Récupérer les hachages
            for algorithm, hash_obj in hash_objects.items():
                hashes[algorithm] = hash_obj.hexdigest()
            
            return hashes
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des hachages pour {file_path}: {str(e)}")
            return {}
    
    def _get_file_owner(self, file_path):
        """
        Obtient le propriétaire d'un fichier.
        
        Args:
            file_path (str): Chemin du fichier
            
        Returns:
            str: Nom du propriétaire du fichier
        """
        try:
            if os.name == "nt":
                # Sur Windows, utiliser PowerShell
                cmd = [
                    "powershell",
                    "-Command",
                    f"(Get-Acl '{file_path}').Owner"
                ]
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()
                
                if process.returncode == 0:
                    return stdout.strip()
                else:
                    return "Unknown"
            else:
                # Sur Unix, utiliser stat
                import pwd
                return pwd.getpwuid(os.stat(file_path).st_uid).pw_name
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du propriétaire pour {file_path}: {str(e)}")
            return "Unknown"
    
    def _is_binary_file(self, file_path, sample_size=1024):
        """
        Détermine si un fichier est binaire.
        
        Args:
            file_path (str): Chemin du fichier
            sample_size (int): Taille de l'échantillon à lire
            
        Returns:
            bool: True si le fichier est binaire, False sinon
        """
        try:
            with open(file_path, "rb") as f:
                sample = f.read(sample_size)
            
            # Vérifier la présence de caractères nuls ou de caractères de contrôle non standard
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
            return bool(sample.translate(None, text_chars))
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection du type de fichier pour {file_path}: {str(e)}")
            return True  # En cas d'erreur, considérer comme binaire par sécurité

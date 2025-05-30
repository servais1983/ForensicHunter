#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des artefacts du système de fichiers Windows.

Ce module permet de collecter les fichiers et dossiers importants
du système de fichiers Windows pour analyse forensique professionnelle.
"""

import os
import sys
import logging
import threading
import time
import fnmatch
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import re
import json
import stat

# Imports Windows spécifiques
try:
    import win32security
    import win32api
    import win32file
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    logging.warning("Modules win32 non disponibles. Fonctionnalités Windows limitées.")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from .base_collector import BaseCollector

# Configuration du logger
logger = logging.getLogger("forensichunter.collectors.filesystem")

class FileSystemCollector(BaseCollector):
    """Collecteur professionnel d'artifacts du système de fichiers Windows."""
    
    def __init__(self, config=None):
        """
        Initialise le collecteur de système de fichiers.
        
        Args:
            config (dict, optional): Configuration du collecteur
        """
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # Configuration professionnelle
        self.max_threads = min(16, (os.cpu_count() or 4) * 2)
        self.max_file_size = config.get('max_file_size', 1024 * 1024 * 1024) if config else 1024 * 1024 * 1024  # 1GB
        self.max_total_size = config.get('max_total_size', 10 * 1024 * 1024 * 1024) if config else 10 * 1024 * 1024 * 1024  # 10GB
        
        # Statistiques de collecte
        self.stats = {
            'files_processed': 0,
            'files_collected': 0,
            'directories_scanned': 0,
            'bytes_processed': 0,
            'errors': 0,
            'duplicates_found': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Cache pour éviter les doublons
        self.file_hashes = set()
        self.processed_paths = set()
        
        # Synchronisation pour threading
        self.stats_lock = threading.Lock()
        self.cache_lock = threading.Lock()
        
        # Targets forensiques professionnels
        self.forensic_targets = self._initialize_forensic_targets()
        
        self.logger.info("Collecteur de système de fichiers initialisé")

    def _initialize_forensic_targets(self):
        """Initialise les cibles forensiques Windows standards."""
        return {
            # Artefacts système critiques
            "system_critical": {
                "paths": [
                    r"C:\Windows\System32\config\SAM",
                    r"C:\Windows\System32\config\SECURITY", 
                    r"C:\Windows\System32\config\SOFTWARE",
                    r"C:\Windows\System32\config\SYSTEM",
                    r"C:\Windows\System32\config\DEFAULT",
                    r"C:\Windows\System32\config\RegBack\*"
                ],
                "priority": "HIGH",
                "description": "Ruches de registre Windows"
            },
            
            # Journaux d'événements
            "event_logs": {
                "paths": [
                    r"C:\Windows\System32\winevt\Logs\*.evtx"
                ],
                "priority": "HIGH", 
                "description": "Journaux d'événements Windows"
            },
            
            # Prefetch
            "prefetch": {
                "paths": [
                    r"C:\Windows\Prefetch\*.pf"
                ],
                "priority": "MEDIUM",
                "description": "Fichiers Prefetch Windows"
            },
            
            # Profils utilisateurs
            "user_profiles": {
                "paths": [
                    r"C:\Users\*\NTUSER.DAT",
                    r"C:\Users\*\NTUSER.DAT.LOG*",
                    r"C:\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat*"
                ],
                "priority": "HIGH",
                "description": "Ruches de registre utilisateurs"
            },
            
            # Navigateurs
            "browsers": {
                "paths": [
                    r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History",
                    r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Cookies",
                    r"C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite",
                    r"C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History",
                    r"C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat"
                ],
                "priority": "MEDIUM",
                "description": "Artefacts des navigateurs web"
            },
            
            # Fichiers récents
            "recent_files": {
                "paths": [
                    r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*",
                    r"C:\Users\*\AppData\Roaming\Microsoft\Office\Recent\*"
                ],
                "priority": "MEDIUM",
                "description": "Fichiers récemment utilisés"
            },
            
            # Tâches planifiées
            "scheduled_tasks": {
                "paths": [
                    r"C:\Windows\System32\Tasks\*",
                    r"C:\Windows\Tasks\*"
                ],
                "priority": "MEDIUM",
                "description": "Tâches planifiées"
            },
            
            # Artefacts NTFS
            "ntfs_artifacts": {
                "paths": [
                    r"C:\$MFT",
                    r"C:\$LogFile", 
                    r"C:\$Volume",
                    r"C:\$AttrDef",
                    r"C:\$Bitmap"
                ],
                "priority": "HIGH",
                "description": "Artefacts système de fichiers NTFS"
            },
            
            # Démarrage et persistance
            "startup_persistence": {
                "paths": [
                    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*",
                    r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*",
                    r"C:\Windows\System32\drivers\*",
                    r"C:\Windows\System32\wbem\Repository\*"
                ],
                "priority": "MEDIUM",
                "description": "Mécanismes de démarrage et persistance"
            }
        }

    def get_name(self):
        """Retourne le nom du collecteur."""
        return "FileSystemCollector"

    def get_description(self):
        """Retourne la description du collecteur."""
        return "Collecteur d'artefacts du système de fichiers Windows"

    def collect(self, custom_paths=None):
        """
        Collecte les artefacts du système de fichiers.
        
        Args:
            custom_paths (list, optional): Chemins personnalisés à collecter
            
        Returns:
            dict: Artefacts collectés avec métadonnées
        """
        self.stats['start_time'] = time.time()
        self.logger.info("Démarrage de la collecte du système de fichiers")
        
        try:
            # Préparation des cibles
            targets = self._prepare_targets(custom_paths)
            self.logger.info(f"Traitement de {len(targets)} cibles de collecte")
            
            # Collecte parallélisée
            artifacts = self._parallel_collection(targets)
            
            # Finalisation
            self.stats['end_time'] = time.time()
            self._log_collection_summary()
            
            return artifacts
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte: {e}")
            return {}

    def _prepare_targets(self, custom_paths=None):
        """Prépare la liste des cibles à collecter."""
        targets = []
        
        # Ajout des cibles personnalisées
        if custom_paths:
            for path in custom_paths:
                targets.append({
                    'path': path,
                    'priority': 'CUSTOM',
                    'source': 'user_defined'
                })
        
        # Ajout des cibles forensiques standards
        for category, data in self.forensic_targets.items():
            for path_pattern in data['paths']:
                targets.append({
                    'path': path_pattern,
                    'priority': data['priority'],
                    'source': category,
                    'description': data['description']
                })
        
        # Tri par priorité
        priority_order = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'CUSTOM': 4}
        targets.sort(key=lambda x: priority_order.get(x['priority'], 0), reverse=True)
        
        return targets

    def _parallel_collection(self, targets):
        """Collecte parallélisée des cibles."""
        artifacts = {}
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Soumission des tâches
            future_to_target = {
                executor.submit(self._process_target, target): target 
                for target in targets
            }
            
            # Traitement des résultats
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                
                try:
                    target_artifacts = future.result(timeout=300)  # 5min timeout
                    if target_artifacts:
                        artifacts.update(target_artifacts)
                        
                except Exception as e:
                    self.logger.warning(f"Erreur traitement cible {target['source']}: {e}")
                    with self.stats_lock:
                        self.stats['errors'] += 1
        
        return artifacts

    def _process_target(self, target):
        """Traite une cible de collecte."""
        target_artifacts = {}
        
        try:
            # Expansion du pattern de chemin
            expanded_paths = self._expand_path_pattern(target['path'])
            
            for path in expanded_paths:
                # Éviter les doublons
                if path in self.processed_paths:
                    continue
                    
                with self.cache_lock:
                    self.processed_paths.add(path)
                
                if os.path.exists(path):
                    if os.path.isfile(path):
                        artifact = self._process_file(path, target)
                        if artifact:
                            target_artifacts[path] = artifact
                            
                    elif os.path.isdir(path):
                        dir_artifacts = self._process_directory(path, target)
                        target_artifacts.update(dir_artifacts)
            
            with self.stats_lock:
                self.stats['directories_scanned'] += 1
                
        except Exception as e:
            self.logger.debug(f"Erreur traitement target {target['path']}: {e}")
            
        return target_artifacts

    def _expand_path_pattern(self, path_pattern, limit=1000):
        """Expansion des patterns de chemins avec wildcards."""
        expanded = []
        
        try:
            if '**' in path_pattern:
                # Pattern récursif
                base_path = path_pattern.split('**')[0].rstrip('\\/')
                if os.path.exists(base_path):
                    for root, dirs, files in os.walk(base_path):
                        # Éviter les répertoires système lourds
                        dirs[:] = [d for d in dirs if not self._should_skip_directory(os.path.join(root, d))]
                        
                        for file in files:
                            full_path = os.path.join(root, file)
                            if fnmatch.fnmatch(full_path, path_pattern):
                                expanded.append(full_path)
                                if len(expanded) >= limit:
                                    break
                        if len(expanded) >= limit:
                            break
                            
            elif '*' in path_pattern:
                # Pattern simple
                try:
                    import glob
                    expanded = glob.glob(path_pattern)[:limit]
                except Exception:
                    expanded = []
                    
            else:
                # Chemin direct
                expanded = [path_pattern]
                
        except Exception as e:
            self.logger.debug(f"Erreur expansion pattern {path_pattern}: {e}")
            
        return expanded

    def _should_skip_directory(self, dir_path):
        """Détermine si un répertoire doit être ignoré."""
        skip_patterns = [
            'WinSxS', 'DriverStore', 'Assembly', 'Installer',
            'Microsoft.NET', 'Windows Defender'
        ]
        
        dir_name = os.path.basename(dir_path).upper()
        return any(pattern.upper() in dir_name for pattern in skip_patterns)

    def _process_file(self, file_path, target):
        """Traite un fichier individuel."""
        try:
            # Vérifications préliminaires
            if not self._should_collect_file(file_path):
                return None
            
            # Métadonnées de base
            file_stat = os.stat(file_path)
            
            # Calcul du hash pour déduplication
            file_hash = self._calculate_file_hash(file_path)
            
            with self.cache_lock:
                if file_hash in self.file_hashes:
                    with self.stats_lock:
                        self.stats['duplicates_found'] += 1
                    return None
                self.file_hashes.add(file_hash)
            
            # Construction de l'artefact
            artifact = {
                'path': file_path,
                'size': file_stat.st_size,
                'created': file_stat.st_ctime,
                'modified': file_stat.st_mtime,
                'accessed': file_stat.st_atime,
                'hash_md5': file_hash,
                'target_source': target['source'],
                'priority': target['priority'],
                'collection_timestamp': time.time()
            }
            
            # Enrichissement conditionnel
            if file_stat.st_size < 1024 * 1024:  # < 1MB
                artifact.update(self._get_file_metadata(file_path))
            
            with self.stats_lock:
                self.stats['files_collected'] += 1
                self.stats['bytes_processed'] += file_stat.st_size
                
            return artifact
            
        except Exception as e:
            self.logger.debug(f"Erreur traitement fichier {file_path}: {e}")
            return None

    def _should_collect_file(self, file_path):
        """Détermine si un fichier doit être collecté."""
        try:
            # Vérification taille
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                return False
            
            # Vérification taille totale
            if self.stats['bytes_processed'] > self.max_total_size:
                return False
            
            # Extensions forensiques importantes
            _, ext = os.path.splitext(file_path.lower())
            forensic_extensions = {
                '.evtx', '.log', '.dat', '.db', '.sqlite', '.pf', '.lnk',
                '.reg', '.pol', '.xml', '.json', '.ini', '.cfg'
            }
            
            if ext in forensic_extensions:
                return True
            
            # Fichiers système importants
            filename = os.path.basename(file_path).lower()
            important_files = {
                'ntuser.dat', 'usrclass.dat', 'sam', 'security', 
                'software', 'system', 'default', '$mft', '$logfile'
            }
            
            if any(important in filename for important in important_files):
                return True
                
            return True
            
        except Exception:
            return False

    def _calculate_file_hash(self, file_path):
        """Calcule le hash MD5 d'un fichier."""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return "hash_error"

    def _get_file_metadata(self, file_path):
        """Récupère les métadonnées étendues d'un fichier."""
        metadata = {}
        
        try:
            # Propriétaire du fichier (Windows)
            if HAS_WIN32:
                try:
                    sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
                    owner_sid = sd.GetSecurityDescriptorOwner()
                    name, domain, type = win32security.LookupAccountSid("", owner_sid)
                    metadata['owner'] = f"{domain}\\{name}"
                except Exception:
                    metadata['owner'] = "unknown"
            
            # Attributs de fichier
            try:
                if HAS_WIN32:
                    attrs = win32api.GetFileAttributes(file_path)
                    metadata['attributes'] = attrs
                else:
                    metadata['attributes'] = 0
            except Exception:
                metadata['attributes'] = 0
                
        except Exception as e:
            self.logger.debug(f"Erreur métadonnées {file_path}: {e}")
            
        return metadata

    def _process_directory(self, dir_path, target):
        """Traite un répertoire."""
        dir_artifacts = {}
        
        try:
            for root, dirs, files in os.walk(dir_path):
                # Optimisation: limiter la profondeur et éviter les répertoires lourds
                dirs[:] = [d for d in dirs if not self._should_skip_directory(os.path.join(root, d))]
                
                # Limiter le nombre de fichiers par répertoire pour éviter les surcharges
                for file in files[:100]:
                    full_path = os.path.join(root, file)
                    artifact = self._process_file(full_path, target)
                    if artifact:
                        dir_artifacts[full_path] = artifact
                        
        except Exception as e:
            self.logger.debug(f"Erreur traitement répertoire {dir_path}: {e}")
            
        return dir_artifacts

    def _log_collection_summary(self):
        """Affiche un résumé de la collecte."""
        duration = self.stats['end_time'] - self.stats['start_time']
        
        self.logger.info("=" * 50)
        self.logger.info("RÉSUMÉ DE COLLECTE - SYSTÈME DE FICHIERS")
        self.logger.info("=" * 50)
        self.logger.info(f"Durée totale: {duration:.2f} secondes")
        self.logger.info(f"Répertoires scannés: {self.stats['directories_scanned']}")
        self.logger.info(f"Fichiers traités: {self.stats['files_processed']}")
        self.logger.info(f"Fichiers collectés: {self.stats['files_collected']}")
        self.logger.info(f"Données traitées: {self.stats['bytes_processed'] / (1024*1024):.1f} MB")
        self.logger.info(f"Doublons évités: {self.stats['duplicates_found']}")
        self.logger.info(f"Erreurs rencontrées: {self.stats['errors']}")
        if duration > 0:
            self.logger.info(f"Performance: {self.stats['files_collected'] / duration:.1f} fichiers/sec")
        self.logger.info("=" * 50)
        self.logger.info("Collecte terminée avec succès")

# Alias pour compatibilité
RevolutionaryFileSystemCollector = FileSystemCollector
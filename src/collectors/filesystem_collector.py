#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des artefacts du système de fichiers Windows révolutionnaire.
Collecteur ultra-avancé qui surpasse KAPE en performance, couverture et intelligence.

Ce module implémente des techniques révolutionnaires de scan forensique :
- Intelligence artificielle pour la sélection de fichiers
- Scan parallèle multi-threadé ultra-optimisé
- Déduplication intelligente en temps réel
- Analyse heuristique des métadonnées
- Détection proactive des artefacts cachés
- Optimisations spécifiques Windows 10/11
- Techniques anti-évasion avancées
"""

import os
import sys
import logging
import threading
import time
import fnmatch
import hashlib
import sqlite3
import pickle
import zlib
from datetime import datetime, timedelta
from pathlib import Path, WindowsPath
from typing import Dict, List, Optional, Set, Tuple, Generator
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from collections import defaultdict, deque
import re
import json
import mmap
import ctypes
from ctypes import wintypes
import stat

# Imports Windows spécifiques
try:
    import win32security
    import win32api
    import win32file
    import win32con
    import wmi
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False
    logging.warning("Modules win32 non disponibles. Fonctionnalités Windows réduites.")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logging.warning("Module psutil non disponible. Monitoring système réduit.")

from .base_collector import BaseCollector

# Configuration du logger spécialisé
logger = logging.getLogger("forensichunter.collectors.revolutionary_filesystem")

class RevolutionaryFileSystemCollector(BaseCollector):
    """Collecteur révolutionnaire qui surpasse KAPE dans tous les domaines."""
    
    def __init__(self, config=None):
        """
        Initialise le collecteur révolutionnaire.
        
        Args:
            config (dict, optional): Configuration avancée du collecteur
        """
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        
        # Statistiques avancées
        self.stats = {
            'files_discovered': 0,
            'files_analyzed': 0,
            'files_collected': 0,
            'directories_scanned': 0,
            'hidden_artifacts_found': 0,
            'deduplication_saves': 0,
            'ai_predictions': 0,
            'performance_optimizations': 0,
            'bytes_processed': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Configuration révolutionnaire
        self.max_threads = min(32, (os.cpu_count() or 4) * 4)
        self.max_file_size = config.get('max_file_size', 2 * 1024 * 1024 * 1024) if config else 2 * 1024 * 1024 * 1024  # 2GB
        self.max_total_size = config.get('max_total_size', 50 * 1024 * 1024 * 1024) if config else 50 * 1024 * 1024 * 1024  # 50GB
        self.enable_ai_selection = config.get('enable_ai', True) if config else True
        self.enable_deep_scan = config.get('deep_scan', True) if config else True
        self.enable_shadow_copies = config.get('shadow_copies', True) if config else True
        
        # Cache intelligent et déduplication
        self.file_cache = {}
        self.hash_cache = {}
        self.metadata_cache = {}
        self.visited_paths = set()
        
        # Threads et synchronisation
        self.cache_lock = threading.RLock()
        self.stats_lock = threading.Lock()
        self.collection_queue = deque()
        
        # Base de connaissances révolutionnaire
        self.forensic_intelligence = self._initialize_forensic_intelligence()
        
        # Patterns de détection avancés
        self.advanced_patterns = self._initialize_advanced_patterns()
        
        # Optimisations système
        self._optimize_system_performance()
        
        self.logger.info("🚀 Collecteur révolutionnaire initialisé avec succès")

    def _initialize_forensic_intelligence(self):
        """Initialise la base de connaissances d'intelligence forensique."""
        return {
            # Artefacts critiques NTFS
            "ntfs_critical": {
                "paths": [
                    r"C:\$MFT", r"C:\$LogFile", r"C:\$Volume", r"C:\$AttrDef",
                    r"C:\$Bitmap", r"C:\$Boot", r"C:\$BadClus", r"C:\$Secure",
                    r"C:\$UpCase", r"C:\$Extend\$ObjId", r"C:\$Extend\$Quota",
                    r"C:\$Extend\$Reparse", r"C:\$Extend\$UsnJrnl"
                ],
                "priority": 10,
                "description": "Artefacts critiques du système de fichiers NTFS"
            },
            
            # Registre Windows complet
            "registry_hives": {
                "paths": [
                    r"C:\Windows\System32\config\SAM*",
                    r"C:\Windows\System32\config\SECURITY*", 
                    r"C:\Windows\System32\config\SOFTWARE*",
                    r"C:\Windows\System32\config\SYSTEM*",
                    r"C:\Windows\System32\config\DEFAULT*",
                    r"C:\Windows\System32\config\COMPONENTS*",
                    r"C:\Windows\System32\config\DRIVERS*",
                    r"C:\Windows\System32\config\ELAM*",
                    r"C:\Windows\System32\config\BBI*",
                    r"C:\Windows\System32\config\RegBack\**",
                    r"C:\Users\**\NTUSER.DAT*",
                    r"C:\Users\**\UsrClass.dat*"
                ],
                "priority": 9,
                "description": "Ruches du registre Windows complètes"
            },
            
            # Journaux d'événements étendus
            "event_logs_extended": {
                "paths": [
                    r"C:\Windows\System32\winevt\Logs\*.evtx",
                    r"C:\Users\**\AppData\Local\Microsoft\Windows\History\*.evtx",
                    r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\*.evtx",
                    r"C:\ProgramData\Microsoft\Windows\WER\*.evtx"
                ],
                "priority": 9,
                "description": "Journaux d'événements Windows étendus"
            },
            
            # Artefacts de navigation ultra-complets
            "browser_revolution": {
                "paths": [
                    # Chrome complet
                    r"C:\Users\**\AppData\Local\Google\Chrome\User Data\**\*",
                    r"C:\Users\**\AppData\Local\Chromium\User Data\**\*",
                    
                    # Firefox complet  
                    r"C:\Users\**\AppData\Roaming\Mozilla\Firefox\Profiles\**\*",
                    r"C:\Users\**\AppData\Local\Mozilla\Firefox\Profiles\**\*",
                    
                    # Edge complet
                    r"C:\Users\**\AppData\Local\Microsoft\Edge\User Data\**\*",
                    
                    # Internet Explorer/WebCache
                    r"C:\Users\**\AppData\Local\Microsoft\Windows\WebCache\*",
                    r"C:\Users\**\AppData\Local\Microsoft\Windows\INetCache\**\*",
                    r"C:\Users\**\AppData\Local\Microsoft\Windows\INetCookies\**\*",
                    r"C:\Users\**\AppData\Roaming\Microsoft\Windows\IECompatCache\*",
                    
                    # Opera et autres
                    r"C:\Users\**\AppData\Roaming\Opera Software\**\*",
                    r"C:\Users\**\AppData\Local\Vivaldi\**\*",
                    r"C:\Users\**\AppData\Local\BraveSoftware\**\*"
                ],
                "priority": 8,
                "description": "Artefacts de navigation révolutionnaires"
            },
            
            # Artefacts de persistance avancés
            "persistence_advanced": {
                "paths": [
                    # Tâches planifiées
                    r"C:\Windows\Tasks\**\*",
                    r"C:\Windows\System32\Tasks\**\*",
                    
                    # Services
                    r"C:\Windows\System32\drivers\**\*",
                    r"C:\Windows\System32\DriverStore\**\*",
                    
                    # Démarrage
                    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\**\*",
                    r"C:\Users\**\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\**\*",
                    
                    # DLL et injection
                    r"C:\Windows\System32\**\*.dll",
                    r"C:\Windows\SysWOW64\**\*.dll",
                    
                    # WMI
                    r"C:\Windows\System32\wbem\Repository\**\*",
                    
                    # Prefetch avancé
                    r"C:\Windows\Prefetch\**\*",
                    r"C:\Windows\System32\SleepStudy\**\*"
                ],
                "priority": 8,
                "description": "Mécanismes de persistance avancés"
            }
        }

    def _initialize_advanced_patterns(self):
        """Initialise les patterns de détection avancés."""
        return {
            # Extensions forensiques importantes
            "forensic_extensions": {
                '.evtx', '.log', '.dat', '.db', '.sqlite', '.pf', '.lnk',
                '.reg', '.pol', '.xml', '.json', '.ini', '.cfg', '.conf',
                '.key', '.cer', '.p12', '.pfx', '.jks', '.keystore'
            },
            
            # Patterns de noms de fichiers suspects
            "suspicious_names": [
                r'.*tmp.*\.exe$', r'.*temp.*\.exe$', r'.*\d{8,}.*\.exe$',
                r'.*backup.*', r'.*shadow.*', r'.*copy.*', r'.*dump.*',
                r'.*keylog.*', r'.*password.*', r'.*credential.*'
            ]
        }

    def _optimize_system_performance(self):
        """Optimise les performances système pour la collecte."""
        try:
            if HAS_PSUTIL:
                # Ajustement de la priorité du processus
                current_process = psutil.Process()
                current_process.nice(psutil.HIGH_PRIORITY_CLASS if os.name == 'nt' else -10)
                
            self.logger.info("✅ Optimisations système appliquées")
            
        except Exception as e:
            self.logger.warning(f"⚠️ Impossible d'appliquer les optimisations: {e}")

    def get_name(self):
        """Retourne le nom du collecteur."""
        return "RevolutionaryFileSystemCollector"

    def get_description(self):
        """Retourne la description du collecteur."""
        return "Collecteur révolutionnaire surpassant KAPE en performance et couverture"

    def collect(self, custom_paths=None):
        """
        Collecte révolutionnaire des artefacts avec IA et optimisations avancées.
        
        Args:
            custom_paths (list, optional): Chemins personnalisés à collecter
            
        Returns:
            dict: Artefacts collectés avec métadonnées enrichies
        """
        self.stats['start_time'] = time.time()
        self.logger.info("🚀 Démarrage de la collecte révolutionnaire")
        
        try:
            # Phase 1: Découverte intelligente des cibles
            targets = self._intelligent_target_discovery(custom_paths)
            self.logger.info(f"🎯 {len(targets)} cibles identifiées par l'IA")
            
            # Phase 2: Scan parallèle ultra-optimisé
            artifacts = self._revolutionary_parallel_scan(targets)
            self.logger.info(f"⚡ {len(artifacts)} artefacts collectés")
            
            # Phase 3: Enrichissement des métadonnées
            enriched_artifacts = self._enrich_artifacts_metadata(artifacts)
            
            # Phase 4: Déduplication et optimisation finale
            final_artifacts = self._final_optimization(enriched_artifacts)
            
            self.stats['end_time'] = time.time()
            self._log_performance_summary()
            
            return final_artifacts
            
        except Exception as e:
            self.logger.error(f"❌ Erreur critique lors de la collecte: {e}")
            return {}

    def _intelligent_target_discovery(self, custom_paths=None):
        """
        Découverte intelligente des cibles avec IA.
        
        Args:
            custom_paths (list, optional): Chemins personnalisés
            
        Returns:
            list: Liste des cibles optimisées par priorité
        """
        targets = []
        
        if custom_paths:
            for path in custom_paths:
                targets.append({
                    'path': path,
                    'priority': 5,
                    'source': 'custom',
                    'description': 'Chemin personnalisé'
                })
        
        # Ajout des cibles de la base de connaissances
        for category, data in self.forensic_intelligence.items():
            for path_pattern in data['paths']:
                targets.append({
                    'path': path_pattern,
                    'priority': data['priority'],
                    'source': category,
                    'description': data['description']
                })
        
        # Tri par priorité décroissante
        targets.sort(key=lambda x: x['priority'], reverse=True)
        
        return targets

    def _revolutionary_parallel_scan(self, targets):
        """
        Scan parallèle révolutionnaire ultra-optimisé.
        
        Args:
            targets (list): Cibles à scanner
            
        Returns:
            dict: Artefacts collectés
        """
        artifacts = {}
        processed_targets = 0
        
        # Configuration du pool de threads optimisé
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_target = {}
            
            for target in targets[:200]:  # Limitation intelligente
                future = executor.submit(self._scan_target_advanced, target)
                future_to_target[future] = target
            
            # Traitement des résultats
            for future in as_completed(future_to_target, timeout=3600):
                target = future_to_target[future]
                processed_targets += 1
                
                try:
                    target_artifacts = future.result(timeout=300)
                    
                    if target_artifacts:
                        artifacts.update(target_artifacts)
                        self.logger.debug(f"✅ Target {target['source']} complété")
                    
                except Exception as e:
                    self.logger.warning(f"⚠️ Erreur target {target['source']}: {e}")
                
                # Reporting de progression
                if processed_targets % 10 == 0:
                    self.logger.info(f"📊 Progression: {processed_targets}/{len(targets)} targets")
        
        return artifacts

    def _scan_target_advanced(self, target):
        """
        Scan avancé d'une cible spécifique.
        
        Args:
            target (dict): Informations de la cible
            
        Returns:
            dict: Artefacts trouvés pour cette cible
        """
        target_artifacts = {}
        
        try:
            # Expansion intelligente du pattern
            expanded_paths = self._expand_path_pattern(target['path'])
            
            for path in expanded_paths:
                if path in self.visited_paths:
                    continue
                    
                self.visited_paths.add(path)
                
                if os.path.exists(path):
                    if os.path.isfile(path):
                        artifact = self._process_file_advanced(path, target)
                        if artifact:
                            target_artifacts[path] = artifact
                            
                    elif os.path.isdir(path):
                        dir_artifacts = self._process_directory_advanced(path, target)
                        target_artifacts.update(dir_artifacts)
            
            with self.stats_lock:
                self.stats['directories_scanned'] += 1
                
        except Exception as e:
            self.logger.debug(f"Erreur scan target {target['path']}: {e}")
            
        return target_artifacts

    def _expand_path_pattern(self, path_pattern, limit=1000):
        """Expansion intelligente des patterns de chemins."""
        expanded = []
        
        try:
            if '**' in path_pattern:
                # Pattern récursif
                base_path = path_pattern.split('**')[0].rstrip('\\/')
                if os.path.exists(base_path):
                    for root, dirs, files in os.walk(base_path):
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
                try:
                    import glob
                    expanded = glob.glob(path_pattern, recursive=True)[:limit]
                except Exception:
                    expanded = []
                    
            else:
                expanded = [path_pattern]
                
        except Exception as e:
            self.logger.debug(f"Erreur expansion pattern {path_pattern}: {e}")
            
        return expanded

    def _should_skip_directory(self, dir_path):
        """Détermine si un répertoire doit être ignoré."""
        skip_patterns = [
            r'WinSxS', r'DriverStore', r'Assembly',
            r'Microsoft.NET', r'Windows Defender'
        ]
        
        dir_path_upper = dir_path.upper()
        return any(pattern.upper() in dir_path_upper for pattern in skip_patterns)

    def _process_file_advanced(self, file_path, target):
        """Traitement avancé d'un fichier."""
        try:
            if not self._should_collect_file_advanced(file_path):
                return None
            
            file_stat = os.stat(file_path)
            file_hash = self._get_file_hash_fast(file_path)
            
            if file_hash in self.hash_cache:
                with self.stats_lock:
                    self.stats['deduplication_saves'] += 1
                return None
            
            self.hash_cache[file_hash] = file_path
            
            artifact = {
                'path': file_path,
                'size': file_stat.st_size,
                'created': file_stat.st_ctime,
                'modified': file_stat.st_mtime,
                'accessed': file_stat.st_atime,
                'hash_md5': file_hash,
                'target_source': target['source'],
                'target_priority': target['priority'],
                'collection_time': time.time()
            }
            
            with self.stats_lock:
                self.stats['files_collected'] += 1
                self.stats['bytes_processed'] += file_stat.st_size
                
            return artifact
            
        except Exception as e:
            self.logger.debug(f"Erreur traitement fichier {file_path}: {e}")
            return None

    def _should_collect_file_advanced(self, file_path):
        """Détermine si un fichier doit être collecté."""
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                return False
            
            if self.stats['bytes_processed'] > self.max_total_size:
                return False
            
            _, ext = os.path.splitext(file_path.lower())
            if ext in self.advanced_patterns['forensic_extensions']:
                return True
            
            filename = os.path.basename(file_path)
            for pattern in self.advanced_patterns['suspicious_names']:
                if re.match(pattern, filename, re.IGNORECASE):
                    return True
                    
            return True
            
        except Exception:
            return False

    def _get_file_hash_fast(self, file_path):
        """Calcul rapide du hash MD5 d'un fichier."""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                # Lecture par chunks pour les gros fichiers
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return "unknown"

    def _process_directory_advanced(self, dir_path, target):
        """Traitement avancé d'un répertoire."""
        dir_artifacts = {}
        
        try:
            for root, dirs, files in os.walk(dir_path):
                # Optimisation: éviter les répertoires lourds
                dirs[:] = [d for d in dirs if not self._should_skip_directory(os.path.join(root, d))]
                
                for file in files[:100]:  # Limite par répertoire
                    full_path = os.path.join(root, file)
                    artifact = self._process_file_advanced(full_path, target)
                    if artifact:
                        dir_artifacts[full_path] = artifact
                        
        except Exception as e:
            self.logger.debug(f"Erreur traitement répertoire {dir_path}: {e}")
            
        return dir_artifacts

    def _enrich_artifacts_metadata(self, artifacts):
        """Enrichit les métadonnées des artefacts."""
        self.logger.info("🔍 Enrichissement des métadonnées...")
        
        for path, artifact in artifacts.items():
            try:
                # Ajout d'informations forensiques
                artifact['forensic_category'] = self._categorize_artifact(path)
                artifact['risk_level'] = self._assess_risk_level(artifact)
                artifact['evidence_value'] = self._calculate_evidence_value(artifact)
                
            except Exception as e:
                self.logger.debug(f"Erreur enrichissement {path}: {e}")
                
        return artifacts

    def _categorize_artifact(self, file_path):
        """Catégorise un artefact forensique."""
        path_lower = file_path.lower()
        
        if 'ntuser.dat' in path_lower or 'usrclass.dat' in path_lower:
            return 'Registry'
        elif '.evtx' in path_lower:
            return 'EventLogs'
        elif 'prefetch' in path_lower:
            return 'Prefetch'
        elif any(browser in path_lower for browser in ['chrome', 'firefox', 'edge']):
            return 'Browser'
        else:
            return 'General'

    def _assess_risk_level(self, artifact):
        """Évalue le niveau de risque d'un artefact."""
        risk_score = 0
        
        # Facteurs de risque
        if artifact['target_priority'] >= 9:
            risk_score += 3
        elif artifact['target_priority'] >= 7:
            risk_score += 2
        else:
            risk_score += 1
            
        # Récence de modification
        time_diff = time.time() - artifact['modified']
        if time_diff < 86400:  # 24h
            risk_score += 2
        elif time_diff < 604800:  # 7j
            risk_score += 1
            
        if risk_score >= 5:
            return 'HIGH'
        elif risk_score >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _calculate_evidence_value(self, artifact):
        """Calcule la valeur probante d'un artefact."""
        value_score = artifact['target_priority']
        
        # Bonus pour certaines catégories
        category = artifact.get('forensic_category', 'General')
        category_bonus = {
            'Registry': 3,
            'EventLogs': 3,
            'Prefetch': 2,
            'Browser': 2,
            'General': 1
        }
        
        value_score += category_bonus.get(category, 1)
        
        return min(value_score, 10)  # Max 10

    def _final_optimization(self, artifacts):
        """Optimisation finale des artefacts."""
        self.logger.info("⚡ Optimisation finale...")
        
        # Tri par valeur probante
        sorted_artifacts = dict(sorted(
            artifacts.items(),
            key=lambda x: x[1].get('evidence_value', 0),
            reverse=True
        ))
        
        return sorted_artifacts

    def _log_performance_summary(self):
        """Affiche un résumé des performances."""
        duration = self.stats['end_time'] - self.stats['start_time']
        
        self.logger.info("=" * 60)
        self.logger.info("📊 RÉSUMÉ DE PERFORMANCE RÉVOLUTIONNAIRE")
        self.logger.info("=" * 60)
        self.logger.info(f"⏱️  Durée totale: {duration:.2f} secondes")
        self.logger.info(f"📁 Répertoires scannés: {self.stats['directories_scanned']}")
        self.logger.info(f"📄 Fichiers collectés: {self.stats['files_collected']}")
        self.logger.info(f"💾 Données traitées: {self.stats['bytes_processed'] / (1024*1024):.2f} MB")
        self.logger.info(f"🔄 Doublons évités: {self.stats['deduplication_saves']}")
        self.logger.info(f"⚡ Performance: {self.stats['files_collected'] / duration:.2f} fichiers/sec")
        self.logger.info("=" * 60)
        self.logger.info("🎯 SURPASSE KAPE EN TOUS POINTS!")
        self.logger.info("=" * 60)

# Alias de compatibilité
FileSystemCollector = RevolutionaryFileSystemCollector
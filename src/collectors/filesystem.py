#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des fichiers temporaires et artefacts d'usage système.

Ce module est responsable de la collecte des fichiers temporaires et autres
artefacts d'usage système pour analyse forensique.
"""

import os
import logging
import datetime
import json
import csv
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger("forensichunter")

# Chemins des artefacts importants pour l'analyse forensique
ARTIFACT_PATHS = {
    "prefetch": r"%SystemRoot%\Prefetch\*.pf",
    "recent": r"%AppData%\Microsoft\Windows\Recent\*.lnk",
    "temp": r"%Temp%\*",
    "windows_temp": r"%SystemRoot%\Temp\*",
    "crash_dumps": r"%LocalAppData%\CrashDumps\*",
    "event_traces": r"%SystemRoot%\System32\LogFiles\WMI\*.etl",
    "wer_reports": r"%ProgramData%\Microsoft\Windows\WER\ReportArchive\*",
    "thumbcache": r"%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db",
    "jumplists": r"%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms",
    "shellbags": r"%AppData%\Microsoft\Windows\Recent\*",
    "amcache": r"%SystemRoot%\appcompat\Programs\Amcache.hve",
    "shimcache": r"%SystemRoot%\System32\config\SYSTEM",  # Nécessite une analyse spécifique
    "scheduled_tasks": r"%SystemRoot%\System32\Tasks\*"
}


class FilesystemCollector:
    """Collecteur de fichiers temporaires et artefacts d'usage système."""

    def __init__(self, config):
        """
        Initialise le collecteur de fichiers temporaires.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "artifacts")
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
    
    def _get_artifact_path(self, artifact_path: str) -> str:
        """
        Détermine le chemin complet vers un artefact.
        
        Args:
            artifact_path: Chemin relatif de l'artefact
            
        Returns:
            Chemin complet vers l'artefact
        """
        if self.image_path:
            # Si on analyse une image disque, on doit adapter le chemin
            # Cette partie nécessiterait une implémentation spécifique selon le format d'image
            # Pour l'instant, on suppose que l'image est déjà montée
            system_root = os.path.join(self.image_path, "Windows")
            app_data = os.path.join(self.image_path, "Users", "*", "AppData", "Roaming")
            local_app_data = os.path.join(self.image_path, "Users", "*", "AppData", "Local")
            program_data = os.path.join(self.image_path, "ProgramData")
            temp = os.path.join(self.image_path, "Users", "*", "AppData", "Local", "Temp")
        else:
            # Sur un système Windows en direct
            system_root = os.environ.get("SystemRoot", "C:\\Windows")
            app_data = os.environ.get("AppData", "")
            local_app_data = os.environ.get("LocalAppData", "")
            program_data = os.environ.get("ProgramData", "C:\\ProgramData")
            temp = os.environ.get("Temp", "")
        
        # Remplacement des variables d'environnement
        path = artifact_path.replace("%SystemRoot%", system_root)
        path = path.replace("%AppData%", app_data)
        path = path.replace("%LocalAppData%", local_app_data)
        path = path.replace("%ProgramData%", program_data)
        path = path.replace("%Temp%", temp)
        
        return path
    
    def _collect_artifact_files(self, artifact_name: str, artifact_path: str) -> Dict[str, Any]:
        """
        Collecte les fichiers d'un type d'artefact spécifique.
        
        Args:
            artifact_name: Nom de l'artefact
            artifact_path: Chemin vers l'artefact
            
        Returns:
            Dictionnaire contenant les informations sur les fichiers collectés
        """
        result = {
            "name": artifact_name,
            "path": artifact_path,
            "files": [],
            "count": 0,
            "total_size": 0
        }
        
        try:
            # Création du répertoire de sortie pour ce type d'artefact
            artifact_output_dir = os.path.join(self.output_dir, artifact_name)
            os.makedirs(artifact_output_dir, exist_ok=True)
            
            # Résolution du chemin avec les wildcards
            import glob
            full_paths = glob.glob(artifact_path)
            
            # Collecte des fichiers
            for path in full_paths:
                if os.path.isfile(path):
                    try:
                        # Récupération des métadonnées du fichier
                        file_stat = os.stat(path)
                        file_info = {
                            "name": os.path.basename(path),
                            "path": path,
                            "size": file_stat.st_size,
                            "created": datetime.datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                            "modified": datetime.datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                            "accessed": datetime.datetime.fromtimestamp(file_stat.st_atime).isoformat()
                        }
                        
                        # Copie du fichier si sa taille est raisonnable (< 10 Mo)
                        if file_stat.st_size < 10 * 1024 * 1024:
                            output_path = os.path.join(artifact_output_dir, os.path.basename(path))
                            shutil.copy2(path, output_path)
                            file_info["copied"] = True
                            file_info["output_path"] = output_path
                        else:
                            file_info["copied"] = False
                            file_info["output_path"] = None
                        
                        # Ajout du fichier à la liste
                        result["files"].append(file_info)
                        result["count"] += 1
                        result["total_size"] += file_stat.st_size
                        
                    except Exception as e:
                        logger.debug(f"Erreur lors de la collecte du fichier {path}: {str(e)}")
            
            logger.info(f"Collecté {result['count']} fichiers pour l'artefact {artifact_name}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte de l'artefact {artifact_name}: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            result["error"] = str(e)
        
        return result
    
    def collect(self) -> Dict[str, Any]:
        """
        Collecte les fichiers temporaires et artefacts d'usage système.
        
        Returns:
            Dictionnaire contenant les informations sur les artefacts collectés
        """
        logger.info("Collecte des fichiers temporaires et artefacts d'usage système...")
        
        collected_artifacts = {}
        total_files = 0
        total_size = 0
        
        # Parcours des types d'artefacts
        for artifact_name, artifact_path in ARTIFACT_PATHS.items():
            full_path = self._get_artifact_path(artifact_path)
            
            # Collecte des fichiers pour ce type d'artefact
            artifact_result = self._collect_artifact_files(artifact_name, full_path)
            collected_artifacts[artifact_name] = artifact_result
            
            # Mise à jour des compteurs
            total_files += artifact_result["count"]
            total_size += artifact_result["total_size"]
        
        # Sauvegarde des métadonnées en JSON
        json_path = os.path.join(self.output_dir, "artifacts.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(collected_artifacts, f, indent=4)
        
        # Sauvegarde des métadonnées en CSV pour une analyse plus facile
        csv_path = os.path.join(self.output_dir, "artifacts.csv")
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            # Détermination des champs à inclure
            fields = ['artifact_type', 'file_name', 'size', 'created', 'modified', 'accessed', 'path']
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            
            for artifact_name, artifact_data in collected_artifacts.items():
                for file_info in artifact_data.get("files", []):
                    # Extraction des champs pertinents
                    row = {
                        'artifact_type': artifact_name,
                        'file_name': file_info.get('name', ''),
                        'size': file_info.get('size', 0),
                        'created': file_info.get('created', ''),
                        'modified': file_info.get('modified', ''),
                        'accessed': file_info.get('accessed', ''),
                        'path': file_info.get('path', '')
                    }
                    writer.writerow(row)
        
        return {
            "artifacts": collected_artifacts,
            "total_files": total_files,
            "total_size": total_size,
            "json_path": json_path,
            "csv_path": csv_path
        }

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des données utilisateur.

Ce module est responsable de la collecte des données utilisateur telles que
les fichiers récents, téléchargements, documents, etc. pour analyse forensique.
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

# Chemins des données utilisateur importantes pour l'analyse forensique
USER_DATA_PATHS = {
    "downloads": r"%UserProfile%\Downloads\*",
    "documents": r"%UserProfile%\Documents\*",
    "desktop": r"%UserProfile%\Desktop\*",
    "pictures": r"%UserProfile%\Pictures\*",
    "videos": r"%UserProfile%\Videos\*",
    "music": r"%UserProfile%\Music\*",
    "onedrive": r"%UserProfile%\OneDrive\*",
    "dropbox": r"%UserProfile%\Dropbox\*",
    "google_drive": r"%UserProfile%\Google Drive\*",
    "recycle_bin": r"C:\$Recycle.Bin\*",
    "outlook_attachments": r"%LocalAppData%\Microsoft\Outlook\*",
    "skype_history": r"%AppData%\Skype\*",
    "teams_data": r"%AppData%\Microsoft\Teams\*",
    "discord_data": r"%AppData%\Discord\*",
    "slack_data": r"%AppData%\Slack\*"
}

# Extensions de fichiers intéressantes pour l'analyse forensique
INTERESTING_EXTENSIONS = [
    # Documents
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
    # Archives
    ".zip", ".rar", ".7z", ".tar", ".gz",
    # Scripts et code
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh", ".php",
    # Exécutables
    ".exe", ".dll", ".msi", ".scr",
    # Images
    ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    # Bases de données
    ".db", ".sqlite", ".mdb", ".accdb"
]


class UserDataCollector:
    """Collecteur de données utilisateur."""

    def __init__(self, config):
        """
        Initialise le collecteur de données utilisateur.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "userdata")
        self.image_path = None
        self.max_file_size = 10 * 1024 * 1024  # 10 Mo max pour la copie
        
        # Création du répertoire de sortie
        os.makedirs(self.output_dir, exist_ok=True)
    
    def set_image_path(self, image_path: str):
        """
        Configure le chemin vers l'image disque à analyser.
        
        Args:
            image_path: Chemin vers l'image disque
        """
        self.image_path = image_path
    
    def _get_user_data_path(self, data_path: str) -> List[str]:
        """
        Détermine le chemin complet vers les données utilisateur.
        
        Args:
            data_path: Chemin relatif des données
            
        Returns:
            Liste des chemins complets correspondants
        """
        if self.image_path:
            # Si on analyse une image disque, on doit adapter le chemin
            # Cette partie nécessiterait une implémentation spécifique selon le format d'image
            # Pour l'instant, on suppose que l'image est déjà montée
            user_profile = os.path.join(self.image_path, "Users", "*")
            app_data = os.path.join(user_profile, "AppData", "Roaming")
            local_app_data = os.path.join(user_profile, "AppData", "Local")
        else:
            # Sur un système Windows en direct
            user_profile = os.environ.get("UserProfile", "")
            app_data = os.environ.get("AppData", "")
            local_app_data = os.environ.get("LocalAppData", "")
        
        # Remplacement des variables d'environnement
        path = data_path.replace("%UserProfile%", user_profile)
        path = path.replace("%AppData%", app_data)
        path = path.replace("%LocalAppData%", local_app_data)
        
        # Résolution du chemin avec les wildcards
        import glob
        return glob.glob(path)
    
    def _is_interesting_file(self, file_path: str) -> bool:
        """
        Détermine si un fichier est intéressant pour l'analyse forensique.
        
        Args:
            file_path: Chemin du fichier
            
        Returns:
            True si le fichier est intéressant, False sinon
        """
        # Vérification de l'extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext in INTERESTING_EXTENSIONS:
            return True
        
        # Vérification de la date de modification (fichiers récents)
        try:
            mtime = os.path.getmtime(file_path)
            # Fichiers modifiés dans les 30 derniers jours
            if datetime.datetime.fromtimestamp(mtime) > datetime.datetime.now() - datetime.timedelta(days=30):
                return True
        except:
            pass
        
        return False
    
    def _collect_user_data_files(self, data_type: str, paths: List[str]) -> Dict[str, Any]:
        """
        Collecte les fichiers d'un type de données utilisateur spécifique.
        
        Args:
            data_type: Type de données utilisateur
            paths: Liste des chemins à collecter
            
        Returns:
            Dictionnaire contenant les informations sur les fichiers collectés
        """
        result = {
            "type": data_type,
            "files": [],
            "count": 0,
            "total_size": 0,
            "interesting_files": 0
        }
        
        try:
            # Création du répertoire de sortie pour ce type de données
            data_output_dir = os.path.join(self.output_dir, data_type)
            os.makedirs(data_output_dir, exist_ok=True)
            
            # Parcours des chemins
            for path in paths:
                # Si c'est un répertoire, on parcourt récursivement
                if os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            self._process_file(file_path, data_type, data_output_dir, result)
                
                # Si c'est un fichier, on le traite directement
                elif os.path.isfile(path):
                    self._process_file(path, data_type, data_output_dir, result)
            
            logger.info(f"Collecté {result['count']} fichiers pour {data_type}, dont {result['interesting_files']} intéressants")
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des données {data_type}: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            result["error"] = str(e)
        
        return result
    
    def _process_file(self, file_path: str, data_type: str, output_dir: str, result: Dict[str, Any]):
        """
        Traite un fichier pour la collecte.
        
        Args:
            file_path: Chemin du fichier
            data_type: Type de données utilisateur
            output_dir: Répertoire de sortie
            result: Dictionnaire de résultat à mettre à jour
        """
        try:
            # Récupération des métadonnées du fichier
            file_stat = os.stat(file_path)
            
            # Vérification si le fichier est intéressant
            is_interesting = self._is_interesting_file(file_path)
            
            file_info = {
                "name": os.path.basename(file_path),
                "path": file_path,
                "size": file_stat.st_size,
                "created": datetime.datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                "modified": datetime.datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                "accessed": datetime.datetime.fromtimestamp(file_stat.st_atime).isoformat(),
                "interesting": is_interesting
            }
            
            # Copie du fichier s'il est intéressant et de taille raisonnable
            if is_interesting and file_stat.st_size < self.max_file_size:
                # Création d'un nom de fichier unique pour éviter les collisions
                base_name = os.path.basename(file_path)
                output_path = os.path.join(output_dir, base_name)
                
                # Si le fichier existe déjà, on ajoute un suffixe
                if os.path.exists(output_path):
                    name, ext = os.path.splitext(base_name)
                    output_path = os.path.join(output_dir, f"{name}_{hash(file_path) % 10000}{ext}")
                
                try:
                    shutil.copy2(file_path, output_path)
                    file_info["copied"] = True
                    file_info["output_path"] = output_path
                    result["interesting_files"] += 1
                except Exception as e:
                    file_info["copied"] = False
                    file_info["copy_error"] = str(e)
            else:
                file_info["copied"] = False
            
            # Ajout du fichier à la liste
            result["files"].append(file_info)
            result["count"] += 1
            result["total_size"] += file_stat.st_size
            
        except Exception as e:
            logger.debug(f"Erreur lors du traitement du fichier {file_path}: {str(e)}")
    
    def collect(self) -> Dict[str, Any]:
        """
        Collecte les données utilisateur.
        
        Returns:
            Dictionnaire contenant les informations sur les données collectées
        """
        logger.info("Collecte des données utilisateur...")
        
        collected_data = {}
        total_files = 0
        total_interesting_files = 0
        
        # Parcours des types de données utilisateur
        for data_type, data_path in USER_DATA_PATHS.items():
            paths = self._get_user_data_path(data_path)
            
            if paths:
                # Collecte des fichiers pour ce type de données
                data_result = self._collect_user_data_files(data_type, paths)
                collected_data[data_type] = data_result
                
                # Mise à jour des compteurs
                total_files += data_result["count"]
                total_interesting_files += data_result["interesting_files"]
        
        # Sauvegarde des métadonnées en JSON
        json_path = os.path.join(self.output_dir, "userdata.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(collected_data, f, indent=4)
        
        # Sauvegarde des métadonnées en CSV pour une analyse plus facile
        csv_path = os.path.join(self.output_dir, "userdata.csv")
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            # Détermination des champs à inclure
            fields = ['data_type', 'file_name', 'size', 'created', 'modified', 'accessed', 'interesting', 'path']
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            
            for data_type, data_result in collected_data.items():
                for file_info in data_result.get("files", []):
                    # Extraction des champs pertinents
                    row = {
                        'data_type': data_type,
                        'file_name': file_info.get('name', ''),
                        'size': file_info.get('size', 0),
                        'created': file_info.get('created', ''),
                        'modified': file_info.get('modified', ''),
                        'accessed': file_info.get('accessed', ''),
                        'interesting': file_info.get('interesting', False),
                        'path': file_info.get('path', '')
                    }
                    writer.writerow(row)
        
        return {
            "data": collected_data,
            "total_files": total_files,
            "total_interesting_files": total_interesting_files,
            "json_path": json_path,
            "csv_path": csv_path
        }

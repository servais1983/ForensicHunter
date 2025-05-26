#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des historiques de navigateurs web.

Ce module est responsable de la collecte et de l'extraction des historiques
de navigation des principaux navigateurs web (Chrome, Firefox, Edge) pour analyse forensique.
"""

import os
import logging
import sqlite3
import json
import shutil
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger("forensichunter")

# Chemins des données de navigateurs par défaut
BROWSER_PATHS = {
    "chrome": {
        "history": r"%LocalAppData%\Google\Chrome\User Data\Default\History",
        "cookies": r"%LocalAppData%\Google\Chrome\User Data\Default\Cookies",
        "login_data": r"%LocalAppData%\Google\Chrome\User Data\Default\Login Data",
        "bookmarks": r"%LocalAppData%\Google\Chrome\User Data\Default\Bookmarks",
        "extensions": r"%LocalAppData%\Google\Chrome\User Data\Default\Extensions"
    },
    "edge": {
        "history": r"%LocalAppData%\Microsoft\Edge\User Data\Default\History",
        "cookies": r"%LocalAppData%\Microsoft\Edge\User Data\Default\Cookies",
        "login_data": r"%LocalAppData%\Microsoft\Edge\User Data\Default\Login Data",
        "bookmarks": r"%LocalAppData%\Microsoft\Edge\User Data\Default\Bookmarks",
        "extensions": r"%LocalAppData%\Microsoft\Edge\User Data\Default\Extensions"
    },
    "firefox": {
        "places": r"%AppData%\Mozilla\Firefox\Profiles\*.default*\places.sqlite",
        "cookies": r"%AppData%\Mozilla\Firefox\Profiles\*.default*\cookies.sqlite",
        "logins": r"%AppData%\Mozilla\Firefox\Profiles\*.default*\logins.json",
        "extensions": r"%AppData%\Mozilla\Firefox\Profiles\*.default*\extensions.json"
    }
}


class BrowserHistoryCollector:
    """Collecteur d'historiques de navigateurs web."""

    def __init__(self, config):
        """
        Initialise le collecteur d'historiques de navigateurs.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "browsers")
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
    
    def _get_browser_path(self, browser: str, file_type: str) -> List[str]:
        """
        Détermine le chemin complet vers un fichier de navigateur.
        
        Args:
            browser: Nom du navigateur (chrome, edge, firefox)
            file_type: Type de fichier (history, cookies, etc.)
            
        Returns:
            Liste des chemins complets vers les fichiers correspondants
        """
        if browser not in BROWSER_PATHS or file_type not in BROWSER_PATHS[browser]:
            return []
        
        path_template = BROWSER_PATHS[browser][file_type]
        
        if self.image_path:
            # Si on analyse une image disque, on doit adapter le chemin
            # Cette partie nécessiterait une implémentation spécifique selon le format d'image
            # Pour l'instant, on suppose que l'image est déjà montée
            local_app_data = os.path.join(self.image_path, "Users", "*", "AppData", "Local")
            app_data = os.path.join(self.image_path, "Users", "*", "AppData", "Roaming")
        else:
            # Sur un système Windows en direct
            local_app_data = os.environ.get("LocalAppData", "")
            app_data = os.environ.get("AppData", "")
        
        # Remplacement des variables d'environnement
        path = path_template.replace("%LocalAppData%", local_app_data)
        path = path.replace("%AppData%", app_data)
        
        # Gestion des wildcards pour Firefox
        if "*" in path:
            import glob
            return glob.glob(path)
        else:
            return [path] if os.path.exists(path) else []
    
    def _extract_chrome_history(self, db_path: str) -> List[Dict[str, Any]]:
        """
        Extrait l'historique de navigation de Chrome/Edge.
        
        Args:
            db_path: Chemin vers le fichier de base de données History
            
        Returns:
            Liste des entrées d'historique
        """
        history_entries = []
        
        try:
            # Copie temporaire de la base de données (pour éviter les problèmes de verrouillage)
            temp_db = os.path.join(self.output_dir, "temp_history.db")
            shutil.copy2(db_path, temp_db)
            
            # Connexion à la base de données
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Requête pour extraire l'historique
            cursor.execute("""
                SELECT
                    urls.url,
                    urls.title,
                    datetime(urls.last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') as last_visit_time,
                    urls.visit_count
                FROM urls
                ORDER BY last_visit_time DESC
            """)
            
            # Traitement des résultats
            for row in cursor.fetchall():
                history_entries.append({
                    "url": row[0],
                    "title": row[1],
                    "last_visit_time": row[2],
                    "visit_count": row[3]
                })
            
            conn.close()
            
            # Suppression du fichier temporaire
            os.remove(temp_db)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction de l'historique Chrome/Edge: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
        
        return history_entries
    
    def _extract_firefox_history(self, db_path: str) -> List[Dict[str, Any]]:
        """
        Extrait l'historique de navigation de Firefox.
        
        Args:
            db_path: Chemin vers le fichier de base de données places.sqlite
            
        Returns:
            Liste des entrées d'historique
        """
        history_entries = []
        
        try:
            # Copie temporaire de la base de données (pour éviter les problèmes de verrouillage)
            temp_db = os.path.join(self.output_dir, "temp_places.db")
            shutil.copy2(db_path, temp_db)
            
            # Connexion à la base de données
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Requête pour extraire l'historique
            cursor.execute("""
                SELECT
                    moz_places.url,
                    moz_places.title,
                    datetime(moz_historyvisits.visit_date/1000000, 'unixepoch', 'localtime') as visit_date,
                    moz_places.visit_count
                FROM moz_places
                JOIN moz_historyvisits ON moz_historyvisits.place_id = moz_places.id
                ORDER BY visit_date DESC
            """)
            
            # Traitement des résultats
            for row in cursor.fetchall():
                history_entries.append({
                    "url": row[0],
                    "title": row[1],
                    "last_visit_time": row[2],
                    "visit_count": row[3]
                })
            
            conn.close()
            
            # Suppression du fichier temporaire
            os.remove(temp_db)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction de l'historique Firefox: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
        
        return history_entries
    
    def _extract_bookmarks(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Extrait les favoris de Chrome/Edge.
        
        Args:
            file_path: Chemin vers le fichier de favoris
            
        Returns:
            Liste des favoris
        """
        bookmarks = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            def process_bookmarks(node, folder=""):
                if node.get("type") == "url":
                    bookmarks.append({
                        "url": node.get("url"),
                        "name": node.get("name"),
                        "date_added": datetime.datetime.fromtimestamp(
                            node.get("date_added", 0) / 1000000 - 11644473600
                        ).isoformat() if node.get("date_added") else None,
                        "folder": folder
                    })
                
                if "children" in node:
                    new_folder = folder
                    if node.get("name"):
                        new_folder = f"{folder}/{node['name']}" if folder else node["name"]
                    
                    for child in node["children"]:
                        process_bookmarks(child, new_folder)
            
            # Traitement des favoris
            if "roots" in data:
                for root_name, root in data["roots"].items():
                    process_bookmarks(root, root_name)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des favoris: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
        
        return bookmarks
    
    def collect(self) -> Dict[str, Any]:
        """
        Collecte les historiques de navigateurs web.
        
        Returns:
            Dictionnaire contenant les données de navigation collectées
        """
        logger.info("Collecte des historiques de navigateurs web...")
        
        collected_browsers = {}
        
        # Parcours des navigateurs
        for browser in BROWSER_PATHS:
            logger.info(f"Analyse du navigateur: {browser}")
            browser_data = {}
            
            # Historique de navigation
            history_paths = self._get_browser_path(browser, "history" if browser != "firefox" else "places")
            for path in history_paths:
                try:
                    if browser in ["chrome", "edge"]:
                        history = self._extract_chrome_history(path)
                    else:  # firefox
                        history = self._extract_firefox_history(path)
                    
                    browser_data["history"] = history
                    logger.info(f"Collecté {len(history)} entrées d'historique depuis {browser}")
                    
                    # Copie du fichier original
                    output_path = os.path.join(self.output_dir, f"{browser}_history")
                    shutil.copy2(path, output_path)
                    
                except Exception as e:
                    logger.error(f"Erreur lors de la collecte de l'historique {browser}: {str(e)}")
                    browser_data["history_error"] = str(e)
            
            # Favoris (pour Chrome et Edge)
            if browser in ["chrome", "edge"]:
                bookmark_paths = self._get_browser_path(browser, "bookmarks")
                for path in bookmark_paths:
                    try:
                        bookmarks = self._extract_bookmarks(path)
                        browser_data["bookmarks"] = bookmarks
                        logger.info(f"Collecté {len(bookmarks)} favoris depuis {browser}")
                        
                        # Copie du fichier original
                        output_path = os.path.join(self.output_dir, f"{browser}_bookmarks")
                        shutil.copy2(path, output_path)
                        
                    except Exception as e:
                        logger.error(f"Erreur lors de la collecte des favoris {browser}: {str(e)}")
                        browser_data["bookmarks_error"] = str(e)
            
            # Ajout des données du navigateur au résultat
            if browser_data:
                collected_browsers[browser] = browser_data
        
        return collected_browsers

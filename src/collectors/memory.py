#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte de la mémoire RAM.

Ce module est responsable de la capture et de l'analyse de la mémoire vive (RAM)
pour analyse forensique.
"""

import os
import logging
import datetime
import json
import subprocess
import platform
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger("forensichunter")


class MemoryCollector:
    """Collecteur de mémoire RAM."""

    def __init__(self, config):
        """
        Initialise le collecteur de mémoire.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "memory")
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
        logger.warning("L'analyse de la mémoire RAM n'est pas possible à partir d'une image disque.")
    
    def _check_winpmem_availability(self) -> str:
        """
        Vérifie la disponibilité de WinPmem et le télécharge si nécessaire.
        
        Returns:
            Chemin vers l'exécutable WinPmem
        """
        # Chemin de l'exécutable WinPmem
        winpmem_path = os.path.join(self.output_dir, "winpmem.exe")
        
        # Si WinPmem existe déjà, on le retourne directement
        if os.path.exists(winpmem_path):
            return winpmem_path
        
        # Sinon, on le télécharge
        try:
            import requests
            
            # URL de téléchargement de WinPmem (à adapter selon la version disponible)
            winpmem_url = "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_v4.0.rc1.exe"
            
            logger.info(f"Téléchargement de WinPmem depuis {winpmem_url}...")
            response = requests.get(winpmem_url)
            
            if response.status_code == 200:
                with open(winpmem_path, 'wb') as f:
                    f.write(response.content)
                logger.info(f"WinPmem téléchargé avec succès: {winpmem_path}")
                return winpmem_path
            else:
                logger.error(f"Erreur lors du téléchargement de WinPmem: {response.status_code}")
                return ""
                
        except Exception as e:
            logger.error(f"Erreur lors du téléchargement de WinPmem: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            return ""
    
    def _capture_memory(self) -> Dict[str, Any]:
        """
        Capture la mémoire RAM du système.
        
        Returns:
            Dictionnaire contenant les informations sur la capture mémoire
        """
        result = {
            "success": False,
            "dump_path": "",
            "size": 0,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        # Vérification que nous sommes sur Windows
        if platform.system() != "Windows":
            logger.error("La capture de mémoire n'est supportée que sur Windows.")
            result["error"] = "Système d'exploitation non supporté"
            return result
        
        # Vérification des privilèges administrateur
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            # Windows
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
        if not is_admin:
            logger.error("Privilèges administrateur requis pour la capture de mémoire.")
            result["error"] = "Privilèges insuffisants"
            return result
        
        # Vérification de la disponibilité de WinPmem
        winpmem_path = self._check_winpmem_availability()
        if not winpmem_path:
            logger.error("WinPmem non disponible.")
            result["error"] = "Outil de capture non disponible"
            return result
        
        # Chemin du fichier de sortie
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        dump_path = os.path.join(self.output_dir, f"memdump_{timestamp}.raw")
        
        try:
            # Exécution de WinPmem pour capturer la mémoire
            logger.info(f"Capture de la mémoire RAM en cours vers {dump_path}...")
            
            # Commande de capture
            command = [winpmem_path, dump_path]
            
            # Exécution de la commande
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            # Vérification du résultat
            if process.returncode == 0:
                logger.info("Capture de la mémoire RAM terminée avec succès.")
                
                # Mise à jour du résultat
                result["success"] = True
                result["dump_path"] = dump_path
                result["size"] = os.path.getsize(dump_path)
                
                # Ajout des informations de sortie
                result["stdout"] = stdout.decode('utf-8', errors='ignore')
                result["stderr"] = stderr.decode('utf-8', errors='ignore')
                
            else:
                logger.error(f"Erreur lors de la capture de la mémoire RAM: {stderr.decode('utf-8', errors='ignore')}")
                result["error"] = stderr.decode('utf-8', errors='ignore')
                result["stdout"] = stdout.decode('utf-8', errors='ignore')
                
        except Exception as e:
            logger.error(f"Erreur lors de la capture de la mémoire RAM: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            result["error"] = str(e)
        
        return result
    
    def collect(self) -> Dict[str, Any]:
        """
        Collecte la mémoire RAM du système.
        
        Returns:
            Dictionnaire contenant les informations sur la collecte de mémoire
        """
        logger.info("Collecte de la mémoire RAM...")
        
        # Si on analyse une image disque, cette collecte n'est pas possible
        if self.image_path:
            return {"error": "La collecte de la mémoire RAM n'est pas possible à partir d'une image disque"}
        
        # Capture de la mémoire
        capture_result = self._capture_memory()
        
        # Sauvegarde des métadonnées en JSON
        json_path = os.path.join(self.output_dir, "memory_capture.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(capture_result, f, indent=4)
        
        return {
            "capture": capture_result,
            "json_path": json_path
        }

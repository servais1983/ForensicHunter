#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de logging pour ForensicHunter.

Ce module fournit des fonctions pour configurer et utiliser le système de logging
dans l'application ForensicHunter.
"""

import os
import logging
import datetime
from logging.handlers import RotatingFileHandler

def setup_logger(name="forensichunter", log_dir=None, level=logging.INFO):
    """
    Configure et retourne un logger avec le nom spécifié.
    
    Args:
        name (str): Nom du logger
        log_dir (str): Répertoire où stocker les fichiers de log
        level (int): Niveau de logging (par défaut: logging.INFO)
        
    Returns:
        logging.Logger: Logger configuré
    """
    # Créer le logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Éviter les handlers dupliqués
    if logger.handlers:
        return logger
    
    # Formatter pour les logs
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler pour la console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Handler pour les fichiers si un répertoire est spécifié
    if log_dir:
        try:
            os.makedirs(log_dir, exist_ok=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = os.path.join(log_dir, f"{name}_{timestamp}.log")
            
            file_handler = RotatingFileHandler(
                log_file, 
                maxBytes=10*1024*1024,  # 10 MB
                backupCount=5
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
            logger.info(f"Logs will be saved to: {log_file}")
        except Exception as e:
            logger.error(f"Failed to set up file logging: {str(e)}")
    
    return logger

def get_logger(name="forensichunter"):
    """
    Récupère un logger existant ou en crée un nouveau.
    
    Args:
        name (str): Nom du logger à récupérer
        
    Returns:
        logging.Logger: Logger demandé
    """
    logger = logging.getLogger(name)
    
    # Si le logger n'a pas de handlers, le configurer
    if not logger.handlers:
        return setup_logger(name)
    
    return logger

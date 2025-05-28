#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'aide pour ForensicHunter.

Ce module fournit des fonctions utilitaires communes pour l'application ForensicHunter.
"""

import os
import sys
import ctypes
import platform
import datetime
from pathlib import Path

def check_admin_privileges():
    """
    Vérifie si le script est exécuté avec des privilèges administrateur.
    
    Returns:
        bool: True si exécuté en tant qu'administrateur, False sinon
    """
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def create_output_dir(base_dir):
    """
    Crée un répertoire de sortie pour les résultats.
    
    Args:
        base_dir (str): Répertoire de base
        
    Returns:
        str: Chemin complet du répertoire créé
    """
    # Ajout d'un timestamp pour éviter les écrasements
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(os.path.abspath(base_dir), timestamp)
    
    # Création du répertoire
    os.makedirs(output_dir, exist_ok=True)
    
    return output_dir

def get_file_hash(file_path, hash_type="sha256"):
    """
    Calcule le hash d'un fichier.
    
    Args:
        file_path (str): Chemin du fichier
        hash_type (str): Type de hash (md5, sha1, sha256)
        
    Returns:
        str: Hash du fichier
    """
    import hashlib
    
    hash_functions = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256
    }
    
    if hash_type not in hash_functions:
        raise ValueError(f"Type de hash non supporté: {hash_type}")
    
    hash_obj = hash_functions[hash_type]()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()

def format_file_size(size_bytes):
    """
    Formate une taille en bytes en une chaîne lisible.
    
    Args:
        size_bytes (int): Taille en bytes
        
    Returns:
        str: Taille formatée
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def is_valid_path(path):
    """
    Vérifie si un chemin est valide.
    
    Args:
        path (str): Chemin à vérifier
        
    Returns:
        bool: True si le chemin est valide, False sinon
    """
    try:
        Path(path).resolve()
        return True
    except (TypeError, ValueError):
        return False

def get_project_root():
    """
    Récupère le chemin racine du projet.
    
    Returns:
        str: Chemin racine du projet
    """
    # Si exécuté comme script
    if __file__:
        # Remonter de deux niveaux depuis ce fichier (utils -> src -> racine)
        return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Si exécuté dans un environnement interactif
    return os.getcwd()

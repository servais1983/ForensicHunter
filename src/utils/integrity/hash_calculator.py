#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de calcul de hashes pour garantir l'intégrité des preuves.

Ce module fournit des fonctions pour calculer différents types de hashes
(MD5, SHA-1, SHA-256, etc.) sur des fichiers et des données en mémoire,
sans modifier les preuves originales.
"""

import os
import hashlib
import logging
from typing import Dict, List, Any, Optional, BinaryIO, Union

logger = logging.getLogger("forensichunter")


class HashCalculator:
    """Calculateur de hashes pour l'intégrité des preuves."""

    @staticmethod
    def calculate_file_hashes(file_path: str, algorithms: List[str] = None) -> Dict[str, str]:
        """
        Calcule les hashes d'un fichier sans le modifier.
        
        Args:
            file_path: Chemin vers le fichier
            algorithms: Liste des algorithmes à utiliser (par défaut: MD5, SHA-1, SHA-256)
            
        Returns:
            Dictionnaire contenant les hashes calculés
        """
        if algorithms is None:
            algorithms = ["md5", "sha1", "sha256"]
        
        hashes = {}
        
        try:
            # Ouverture du fichier en mode binaire et lecture seule
            with open(file_path, 'rb') as f:
                for algorithm in algorithms:
                    f.seek(0)  # Retour au début du fichier pour chaque algorithme
                    hash_obj = HashCalculator._get_hash_object(algorithm)
                    
                    if hash_obj:
                        # Lecture par blocs pour éviter de charger tout le fichier en mémoire
                        for chunk in iter(lambda: f.read(4096), b''):
                            hash_obj.update(chunk)
                        
                        hashes[algorithm] = hash_obj.hexdigest()
                    else:
                        logger.warning(f"Algorithme de hash non supporté: {algorithm}")
            
            logger.debug(f"Hashes calculés pour {file_path}: {hashes}")
            return hashes
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des hashes pour {file_path}: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            return {"error": str(e)}
    
    @staticmethod
    def calculate_data_hashes(data: Union[bytes, bytearray, memoryview], algorithms: List[str] = None) -> Dict[str, str]:
        """
        Calcule les hashes de données en mémoire.
        
        Args:
            data: Données à hasher
            algorithms: Liste des algorithmes à utiliser (par défaut: MD5, SHA-1, SHA-256)
            
        Returns:
            Dictionnaire contenant les hashes calculés
        """
        if algorithms is None:
            algorithms = ["md5", "sha1", "sha256"]
        
        hashes = {}
        
        try:
            for algorithm in algorithms:
                hash_obj = HashCalculator._get_hash_object(algorithm)
                
                if hash_obj:
                    hash_obj.update(data)
                    hashes[algorithm] = hash_obj.hexdigest()
                else:
                    logger.warning(f"Algorithme de hash non supporté: {algorithm}")
            
            return hashes
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des hashes pour les données: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            return {"error": str(e)}
    
    @staticmethod
    def _get_hash_object(algorithm: str):
        """
        Retourne un objet hash pour l'algorithme spécifié.
        
        Args:
            algorithm: Nom de l'algorithme (md5, sha1, sha256, etc.)
            
        Returns:
            Objet hash ou None si l'algorithme n'est pas supporté
        """
        algorithm = algorithm.lower()
        
        if algorithm == "md5":
            return hashlib.md5()
        elif algorithm == "sha1":
            return hashlib.sha1()
        elif algorithm == "sha256":
            return hashlib.sha256()
        elif algorithm == "sha512":
            return hashlib.sha512()
        else:
            return None
    
    @staticmethod
    def verify_file_hash(file_path: str, expected_hash: str, algorithm: str = "sha256") -> bool:
        """
        Vérifie si le hash d'un fichier correspond à une valeur attendue.
        
        Args:
            file_path: Chemin vers le fichier
            expected_hash: Hash attendu
            algorithm: Algorithme à utiliser (par défaut: SHA-256)
            
        Returns:
            True si le hash correspond, False sinon
        """
        try:
            calculated_hash = HashCalculator.calculate_file_hashes(file_path, [algorithm])
            
            if algorithm in calculated_hash:
                return calculated_hash[algorithm].lower() == expected_hash.lower()
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du hash pour {file_path}: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            return False

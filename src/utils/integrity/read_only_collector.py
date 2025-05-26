#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte en lecture seule pour ForensicHunter.

Ce module fournit des classes et fonctions pour garantir que toutes les opérations
de collecte d'artefacts sont effectuées en mode strictement lecture seule,
sans aucune modification des preuves originales.
"""

import os
import shutil
import logging
import tempfile
import datetime
import platform
import stat
from typing import Dict, List, Any, Optional, BinaryIO, Union

from src.utils.integrity.hash_calculator import HashCalculator
from src.utils.integrity.chain_of_custody import ChainOfCustody
from src.utils.integrity.audit_logger import AuditLogger

logger = logging.getLogger("forensichunter")


class ReadOnlyCollector:
    """Base pour tous les collecteurs en lecture seule."""

    def __init__(self, config, case_id: str = None, output_dir: str = None):
        """
        Initialise le collecteur en lecture seule.
        
        Args:
            config: Configuration de l'application
            case_id: Identifiant unique de l'affaire
            output_dir: Répertoire de sortie pour les artefacts collectés
        """
        self.config = config
        self.case_id = case_id or f"case_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.output_dir = output_dir or os.path.join(os.getcwd(), "evidence")
        
        # Création du répertoire de sortie s'il n'existe pas
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialisation des modules d'intégrité
        self.hash_calculator = HashCalculator()
        self.chain_of_custody = ChainOfCustody(self.case_id, os.path.join(self.output_dir, "custody"))
        self.audit_logger = AuditLogger(self.case_id, os.path.join(self.output_dir, "audit"))
        
        # Vérification du mode lecture seule
        self._verify_read_only_mode()
    
    def _verify_read_only_mode(self):
        """Vérifie que le mode lecture seule est activé."""
        logger.info("Vérification du mode lecture seule...")
        
        # Journalisation de la vérification
        self.audit_logger.log_event(
            event_type="system",
            action="verify_read_only",
            description="Vérification du mode lecture seule",
            details={
                "collector": self.__class__.__name__
            }
        )
    
    def safe_read_file(self, file_path: str, binary: bool = False) -> Union[str, bytes, None]:
        """
        Lit un fichier en mode lecture seule de manière sécurisée.
        
        Args:
            file_path: Chemin vers le fichier à lire
            binary: True pour lire en mode binaire, False pour lire en mode texte
            
        Returns:
            Contenu du fichier ou None en cas d'erreur
        """
        if not os.path.isfile(file_path):
            logger.warning(f"Fichier non trouvé: {file_path}")
            self.audit_logger.log_error(
                error_type="file_not_found",
                error_message=f"Fichier non trouvé: {file_path}",
                details={"file_path": file_path}
            )
            return None
        
        try:
            # Vérification des permissions
            if not os.access(file_path, os.R_OK):
                logger.warning(f"Permissions insuffisantes pour lire le fichier: {file_path}")
                self.audit_logger.log_error(
                    error_type="permission_denied",
                    error_message=f"Permissions insuffisantes pour lire le fichier: {file_path}",
                    details={"file_path": file_path}
                )
                return None
            
            # Journalisation de l'accès au fichier
            self.audit_logger.log_file_access(
                file_path=file_path,
                access_type="read",
                description=f"Lecture du fichier {os.path.basename(file_path)}",
                details={"binary": binary}
            )
            
            # Lecture du fichier
            mode = "rb" if binary else "r"
            encoding = None if binary else "utf-8"
            
            with open(file_path, mode, encoding=encoding) as f:
                content = f.read()
            
            return content
            
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du fichier {file_path}: {str(e)}")
            self.audit_logger.log_error(
                error_type="file_read_error",
                error_message=f"Erreur lors de la lecture du fichier: {str(e)}",
                details={"file_path": file_path, "exception": str(e)}
            )
            return None
    
    def safe_copy_file(self, source_path: str, destination_dir: str) -> str:
        """
        Copie un fichier de manière sécurisée sans modifier l'original.
        
        Args:
            source_path: Chemin vers le fichier source
            destination_dir: Répertoire de destination
            
        Returns:
            Chemin vers le fichier copié ou chaîne vide en cas d'erreur
        """
        if not os.path.isfile(source_path):
            logger.warning(f"Fichier source non trouvé: {source_path}")
            self.audit_logger.log_error(
                error_type="file_not_found",
                error_message=f"Fichier source non trouvé: {source_path}",
                details={"source_path": source_path}
            )
            return ""
        
        try:
            # Création du répertoire de destination s'il n'existe pas
            os.makedirs(destination_dir, exist_ok=True)
            
            # Génération du nom de fichier de destination
            file_name = os.path.basename(source_path)
            destination_path = os.path.join(destination_dir, file_name)
            
            # Si le fichier existe déjà, ajouter un suffixe
            if os.path.exists(destination_path):
                base_name, extension = os.path.splitext(file_name)
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                destination_path = os.path.join(destination_dir, f"{base_name}_{timestamp}{extension}")
            
            # Calcul des hashes avant la copie
            source_hashes = self.hash_calculator.calculate_file_hashes(source_path)
            
            # Journalisation de l'accès au fichier source
            self.audit_logger.log_file_access(
                file_path=source_path,
                access_type="read",
                description=f"Lecture du fichier source pour copie: {os.path.basename(source_path)}",
                details={"destination": destination_path}
            )
            
            # Copie du fichier
            shutil.copy2(source_path, destination_path)
            
            # Calcul des hashes après la copie
            destination_hashes = self.hash_calculator.calculate_file_hashes(destination_path)
            
            # Vérification de l'intégrité
            if source_hashes.get("sha256") != destination_hashes.get("sha256"):
                logger.warning(f"Intégrité compromise lors de la copie de {source_path} vers {destination_path}")
                self.audit_logger.log_error(
                    error_type="integrity_error",
                    error_message="Intégrité compromise lors de la copie",
                    details={
                        "source_path": source_path,
                        "destination_path": destination_path,
                        "source_hash": source_hashes.get("sha256"),
                        "destination_hash": destination_hashes.get("sha256")
                    }
                )
                return ""
            
            # Enregistrement dans la chaîne de custody
            self.chain_of_custody.register_artifact(
                artifact_path=destination_path,
                artifact_type="file",
                source=source_path,
                description=f"Copie du fichier {os.path.basename(source_path)}",
                metadata={
                    "hashes": destination_hashes,
                    "original_hashes": source_hashes
                }
            )
            
            # Journalisation de la copie
            self.audit_logger.log_artifact_collection(
                artifact_type="file",
                source=source_path,
                destination=destination_path,
                description=f"Copie du fichier {os.path.basename(source_path)}",
                details={
                    "hashes": destination_hashes,
                    "original_hashes": source_hashes
                }
            )
            
            return destination_path
            
        except Exception as e:
            logger.error(f"Erreur lors de la copie du fichier {source_path}: {str(e)}")
            self.audit_logger.log_error(
                error_type="file_copy_error",
                error_message=f"Erreur lors de la copie du fichier: {str(e)}",
                details={"source_path": source_path, "destination_dir": destination_dir, "exception": str(e)}
            )
            return ""
    
    def safe_extract_data(self, source_path: str, extraction_function, extraction_args: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Extrait des données d'un fichier de manière sécurisée sans modifier l'original.
        
        Args:
            source_path: Chemin vers le fichier source
            extraction_function: Fonction d'extraction à utiliser
            extraction_args: Arguments pour la fonction d'extraction
            
        Returns:
            Dictionnaire contenant les données extraites ou dictionnaire vide en cas d'erreur
        """
        if not os.path.isfile(source_path):
            logger.warning(f"Fichier source non trouvé: {source_path}")
            self.audit_logger.log_error(
                error_type="file_not_found",
                error_message=f"Fichier source non trouvé: {source_path}",
                details={"source_path": source_path}
            )
            return {}
        
        try:
            # Calcul des hashes avant l'extraction
            source_hashes_before = self.hash_calculator.calculate_file_hashes(source_path)
            
            # Journalisation de l'accès au fichier
            self.audit_logger.log_file_access(
                file_path=source_path,
                access_type="read",
                description=f"Extraction de données du fichier {os.path.basename(source_path)}",
                details={"extraction_function": extraction_function.__name__}
            )
            
            # Extraction des données
            extraction_args = extraction_args or {}
            extracted_data = extraction_function(source_path, **extraction_args)
            
            # Calcul des hashes après l'extraction
            source_hashes_after = self.hash_calculator.calculate_file_hashes(source_path)
            
            # Vérification de l'intégrité
            if source_hashes_before.get("sha256") != source_hashes_after.get("sha256"):
                logger.warning(f"Intégrité compromise lors de l'extraction de données de {source_path}")
                self.audit_logger.log_error(
                    error_type="integrity_error",
                    error_message="Intégrité compromise lors de l'extraction de données",
                    details={
                        "source_path": source_path,
                        "hash_before": source_hashes_before.get("sha256"),
                        "hash_after": source_hashes_after.get("sha256")
                    }
                )
                return {}
            
            # Journalisation de l'extraction
            self.audit_logger.log_event(
                event_type="data",
                action="extract",
                description=f"Extraction de données du fichier {os.path.basename(source_path)}",
                details={
                    "source_path": source_path,
                    "extraction_function": extraction_function.__name__,
                    "extraction_args": extraction_args,
                    "data_size": len(str(extracted_data))
                }
            )
            
            return extracted_data
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction de données de {source_path}: {str(e)}")
            self.audit_logger.log_error(
                error_type="data_extraction_error",
                error_message=f"Erreur lors de l'extraction de données: {str(e)}",
                details={"source_path": source_path, "extraction_function": extraction_function.__name__, "exception": str(e)}
            )
            return {}
    
    def create_temp_copy(self, source_path: str) -> str:
        """
        Crée une copie temporaire d'un fichier pour traitement.
        
        Args:
            source_path: Chemin vers le fichier source
            
        Returns:
            Chemin vers la copie temporaire ou chaîne vide en cas d'erreur
        """
        if not os.path.isfile(source_path):
            logger.warning(f"Fichier source non trouvé: {source_path}")
            return ""
        
        try:
            # Création d'un fichier temporaire
            fd, temp_path = tempfile.mkstemp(suffix=os.path.splitext(source_path)[1])
            os.close(fd)
            
            # Copie du fichier source vers le fichier temporaire
            shutil.copy2(source_path, temp_path)
            
            # Calcul des hashes
            source_hash = self.hash_calculator.calculate_file_hashes(source_path).get("sha256", "")
            temp_hash = self.hash_calculator.calculate_file_hashes(temp_path).get("sha256", "")
            
            # Vérification de l'intégrité
            if source_hash != temp_hash:
                logger.warning(f"Intégrité compromise lors de la création de la copie temporaire de {source_path}")
                os.unlink(temp_path)
                return ""
            
            # Journalisation
            self.audit_logger.log_event(
                event_type="file",
                action="temp_copy",
                description=f"Création d'une copie temporaire de {os.path.basename(source_path)}",
                details={
                    "source_path": source_path,
                    "temp_path": temp_path,
                    "source_hash": source_hash,
                    "temp_hash": temp_hash
                }
            )
            
            return temp_path
            
        except Exception as e:
            logger.error(f"Erreur lors de la création de la copie temporaire de {source_path}: {str(e)}")
            return ""
    
    def set_read_only(self, file_path: str) -> bool:
        """
        Définit un fichier comme étant en lecture seule.
        
        Args:
            file_path: Chemin vers le fichier
            
        Returns:
            True si l'opération a réussi, False sinon
        """
        try:
            # Récupération des permissions actuelles
            current_mode = os.stat(file_path).st_mode
            
            # Définition des permissions en lecture seule
            os.chmod(file_path, current_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            
            # Journalisation
            self.audit_logger.log_event(
                event_type="file",
                action="set_read_only",
                description=f"Définition du fichier {os.path.basename(file_path)} en lecture seule",
                details={"file_path": file_path}
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la définition du fichier {file_path} en lecture seule: {str(e)}")
            return False
    
    def is_read_only(self, file_path: str) -> bool:
        """
        Vérifie si un fichier est en lecture seule.
        
        Args:
            file_path: Chemin vers le fichier
            
        Returns:
            True si le fichier est en lecture seule, False sinon
        """
        try:
            # Récupération des permissions
            mode = os.stat(file_path).st_mode
            
            # Vérification des permissions d'écriture
            return not (mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification des permissions du fichier {file_path}: {str(e)}")
            return False
    
    def verify_windows_version_compatibility(self) -> Dict[str, Any]:
        """
        Vérifie la compatibilité avec la version de Windows.
        
        Returns:
            Dictionnaire contenant les informations de compatibilité
        """
        windows_version = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "compatible": False,
            "compatibility_issues": []
        }
        
        # Vérification du système d'exploitation
        if windows_version["system"] != "Windows":
            windows_version["compatibility_issues"].append("Système d'exploitation non Windows")
            return windows_version
        
        # Extraction de la version majeure de Windows
        try:
            # Windows 10/11 : 10.0.XXXXX
            # Windows 8.1 : 6.3.XXXXX
            # Windows 8 : 6.2.XXXXX
            # Windows 7 : 6.1.XXXXX
            # Windows Vista : 6.0.XXXXX
            # Windows XP : 5.1.XXXXX
            # Windows 2000 : 5.0.XXXXX
            version_parts = windows_version["version"].split(".")
            major_version = int(version_parts[0])
            minor_version = int(version_parts[1]) if len(version_parts) > 1 else 0
            
            if major_version < 5:
                windows_version["compatibility_issues"].append("Version de Windows trop ancienne (antérieure à Windows 2000)")
            elif major_version == 5 and minor_version == 0:
                windows_version["compatibility_issues"].append("Windows 2000 détecté - support limité")
            elif major_version == 5 and minor_version == 1:
                windows_version["compatibility_issues"].append("Windows XP détecté - support limité")
            
        except Exception as e:
            windows_version["compatibility_issues"].append(f"Erreur lors de l'analyse de la version: {str(e)}")
        
        # Vérification de la compatibilité
        windows_version["compatible"] = len(windows_version["compatibility_issues"]) == 0
        
        # Journalisation
        self.audit_logger.log_event(
            event_type="system",
            action="verify_compatibility",
            description="Vérification de la compatibilité avec la version de Windows",
            details=windows_version
        )
        
        return windows_version

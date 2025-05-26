#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de journalisation d'audit pour ForensicHunter.

Ce module fournit des fonctionnalités avancées de journalisation pour
tracer toutes les opérations effectuées par l'outil, garantissant ainsi
une transparence totale et une traçabilité complète pour les besoins judiciaires.
"""

import os
import json
import logging
import datetime
import platform
import getpass
import socket
import uuid
from typing import Dict, List, Any, Optional

logger = logging.getLogger("forensichunter")


class AuditLogger:
    """Gestionnaire de journalisation d'audit pour ForensicHunter."""

    def __init__(self, case_id: str, output_dir: str = None):
        """
        Initialise le gestionnaire de journalisation d'audit.
        
        Args:
            case_id: Identifiant unique de l'affaire
            output_dir: Répertoire de sortie pour les journaux d'audit
        """
        self.case_id = case_id
        self.output_dir = output_dir or os.path.join(os.getcwd(), "audit_logs")
        
        # Création du répertoire de sortie s'il n'existe pas
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Informations sur l'environnement d'exécution
        self.environment = {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "user": getpass.getuser(),
            "ip_address": self._get_ip_address(),
            "date": datetime.datetime.now().isoformat()
        }
        
        # Configuration du logger d'audit
        self._setup_audit_logger()
        
        # Journalisation du démarrage
        self.log_event(
            event_type="system",
            action="startup",
            description="Démarrage du système de journalisation d'audit",
            details={
                "case_id": self.case_id,
                "environment": self.environment
            }
        )
    
    def _get_ip_address(self) -> str:
        """
        Récupère l'adresse IP de la machine.
        
        Returns:
            Adresse IP de la machine
        """
        try:
            # Création d'une connexion socket pour déterminer l'adresse IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
            return ip_address
        except Exception:
            return "127.0.0.1"
    
    def _setup_audit_logger(self):
        """Configure le logger d'audit."""
        # Création d'un handler pour le fichier de log d'audit
        audit_file = os.path.join(self.output_dir, f"audit_{self.case_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        # Configuration du handler de fichier
        file_handler = logging.FileHandler(audit_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Format du log d'audit (JSON)
        formatter = logging.Formatter('%(message)s')
        file_handler.setFormatter(formatter)
        
        # Création d'un logger spécifique pour l'audit
        self.audit_logger = logging.getLogger("forensichunter.audit")
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.addHandler(file_handler)
        
        # Désactivation de la propagation pour éviter la duplication des logs
        self.audit_logger.propagate = False
    
    def log_event(self, event_type: str, action: str, description: str, details: Dict[str, Any] = None) -> str:
        """
        Journalise un événement d'audit.
        
        Args:
            event_type: Type d'événement (system, file, registry, network, etc.)
            action: Action effectuée (read, write, collect, analyze, etc.)
            description: Description de l'événement
            details: Détails supplémentaires sur l'événement
            
        Returns:
            Identifiant unique de l'événement
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now().isoformat()
        
        event = {
            "id": event_id,
            "timestamp": timestamp,
            "case_id": self.case_id,
            "type": event_type,
            "action": action,
            "description": description,
            "user": getpass.getuser(),
            "details": details or {}
        }
        
        # Journalisation de l'événement au format JSON
        self.audit_logger.info(json.dumps(event))
        
        return event_id
    
    def log_file_access(self, file_path: str, access_type: str, description: str = None, details: Dict[str, Any] = None) -> str:
        """
        Journalise un accès à un fichier.
        
        Args:
            file_path: Chemin vers le fichier
            access_type: Type d'accès (read, write, create, delete, etc.)
            description: Description de l'accès
            details: Détails supplémentaires sur l'accès
            
        Returns:
            Identifiant unique de l'événement
        """
        # Vérification que l'accès est en lecture seule pour les preuves
        if access_type != "read" and self._is_evidence_file(file_path):
            logger.warning(f"Tentative d'accès non-lecture à un fichier de preuve: {file_path}")
            # On journalise quand même l'événement pour des raisons d'audit
        
        file_details = self._get_file_details(file_path)
        
        event_details = {
            "file_path": file_path,
            "access_type": access_type,
            "file_details": file_details
        }
        
        if details:
            event_details.update(details)
        
        return self.log_event(
            event_type="file",
            action=access_type,
            description=description or f"Accès {access_type} au fichier {os.path.basename(file_path)}",
            details=event_details
        )
    
    def log_registry_access(self, hive: str, key_path: str, access_type: str, description: str = None, details: Dict[str, Any] = None) -> str:
        """
        Journalise un accès au registre.
        
        Args:
            hive: Ruche de registre
            key_path: Chemin de la clé
            access_type: Type d'accès (read, write, create, delete, etc.)
            description: Description de l'accès
            details: Détails supplémentaires sur l'accès
            
        Returns:
            Identifiant unique de l'événement
        """
        # Vérification que l'accès est en lecture seule pour les preuves
        if access_type != "read":
            logger.warning(f"Tentative d'accès non-lecture au registre: {hive}\\{key_path}")
            # On journalise quand même l'événement pour des raisons d'audit
        
        event_details = {
            "hive": hive,
            "key_path": key_path,
            "access_type": access_type
        }
        
        if details:
            event_details.update(details)
        
        return self.log_event(
            event_type="registry",
            action=access_type,
            description=description or f"Accès {access_type} à la clé de registre {hive}\\{key_path}",
            details=event_details
        )
    
    def log_network_access(self, host: str, port: int, protocol: str, description: str = None, details: Dict[str, Any] = None) -> str:
        """
        Journalise un accès réseau.
        
        Args:
            host: Hôte distant
            port: Port distant
            protocol: Protocole utilisé
            description: Description de l'accès
            details: Détails supplémentaires sur l'accès
            
        Returns:
            Identifiant unique de l'événement
        """
        event_details = {
            "host": host,
            "port": port,
            "protocol": protocol
        }
        
        if details:
            event_details.update(details)
        
        return self.log_event(
            event_type="network",
            action="connect",
            description=description or f"Connexion {protocol} à {host}:{port}",
            details=event_details
        )
    
    def log_process_access(self, pid: int, process_name: str, access_type: str, description: str = None, details: Dict[str, Any] = None) -> str:
        """
        Journalise un accès à un processus.
        
        Args:
            pid: Identifiant du processus
            process_name: Nom du processus
            access_type: Type d'accès (read, kill, suspend, etc.)
            description: Description de l'accès
            details: Détails supplémentaires sur l'accès
            
        Returns:
            Identifiant unique de l'événement
        """
        event_details = {
            "pid": pid,
            "process_name": process_name,
            "access_type": access_type
        }
        
        if details:
            event_details.update(details)
        
        return self.log_event(
            event_type="process",
            action=access_type,
            description=description or f"Accès {access_type} au processus {process_name} (PID: {pid})",
            details=event_details
        )
    
    def log_memory_access(self, pid: int, process_name: str, address: str, size: int, description: str = None, details: Dict[str, Any] = None) -> str:
        """
        Journalise un accès à la mémoire.
        
        Args:
            pid: Identifiant du processus
            process_name: Nom du processus
            address: Adresse mémoire
            size: Taille de la mémoire accédée
            description: Description de l'accès
            details: Détails supplémentaires sur l'accès
            
        Returns:
            Identifiant unique de l'événement
        """
        event_details = {
            "pid": pid,
            "process_name": process_name,
            "address": address,
            "size": size
        }
        
        if details:
            event_details.update(details)
        
        return self.log_event(
            event_type="memory",
            action="read",
            description=description or f"Lecture de la mémoire du processus {process_name} (PID: {pid})",
            details=event_details
        )
    
    def log_artifact_collection(self, artifact_type: str, source: str, destination: str, description: str = None, details: Dict[str, Any] = None) -> str:
        """
        Journalise la collecte d'un artefact.
        
        Args:
            artifact_type: Type d'artefact
            source: Source de l'artefact
            destination: Destination de l'artefact
            description: Description de la collecte
            details: Détails supplémentaires sur la collecte
            
        Returns:
            Identifiant unique de l'événement
        """
        event_details = {
            "artifact_type": artifact_type,
            "source": source,
            "destination": destination
        }
        
        if details:
            event_details.update(details)
        
        return self.log_event(
            event_type="artifact",
            action="collect",
            description=description or f"Collecte d'un artefact de type {artifact_type}",
            details=event_details
        )
    
    def log_analysis(self, artifact_type: str, artifact_path: str, analysis_type: str, description: str = None, details: Dict[str, Any] = None) -> str:
        """
        Journalise une analyse.
        
        Args:
            artifact_type: Type d'artefact
            artifact_path: Chemin vers l'artefact
            analysis_type: Type d'analyse
            description: Description de l'analyse
            details: Détails supplémentaires sur l'analyse
            
        Returns:
            Identifiant unique de l'événement
        """
        event_details = {
            "artifact_type": artifact_type,
            "artifact_path": artifact_path,
            "analysis_type": analysis_type
        }
        
        if details:
            event_details.update(details)
        
        return self.log_event(
            event_type="analysis",
            action="analyze",
            description=description or f"Analyse {analysis_type} d'un artefact de type {artifact_type}",
            details=event_details
        )
    
    def log_report_generation(self, report_type: str, report_path: str, description: str = None, details: Dict[str, Any] = None) -> str:
        """
        Journalise la génération d'un rapport.
        
        Args:
            report_type: Type de rapport
            report_path: Chemin vers le rapport
            description: Description de la génération
            details: Détails supplémentaires sur la génération
            
        Returns:
            Identifiant unique de l'événement
        """
        event_details = {
            "report_type": report_type,
            "report_path": report_path
        }
        
        if details:
            event_details.update(details)
        
        return self.log_event(
            event_type="report",
            action="generate",
            description=description or f"Génération d'un rapport de type {report_type}",
            details=event_details
        )
    
    def log_error(self, error_type: str, error_message: str, description: str = None, details: Dict[str, Any] = None) -> str:
        """
        Journalise une erreur.
        
        Args:
            error_type: Type d'erreur
            error_message: Message d'erreur
            description: Description de l'erreur
            details: Détails supplémentaires sur l'erreur
            
        Returns:
            Identifiant unique de l'événement
        """
        event_details = {
            "error_type": error_type,
            "error_message": error_message
        }
        
        if details:
            event_details.update(details)
        
        return self.log_event(
            event_type="error",
            action="error",
            description=description or f"Erreur de type {error_type}: {error_message}",
            details=event_details
        )
    
    def _is_evidence_file(self, file_path: str) -> bool:
        """
        Vérifie si un fichier est un fichier de preuve.
        
        Args:
            file_path: Chemin vers le fichier
            
        Returns:
            True si le fichier est un fichier de preuve, False sinon
        """
        # Logique pour déterminer si un fichier est un fichier de preuve
        # Par exemple, vérifier s'il se trouve dans un répertoire spécifique
        evidence_dirs = ["evidence", "artifacts", "collected"]
        
        for evidence_dir in evidence_dirs:
            if evidence_dir in file_path.lower():
                return True
        
        return False
    
    def _get_file_details(self, file_path: str) -> Dict[str, Any]:
        """
        Récupère les détails d'un fichier.
        
        Args:
            file_path: Chemin vers le fichier
            
        Returns:
            Dictionnaire contenant les détails du fichier
        """
        file_details = {}
        
        if os.path.exists(file_path):
            try:
                file_stats = os.stat(file_path)
                file_details = {
                    "exists": True,
                    "size": file_stats.st_size,
                    "created": datetime.datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                    "modified": datetime.datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                    "accessed": datetime.datetime.fromtimestamp(file_stats.st_atime).isoformat(),
                    "is_file": os.path.isfile(file_path),
                    "is_dir": os.path.isdir(file_path),
                    "is_link": os.path.islink(file_path)
                }
            except Exception as e:
                file_details = {
                    "exists": True,
                    "error": str(e)
                }
        else:
            file_details = {
                "exists": False
            }
        
        return file_details
    
    def shutdown(self):
        """Arrête le système de journalisation d'audit."""
        self.log_event(
            event_type="system",
            action="shutdown",
            description="Arrêt du système de journalisation d'audit",
            details={
                "case_id": self.case_id
            }
        )
        
        # Fermeture des handlers
        for handler in self.audit_logger.handlers[:]:
            handler.close()
            self.audit_logger.removeHandler(handler)

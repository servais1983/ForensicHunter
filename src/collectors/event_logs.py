#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des journaux d'événements Windows.

Ce module est responsable de la collecte et de l'extraction des journaux
d'événements Windows (Event Logs) pour analyse forensique.
"""

import os
import logging
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx
import Evtx.Views as evtx_views

logger = logging.getLogger("forensichunter")

# Journaux d'événements importants pour l'analyse forensique
IMPORTANT_EVENT_LOGS = [
    "System",
    "Security",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational"
]

# Événements d'intérêt pour la sécurité
SECURITY_EVENTS = {
    # Événements de connexion/déconnexion
    "4624": "Connexion réussie",
    "4625": "Échec de connexion",
    "4634": "Déconnexion",
    "4647": "Déconnexion initiée par l'utilisateur",
    "4648": "Connexion explicite",
    "4672": "Privilèges spéciaux attribués",
    
    # Événements de gestion des comptes
    "4720": "Compte utilisateur créé",
    "4722": "Compte utilisateur activé",
    "4723": "Tentative de changement de mot de passe",
    "4724": "Réinitialisation de mot de passe",
    "4725": "Compte utilisateur désactivé",
    "4726": "Compte utilisateur supprimé",
    "4728": "Membre ajouté à un groupe privilégié",
    "4732": "Membre ajouté à un groupe local",
    "4756": "Membre ajouté à un groupe universel",
    
    # Événements de politique de sécurité
    "4616": "Heure système modifiée",
    "4657": "Modification d'un registre d'audit",
    "4697": "Service installé",
    "4698": "Tâche planifiée créée",
    "4699": "Tâche planifiée supprimée",
    "4700": "Tâche planifiée activée",
    "4701": "Tâche planifiée désactivée",
    "4702": "Tâche planifiée mise à jour",
    
    # Événements d'exécution de code
    "4688": "Nouveau processus créé",
    "4689": "Processus terminé",
    "7045": "Service installé"
}


class EventLogCollector:
    """Collecteur de journaux d'événements Windows."""

    def __init__(self, config):
        """
        Initialise le collecteur de journaux d'événements.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "eventlogs")
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
    
    def _get_event_logs_path(self) -> str:
        """
        Détermine le chemin vers les journaux d'événements.
        
        Returns:
            Chemin vers le répertoire des journaux d'événements
        """
        if self.image_path:
            # Si on analyse une image disque, on doit monter l'image et trouver le chemin
            # Cette partie nécessiterait une implémentation spécifique selon le format d'image
            # Pour l'instant, on suppose que l'image est déjà montée et on utilise un chemin relatif
            return os.path.join(self.image_path, "Windows", "System32", "winevt", "Logs")
        else:
            # Sur un système Windows en direct
            return os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "winevt", "Logs")
    
    def _extract_event_data(self, record) -> Dict[str, Any]:
        """
        Extrait les données d'un événement.
        
        Args:
            record: Enregistrement d'événement
        
        Returns:
            Dictionnaire contenant les données de l'événement
        """
        try:
            xml_string = record.xml()
            root = ET.fromstring(xml_string)
            
            # Extraction des informations de base
            system = root.find("./System")
            event_id = system.find("EventID").text
            time_created = system.find("TimeCreated").get("SystemTime")
            provider = system.find("Provider").get("Name")
            computer = system.find("Computer").text
            
            # Extraction des données spécifiques à l'événement
            event_data = {}
            data_element = root.find("./EventData")
            
            if data_element is not None:
                for data in data_element.findall("Data"):
                    name = data.get("Name")
                    if name:
                        event_data[name] = data.text
                    elif data.text:
                        event_data[f"Data_{len(event_data)}"] = data.text
            
            # Construction du résultat
            result = {
                "EventID": event_id,
                "TimeCreated": time_created,
                "Provider": provider,
                "Computer": computer,
                "Description": SECURITY_EVENTS.get(event_id, ""),
                "Data": event_data
            }
            
            return result
        
        except Exception as e:
            logger.debug(f"Erreur lors de l'extraction des données d'événement: {str(e)}")
            return {
                "EventID": "Unknown",
                "TimeCreated": "",
                "Provider": "",
                "Computer": "",
                "Description": "Erreur d'extraction",
                "Data": {"Error": str(e)}
            }
    
    def collect(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Collecte les journaux d'événements Windows.
        
        Returns:
            Dictionnaire contenant les événements collectés par journal
        """
        logger.info("Collecte des journaux d'événements Windows...")
        
        event_logs_path = self._get_event_logs_path()
        collected_logs = {}
        
        # Vérification de l'existence du répertoire des journaux
        if not os.path.exists(event_logs_path):
            logger.error(f"Répertoire des journaux d'événements non trouvé: {event_logs_path}")
            return {"error": f"Répertoire non trouvé: {event_logs_path}"}
        
        # Parcours des journaux d'événements importants
        for log_name in IMPORTANT_EVENT_LOGS:
            log_path = os.path.join(event_logs_path, f"{log_name}.evtx")
            
            if not os.path.exists(log_path):
                logger.warning(f"Journal d'événements non trouvé: {log_path}")
                continue
            
            try:
                logger.info(f"Analyse du journal: {log_name}")
                
                # Copie du fichier journal pour analyse
                output_path = os.path.join(self.output_dir, f"{log_name}.evtx")
                with open(log_path, "rb") as src, open(output_path, "wb") as dst:
                    dst.write(src.read())
                
                # Extraction des événements
                events = []
                with evtx.Evtx(output_path) as log:
                    for record in log.records():
                        event_data = self._extract_event_data(record)
                        events.append(event_data)
                
                collected_logs[log_name] = events
                logger.info(f"Collecté {len(events)} événements depuis {log_name}")
                
            except Exception as e:
                logger.error(f"Erreur lors de la collecte du journal {log_name}: {str(e)}")
                logger.debug("Détails de l'erreur:", exc_info=True)
                collected_logs[log_name] = {"error": str(e)}
        
        return collected_logs

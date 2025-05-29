#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des journaux d'événements Windows.

Ce module permet de collecter les journaux d'événements Windows
(Application, Système, Sécurité, etc.) pour analyse forensique.
"""

import os
import logging
import datetime
import json
import subprocess
from pathlib import Path

from .base_collector import BaseCollector, Artifact

# Configuration du logger
logger = logging.getLogger("forensichunter.collectors.event_log")

class EventLogCollector(BaseCollector):
    """Collecteur de journaux d'événements Windows."""
    
    def __init__(self, config=None):
        """
        Initialise un nouveau collecteur de journaux d'événements.
        
        Args:
            config (dict, optional): Configuration du collecteur
        """
        super().__init__(config)
        self.log_types = self.config.get("log_types", ["Application", "System", "Security"])
        self.max_events = self.config.get("max_events", 100)  # Réduire pour éviter les erreurs
        self.start_time = self.config.get("start_time", None)
        self.end_time = self.config.get("end_time", None)
        self.event_ids = self.config.get("event_ids", [])
        self.use_powershell = self.config.get("use_powershell", True)
        self.use_wevtutil = self.config.get("use_wevtutil", False)  # Désactivé par défaut
        self.use_python_win32 = self.config.get("use_python_win32", True)
    
    def get_name(self):
        """
        Retourne le nom du collecteur.
        
        Returns:
            str: Nom du collecteur
        """
        return "EventLogCollector"
    
    def get_description(self):
        """
        Retourne la description du collecteur.
        
        Returns:
            str: Description du collecteur
        """
        return "Collecteur de journaux d'événements Windows (Application, Système, Sécurité, etc.)"
    
    def collect(self):
        """
        Collecte les journaux d'événements Windows.
        
        Returns:
            list: Liste d'objets Artifact collectés
        """
        self.clear_artifacts()
        
        # Vérifier si nous sommes sur Windows
        if os.name != "nt":
            logger.warning("Ce collecteur ne fonctionne que sur Windows. Aucun artefact collecté.")
            return self.artifacts
        
        # Essayer différentes méthodes de collecte
        if self.use_python_win32 and self._collect_with_win32():
            logger.info("Collecte avec win32 réussie")
        elif self.use_powershell and self._collect_with_powershell():
            logger.info("Collecte avec PowerShell réussie")
        elif self.use_wevtutil and self._collect_with_wevtutil():
            logger.info("Collecte avec wevtutil réussie")
        else:
            logger.warning("Toutes les méthodes de collecte ont échoué, collecte basique des événements")
            self._collect_basic_events()
        
        return self.artifacts
    
    def _collect_with_powershell(self):
        """
        Collecte les journaux d'événements avec PowerShell.
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            for log_type in self.log_types:
                logger.info(f"Collecte des événements {log_type} avec PowerShell...")
                
                # Construire la commande PowerShell simplifiée
                cmd = [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"Get-WinEvent -LogName '{log_type}' -MaxEvents {self.max_events} -ErrorAction SilentlyContinue | Select-Object Id, TimeCreated, ProviderName, LevelDisplayName, Message | ConvertTo-Json -Depth 2"
                ]
                
                # Exécuter la commande avec gestion d'encodage
                try:
                    process = subprocess.Popen(
                        cmd, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE, 
                        text=True,
                        encoding='utf-8',
                        errors='replace'  # Remplacer les caractères non-UTF-8
                    )
                    stdout, stderr = process.communicate(timeout=30)  # Timeout de 30 secondes
                    
                    if process.returncode != 0:
                        logger.error(f"Erreur lors de l'exécution de PowerShell pour {log_type}: {stderr}")
                        continue
                    
                    if not stdout or stdout.strip() == "":
                        logger.warning(f"Aucun événement trouvé pour {log_type}")
                        continue
                    
                    # Traiter les résultats
                    try:
                        events = json.loads(stdout)
                        
                        # Si un seul événement est retourné, le convertir en liste
                        if not isinstance(events, list):
                            events = [events] if events else []
                        
                        for event in events:
                            if not isinstance(event, dict):
                                continue
                                
                            # Extraire les informations pertinentes
                            event_id = event.get("Id", 0)
                            time_created = event.get("TimeCreated", "")
                            provider_name = event.get("ProviderName", "")
                            level = event.get("LevelDisplayName", "")
                            message = event.get("Message", "")
                            
                            # Créer un artefact
                            metadata = {
                                "event_id": str(event_id),
                                "time_created": str(time_created),
                                "provider_name": str(provider_name),
                                "level": str(level),
                                "log_type": log_type
                            }
                            
                            self.add_artifact(
                                artifact_type="event_log",
                                source=f"powershell_{log_type}",
                                data={
                                    "message": str(message),
                                    "event_data": event
                                },
                                metadata=metadata
                            )
                        
                        logger.info(f"{len(events)} événements collectés pour {log_type}")
                        
                    except json.JSONDecodeError as e:
                        logger.error(f"Erreur lors du décodage JSON pour {log_type}: {str(e)}")
                        continue
                        
                except subprocess.TimeoutExpired:
                    logger.error(f"Timeout lors de la collecte PowerShell pour {log_type}")
                    process.kill()
                    continue
                except Exception as e:
                    logger.error(f"Erreur lors de l'exécution PowerShell pour {log_type}: {str(e)}")
                    continue
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec PowerShell: {str(e)}")
            return False
    
    def _collect_with_wevtutil(self):
        """
        Collecte les journaux d'événements avec wevtutil (méthode alternative).
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            for log_type in self.log_types:
                logger.info(f"Collecte des événements {log_type} avec wevtutil...")
                
                # Construire la commande wevtutil pour lister les événements récents
                cmd = [
                    "wevtutil",
                    "qe",
                    log_type,
                    "/c:{}".format(self.max_events),
                    "/rd:true",
                    "/f:text"
                ]
                
                # Exécuter la commande
                try:
                    process = subprocess.Popen(
                        cmd, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE, 
                        text=True,
                        encoding='utf-8',
                        errors='replace'
                    )
                    stdout, stderr = process.communicate(timeout=30)
                    
                    if process.returncode != 0:
                        logger.error(f"Erreur lors de l'exécution de wevtutil pour {log_type}: {stderr}")
                        continue
                    
                    if stdout:
                        # Parser la sortie texte de wevtutil
                        events = self._parse_wevtutil_output(stdout, log_type)
                        logger.info(f"{len(events)} événements collectés pour {log_type}")
                    else:
                        logger.warning(f"Aucun événement trouvé pour {log_type}")
                    
                except subprocess.TimeoutExpired:
                    logger.error(f"Timeout lors de la collecte wevtutil pour {log_type}")
                    process.kill()
                    continue
                except Exception as e:
                    logger.error(f"Erreur lors de l'exécution wevtutil pour {log_type}: {str(e)}")
                    continue
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec wevtutil: {str(e)}")
            return False
    
    def _parse_wevtutil_output(self, output, log_type):
        """
        Parse la sortie texte de wevtutil.
        
        Args:
            output (str): Sortie de wevtutil
            log_type (str): Type de journal
            
        Returns:
            list: Liste des événements parsés
        """
        events = []
        current_event = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                if current_event:
                    # Créer un artefact pour l'événement actuel
                    metadata = {
                        "event_id": current_event.get("Event ID", ""),
                        "time_created": current_event.get("Date", ""),
                        "provider_name": current_event.get("Source", ""),
                        "level": current_event.get("Level", ""),
                        "log_type": log_type
                    }
                    
                    self.add_artifact(
                        artifact_type="event_log",
                        source=f"wevtutil_{log_type}",
                        data={
                            "message": current_event.get("Description", ""),
                            "event_data": current_event
                        },
                        metadata=metadata
                    )
                    
                    events.append(current_event)
                    current_event = {}
            else:
                if ':' in line:
                    key, value = line.split(':', 1)
                    current_event[key.strip()] = value.strip()
        
        # Traiter le dernier événement
        if current_event:
            metadata = {
                "event_id": current_event.get("Event ID", ""),
                "time_created": current_event.get("Date", ""),
                "provider_name": current_event.get("Source", ""),
                "level": current_event.get("Level", ""),
                "log_type": log_type
            }
            
            self.add_artifact(
                artifact_type="event_log",
                source=f"wevtutil_{log_type}",
                data={
                    "message": current_event.get("Description", ""),
                    "event_data": current_event
                },
                metadata=metadata
            )
            
            events.append(current_event)
        
        return events
    
    def _collect_with_win32(self):
        """
        Collecte les journaux d'événements avec win32evtlog.
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            # Importer win32evtlog
            try:
                import win32evtlog
                import win32evtlogutil
                import win32con
            except ImportError:
                logger.warning("Module win32evtlog non disponible")
                return False
            
            for log_type in self.log_types:
                logger.info(f"Collecte des événements {log_type} avec win32evtlog...")
                
                try:
                    # Ouvrir le journal d'événements
                    hand = win32evtlog.OpenEventLog(None, log_type)
                    
                    # Lire les événements
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = []
                    
                    try:
                        while len(events) < self.max_events:
                            events_batch = win32evtlog.ReadEventLog(hand, flags, 0)
                            
                            if not events_batch:
                                break
                            
                            for event in events_batch:
                                events.append(event)
                                
                                if len(events) >= self.max_events:
                                    break
                    
                    finally:
                        win32evtlog.CloseEventLog(hand)
                    
                    # Traiter les événements
                    for event in events:
                        # Extraire les informations pertinentes
                        event_id = event.EventID & 0xFFFF  # Masquer les bits de poids fort
                        time_generated = event.TimeGenerated.Format()
                        source_name = event.SourceName
                        event_type = event.EventType
                        
                        # Convertir le type d'événement en niveau
                        level_map = {
                            win32con.EVENTLOG_ERROR_TYPE: "Error",
                            win32con.EVENTLOG_WARNING_TYPE: "Warning",
                            win32con.EVENTLOG_INFORMATION_TYPE: "Information",
                            win32con.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
                            win32con.EVENTLOG_AUDIT_FAILURE: "Audit Failure"
                        }
                        level = level_map.get(event_type, str(event_type))
                        
                        # Extraire le message
                        try:
                            message = win32evtlogutil.SafeFormatMessage(event, log_type)
                        except:
                            message = f"<Message non disponible pour l'événement {event_id}>"
                        
                        # Créer un artefact
                        metadata = {
                            "event_id": str(event_id),
                            "time_created": time_generated,
                            "provider_name": source_name,
                            "level": level,
                            "log_type": log_type
                        }
                        
                        self.add_artifact(
                            artifact_type="event_log",
                            source=f"win32evtlog_{log_type}",
                            data={
                                "message": message,
                                "event_data": {
                                    "event_id": event_id,
                                    "time_generated": time_generated,
                                    "source_name": source_name,
                                    "event_type": event_type
                                }
                            },
                            metadata=metadata
                        )
                    
                    logger.info(f"{len(events)} événements collectés pour {log_type}")
                
                except Exception as e:
                    logger.error(f"Erreur lors de la collecte win32 pour {log_type}: {str(e)}")
                    continue
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec win32evtlog: {str(e)}")
            return False
    
    def _collect_basic_events(self):
        """
        Collecte basique d'événements en cas d'échec des autres méthodes.
        """
        try:
            # Créer quelques artefacts d'exemple pour indiquer que la collecte a été tentée
            for log_type in self.log_types:
                metadata = {
                    "event_id": "0",
                    "time_created": datetime.datetime.now().isoformat(),
                    "provider_name": "ForensicHunter",
                    "level": "Information",
                    "log_type": log_type
                }
                
                self.add_artifact(
                    artifact_type="event_log",
                    source=f"basic_{log_type}",
                    data={
                        "message": f"Collecte d'événements {log_type} tentée mais aucune méthode disponible",
                        "event_data": {}
                    },
                    metadata=metadata
                )
            
            logger.info(f"Collecte basique effectuée pour {len(self.log_types)} types de journaux")
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte basique: {str(e)}")

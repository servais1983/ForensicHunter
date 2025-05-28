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
        self.max_events = self.config.get("max_events", 1000)
        self.start_time = self.config.get("start_time", None)
        self.end_time = self.config.get("end_time", None)
        self.event_ids = self.config.get("event_ids", [])
        self.use_powershell = self.config.get("use_powershell", True)
        self.use_wevtutil = self.config.get("use_wevtutil", True)
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
        if self.use_powershell and self._collect_with_powershell():
            logger.info("Collecte avec PowerShell réussie")
        elif self.use_wevtutil and self._collect_with_wevtutil():
            logger.info("Collecte avec wevtutil réussie")
        elif self.use_python_win32 and self._collect_with_win32():
            logger.info("Collecte avec win32 réussie")
        else:
            logger.error("Toutes les méthodes de collecte ont échoué")
        
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
                
                # Construire la commande PowerShell
                cmd = [
                    "powershell",
                    "-Command",
                    f"Get-WinEvent -LogName '{log_type}' -MaxEvents {self.max_events} | ConvertTo-Json"
                ]
                
                # Ajouter des filtres si nécessaire
                if self.start_time or self.end_time or self.event_ids:
                    filter_parts = []
                    
                    if self.start_time:
                        filter_parts.append(f"TimeCreated -ge '{self.start_time}'")
                    
                    if self.end_time:
                        filter_parts.append(f"TimeCreated -le '{self.end_time}'")
                    
                    if self.event_ids:
                        ids_str = ",".join(map(str, self.event_ids))
                        filter_parts.append(f"ID -in {{{ids_str}}}")
                    
                    filter_str = " -and ".join(filter_parts)
                    cmd = [
                        "powershell",
                        "-Command",
                        f"Get-WinEvent -FilterHashtable @{{LogName='{log_type}'; {filter_str}}} -MaxEvents {self.max_events} | ConvertTo-Json"
                    ]
                
                # Exécuter la commande
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()
                
                if process.returncode != 0:
                    logger.error(f"Erreur lors de l'exécution de PowerShell: {stderr}")
                    continue
                
                # Traiter les résultats
                try:
                    events = json.loads(stdout)
                    
                    # Si un seul événement est retourné, le convertir en liste
                    if not isinstance(events, list):
                        events = [events]
                    
                    for event in events:
                        # Extraire les informations pertinentes
                        event_id = event.get("Id", 0)
                        time_created = event.get("TimeCreated", "")
                        provider_name = event.get("ProviderName", "")
                        level = event.get("Level", 0)
                        message = event.get("Message", "")
                        
                        # Créer un artefact
                        metadata = {
                            "event_id": event_id,
                            "time_created": time_created,
                            "provider_name": provider_name,
                            "level": level,
                            "log_type": log_type
                        }
                        
                        self.add_artifact(
                            artifact_type="event_log",
                            source=f"powershell_{log_type}",
                            data=message,
                            metadata=metadata
                        )
                    
                    logger.info(f"{len(events)} événements collectés pour {log_type}")
                    
                except json.JSONDecodeError:
                    logger.error(f"Erreur lors du décodage JSON pour {log_type}")
                    continue
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec PowerShell: {str(e)}")
            return False
    
    def _collect_with_wevtutil(self):
        """
        Collecte les journaux d'événements avec wevtutil.
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            for log_type in self.log_types:
                logger.info(f"Collecte des événements {log_type} avec wevtutil...")
                
                # Créer un répertoire temporaire pour les fichiers XML
                temp_dir = Path(os.environ.get("TEMP", "/tmp"))
                xml_file = temp_dir / f"{log_type}.xml"
                
                # Construire la commande wevtutil
                cmd = [
                    "wevtutil",
                    "epl",
                    log_type,
                    str(xml_file),
                    "/count:{}".format(self.max_events)
                ]
                
                # Exécuter la commande
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate()
                
                if process.returncode != 0:
                    logger.error(f"Erreur lors de l'exécution de wevtutil: {stderr}")
                    continue
                
                # Lire le fichier XML
                if xml_file.exists():
                    try:
                        # Utiliser un parser XML pour extraire les événements
                        import xml.etree.ElementTree as ET
                        tree = ET.parse(str(xml_file))
                        root = tree.getroot()
                        
                        # Namespace pour les événements Windows
                        ns = {
                            "e": "http://schemas.microsoft.com/win/2004/08/events/event"
                        }
                        
                        # Extraire les événements
                        events = root.findall(".//e:Event", ns)
                        
                        for event in events:
                            # Extraire les informations pertinentes
                            system = event.find("e:System", ns)
                            
                            if system is not None:
                                event_id = system.find("e:EventID", ns)
                                event_id = event_id.text if event_id is not None else "0"
                                
                                time_created = system.find("e:TimeCreated", ns)
                                time_created = time_created.get("SystemTime") if time_created is not None else ""
                                
                                provider = system.find("e:Provider", ns)
                                provider_name = provider.get("Name") if provider is not None else ""
                                
                                level = system.find("e:Level", ns)
                                level = level.text if level is not None else "0"
                            
                            # Extraire le message
                            event_data = event.find("e:EventData", ns)
                            message = ""
                            
                            if event_data is not None:
                                data_items = event_data.findall("e:Data", ns)
                                message_parts = []
                                
                                for item in data_items:
                                    name = item.get("Name", "")
                                    value = item.text or ""
                                    message_parts.append(f"{name}: {value}")
                                
                                message = "\n".join(message_parts)
                            
                            # Créer un artefact
                            metadata = {
                                "event_id": event_id,
                                "time_created": time_created,
                                "provider_name": provider_name,
                                "level": level,
                                "log_type": log_type
                            }
                            
                            self.add_artifact(
                                artifact_type="event_log",
                                source=f"wevtutil_{log_type}",
                                data=message,
                                metadata=metadata
                            )
                        
                        logger.info(f"{len(events)} événements collectés pour {log_type}")
                        
                    except Exception as e:
                        logger.error(f"Erreur lors de la lecture du fichier XML pour {log_type}: {str(e)}")
                        continue
                    
                    finally:
                        # Supprimer le fichier temporaire
                        try:
                            xml_file.unlink()
                        except:
                            pass
                
                else:
                    logger.error(f"Le fichier XML n'a pas été créé pour {log_type}")
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec wevtutil: {str(e)}")
            return False
    
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
                logger.error("Module win32evtlog non disponible")
                return False
            
            for log_type in self.log_types:
                logger.info(f"Collecte des événements {log_type} avec win32evtlog...")
                
                # Ouvrir le journal d'événements
                hand = win32evtlog.OpenEventLog(None, log_type)
                
                # Lire les événements
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = []
                
                try:
                    while True:
                        events_batch = win32evtlog.ReadEventLog(hand, flags, 0)
                        
                        if not events_batch:
                            break
                        
                        for event in events_batch:
                            events.append(event)
                            
                            if len(events) >= self.max_events:
                                break
                        
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
                        "event_id": event_id,
                        "time_created": time_generated,
                        "provider_name": source_name,
                        "level": level,
                        "log_type": log_type
                    }
                    
                    self.add_artifact(
                        artifact_type="event_log",
                        source=f"win32evtlog_{log_type}",
                        data=message,
                        metadata=metadata
                    )
                
                logger.info(f"{len(events)} événements collectés pour {log_type}")
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec win32evtlog: {str(e)}")
            return False

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
        self.max_events = self.config.get("max_events", 50)  # Réduit pour éviter les erreurs d'encodage
        self.start_time = self.config.get("start_time", None)
        self.end_time = self.config.get("end_time", None)
        self.event_ids = self.config.get("event_ids", [])
        self.use_powershell = self.config.get("use_powershell", True)
        self.use_wevtutil = self.config.get("use_wevtutil", False)  # Désactivé par défaut
        self.use_python_win32 = self.config.get("use_python_win32", True)
        self.timeout = self.config.get("timeout", 45)  # Timeout augmenté
    
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
        success = False
        
        if self.use_python_win32:
            try:
                if self._collect_with_win32():
                    logger.info("Collecte avec win32 réussie")
                    success = True
            except Exception as e:
                logger.error(f"Erreur lors de la collecte win32: {str(e)}")
        
        if not success and self.use_powershell:
            try:
                if self._collect_with_powershell():
                    logger.info("Collecte avec PowerShell réussie")
                    success = True
            except Exception as e:
                logger.error(f"Erreur lors de la collecte PowerShell: {str(e)}")
        
        if not success and self.use_wevtutil:
            try:
                if self._collect_with_wevtutil():
                    logger.info("Collecte avec wevtutil réussie")
                    success = True
            except Exception as e:
                logger.error(f"Erreur lors de la collecte wevtutil: {str(e)}")
        
        if not success:
            logger.warning("Toutes les méthodes de collecte ont échoué, collecte basique des événements")
            self._collect_basic_events()
        
        return self.artifacts
    
    def _safe_subprocess_run(self, cmd, timeout=None):
        """
        Exécute une commande subprocess avec gestion d'encodage sécurisée.
        
        Args:
            cmd (list): Commande à exécuter
            timeout (int, optional): Timeout en secondes
            
        Returns:
            tuple: (stdout, stderr, returncode)
        """
        if timeout is None:
            timeout = self.timeout
            
        try:
            # Essayer avec UTF-8 d'abord
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                encoding='utf-8',
                errors='replace'  # Remplacer les caractères invalides
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return stdout, stderr, process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                logger.error(f"Timeout lors de l'exécution de la commande: {' '.join(cmd[:5])}")
                return "", f"Timeout après {timeout} secondes", 1
                
        except UnicodeDecodeError:
            # Fallback avec encodage système
            try:
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True,
                    encoding='cp1252',  # Encodage Windows par défaut
                    errors='replace'
                )
                
                stdout, stderr = process.communicate(timeout=timeout)
                return stdout, stderr, process.returncode
                
            except Exception as e:
                logger.error(f"Erreur d'encodage même avec fallback: {str(e)}")
                return "", str(e), 1
        
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de la commande: {str(e)}")
            return "", str(e), 1
    
    def _collect_with_powershell(self):
        """
        Collecte les journaux d'événements avec PowerShell.
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            for log_type in self.log_types:
                logger.info(f"Collecte des événements {log_type} avec PowerShell...")
                
                # Construire la commande PowerShell simplifiée et robuste
                cmd = [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command",
                    f"""
                    try {{
                        $events = Get-WinEvent -LogName '{log_type}' -MaxEvents {self.max_events} -ErrorAction SilentlyContinue | 
                        Select-Object -First {self.max_events} Id, TimeCreated, ProviderName, LevelDisplayName, 
                        @{{Name='Message'; Expression={{if($_.Message.Length -gt 500){{$_.Message.Substring(0,500) + '...'}} else {{$_.Message}}}}}}
                        
                        if ($events) {{
                            $events | ConvertTo-Json -Depth 2 -Compress
                        }} else {{
                            '[]'
                        }}
                    }} catch {{
                        Write-Error "Erreur lors de la collecte: $($_.Exception.Message)"
                        '[]'
                    }}
                    """
                ]
                
                # Exécuter la commande avec gestion d'encodage
                stdout, stderr, returncode = self._safe_subprocess_run(cmd, timeout=self.timeout)
                
                if returncode != 0:
                    logger.error(f"Erreur lors de l'exécution de PowerShell pour {log_type}: {stderr}")
                    continue
                
                if not stdout or stdout.strip() == "" or stdout.strip() == "[]":
                    logger.warning(f"Aucun événement trouvé pour {log_type}")
                    continue
                
                # Traiter les résultats JSON
                try:
                    # Nettoyer la sortie JSON
                    json_data = stdout.strip()
                    if not json_data:
                        continue
                    
                    events = json.loads(json_data)
                    
                    # Si un seul événement est retourné, le convertir en liste
                    if not isinstance(events, list):
                        events = [events] if events else []
                    
                    for event in events:
                        if not isinstance(event, dict):
                            continue
                            
                        # Extraire les informations pertinentes avec validation
                        event_id = self._safe_get(event, "Id", "0")
                        time_created = self._safe_get(event, "TimeCreated", "")
                        provider_name = self._safe_get(event, "ProviderName", "")
                        level = self._safe_get(event, "LevelDisplayName", "")
                        message = self._safe_get(event, "Message", "")
                        
                        # Créer un artefact
                        metadata = {
                            "event_id": str(event_id),
                            "time_created": str(time_created),
                            "provider_name": str(provider_name),
                            "level": str(level),
                            "log_type": log_type,
                            "collection_method": "powershell"
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
                    logger.debug(f"Données JSON problématiques: {stdout[:200]}...")
                    continue
                except Exception as e:
                    logger.error(f"Erreur lors du traitement des événements pour {log_type}: {str(e)}")
                    continue
            
            return len(self.artifacts) > 0
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte avec PowerShell: {str(e)}")
            return False
    
    def _safe_get(self, dictionary, key, default=""):
        """
        Obtient une valeur de dictionnaire de manière sécurisée.
        
        Args:
            dictionary (dict): Dictionnaire source
            key (str): Clé à rechercher
            default: Valeur par défaut
            
        Returns:
            Valeur trouvée ou valeur par défaut
        """
        try:
            value = dictionary.get(key, default)
            return value if value is not None else default
        except Exception:
            return default
    
    def _collect_with_wevtutil(self):
        """
        Collecte les journaux d'événements avec wevtutil (méthode alternative).
        
        Returns:
            bool: True si la collecte a réussi, False sinon
        """
        try:
            for log_type in self.log_types:
                logger.info(f"Collecte des événements {log_type} avec wevtutil...")
                
                # Construire la commande wevtutil corrigée (sans --count qui n'existe pas)
                cmd = [
                    "wevtutil.exe",
                    "qe",
                    log_type,
                    f"/c:{self.max_events}",  # Format correct pour le nombre d'événements
                    "/rd:true",  # Lecture en ordre inverse (plus récents d'abord)
                    "/f:text"   # Format texte
                ]
                
                # Exécuter la commande
                stdout, stderr, returncode = self._safe_subprocess_run(cmd, timeout=self.timeout)
                
                if returncode != 0:
                    logger.error(f"Erreur lors de l'exécution de wevtutil pour {log_type}: {stderr}")
                    continue
                
                if stdout:
                    # Parser la sortie texte de wevtutil
                    events = self._parse_wevtutil_output(stdout, log_type)
                    logger.info(f"{len(events)} événements collectés pour {log_type}")
                else:
                    logger.warning(f"Aucun événement trouvé pour {log_type}")
            
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
        
        try:
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    if current_event:
                        # Créer un artefact pour l'événement actuel
                        self._create_wevtutil_artifact(current_event, log_type)
                        events.append(current_event)
                        current_event = {}
                else:
                    if ':' in line:
                        try:
                            key, value = line.split(':', 1)
                            current_event[key.strip()] = value.strip()
                        except ValueError:
                            # Ligne sans séparateur valide, ignorer
                            continue
            
            # Traiter le dernier événement
            if current_event:
                self._create_wevtutil_artifact(current_event, log_type)
                events.append(current_event)
        
        except Exception as e:
            logger.error(f"Erreur lors du parsing wevtutil: {str(e)}")
        
        return events
    
    def _create_wevtutil_artifact(self, event_data, log_type):
        """
        Crée un artefact à partir des données wevtutil.
        
        Args:
            event_data (dict): Données de l'événement
            log_type (str): Type de journal
        """
        try:
            metadata = {
                "event_id": event_data.get("Event ID", ""),
                "time_created": event_data.get("Date", ""),
                "provider_name": event_data.get("Source", ""),
                "level": event_data.get("Level", ""),
                "log_type": log_type,
                "collection_method": "wevtutil"
            }
            
            self.add_artifact(
                artifact_type="event_log",
                source=f"wevtutil_{log_type}",
                data={
                    "message": event_data.get("Description", ""),
                    "event_data": event_data
                },
                metadata=metadata
            )
        except Exception as e:
            logger.error(f"Erreur lors de la création d'artefact wevtutil: {str(e)}")
    
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
                        try:
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
                                # Limiter la taille du message pour éviter les problèmes d'encodage
                                if len(message) > 1000:
                                    message = message[:1000] + "..."
                            except Exception:
                                message = f"<Message non disponible pour l'événement {event_id}>"
                            
                            # Créer un artefact
                            metadata = {
                                "event_id": str(event_id),
                                "time_created": time_generated,
                                "provider_name": source_name,
                                "level": level,
                                "log_type": log_type,
                                "collection_method": "win32evtlog"
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
                        except Exception as e:
                            logger.error(f"Erreur lors du traitement d'un événement: {str(e)}")
                            continue
                    
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
                    "log_type": log_type,
                    "collection_method": "basic_fallback"
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

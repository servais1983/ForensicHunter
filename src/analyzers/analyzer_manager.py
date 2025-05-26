#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion des analyseurs d'anomalies.

Ce module coordonne l'exécution des différents analyseurs d'anomalies
et agrège leurs résultats pour la détection de comportements suspects.
"""

import os
import logging
from typing import Dict, List, Any, Optional

from src.analyzers.event_analyzer import EventLogAnalyzer
from src.analyzers.registry_analyzer import RegistryAnalyzer
from src.analyzers.filesystem_analyzer import FilesystemAnalyzer
from src.analyzers.browser_analyzer import BrowserAnalyzer
from src.analyzers.process_analyzer import ProcessAnalyzer
from src.analyzers.network_analyzer import NetworkAnalyzer
from src.analyzers.usb_analyzer import USBAnalyzer
from src.analyzers.userdata_analyzer import UserDataAnalyzer

logger = logging.getLogger("forensichunter")


class AnalyzerManager:
    """Gestionnaire des analyseurs d'anomalies."""

    def __init__(self, config):
        """
        Initialise le gestionnaire d'analyseurs.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.analyzers = {}
        self._register_analyzers()
    
    def _register_analyzers(self):
        """Enregistre les analyseurs disponibles."""
        self.analyzers = {
            "eventlogs": EventLogAnalyzer(self.config),
            "registry": RegistryAnalyzer(self.config),
            "filesystem": FilesystemAnalyzer(self.config),
            "browser": BrowserAnalyzer(self.config),
            "process": ProcessAnalyzer(self.config),
            "network": NetworkAnalyzer(self.config),
            "usb": USBAnalyzer(self.config),
            "userdata": UserDataAnalyzer(self.config)
        }
    
    def analyze_artifacts(self, artifacts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse les artefacts collectés pour détecter des anomalies.
        
        Args:
            artifacts: Dictionnaire contenant tous les artefacts collectés
            
        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        analysis_results = {
            "alerts": [],
            "scores": {},
            "summary": {}
        }
        
        logger.info("Démarrage de l'analyse des artefacts...")
        
        # Analyse des journaux d'événements
        if "EventLogCollector" in artifacts:
            try:
                eventlog_results = self.analyzers["eventlogs"].analyze(artifacts["EventLogCollector"])
                self._merge_analysis_results(analysis_results, eventlog_results)
                logger.info(f"Analyse des journaux d'événements terminée: {len(eventlog_results.get('alerts', []))} alertes")
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse des journaux d'événements: {str(e)}")
                logger.debug("Détails de l'erreur:", exc_info=True)
        
        # Analyse du registre
        if "RegistryCollector" in artifacts:
            try:
                registry_results = self.analyzers["registry"].analyze(artifacts["RegistryCollector"])
                self._merge_analysis_results(analysis_results, registry_results)
                logger.info(f"Analyse du registre terminée: {len(registry_results.get('alerts', []))} alertes")
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse du registre: {str(e)}")
                logger.debug("Détails de l'erreur:", exc_info=True)
        
        # Analyse des artefacts du système de fichiers
        if "FilesystemCollector" in artifacts:
            try:
                filesystem_results = self.analyzers["filesystem"].analyze(artifacts["FilesystemCollector"])
                self._merge_analysis_results(analysis_results, filesystem_results)
                logger.info(f"Analyse des artefacts du système de fichiers terminée: {len(filesystem_results.get('alerts', []))} alertes")
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse des artefacts du système de fichiers: {str(e)}")
                logger.debug("Détails de l'erreur:", exc_info=True)
        
        # Analyse de l'historique des navigateurs
        if "BrowserHistoryCollector" in artifacts:
            try:
                browser_results = self.analyzers["browser"].analyze(artifacts["BrowserHistoryCollector"])
                self._merge_analysis_results(analysis_results, browser_results)
                logger.info(f"Analyse de l'historique des navigateurs terminée: {len(browser_results.get('alerts', []))} alertes")
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse de l'historique des navigateurs: {str(e)}")
                logger.debug("Détails de l'erreur:", exc_info=True)
        
        # Analyse des processus
        if "ProcessCollector" in artifacts:
            try:
                process_results = self.analyzers["process"].analyze(artifacts["ProcessCollector"])
                self._merge_analysis_results(analysis_results, process_results)
                logger.info(f"Analyse des processus terminée: {len(process_results.get('alerts', []))} alertes")
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse des processus: {str(e)}")
                logger.debug("Détails de l'erreur:", exc_info=True)
        
        # Analyse des connexions réseau
        if "NetworkCollector" in artifacts:
            try:
                network_results = self.analyzers["network"].analyze(artifacts["NetworkCollector"])
                self._merge_analysis_results(analysis_results, network_results)
                logger.info(f"Analyse des connexions réseau terminée: {len(network_results.get('alerts', []))} alertes")
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse des connexions réseau: {str(e)}")
                logger.debug("Détails de l'erreur:", exc_info=True)
        
        # Analyse des périphériques USB
        if "USBCollector" in artifacts:
            try:
                usb_results = self.analyzers["usb"].analyze(artifacts["USBCollector"])
                self._merge_analysis_results(analysis_results, usb_results)
                logger.info(f"Analyse des périphériques USB terminée: {len(usb_results.get('alerts', []))} alertes")
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse des périphériques USB: {str(e)}")
                logger.debug("Détails de l'erreur:", exc_info=True)
        
        # Analyse des données utilisateur
        if "UserDataCollector" in artifacts:
            try:
                userdata_results = self.analyzers["userdata"].analyze(artifacts["UserDataCollector"])
                self._merge_analysis_results(analysis_results, userdata_results)
                logger.info(f"Analyse des données utilisateur terminée: {len(userdata_results.get('alerts', []))} alertes")
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse des données utilisateur: {str(e)}")
                logger.debug("Détails de l'erreur:", exc_info=True)
        
        # Calcul du score global
        analysis_results["global_score"] = self._calculate_global_score(analysis_results["scores"])
        
        # Génération du résumé global
        analysis_results["summary"]["total_alerts"] = len(analysis_results["alerts"])
        analysis_results["summary"]["alert_types"] = self._count_alert_types(analysis_results["alerts"])
        analysis_results["summary"]["severity_distribution"] = self._count_severity_distribution(analysis_results["alerts"])
        
        logger.info(f"Analyse terminée: {analysis_results['summary']['total_alerts']} alertes détectées")
        
        return analysis_results
    
    def _merge_analysis_results(self, target: Dict[str, Any], source: Dict[str, Any]):
        """
        Fusionne les résultats d'analyse d'un analyseur dans les résultats globaux.
        
        Args:
            target: Dictionnaire cible (résultats globaux)
            source: Dictionnaire source (résultats d'un analyseur)
        """
        # Fusion des alertes
        if "alerts" in source and isinstance(source["alerts"], list):
            target["alerts"].extend(source["alerts"])
        
        # Fusion des scores
        if "scores" in source and isinstance(source["scores"], dict):
            for category, score in source["scores"].items():
                target["scores"][category] = score
        
        # Fusion des résumés
        if "summary" in source and isinstance(source["summary"], dict):
            for key, value in source["summary"].items():
                target["summary"][key] = value
    
    def _calculate_global_score(self, scores: Dict[str, float]) -> float:
        """
        Calcule un score global à partir des scores par catégorie.
        
        Args:
            scores: Dictionnaire des scores par catégorie
            
        Returns:
            Score global
        """
        if not scores:
            return 0.0
        
        # Pondération des catégories
        weights = {
            "eventlogs": 1.0,
            "registry": 1.0,
            "filesystem": 0.8,
            "browser": 0.6,
            "process": 1.2,
            "network": 1.2,
            "usb": 0.7,
            "userdata": 0.5
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for category, score in scores.items():
            weight = weights.get(category, 1.0)
            total_score += score * weight
            total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        # Normalisation du score entre 0 et 100
        return min(100.0, max(0.0, total_score / total_weight))
    
    def _count_alert_types(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Compte le nombre d'alertes par type.
        
        Args:
            alerts: Liste des alertes
            
        Returns:
            Dictionnaire contenant le nombre d'alertes par type
        """
        alert_types = {}
        
        for alert in alerts:
            alert_type = alert.get("type", "unknown")
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
        
        return alert_types
    
    def _count_severity_distribution(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Compte le nombre d'alertes par niveau de sévérité.
        
        Args:
            alerts: Liste des alertes
            
        Returns:
            Dictionnaire contenant le nombre d'alertes par niveau de sévérité
        """
        severity_distribution = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for alert in alerts:
            severity = alert.get("severity", "info").lower()
            if severity in severity_distribution:
                severity_distribution[severity] += 1
        
        return severity_distribution

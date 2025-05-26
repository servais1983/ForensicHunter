#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'analyse forensique à distance pour ForensicHunter (Phase 3).

Ce module permet d'effectuer des analyses forensiques à distance sur des
systèmes connectés au réseau, sans nécessiter d'accès physique.
"""

import os
import json
import logging
import datetime
import socket
import ssl
import time
import uuid
import threading
from typing import Dict, List, Any, Optional, Union

from src.utils.security.security_manager import SecurityManager

logger = logging.getLogger("forensichunter")


class RemoteAnalyzer:
    """Classe principale pour l'analyse forensique à distance."""

    def __init__(self, config):
        """
        Initialise l'analyseur à distance.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.security_manager = SecurityManager(config)
        self.sessions = {}
        self.agents = {}
        self._load_agent_templates()
    
    def _load_agent_templates(self):
        """
        Charge les modèles d'agents à distance.
        """
        logger.info("Chargement des modèles d'agents à distance")
        
        try:
            # Vérification des répertoires de modèles
            agents_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agents")
            os.makedirs(agents_dir, exist_ok=True)
            
            # Chargement des modèles d'agents (simulation pour l'instant)
            self.agents["windows"] = self._load_agent_template(agents_dir, "windows")
            self.agents["linux"] = self._load_agent_template(agents_dir, "linux")
            self.agents["macos"] = self._load_agent_template(agents_dir, "macos")
            
            logger.info(f"{len(self.agents)} modèles d'agents chargés avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement des modèles d'agents: {str(e)}")
    
    def _load_agent_template(self, agents_dir: str, os_type: str) -> Dict[str, Any]:
        """
        Charge un modèle d'agent pour un système d'exploitation spécifique.
        
        Args:
            agents_dir: Répertoire des agents
            os_type: Type de système d'exploitation
            
        Returns:
            Modèle d'agent
        """
        # Simulation de chargement de modèle d'agent
        agent_path = os.path.join(agents_dir, f"{os_type}_agent.template")
        
        # Vérifier si le modèle existe
        if os.path.exists(agent_path):
            logger.info(f"Chargement du modèle d'agent {os_type} depuis {agent_path}")
            # Ici, on chargerait réellement le modèle
            with open(agent_path, "r") as f:
                agent_template = f.read()
        else:
            logger.warning(f"Modèle d'agent {os_type} non trouvé à {agent_path}, utilisation du modèle par défaut")
            # Modèle par défaut
            agent_template = f"# Agent ForensicHunter pour {os_type}\n# Modèle par défaut\n"
        
        return {
            "template": agent_template,
            "os_type": os_type,
            "version": "1.0.0"
        }
    
    def create_session(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """
        Crée une session d'analyse à distance.
        
        Args:
            target: Informations sur la cible (adresse IP, port, système d'exploitation, etc.)
            
        Returns:
            Informations sur la session créée
        """
        logger.info(f"Création d'une session d'analyse à distance pour {target.get('hostname', target.get('ip', 'cible inconnue'))}")
        
        # Validation de la cible
        if not self._validate_target(target):
            error_msg = "Cible d'analyse à distance invalide"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Génération d'un identifiant de session unique
        session_id = str(uuid.uuid4())
        
        # Création de la session
        session = {
            "id": session_id,
            "target": target,
            "status": "created",
            "created_at": datetime.datetime.now().isoformat(),
            "updated_at": datetime.datetime.now().isoformat(),
            "artifacts": {},
            "logs": []
        }
        
        # Enregistrement de la session
        self.sessions[session_id] = session
        
        # Ajout d'un log
        self._add_session_log(session_id, "Session créée")
        
        return {"session_id": session_id, "status": "created"}
    
    def deploy_agent(self, session_id: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Déploie un agent sur la cible.
        
        Args:
            session_id: Identifiant de la session
            options: Options de déploiement
            
        Returns:
            Résultat du déploiement
        """
        logger.info(f"Déploiement d'un agent pour la session {session_id}")
        
        # Vérification de la session
        if session_id not in self.sessions:
            error_msg = f"Session {session_id} introuvable"
            logger.error(error_msg)
            return {"error": error_msg}
        
        session = self.sessions[session_id]
        
        # Vérification du statut de la session
        if session["status"] != "created":
            error_msg = f"La session {session_id} n'est pas dans l'état 'created' (état actuel: {session['status']})"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Récupération du type de système d'exploitation
        os_type = session["target"].get("os_type", "windows")
        if os_type not in self.agents:
            error_msg = f"Type de système d'exploitation non supporté: {os_type}"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Simulation du déploiement de l'agent
        try:
            # Dans une implémentation réelle, on déploierait l'agent sur la cible
            # via SSH, WinRM, SMB, etc.
            
            # Mise à jour du statut de la session
            session["status"] = "agent_deployed"
            session["updated_at"] = datetime.datetime.now().isoformat()
            session["agent"] = {
                "type": os_type,
                "version": self.agents[os_type]["version"],
                "deployed_at": datetime.datetime.now().isoformat()
            }
            
            # Ajout d'un log
            self._add_session_log(session_id, f"Agent déployé sur la cible ({os_type})")
            
            return {"status": "agent_deployed", "agent_type": os_type}
            
        except Exception as e:
            error_msg = f"Erreur lors du déploiement de l'agent: {str(e)}"
            logger.error(error_msg)
            self._add_session_log(session_id, error_msg)
            return {"error": error_msg}
    
    def collect_artifacts(self, session_id: str, artifact_types: List[str]) -> Dict[str, Any]:
        """
        Collecte des artefacts sur la cible.
        
        Args:
            session_id: Identifiant de la session
            artifact_types: Types d'artefacts à collecter
            
        Returns:
            Résultat de la collecte
        """
        logger.info(f"Collecte d'artefacts pour la session {session_id}")
        
        # Vérification de la session
        if session_id not in self.sessions:
            error_msg = f"Session {session_id} introuvable"
            logger.error(error_msg)
            return {"error": error_msg}
        
        session = self.sessions[session_id]
        
        # Vérification du statut de la session
        if session["status"] != "agent_deployed":
            error_msg = f"La session {session_id} n'est pas dans l'état 'agent_deployed' (état actuel: {session['status']})"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Validation des types d'artefacts
        valid_artifact_types = ["event_logs", "registry", "browser_history", "processes", "network", "usb_devices", "filesystem", "memory", "user_data"]
        for artifact_type in artifact_types:
            if artifact_type not in valid_artifact_types:
                error_msg = f"Type d'artefact non supporté: {artifact_type}"
                logger.error(error_msg)
                return {"error": error_msg}
        
        # Simulation de la collecte d'artefacts
        try:
            # Dans une implémentation réelle, on enverrait des commandes à l'agent
            # pour collecter les artefacts demandés
            
            # Mise à jour du statut de la session
            session["status"] = "collecting"
            session["updated_at"] = datetime.datetime.now().isoformat()
            
            # Ajout d'un log
            self._add_session_log(session_id, f"Début de la collecte d'artefacts: {', '.join(artifact_types)}")
            
            # Simulation de la collecte (asynchrone)
            thread = threading.Thread(target=self._simulate_collection, args=(session_id, artifact_types))
            thread.daemon = True
            thread.start()
            
            return {"status": "collecting", "artifact_types": artifact_types}
            
        except Exception as e:
            error_msg = f"Erreur lors de la collecte d'artefacts: {str(e)}"
            logger.error(error_msg)
            self._add_session_log(session_id, error_msg)
            return {"error": error_msg}
    
    def _simulate_collection(self, session_id: str, artifact_types: List[str]):
        """
        Simule la collecte d'artefacts (asynchrone).
        
        Args:
            session_id: Identifiant de la session
            artifact_types: Types d'artefacts à collecter
        """
        session = self.sessions[session_id]
        
        # Simulation de la collecte
        for artifact_type in artifact_types:
            # Simulation de délai
            time.sleep(2)
            
            # Ajout d'un log
            self._add_session_log(session_id, f"Collecte de {artifact_type} en cours...")
            
            # Simulation de données collectées
            if artifact_type == "event_logs":
                session["artifacts"][artifact_type] = {
                    "system": {"count": 150, "size": 1024000},
                    "security": {"count": 200, "size": 2048000},
                    "application": {"count": 100, "size": 512000}
                }
            elif artifact_type == "registry":
                session["artifacts"][artifact_type] = {
                    "hives": ["SYSTEM", "SOFTWARE", "SECURITY", "SAM"],
                    "count": 500,
                    "size": 5120000
                }
            elif artifact_type == "processes":
                session["artifacts"][artifact_type] = {
                    "count": 50,
                    "size": 256000
                }
            else:
                session["artifacts"][artifact_type] = {
                    "count": 100,
                    "size": 1024000
                }
            
            # Ajout d'un log
            self._add_session_log(session_id, f"Collecte de {artifact_type} terminée")
        
        # Mise à jour du statut de la session
        session["status"] = "collected"
        session["updated_at"] = datetime.datetime.now().isoformat()
        
        # Ajout d'un log
        self._add_session_log(session_id, "Collecte d'artefacts terminée")
    
    def analyze_artifacts(self, session_id: str) -> Dict[str, Any]:
        """
        Analyse les artefacts collectés.
        
        Args:
            session_id: Identifiant de la session
            
        Returns:
            Résultat de l'analyse
        """
        logger.info(f"Analyse des artefacts pour la session {session_id}")
        
        # Vérification de la session
        if session_id not in self.sessions:
            error_msg = f"Session {session_id} introuvable"
            logger.error(error_msg)
            return {"error": error_msg}
        
        session = self.sessions[session_id]
        
        # Vérification du statut de la session
        if session["status"] != "collected":
            error_msg = f"La session {session_id} n'est pas dans l'état 'collected' (état actuel: {session['status']})"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Vérification des artefacts
        if not session["artifacts"]:
            error_msg = "Aucun artefact à analyser"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Simulation de l'analyse des artefacts
        try:
            # Dans une implémentation réelle, on analyserait les artefacts collectés
            
            # Mise à jour du statut de la session
            session["status"] = "analyzing"
            session["updated_at"] = datetime.datetime.now().isoformat()
            
            # Ajout d'un log
            self._add_session_log(session_id, "Début de l'analyse des artefacts")
            
            # Simulation de l'analyse (asynchrone)
            thread = threading.Thread(target=self._simulate_analysis, args=(session_id,))
            thread.daemon = True
            thread.start()
            
            return {"status": "analyzing"}
            
        except Exception as e:
            error_msg = f"Erreur lors de l'analyse des artefacts: {str(e)}"
            logger.error(error_msg)
            self._add_session_log(session_id, error_msg)
            return {"error": error_msg}
    
    def _simulate_analysis(self, session_id: str):
        """
        Simule l'analyse des artefacts (asynchrone).
        
        Args:
            session_id: Identifiant de la session
        """
        session = self.sessions[session_id]
        
        # Simulation de l'analyse
        time.sleep(5)
        
        # Simulation des résultats
        session["analysis"] = {
            "timestamp": datetime.datetime.now().isoformat(),
            "findings": [
                {
                    "type": "malware",
                    "severity": "high",
                    "description": "Malware détecté dans les processus",
                    "artifacts": ["processes"],
                    "confidence": 0.85
                },
                {
                    "type": "unauthorized_access",
                    "severity": "medium",
                    "description": "Tentative d'accès non autorisé détectée dans les journaux d'événements",
                    "artifacts": ["event_logs"],
                    "confidence": 0.75
                },
                {
                    "type": "data_exfiltration",
                    "severity": "high",
                    "description": "Exfiltration de données détectée dans les connexions réseau",
                    "artifacts": ["network"],
                    "confidence": 0.9
                }
            ],
            "summary": "Système compromis avec présence de malware et exfiltration de données"
        }
        
        # Mise à jour du statut de la session
        session["status"] = "analyzed"
        session["updated_at"] = datetime.datetime.now().isoformat()
        
        # Ajout d'un log
        self._add_session_log(session_id, "Analyse des artefacts terminée")
    
    def generate_report(self, session_id: str, format: str = "html") -> Dict[str, Any]:
        """
        Génère un rapport d'analyse.
        
        Args:
            session_id: Identifiant de la session
            format: Format du rapport (html, json, pdf)
            
        Returns:
            Résultat de la génération du rapport
        """
        logger.info(f"Génération d'un rapport {format} pour la session {session_id}")
        
        # Vérification de la session
        if session_id not in self.sessions:
            error_msg = f"Session {session_id} introuvable"
            logger.error(error_msg)
            return {"error": error_msg}
        
        session = self.sessions[session_id]
        
        # Vérification du statut de la session
        if session["status"] != "analyzed":
            error_msg = f"La session {session_id} n'est pas dans l'état 'analyzed' (état actuel: {session['status']})"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Validation du format
        valid_formats = ["html", "json", "pdf"]
        if format not in valid_formats:
            error_msg = f"Format de rapport non supporté: {format}"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Simulation de la génération du rapport
        try:
            # Dans une implémentation réelle, on générerait le rapport
            
            # Génération d'un nom de fichier
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"remote_analysis_{session_id}_{timestamp}.{format}"
            report_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports", report_filename)
            
            # Création du répertoire des rapports si nécessaire
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            
            # Simulation de l'écriture du rapport
            with open(report_path, "w") as f:
                if format == "html":
                    f.write("<html><head><title>Rapport d'analyse à distance</title></head><body>")
                    f.write(f"<h1>Rapport d'analyse à distance</h1>")
                    f.write(f"<p>Session: {session_id}</p>")
                    f.write(f"<p>Cible: {session['target'].get('hostname', session['target'].get('ip', 'inconnue'))}</p>")
                    f.write(f"<p>Date: {datetime.datetime.now().isoformat()}</p>")
                    f.write("<h2>Résultats de l'analyse</h2>")
                    f.write(f"<p>{session['analysis']['summary']}</p>")
                    f.write("<h3>Découvertes</h3>")
                    f.write("<ul>")
                    for finding in session["analysis"]["findings"]:
                        f.write(f"<li><strong>{finding['type']}</strong> ({finding['severity']}): {finding['description']}</li>")
                    f.write("</ul>")
                    f.write("</body></html>")
                elif format == "json":
                    json.dump(session, f, indent=2)
                elif format == "pdf":
                    # Simulation d'un rapport PDF (en réalité, juste du texte)
                    f.write("Rapport d'analyse à distance (PDF simulé)\n")
                    f.write(f"Session: {session_id}\n")
                    f.write(f"Cible: {session['target'].get('hostname', session['target'].get('ip', 'inconnue'))}\n")
                    f.write(f"Date: {datetime.datetime.now().isoformat()}\n")
                    f.write("Résultats de l'analyse:\n")
                    f.write(f"{session['analysis']['summary']}\n")
                    f.write("Découvertes:\n")
                    for finding in session["analysis"]["findings"]:
                        f.write(f"- {finding['type']} ({finding['severity']}): {finding['description']}\n")
            
            # Mise à jour du statut de la session
            session["status"] = "reported"
            session["updated_at"] = datetime.datetime.now().isoformat()
            session["report"] = {
                "format": format,
                "path": report_path,
                "generated_at": datetime.datetime.now().isoformat()
            }
            
            # Ajout d'un log
            self._add_session_log(session_id, f"Rapport {format} généré: {report_path}")
            
            return {"status": "reported", "report_path": report_path}
            
        except Exception as e:
            error_msg = f"Erreur lors de la génération du rapport: {str(e)}"
            logger.error(error_msg)
            self._add_session_log(session_id, error_msg)
            return {"error": error_msg}
    
    def cleanup_session(self, session_id: str) -> Dict[str, Any]:
        """
        Nettoie une session d'analyse à distance.
        
        Args:
            session_id: Identifiant de la session
            
        Returns:
            Résultat du nettoyage
        """
        logger.info(f"Nettoyage de la session {session_id}")
        
        # Vérification de la session
        if session_id not in self.sessions:
            error_msg = f"Session {session_id} introuvable"
            logger.error(error_msg)
            return {"error": error_msg}
        
        session = self.sessions[session_id]
        
        # Simulation du nettoyage
        try:
            # Dans une implémentation réelle, on supprimerait l'agent de la cible
            
            # Mise à jour du statut de la session
            session["status"] = "cleaned"
            session["updated_at"] = datetime.datetime.now().isoformat()
            
            # Ajout d'un log
            self._add_session_log(session_id, "Session nettoyée")
            
            return {"status": "cleaned"}
            
        except Exception as e:
            error_msg = f"Erreur lors du nettoyage de la session: {str(e)}"
            logger.error(error_msg)
            self._add_session_log(session_id, error_msg)
            return {"error": error_msg}
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """
        Récupère le statut d'une session.
        
        Args:
            session_id: Identifiant de la session
            
        Returns:
            Statut de la session
        """
        logger.info(f"Récupération du statut de la session {session_id}")
        
        # Vérification de la session
        if session_id not in self.sessions:
            error_msg = f"Session {session_id} introuvable"
            logger.error(error_msg)
            return {"error": error_msg}
        
        session = self.sessions[session_id]
        
        return {
            "session_id": session_id,
            "status": session["status"],
            "created_at": session["created_at"],
            "updated_at": session["updated_at"],
            "target": session["target"],
            "artifact_count": len(session.get("artifacts", {})),
            "has_analysis": "analysis" in session,
            "has_report": "report" in session
        }
    
    def _validate_target(self, target: Dict[str, Any]) -> bool:
        """
        Valide une cible d'analyse à distance.
        
        Args:
            target: Informations sur la cible
            
        Returns:
            True si la cible est valide, False sinon
        """
        # Vérification des informations requises
        if "ip" not in target and "hostname" not in target:
            logger.error("Adresse IP ou nom d'hôte requis")
            return False
        
        # Validation de l'adresse IP si présente
        if "ip" in target:
            ip = target["ip"]
            if not self.security_manager.validate_input(ip, "ip"):
                logger.error(f"Adresse IP invalide: {ip}")
                return False
        
        # Validation du nom d'hôte si présent
        if "hostname" in target:
            hostname = target["hostname"]
            if not self.security_manager.validate_input(hostname, "hostname"):
                logger.error(f"Nom d'hôte invalide: {hostname}")
                return False
        
        # Validation du port si présent
        if "port" in target:
            port = target["port"]
            if not isinstance(port, int) or port < 1 or port > 65535:
                logger.error(f"Port invalide: {port}")
                return False
        
        return True
    
    def _add_session_log(self, session_id: str, message: str):
        """
        Ajoute un message de log à une session.
        
        Args:
            session_id: Identifiant de la session
            message: Message de log
        """
        if session_id in self.sessions:
            log_entry = {
                "timestamp": datetime.datetime.now().isoformat(),
                "message": message
            }
            self.sessions[session_id]["logs"].append(log_entry)
            logger.info(f"[Session {session_id}] {message}")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion de la chaîne de custody pour les preuves numériques.

Ce module implémente un système de traçabilité complet pour documenter
l'ensemble des manipulations effectuées sur les preuves numériques,
garantissant ainsi leur recevabilité en justice.
"""

import os
import json
import uuid
import datetime
import logging
import platform
import getpass
from typing import Dict, List, Any, Optional

from src.utils.integrity.hash_calculator import HashCalculator

logger = logging.getLogger("forensichunter")


class ChainOfCustody:
    """Gestionnaire de chaîne de custody pour les preuves numériques."""

    def __init__(self, case_id: str, investigator: str = None, output_dir: str = None):
        """
        Initialise le gestionnaire de chaîne de custody.
        
        Args:
            case_id: Identifiant unique de l'affaire
            investigator: Nom de l'investigateur (par défaut: utilisateur actuel)
            output_dir: Répertoire de sortie pour les fichiers de chaîne de custody
        """
        self.case_id = case_id
        self.investigator = investigator or getpass.getuser()
        self.output_dir = output_dir or os.path.join(os.getcwd(), "custody_chain")
        
        # Création du répertoire de sortie s'il n'existe pas
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Informations sur l'environnement d'exécution
        self.environment = {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "date": datetime.datetime.now().isoformat()
        }
        
        # Journal des événements
        self.events = []
        
        # Initialisation de la chaîne de custody
        self._initialize_custody_chain()
    
    def _initialize_custody_chain(self):
        """Initialise la chaîne de custody avec les informations de base."""
        self.add_event(
            event_type="initialization",
            description="Initialisation de la chaîne de custody",
            details={
                "case_id": self.case_id,
                "investigator": self.investigator,
                "environment": self.environment
            }
        )
    
    def add_event(self, event_type: str, description: str, details: Dict[str, Any] = None) -> str:
        """
        Ajoute un événement à la chaîne de custody.
        
        Args:
            event_type: Type d'événement (acquisition, analyse, export, etc.)
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
            "type": event_type,
            "description": description,
            "investigator": self.investigator,
            "details": details or {}
        }
        
        self.events.append(event)
        logger.debug(f"Événement ajouté à la chaîne de custody: {event_id} - {description}")
        
        # Sauvegarde automatique après chaque événement
        self.save()
        
        return event_id
    
    def register_artifact(self, artifact_path: str, artifact_type: str, source: str, 
                         description: str = None, metadata: Dict[str, Any] = None) -> str:
        """
        Enregistre un artefact dans la chaîne de custody.
        
        Args:
            artifact_path: Chemin vers l'artefact
            artifact_type: Type d'artefact (fichier, registre, mémoire, etc.)
            source: Source de l'artefact (chemin original, clé de registre, etc.)
            description: Description de l'artefact
            metadata: Métadonnées supplémentaires sur l'artefact
            
        Returns:
            Identifiant unique de l'artefact
        """
        artifact_id = str(uuid.uuid4())
        timestamp = datetime.datetime.now().isoformat()
        
        # Calcul des hashes pour l'artefact
        hashes = {}
        if os.path.isfile(artifact_path):
            hashes = HashCalculator.calculate_file_hashes(artifact_path)
        
        # Métadonnées du fichier
        file_metadata = {}
        if os.path.exists(artifact_path):
            try:
                file_stats = os.stat(artifact_path)
                file_metadata = {
                    "size": file_stats.st_size,
                    "created": datetime.datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                    "modified": datetime.datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                    "accessed": datetime.datetime.fromtimestamp(file_stats.st_atime).isoformat()
                }
            except Exception as e:
                logger.warning(f"Impossible d'obtenir les métadonnées pour {artifact_path}: {str(e)}")
        
        # Création de l'événement d'acquisition
        event_details = {
            "artifact_id": artifact_id,
            "artifact_path": artifact_path,
            "artifact_type": artifact_type,
            "source": source,
            "description": description or f"Acquisition de {artifact_type}",
            "hashes": hashes,
            "file_metadata": file_metadata,
            "custom_metadata": metadata or {}
        }
        
        self.add_event(
            event_type="artifact_acquisition",
            description=f"Acquisition de l'artefact: {os.path.basename(artifact_path)}",
            details=event_details
        )
        
        return artifact_id
    
    def register_analysis(self, artifact_id: str, analysis_type: str, 
                         description: str, results: Dict[str, Any]) -> str:
        """
        Enregistre une analyse effectuée sur un artefact.
        
        Args:
            artifact_id: Identifiant de l'artefact analysé
            analysis_type: Type d'analyse effectuée
            description: Description de l'analyse
            results: Résultats de l'analyse
            
        Returns:
            Identifiant unique de l'analyse
        """
        analysis_id = str(uuid.uuid4())
        
        event_details = {
            "analysis_id": analysis_id,
            "artifact_id": artifact_id,
            "analysis_type": analysis_type,
            "results": results
        }
        
        self.add_event(
            event_type="artifact_analysis",
            description=description,
            details=event_details
        )
        
        return analysis_id
    
    def register_export(self, artifact_id: str, export_path: str, 
                       export_format: str, description: str = None) -> str:
        """
        Enregistre l'exportation d'un artefact.
        
        Args:
            artifact_id: Identifiant de l'artefact exporté
            export_path: Chemin d'exportation
            export_format: Format d'exportation
            description: Description de l'exportation
            
        Returns:
            Identifiant unique de l'exportation
        """
        export_id = str(uuid.uuid4())
        
        # Calcul des hashes pour le fichier exporté
        hashes = {}
        if os.path.isfile(export_path):
            hashes = HashCalculator.calculate_file_hashes(export_path)
        
        event_details = {
            "export_id": export_id,
            "artifact_id": artifact_id,
            "export_path": export_path,
            "export_format": export_format,
            "hashes": hashes
        }
        
        self.add_event(
            event_type="artifact_export",
            description=description or f"Exportation de l'artefact au format {export_format}",
            details=event_details
        )
        
        return export_id
    
    def save(self) -> str:
        """
        Sauvegarde la chaîne de custody dans un fichier JSON.
        
        Returns:
            Chemin vers le fichier de chaîne de custody
        """
        custody_chain = {
            "case_id": self.case_id,
            "investigator": self.investigator,
            "environment": self.environment,
            "events": self.events
        }
        
        # Génération du nom de fichier
        filename = f"custody_chain_{self.case_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(custody_chain, f, indent=2)
            
            logger.info(f"Chaîne de custody sauvegardée: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la chaîne de custody: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            return ""
    
    def generate_report(self, output_format: str = "html") -> str:
        """
        Génère un rapport de la chaîne de custody.
        
        Args:
            output_format: Format de sortie (html, pdf, txt)
            
        Returns:
            Chemin vers le rapport généré
        """
        # Génération du nom de fichier
        filename = f"custody_report_{self.case_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{output_format}"
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            if output_format == "html":
                self._generate_html_report(filepath)
            elif output_format == "txt":
                self._generate_txt_report(filepath)
            else:
                logger.warning(f"Format de rapport non supporté: {output_format}")
                return ""
            
            logger.info(f"Rapport de chaîne de custody généré: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport de chaîne de custody: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            return ""
    
    def _generate_html_report(self, filepath: str):
        """
        Génère un rapport HTML de la chaîne de custody.
        
        Args:
            filepath: Chemin de sortie du rapport
        """
        html_content = []
        
        # En-tête HTML
        html_content.append("<!DOCTYPE html>")
        html_content.append("<html lang='fr'>")
        html_content.append("<head>")
        html_content.append("  <meta charset='UTF-8'>")
        html_content.append("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html_content.append(f"  <title>Rapport de chaîne de custody - {self.case_id}</title>")
        html_content.append("  <style>")
        html_content.append("    body { font-family: Arial, sans-serif; margin: 20px; }")
        html_content.append("    h1, h2, h3 { color: #2c3e50; }")
        html_content.append("    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }")
        html_content.append("    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        html_content.append("    th { background-color: #f2f2f2; }")
        html_content.append("    tr:nth-child(even) { background-color: #f9f9f9; }")
        html_content.append("    .event { margin-bottom: 20px; border: 1px solid #ddd; padding: 10px; }")
        html_content.append("    .event-header { background-color: #f2f2f2; padding: 5px; margin-bottom: 10px; }")
        html_content.append("    .artifact { background-color: #e8f4f8; }")
        html_content.append("    .analysis { background-color: #f8f4e8; }")
        html_content.append("    .export { background-color: #f4f8e8; }")
        html_content.append("  </style>")
        html_content.append("</head>")
        html_content.append("<body>")
        
        # Informations générales
        html_content.append(f"<h1>Rapport de chaîne de custody - Affaire {self.case_id}</h1>")
        html_content.append("<h2>Informations générales</h2>")
        html_content.append("<table>")
        html_content.append("  <tr><th>Affaire</th><td>" + self.case_id + "</td></tr>")
        html_content.append("  <tr><th>Investigateur</th><td>" + self.investigator + "</td></tr>")
        html_content.append("  <tr><th>Date de génération</th><td>" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "</td></tr>")
        html_content.append("</table>")
        
        # Environnement d'exécution
        html_content.append("<h2>Environnement d'exécution</h2>")
        html_content.append("<table>")
        for key, value in self.environment.items():
            html_content.append(f"  <tr><th>{key}</th><td>{value}</td></tr>")
        html_content.append("</table>")
        
        # Événements
        html_content.append("<h2>Événements</h2>")
        
        for event in self.events:
            event_class = ""
            if event["type"] == "artifact_acquisition":
                event_class = "artifact"
            elif event["type"] == "artifact_analysis":
                event_class = "analysis"
            elif event["type"] == "artifact_export":
                event_class = "export"
            
            html_content.append(f"<div class='event {event_class}'>")
            html_content.append("  <div class='event-header'>")
            html_content.append(f"    <h3>{event['description']}</h3>")
            html_content.append(f"    <p>Type: {event['type']} | Date: {event['timestamp']} | ID: {event['id']}</p>")
            html_content.append("  </div>")
            
            # Détails de l'événement
            if "details" in event and event["details"]:
                html_content.append("  <div class='event-details'>")
                html_content.append("    <table>")
                
                for key, value in event["details"].items():
                    if isinstance(value, dict):
                        html_content.append(f"      <tr><th>{key}</th><td><pre>{json.dumps(value, indent=2)}</pre></td></tr>")
                    else:
                        html_content.append(f"      <tr><th>{key}</th><td>{value}</td></tr>")
                
                html_content.append("    </table>")
                html_content.append("  </div>")
            
            html_content.append("</div>")
        
        # Pied de page
        html_content.append("<footer>")
        html_content.append(f"  <p>Généré par ForensicHunter le {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        html_content.append("</footer>")
        
        html_content.append("</body>")
        html_content.append("</html>")
        
        # Écriture du fichier HTML
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(html_content))
    
    def _generate_txt_report(self, filepath: str):
        """
        Génère un rapport texte de la chaîne de custody.
        
        Args:
            filepath: Chemin de sortie du rapport
        """
        txt_content = []
        
        # Informations générales
        txt_content.append("=" * 80)
        txt_content.append(f"RAPPORT DE CHAÎNE DE CUSTODY - AFFAIRE {self.case_id}")
        txt_content.append("=" * 80)
        txt_content.append("")
        txt_content.append("INFORMATIONS GÉNÉRALES")
        txt_content.append("-" * 80)
        txt_content.append(f"Affaire: {self.case_id}")
        txt_content.append(f"Investigateur: {self.investigator}")
        txt_content.append(f"Date de génération: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        txt_content.append("")
        
        # Environnement d'exécution
        txt_content.append("ENVIRONNEMENT D'EXÉCUTION")
        txt_content.append("-" * 80)
        for key, value in self.environment.items():
            txt_content.append(f"{key}: {value}")
        txt_content.append("")
        
        # Événements
        txt_content.append("ÉVÉNEMENTS")
        txt_content.append("-" * 80)
        
        for event in self.events:
            txt_content.append(f"Description: {event['description']}")
            txt_content.append(f"Type: {event['type']}")
            txt_content.append(f"Date: {event['timestamp']}")
            txt_content.append(f"ID: {event['id']}")
            
            # Détails de l'événement
            if "details" in event and event["details"]:
                txt_content.append("Détails:")
                for key, value in event["details"].items():
                    if isinstance(value, dict):
                        txt_content.append(f"  {key}:")
                        for k, v in value.items():
                            txt_content.append(f"    {k}: {v}")
                    else:
                        txt_content.append(f"  {key}: {value}")
            
            txt_content.append("-" * 80)
        
        # Pied de page
        txt_content.append("")
        txt_content.append(f"Généré par ForensicHunter le {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Écriture du fichier texte
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(txt_content))

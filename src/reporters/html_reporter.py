#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de génération de rapports HTML pour ForensicHunter.

Ce module permet de générer des rapports HTML détaillés et professionnels
à partir des résultats d'analyse forensique.
"""

import os
import logging
import datetime
import json
import base64
import hashlib
from pathlib import Path
import shutil

# Configuration du logger
logger = logging.getLogger("forensichunter.reporters")

class HTMLReporter:
    """Générateur de rapports HTML pour ForensicHunter."""
    
    def __init__(self, config=None):
        """
        Initialise un nouveau générateur de rapports HTML.
        
        Args:
            config (dict, optional): Configuration du générateur
        """
        self.config = config or {}
        self.title = self.config.get("title", "Rapport d'analyse forensique - ForensicHunter")
        self.company_name = self.config.get("company_name", "ForensicHunter")
        self.company_logo = self.config.get("company_logo", "")
        self.include_artifacts = self.config.get("include_artifacts", True)
        self.max_artifacts_per_finding = self.config.get("max_artifacts_per_finding", 10)
        self.include_raw_data = self.config.get("include_raw_data", False)
        self.theme = self.config.get("theme", "light")  # light, dark
        self.static_dir = self.config.get("static_dir", os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "static"))
        self.template_dir = self.config.get("template_dir", os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "templates"))
    
    def get_name(self):
        """
        Retourne le nom du générateur de rapports.
        
        Returns:
            str: Nom du générateur de rapports
        """
        return "HTMLReporter"
    
    def get_description(self):
        """
        Retourne la description du générateur de rapports.
        
        Returns:
            str: Description du générateur de rapports
        """
        return "Générateur de rapports HTML détaillés et professionnels"
    
    def generate_report(self, findings, artifacts, output_path, case_info=None):
        """
        Génère un rapport HTML à partir des résultats d'analyse.
        
        Args:
            findings (list): Liste d'objets Finding résultant de l'analyse
            artifacts (list): Liste d'objets Artifact collectés
            output_path (str): Chemin du fichier de sortie
            case_info (dict, optional): Informations sur le cas
            
        Returns:
            str: Chemin du rapport généré
        """
        try:
            # Créer le répertoire de sortie s'il n'existe pas
            output_dir = os.path.dirname(output_path)
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError as e:
                logger.error(f"Failed to create output directory {output_dir}: {str(e)}")
                return None
            
            # Créer un répertoire pour les ressources statiques
            assets_dir = os.path.join(output_dir, "assets")
            try:
                os.makedirs(assets_dir, exist_ok=True)
            except OSError as e:
                # Log the error, but allow report generation to continue as it might still work (e.g. with default HTML)
                logger.error(f"Failed to create assets directory {assets_dir}: {str(e)}. Report generation will continue but may lack styling.")

            # Copier les ressources statiques
            self._copy_static_assets(assets_dir) # This method handles its own errors
            
            # Préparer les données du rapport
            report_data = self._prepare_report_data(findings, artifacts, case_info) # This method handles its own errors
            
            # Générer le HTML
            html_content = self._generate_html(report_data) # This method handles its own errors
            
            # Écrire le rapport
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
            except IOError as e:
                logger.error(f"Failed to write HTML report to {output_path}: {str(e)}")
                return None
            
            logger.info(f"Rapport HTML généré avec succès: {output_path}")
            return output_path
            
        except Exception as e: # Catch-all for any other unexpected errors during the overall process
            logger.error(f"Unexpected error during HTML report generation: {str(e)}")
            return None
    
    def _prepare_report_data(self, findings, artifacts, case_info=None):
        """
        Prépare les données pour le rapport.
        
        Args:
            findings (list): Liste d'objets Finding résultant de l'analyse
            artifacts (list): Liste d'objets Artifact collectés
            case_info (dict, optional): Informations sur le cas
            
        Returns:
            dict: Données préparées pour le rapport
        """
        # Informations sur le cas
        if not case_info:
            case_info = {
                "case_id": f"FH-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "case_name": "Analyse forensique",
                "analyst": "ForensicHunter",
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        
        # Statistiques générales
        stats = {
            "total_findings": len(findings),
            "total_artifacts": len(artifacts),
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "type_counts": {},
            "artifact_type_counts": {}
        }
        
        # Compter les résultats par sévérité et type
        for finding in findings:
            severity = finding.severity.lower()
            if severity in stats["severity_counts"]:
                stats["severity_counts"][severity] += 1
            
            finding_type = finding.type
            if finding_type not in stats["type_counts"]:
                stats["type_counts"][finding_type] = 0
            stats["type_counts"][finding_type] += 1
        
        # Compter les artefacts par type
        for artifact in artifacts:
            artifact_type = artifact.type
            if artifact_type not in stats["artifact_type_counts"]:
                stats["artifact_type_counts"][artifact_type] = 0
            stats["artifact_type_counts"][artifact_type] += 1
        
        # Créer un index des artefacts pour référence rapide
        artifact_index = {}
        for artifact in artifacts:
            artifact_index[artifact.id] = artifact
        
        # Préparer les résultats pour le rapport
        prepared_findings = []
        for finding in findings:
            # Préparer les artefacts associés
            associated_artifacts = []
            
            if self.include_artifacts:
                for artifact_id in finding.artifacts:
                    if isinstance(artifact_id, str) and artifact_id in artifact_index:
                        artifact = artifact_index[artifact_id]
                        associated_artifacts.append({
                            "id": artifact.id,
                            "type": artifact.type,
                            "source": artifact.source,
                            "timestamp": artifact.timestamp,
                            "metadata": artifact.metadata,
                            "data_preview": self._get_artifact_preview(artifact)
                        })
                    elif hasattr(artifact_id, 'id'):
                        # Si l'artefact est directement fourni
                        artifact = artifact_id
                        associated_artifacts.append({
                            "id": artifact.id,
                            "type": artifact.type,
                            "source": artifact.source,
                            "timestamp": artifact.timestamp,
                            "metadata": artifact.metadata,
                            "data_preview": self._get_artifact_preview(artifact)
                        })
            
            # Limiter le nombre d'artefacts si nécessaire
            if len(associated_artifacts) > self.max_artifacts_per_finding:
                associated_artifacts = associated_artifacts[:self.max_artifacts_per_finding]
                associated_artifacts.append({
                    "id": "...",
                    "type": "...",
                    "source": f"... et {len(finding.artifacts) - self.max_artifacts_per_finding} autres artefacts"
                })
            
            # Préparer le résultat
            prepared_finding = {
                "id": finding.id,
                "type": finding.type,
                "description": finding.description,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "timestamp": finding.timestamp,
                "metadata": finding.metadata,
                "artifacts": associated_artifacts,
                "severity_class": self._get_severity_class(finding.severity),
                "confidence_class": self._get_confidence_class(finding.confidence)
            }
            
            prepared_findings.append(prepared_finding)
        
        # Trier les résultats par sévérité (décroissante) puis par confiance (décroissante)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        prepared_findings.sort(key=lambda x: (severity_order.get(x["severity"].lower(), 999), -x["confidence"]))
        
        # Données complètes du rapport
        report_data = {
            "title": self.title,
            "company_name": self.company_name,
            "company_logo": self.company_logo,
            "case_info": case_info,
            "stats": stats,
            "findings": prepared_findings,
            "generation_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "theme": self.theme
        }
        
        return report_data
    
    def _get_artifact_preview(self, artifact):
        """
        Génère un aperçu du contenu d'un artefact.
        
        Args:
            artifact (Artifact): Artefact à prévisualiser
            
        Returns:
            str: Aperçu du contenu de l'artefact
        """
        try:
            if not hasattr(artifact, 'data') or not artifact.data:
                return "Pas de données disponibles"
            
            data_preview = "Aperçu non disponible" # Default preview

            if isinstance(artifact.data, dict):
                if artifact.type == "filesystem":
                    file_type = artifact.data.get("type", "")
                    
                    if file_type == "text":
                        content = artifact.data.get("content", "")
                        if content:
                            data_preview = content[:500] + "..." if len(content) > 500 else content
                        else:
                            data_preview = "Contenu textuel vide"
                    
                    elif file_type == "binary":
                        data_preview = "Données binaires (aperçu non disponible)"
                    
                    elif file_type == "metadata_only":
                        data_preview = "Métadonnées uniquement (contenu non disponible)"
                    
                    else:
                        data_preview = f"Type de fichier inconnu: {file_type}"
                
                elif artifact.type == "registry":
                    formatted = []
                    for name, value_data in artifact.data.items():
                        if isinstance(value_data, dict):
                            value_str = value_data.get("value", "")
                            value_type = value_data.get("type", "")
                            formatted.append(f"{name} = {str(value_str)[:100]} ({value_type})") # Limit value preview
                        else:
                            formatted.append(f"{name} = {str(value_data)[:100]}")
                    data_preview = "\n".join(formatted)
                    if len(data_preview) > 500: # Overall limit for registry preview
                        data_preview = data_preview[:500] + "..."

                elif artifact.type == "event_log":
                    event_id_str = ""
                    log_type_str = ""
                    if hasattr(artifact, 'metadata') and artifact.metadata:
                         event_id_str = artifact.metadata.get("event_id", "")
                         log_type_str = artifact.metadata.get("log_type", "")
                    data_preview = f"Événement {event_id_str} dans {log_type_str}: {str(artifact.data)[:300]}..."
                
                else: # For other dictionary-based types
                    try:
                        json_str = json.dumps(artifact.data, indent=2)
                        data_preview = json_str[:500] + "..." if len(json_str) > 500 else json_str
                    except TypeError as te: # Handle non-serializable data
                        logger.warning(f"Data for artifact {artifact.id if hasattr(artifact, 'id') else 'UNKNOWN_ID'} of type {artifact.type} is not JSON serializable for preview: {str(te)}")
                        data_preview = "Données non sérialisables pour l'aperçu JSON."

            else: # For non-dictionary data (e.g., simple strings, numbers)
                data_str = str(artifact.data)
                data_preview = data_str[:500] + "..." if len(data_str) > 500 else data_str
            
            return data_preview

        except Exception as e:
            artifact_id_str = artifact.id if hasattr(artifact, 'id') else 'UNKNOWN_ID'
            logger.error(f"Error generating preview for artifact {artifact_id_str}: {str(e)}")
            return "Error generating preview for this artifact."
    
    def _get_severity_class(self, severity):
        """
        Retourne la classe CSS pour une sévérité donnée.
        
        Args:
            severity (str): Sévérité (critical, high, medium, low, info)
            
        Returns:
            str: Classe CSS correspondante
        """
        severity = severity.lower()
        if severity == "critical":
            return "severity-critical"
        elif severity == "high":
            return "severity-high"
        elif severity == "medium":
            return "severity-medium"
        elif severity == "low":
            return "severity-low"
        else:
            return "severity-info"
    
    def _get_confidence_class(self, confidence):
        """
        Retourne la classe CSS pour un niveau de confiance donné.
        
        Args:
            confidence (int): Niveau de confiance (0-100)
            
        Returns:
            str: Classe CSS correspondante
        """
        if confidence >= 80:
            return "confidence-high"
        elif confidence >= 50:
            return "confidence-medium"
        else:
            return "confidence-low"
    
    def _copy_static_assets(self, assets_dir):
        """
        Copie les ressources statiques dans le répertoire de sortie.
        
        Args:
            assets_dir (str): Répertoire de destination des ressources
            
        Returns:
            bool: True si la copie a réussi, False sinon
        """
        try:
            # Vérifier si le répertoire static existe
            if not os.path.isdir(self.static_dir): # Check if it's a directory specifically
                logger.warning(f"Static assets directory {self.static_dir} does not exist or is not a directory. Attempting to create default assets.")
                return self._create_default_assets(assets_dir)
            
            # Copier les ressources
            copied_successfully = True
            for item in os.listdir(self.static_dir):
                src = os.path.join(self.static_dir, item)
                dst = os.path.join(assets_dir, item)
                
                try:
                    if os.path.isdir(src):
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    elif os.path.isfile(src): # Ensure it's a file before copying
                        shutil.copy2(src, dst)
                    else:
                        logger.warning(f"Skipping non-file/non-directory item in static assets: {src}")
                        continue
                except (IOError, OSError, shutil.Error) as e: # Catch specific copy errors
                    logger.error(f"Error copying static asset from {src} to {dst}: {str(e)}")
                    copied_successfully = False # Mark that at least one copy failed
            
            if copied_successfully:
                logger.info(f"Static assets copied to {assets_dir}")
            else:
                logger.warning(f"Some static assets could not be copied to {assets_dir}. Falling back to creating default assets for missing items if necessary.")
                # Optionally, one could try to create default assets only if critical files are missing.
                # For simplicity here, if any copy fails, it might still try to ensure defaults are there.
                return self._create_default_assets(assets_dir) # Fallback if any copy fails
            
            return True # If all successful or handled.
            
        except (OSError, IOError) as e: # Catch errors from os.listdir or initial checks
            logger.error(f"Error accessing static assets directory {self.static_dir}: {str(e)}. Attempting to create default assets.")
            return self._create_default_assets(assets_dir)
        except Exception as e: # Catch any other unexpected errors
            logger.error(f"Unexpected error during static asset copying: {str(e)}. Attempting to create default assets.")
            return self._create_default_assets(assets_dir)

    
    def _create_default_assets(self, assets_dir):
        """
        Crée des ressources statiques par défaut.
        
        Args:
            assets_dir (str): Répertoire de destination des ressources
            
        Returns:
            bool: True si la création a réussi, False sinon
        """
        all_defaults_created = True
        try:
            # Créer le répertoire CSS
            css_dir = os.path.join(assets_dir, "css")
            try:
                os.makedirs(css_dir, exist_ok=True)
            except (IOError, OSError) as e:
                logger.error(f"Failed to create default asset directory {css_dir}: {str(e)}")
                all_defaults_created = False
            
            # Créer le répertoire JS
            js_dir = os.path.join(assets_dir, "js")
            try:
                os.makedirs(js_dir, exist_ok=True)
            except (IOError, OSError) as e:
                logger.error(f"Failed to create default asset directory {js_dir}: {str(e)}")
                all_defaults_created = False

            # Créer le répertoire images
            img_dir = os.path.join(assets_dir, "img")
            try:
                os.makedirs(img_dir, exist_ok=True)
            except (IOError, OSError) as e:
                logger.error(f"Failed to create default asset directory {img_dir}: {str(e)}")
                all_defaults_created = False
            
            # CSS par défaut
            default_css = """
/* ForensicHunter Report CSS */
:root {
    --primary-color: #2c3e50;
    --secondary-color: #3498db;
    --accent-color: #e74c3c;
    --background-color: #f8f9fa;
    --text-color: #333;
    --border-color: #ddd;
    --card-background: #fff;
    --header-background: #2c3e50;
    --header-text: #fff;
    --severity-critical: #e74c3c;
    --severity-high: #e67e22;
    --severity-medium: #f1c40f;
    --severity-low: #3498db;
    --severity-info: #95a5a6;
    --confidence-high: #27ae60;
    --confidence-medium: #f1c40f;
    --confidence-low: #e74c3c;
}

/* Dark theme */
.dark-theme {
    --primary-color: #1a1a2e;
    --secondary-color: #16213e;
    --accent-color: #e94560;
    --background-color: #121212;
    --text-color: #f0f0f0;
    --border-color: #333;
    --card-background: #1e1e1e;
    --header-background: #0f3460;
    --header-text: #f0f0f0;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: var(--text-color);
    background-color: var(--background-color);
    margin: 0;
    padding: 0;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

header {
    background-color: var(--header-background);
    color: var(--header-text);
    padding: 20px 0;
    margin-bottom: 30px;
}

.header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo {
    max-height: 60px;
}

.report-title {
    margin: 0;
    font-size: 24px;
    font-weight: 600;
}

.case-info {
    background-color: var(--card-background);
    border: 1px solid var(--border-color);
    border-radius: 5px;
    padding: 20px;
    margin-bottom: 30px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}

.case-info h2 {
    margin-top: 0;
    color: var(--primary-color);
    border-bottom: 2px solid var(--secondary-color);
    padding-bottom: 10px;
}

.case-details {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 20px;
}

.case-detail-item {
    margin-bottom: 10px;
}

.case-detail-label {
    font-weight: bold;
    color: var(--secondary-color);
}

.stats-section {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.stat-card {
    background-color: var(--card-background);
    border: 1px solid var(--border-color);
    border-radius: 5px;
    padding: 20px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}

.stat-card h3 {
    margin-top: 0;
    color: var(--primary-color);
    border-bottom: 2px solid var(--secondary-color);
    padding-bottom: 10px;
}

.severity-chart, .type-chart {
    height: 250px;
    margin-top: 20px;
}

.findings-section {
    margin-bottom: 30px;
}

.findings-section h2 {
    color: var(--primary-color);
    border-bottom: 2px solid var(--secondary-color);
    padding-bottom: 10px;
}

.findings-filters {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 20px;
}

.filter-button {
    background-color: var(--card-background);
    border: 1px solid var(--border-color);
    border-radius: 20px;
    padding: 5px 15px;
    cursor: pointer;
    transition: all 0.3s ease;
}

.filter-button:hover, .filter-button.active {
    background-color: var(--secondary-color);
    color: white;
}

.finding-card {
    background-color: var(--card-background);
    border: 1px solid var(--border-color);
    border-radius: 5px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}

.finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
}

.finding-title {
    font-size: 18px;
    font-weight: 600;
    margin: 0;
}

.finding-type {
    font-size: 14px;
    color: var(--secondary-color);
    margin-left: 10px;
}

.finding-badges {
    display: flex;
    gap: 10px;
}

.severity-badge, .confidence-badge {
    padding: 5px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: bold;
    color: white;
}

.severity-critical {
    background-color: var(--severity-critical);
}

.severity-high {
    background-color: var(--severity-high);
}

.severity-medium {
    background-color: var(--severity-medium);
    color: #333;
}

.severity-low {
    background-color: var(--severity-low);
}

.severity-info {
    background-color: var(--severity-info);
}

.confidence-high {
    background-color: var(--confidence-high);
}

.confidence-medium {
    background-color: var(--confidence-medium);
    color: #333;
}

.confidence-low {
    background-color: var(--confidence-low);
}

.finding-description {
    margin-bottom: 15px;
    line-height: 1.6;
}

.finding-metadata {
    background-color: rgba(0,0,0,0.05);
    border-radius: 5px;
    padding: 10px;
    margin-bottom: 15px;
    font-family: monospace;
    white-space: pre-wrap;
    overflow-x: auto;
}

.artifacts-section {
    margin-top: 20px;
}

.artifacts-section h4 {
    margin-top: 0;
    color: var(--primary-color);
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 5px;
}

.artifact-item {
    background-color: rgba(0,0,0,0.03);
    border-radius: 5px;
    padding: 10px;
    margin-bottom: 10px;
}

.artifact-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 5px;
    font-weight: bold;
}

.artifact-source {
    color: var(--secondary-color);
}

.artifact-preview {
    font-family: monospace;
    white-space: pre-wrap;
    overflow-x: auto;
    padding: 10px;
    background-color: rgba(0,0,0,0.05);
    border-radius: 3px;
    font-size: 12px;
}

.collapsible {
    cursor: pointer;
}

.collapsible:after {
    content: '\\002B';
    font-weight: bold;
    float: right;
    margin-left: 5px;
}

.active:after {
    content: "\\2212";
}

.collapsible-content {
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.2s ease-out;
}

footer {
    text-align: center;
    padding: 20px;
    margin-top: 50px;
    border-top: 1px solid var(--border-color);
    color: var(--text-color);
    font-size: 14px;
}

/* Responsive adjustments */
@media (max-width: 768px) {
    .header-content {
        flex-direction: column;
        text-align: center;
    }
    
    .logo {
        margin-bottom: 15px;
    }
    
    .case-details, .stats-section {
        grid-template-columns: 1fr;
    }
    
    .finding-header {
        flex-direction: column;
        align-items: flex-start;
    }
    
    .finding-badges {
        margin-top: 10px;
    }
}

/* Print styles */
@media print {
    body {
        background-color: white;
        color: black;
    }
    
    .container {
        max-width: 100%;
        padding: 0;
    }
    
    .finding-card, .case-info, .stat-card {
        break-inside: avoid;
        page-break-inside: avoid;
        box-shadow: none;
        border: 1px solid #ccc;
    }
    
    .filter-button, .theme-toggle {
        display: none;
    }
    
    footer {
        margin-top: 20px;
    }
}
"""
            
            # JavaScript par défaut
            default_js = """
// ForensicHunter Report JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    initCharts();
    
    // Initialize collapsible elements
    initCollapsible();
    
    // Initialize filters
    initFilters();
    
    // Initialize theme toggle
    initThemeToggle();
});

function initCharts() {
    // Check if Chart.js is available
    if (typeof Chart === 'undefined') {
        console.warn('Chart.js is not available. Charts will not be rendered.');
        return;
    }
    
    // Severity chart
    const severityCtx = document.getElementById('severityChart');
    if (severityCtx) {
        const severityData = JSON.parse(severityCtx.getAttribute('data-values'));
        const severityLabels = Object.keys(severityData);
        const severityValues = Object.values(severityData);
        const severityColors = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f1c40f',
            'low': '#3498db',
            'info': '#95a5a6'
        };
        
        new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: severityLabels.map(label => label.charAt(0).toUpperCase() + label.slice(1)),
                datasets: [{
                    data: severityValues,
                    backgroundColor: severityLabels.map(label => severityColors[label.toLowerCase()] || '#95a5a6'),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Résultats par sévérité'
                    }
                }
            }
        });
    }
    
    // Finding types chart
    const typeCtx = document.getElementById('typeChart');
    if (typeCtx) {
        const typeData = JSON.parse(typeCtx.getAttribute('data-values'));
        const typeLabels = Object.keys(typeData);
        const typeValues = Object.values(typeData);
        
        new Chart(typeCtx, {
            type: 'bar',
            data: {
                labels: typeLabels.map(label => label.replace(/_/g, ' ')),
                datasets: [{
                    label: 'Nombre de résultats',
                    data: typeValues,
                    backgroundColor: '#3498db',
                    borderColor: '#2980b9',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Résultats par type'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    }
}

function initCollapsible() {
    const collapsibles = document.getElementsByClassName('collapsible');
    
    for (let i = 0; i < collapsibles.length; i++) {
        collapsibles[i].addEventListener('click', function() {
            this.classList.toggle('active');
            const content = this.nextElementSibling;
            
            if (content.style.maxHeight) {
                content.style.maxHeight = null;
            } else {
                content.style.maxHeight = content.scrollHeight + 'px';
            }
        });
    }
}

function initFilters() {
    const filterButtons = document.querySelectorAll('.filter-button');
    const findingCards = document.querySelectorAll('.finding-card');
    
    filterButtons.forEach(button => {
        button.addEventListener('click', function() {
            const filter = this.getAttribute('data-filter');
            
            // Toggle active class
            if (filter === 'all') {
                filterButtons.forEach(btn => btn.classList.remove('active'));
                this.classList.add('active');
            } else {
                document.querySelector('[data-filter="all"]').classList.remove('active');
                this.classList.toggle('active');
            }
            
            // Apply filters
            const activeFilters = Array.from(document.querySelectorAll('.filter-button.active')).map(btn => btn.getAttribute('data-filter'));
            
            findingCards.forEach(card => {
                if (activeFilters.includes('all') || activeFilters.length === 0) {
                    card.style.display = 'block';
                } else {
                    const severity = card.getAttribute('data-severity');
                    const type = card.getAttribute('data-type');
                    
                    if (activeFilters.includes(severity) || activeFilters.includes(type)) {
                        card.style.display = 'block';
                    } else {
                        card.style.display = 'none';
                    }
                }
            });
        });
    });
}

function initThemeToggle() {
    const themeToggle = document.getElementById('themeToggle');
    
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            document.body.classList.toggle('dark-theme');
            
            const isDarkTheme = document.body.classList.contains('dark-theme');
            themeToggle.textContent = isDarkTheme ? '☀️ Mode clair' : '🌙 Mode sombre';
            
            // Save preference
            localStorage.setItem('darkTheme', isDarkTheme);
            
            // Reinitialize charts with new theme
            initCharts();
        });
        
        // Apply saved preference
        const savedTheme = localStorage.getItem('darkTheme');
        if (savedTheme === 'true') {
            document.body.classList.add('dark-theme');
            themeToggle.textContent = '☀️ Mode clair';
        }
    }
}

// Function to format JSON for display
function formatJSON(json) {
    if (typeof json === 'string') {
        try {
            json = JSON.parse(json);
        } catch (e) {
            return json;
        }
    }
    
    return JSON.stringify(json, null, 2);
}

// Function to toggle visibility of an element
function toggleVisibility(id) {
    const element = document.getElementById(id);
    if (element) {
        element.style.display = element.style.display === 'none' ? 'block' : 'none';
    }
}

// Function to search in findings
function searchFindings() {
    const searchInput = document.getElementById('searchInput');
    const searchTerm = searchInput.value.toLowerCase();
    const findingCards = document.querySelectorAll('.finding-card');
    
    findingCards.forEach(card => {
        const text = card.textContent.toLowerCase();
        if (text.includes(searchTerm)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}
"""
            
            # Écrire les fichiers
            try:
                with open(os.path.join(css_dir, "report.css"), "w", encoding="utf-8") as f:
                    f.write(default_css)
            except (IOError, OSError) as e:
                logger.error(f"Failed to write default CSS file to {css_dir}: {str(e)}")
                all_defaults_created = False
            
            try:
                with open(os.path.join(js_dir, "report.js"), "w", encoding="utf-8") as f:
                    f.write(default_js)
            except (IOError, OSError) as e:
                logger.error(f"Failed to write default JS file to {js_dir}: {str(e)}")
                all_defaults_created = False
            
            # Créer un logo par défaut (base64)
            default_logo_content = """
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60" viewBox="0 0 200 60">
  <rect width="200" height="60" fill="#2c3e50"/>
  <text x="10" y="38" font-family="Arial" font-size="24" fill="white">ForensicHunter</text>
</svg>
"""
            try:
                if os.path.isdir(img_dir): # Ensure img_dir was created
                    with open(os.path.join(img_dir, "logo.svg"), "w", encoding="utf-8") as f:
                        f.write(default_logo_content)
            except (IOError, OSError) as e:
                logger.error(f"Failed to write default logo file to {img_dir}: {str(e)}")
                all_defaults_created = False

            if all_defaults_created:
                logger.info(f"Default static assets created in {assets_dir}")
            else:
                logger.warning(f"Some default static assets could not be created in {assets_dir}.")
            return all_defaults_created # Return status of default asset creation
            
        except Exception as e: # Catch-all for any other unexpected error during default asset creation
            logger.error(f"Unexpected error during default static asset creation: {str(e)}")
            return False # Overall failure
    
    def _generate_html(self, report_data):
        """
        Génère le contenu HTML du rapport.
        
        Args:
            report_data (dict): Données du rapport
            
        Returns:
            str: Contenu HTML du rapport
        """
        try:
            # Vérifier si un template existe
            template_path = os.path.join(self.template_dir, "report_template.html")
            html = None # Initialize html variable

            if os.path.exists(template_path) and os.path.isfile(template_path):
                try:
                    # Utiliser le template existant
                    with open(template_path, "r", encoding="utf-8") as f:
                        template_content = f.read()
                    
                    # Remplacer les variables dans le template
                    html = self._replace_template_variables(template_content, report_data)
                except IOError as e:
                    logger.warning(f"Failed to open HTML template at {template_path}: {str(e)}. Falling back to default HTML generation.")
                    # Fallback handled by html remaining None or by the outer except block
                except Exception as e: # Catch other errors during template processing
                    logger.error(f"Error processing HTML template {template_path}: {str(e)}. Falling back to default HTML generation.")
                    # Fallback handled by html remaining None or by the outer except block
            else:
                logger.info(f"HTML template not found at {template_path} or it's not a file. Generating default HTML.")
                # Fallback handled by html remaining None or by the outer except block

            # If html is still None (due to template not existing, read error, or processing error), generate default
            if html is None:
                html = self._generate_default_html(report_data)
                
            return html
            
        except Exception as e: # Final catch-all for _generate_html
            logger.error(f"Unexpected error during HTML generation: {str(e)}. Falling back to default HTML.")
            # Ensure _generate_default_html is robust enough or has its own detailed error handling
            # For now, assume it returns a basic HTML string even on failure or raises its own errors.
            try:
                return self._generate_default_html(report_data)
            except Exception as default_e:
                logger.error(f"Critical error: Failed to generate even default HTML: {str(default_e)}")
                return "<html><body><h1>Critical Error</h1><p>Report generation failed completely.</p></body></html>"

    def _replace_template_variables(self, template, report_data):
        """
        Remplace les variables dans le template HTML.
        
        Args:
            template (str): Template HTML
            report_data (dict): Données du rapport
            
        Returns:
            str: HTML avec les variables remplacées
        """
        # Remplacer les variables simples
        replacements = {
            "{{title}}": report_data["title"],
            "{{company_name}}": report_data["company_name"],
            "{{company_logo}}": report_data["company_logo"],
            "{{generation_time}}": report_data["generation_time"],
            "{{theme_class}}": "dark-theme" if report_data["theme"] == "dark" else "",
            "{{case_id}}": report_data["case_info"]["case_id"],
            "{{case_name}}": report_data["case_info"]["case_name"],
            "{{analyst}}": report_data["case_info"]["analyst"],
            "{{date}}": report_data["case_info"]["date"],
            "{{total_findings}}": str(report_data["stats"]["total_findings"]),
            "{{total_artifacts}}": str(report_data["stats"]["total_artifacts"]),
            "{{severity_data}}": json.dumps(report_data["stats"]["severity_counts"]),
            "{{type_data}}": json.dumps(report_data["stats"]["type_counts"])
        }
        
        for key, value in replacements.items():
            template = template.replace(key, value)
        
        # Remplacer les sections de résultats
        findings_html = ""
        for finding in report_data["findings"]:
            finding_html = """
            <div class="finding-card" data-severity="{severity}" data-type="{type}">
                <div class="finding-header">
                    <div>
                        <h3 class="finding-title">{description}</h3>
                        <span class="finding-type">{type}</span>
                    </div>
                    <div class="finding-badges">
                        <span class="severity-badge {severity_class}">{severity}</span>
                        <span class="confidence-badge {confidence_class}">Confiance: {confidence}%</span>
                    </div>
                </div>
                <div class="finding-metadata">
                    <strong>ID:</strong> {id}
                    <strong>Timestamp:</strong> {timestamp}
                    <strong>Métadonnées:</strong> {metadata}
                </div>
            """.format(
                id=finding["id"],
                type=finding["type"].replace("_", " ").title(),
                description=finding["description"],
                severity=finding["severity"].upper(),
                severity_class=finding["severity_class"],
                confidence=finding["confidence"],
                confidence_class=finding["confidence_class"],
                timestamp=finding["timestamp"],
                metadata=json.dumps(finding["metadata"], indent=2) if finding["metadata"] else "Aucune"
            )
            
            # Ajouter les artefacts associés
            if finding["artifacts"]:
                finding_html += """
                <div class="artifacts-section">
                    <h4 class="collapsible">Artefacts associés ({count})</h4>
                    <div class="collapsible-content">
                """.format(count=len(finding["artifacts"]))
                
                for artifact in finding["artifacts"]:
                    finding_html += """
                    <div class="artifact-item">
                        <div class="artifact-header">
                            <span>{type}</span>
                            <span class="artifact-source">{source}</span>
                        </div>
                        <div class="artifact-preview">{preview}</div>
                    </div>
                    """.format(
                        type=artifact["type"].replace("_", " ").title(),
                        source=artifact["source"],
                        preview=artifact.get("data_preview", "Aperçu non disponible")
                    )
                
                finding_html += """
                    </div>
                </div>
                """
            
            finding_html += "</div>"
            findings_html += finding_html
        
        template = template.replace("{{findings}}", findings_html)
        
        return template
    
    def _generate_default_html(self, report_data):
        """
        Génère un HTML par défaut pour le rapport.
        
        Args:
            report_data (dict): Données du rapport
            
        Returns:
            str: HTML par défaut
        """
        # En-tête HTML
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data["title"]}</title>
    <link rel="stylesheet" href="assets/css/report.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="{'dark-theme' if report_data['theme'] == 'dark' else ''}">
    <header>
        <div class="container">
            <div class="header-content">
                <img src="assets/img/logo.svg" alt="{report_data['company_name']}" class="logo">
                <h1 class="report-title">{report_data["title"]}</h1>
                <button id="themeToggle">{'☀️ Mode clair' if report_data['theme'] == 'dark' else '🌙 Mode sombre'}</button>
            </div>
        </div>
    </header>
    
    <div class="container">
        <section class="case-info">
            <h2>Informations sur le cas</h2>
            <div class="case-details">
                <div class="case-detail-item">
                    <span class="case-detail-label">ID du cas:</span>
                    <span>{report_data['case_info']['case_id']}</span>
                </div>
                <div class="case-detail-item">
                    <span class="case-detail-label">Nom du cas:</span>
                    <span>{report_data['case_info']['case_name']}</span>
                </div>
                <div class="case-detail-item">
                    <span class="case-detail-label">Analyste:</span>
                    <span>{report_data['case_info']['analyst']}</span>
                </div>
                <div class="case-detail-item">
                    <span class="case-detail-label">Date:</span>
                    <span>{report_data['case_info']['date']}</span>
                </div>
                <div class="case-detail-item">
                    <span class="case-detail-label">Total des résultats:</span>
                    <span>{report_data['stats']['total_findings']}</span>
                </div>
                <div class="case-detail-item">
                    <span class="case-detail-label">Total des artefacts:</span>
                    <span>{report_data['stats']['total_artifacts']}</span>
                </div>
            </div>
        </section>
        
        <section class="stats-section">
            <div class="stat-card">
                <h3>Résultats par sévérité</h3>
                <div class="severity-chart">
                    <canvas id="severityChart" data-values='{json.dumps(report_data["stats"]["severity_counts"])}'></canvas>
                </div>
            </div>
            <div class="stat-card">
                <h3>Résultats par type</h3>
                <div class="type-chart">
                    <canvas id="typeChart" data-values='{json.dumps(report_data["stats"]["type_counts"])}'></canvas>
                </div>
            </div>
        </section>
        
        <section class="findings-section">
            <h2>Résultats d'analyse</h2>
            
            <div class="findings-filters">
                <button class="filter-button active" data-filter="all">Tous</button>
                <button class="filter-button" data-filter="critical">Critique</button>
                <button class="filter-button" data-filter="high">Élevé</button>
                <button class="filter-button" data-filter="medium">Moyen</button>
                <button class="filter-button" data-filter="low">Faible</button>
                <button class="filter-button" data-filter="info">Info</button>
                
                <input type="text" id="searchInput" placeholder="Rechercher..." onkeyup="searchFindings()">
            </div>
"""
        
        # Ajouter les résultats
        for finding in report_data["findings"]:
            html += f"""
            <div class="finding-card" data-severity="{finding['severity']}" data-type="{finding['type']}">
                <div class="finding-header">
                    <div>
                        <h3 class="finding-title">{finding['description']}</h3>
                        <span class="finding-type">{finding['type'].replace('_', ' ').title()}</span>
                    </div>
                    <div class="finding-badges">
                        <span class="severity-badge {finding['severity_class']}">{finding['severity'].upper()}</span>
                        <span class="confidence-badge {finding['confidence_class']}">Confiance: {finding['confidence']}%</span>
                    </div>
                </div>
                <div class="finding-metadata">
                    <strong>ID:</strong> {finding['id']}
                    <strong>Timestamp:</strong> {finding['timestamp']}
                    <strong>Métadonnées:</strong> {json.dumps(finding['metadata'], indent=2) if finding['metadata'] else 'Aucune'}
                </div>
"""
            
            # Ajouter les artefacts associés
            if finding["artifacts"]:
                html += f"""
                <div class="artifacts-section">
                    <h4 class="collapsible">Artefacts associés ({len(finding['artifacts'])})</h4>
                    <div class="collapsible-content">
"""
                
                for artifact in finding["artifacts"]:
                    html += f"""
                    <div class="artifact-item">
                        <div class="artifact-header">
                            <span>{artifact['type'].replace('_', ' ').title()}</span>
                            <span class="artifact-source">{artifact['source']}</span>
                        </div>
                        <div class="artifact-preview">{artifact.get('data_preview', 'Aperçu non disponible')}</div>
                    </div>
"""
                
                html += """
                    </div>
                </div>
"""
            
            html += """
            </div>
"""
        
        # Pied de page
        html += f"""
        </section>
    </div>
    
    <footer>
        <div class="container">
            <p>Rapport généré par ForensicHunter le {report_data['generation_time']}</p>
            <p>&copy; {datetime.datetime.now().year} {report_data['company_name']}. Tous droits réservés.</p>
        </div>
    </footer>
    
    <script src="assets/js/report.js"></script>
</body>
</html>
"""
        
        return html

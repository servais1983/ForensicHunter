#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion des générateurs de rapports.

Ce module coordonne la génération des différents formats de rapports
à partir des artefacts collectés et des résultats d'analyse.
"""

import os
import logging
import datetime
import json
from typing import Dict, List, Any, Optional

from src.reporters.html_reporter import HTMLReporter
from src.reporters.json_reporter import JSONReporter
from src.reporters.csv_reporter import CSVReporter

logger = logging.getLogger("forensichunter")


class ReporterManager:
    """Gestionnaire des générateurs de rapports."""

    def __init__(self, config):
        """
        Initialise le gestionnaire de rapports.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "reports")
        
        # Création du répertoire de sortie
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialisation des reporters
        self.reporters = {
            "html": HTMLReporter(config, self.output_dir),
            "json": JSONReporter(config, self.output_dir),
            "csv": CSVReporter(config, self.output_dir)
        }
    
    def generate_reports(self, artifacts: Dict[str, Any], analysis_results: Dict[str, Any]) -> Dict[str, str]:
        """
        Génère les rapports dans les formats spécifiés.
        
        Args:
            artifacts: Dictionnaire contenant tous les artefacts collectés
            analysis_results: Dictionnaire contenant les résultats d'analyse
            
        Returns:
            Dictionnaire contenant les chemins des rapports générés par format
        """
        report_paths = {}
        
        # Détermination des formats à générer
        formats_to_generate = []
        if self.config.args.format == "all":
            formats_to_generate = list(self.reporters.keys())
        else:
            formats_to_generate = [self.config.args.format]
        
        # Génération des rapports pour chaque format
        for report_format in formats_to_generate:
            if report_format in self.reporters:
                try:
                    logger.info(f"Génération du rapport au format {report_format}...")
                    report_path = self.reporters[report_format].generate(artifacts, analysis_results)
                    report_paths[report_format] = report_path
                    logger.info(f"Rapport {report_format} généré: {report_path}")
                except Exception as e:
                    logger.error(f"Erreur lors de la génération du rapport {report_format}: {str(e)}")
                    logger.debug("Détails de l'erreur:", exc_info=True)
            else:
                logger.warning(f"Format de rapport non supporté: {report_format}")
        
        return report_paths

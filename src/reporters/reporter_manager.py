#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gestionnaire des générateurs de rapports.

Coordonne la génération des différents formats de rapports
à partir des artefacts collectés et des résultats d'analyse.
"""

import os
import logging
import datetime
from typing import Dict, Any

from src.reporters.html_reporter import HTMLReporter
from src.reporters.json_reporter import JSONReporter
from src.reporters.csv_reporter import CSVReporter

logger = logging.getLogger("forensichunter")


class ReporterManager:
    """Gestionnaire des générateurs de rapports."""

    def __init__(self, config):
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "reports")
        os.makedirs(self.output_dir, exist_ok=True)

        self.reporters = {
            "html": HTMLReporter(config, self.output_dir),
            "json": JSONReporter(config, self.output_dir),
            "csv":  CSVReporter(config, self.output_dir),
        }

    def generate_reports(
        self,
        artifacts: Dict[str, Any],
        analysis_results: Dict[str, Any],
    ) -> Dict[str, str]:
        """
        Génère les rapports dans les formats configurés.

        Returns:
            Dictionnaire {format: chemin_fichier}
        """
        report_paths: Dict[str, str] = {}

        args = getattr(self.config, "args", None)
        fmt  = getattr(args, "format", "html") if args else "html"

        formats_to_generate = list(self.reporters.keys()) if fmt == "all" else [fmt]

        for report_format in formats_to_generate:
            reporter = self.reporters.get(report_format)
            if reporter is None:
                logger.warning("Format de rapport non supporté ignoré: %s", report_format)
                continue
            try:
                logger.info("Génération du rapport %s...", report_format.upper())
                path = reporter.generate(artifacts, analysis_results)
                report_paths[report_format] = path
                logger.info("Rapport %s généré: %s", report_format.upper(), path)
            except Exception as exc:
                logger.error(
                    "Erreur lors de la génération du rapport %s: %s", report_format, exc
                )
                logger.debug("Détails:", exc_info=True)

        return report_paths

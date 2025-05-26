#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de génération de rapports JSON.

Ce module est responsable de la génération de rapports JSON à partir
des artefacts collectés et des résultats d'analyse.
"""

import os
import logging
import datetime
import json
from typing import Dict, List, Any, Optional

logger = logging.getLogger("forensichunter")


class JSONReporter:
    """Générateur de rapports JSON."""

    def __init__(self, config, output_dir):
        """
        Initialise le générateur de rapports JSON.
        
        Args:
            config: Configuration de l'application
            output_dir: Répertoire de sortie pour les rapports
        """
        self.config = config
        self.output_dir = output_dir
    
    def generate(self, artifacts: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
        """
        Génère un rapport JSON à partir des artefacts collectés et des résultats d'analyse.
        
        Args:
            artifacts: Dictionnaire contenant tous les artefacts collectés
            analysis_results: Dictionnaire contenant les résultats d'analyse
            
        Returns:
            Chemin vers le rapport JSON généré
        """
        # Préparation des données pour le rapport
        report_data = {
            "metadata": {
                "report_date": datetime.datetime.now().isoformat(),
                "tool_version": "1.0.0",
                "execution_time": getattr(self.config, "execution_time", 0),
                "command_line": getattr(self.config, "command_line", "")
            },
            "system_info": self._get_system_info(),
            "artifacts": artifacts,
            "analysis": analysis_results
        }
        
        # Écriture du rapport dans un fichier
        report_path = os.path.join(self.output_dir, f"forensichunter_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4, default=self._json_serializer)
        
        return report_path
    
    def _get_system_info(self) -> Dict[str, Any]:
        """
        Récupère les informations système.
        
        Returns:
            Dictionnaire contenant les informations système
        """
        import platform
        import socket
        import psutil
        
        system_info = {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "user": os.environ.get("USERNAME", "N/A"),
            "boot_time": psutil.boot_time()
        }
        
        return system_info
    
    def _json_serializer(self, obj):
        """
        Sérialiseur personnalisé pour les objets non sérialisables en JSON.
        
        Args:
            obj: Objet à sérialiser
            
        Returns:
            Version sérialisable de l'objet
        """
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        
        try:
            return str(obj)
        except:
            return None

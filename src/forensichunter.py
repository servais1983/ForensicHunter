#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ForensicHunter - Outil de forensic avancé pour Windows

Ce module est le point d'entrée principal de l'application ForensicHunter.
Il coordonne l'exécution des différents collecteurs, analyseurs et générateurs de rapports.
"""

import os
import sys
import time
import argparse
import logging
import platform
from datetime import datetime
from pathlib import Path

# Ajout du répertoire parent au path pour les imports relatifs
# Cette ligne est cruciale pour permettre l'exécution du script directement
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Imports des modules internes
# Utilisation d'imports relatifs pour plus de robustesse
from utils.logger import setup_logger
from utils.config import Config
from utils.helpers import check_admin_privileges, create_output_dir

# Imports conditionnels pour éviter les erreurs si les modules ne sont pas encore créés
try:
    from utils.banner import display_banner
    from collectors.collector_manager import CollectorManager
    from analyzers.analyzer_manager import AnalyzerManager
    from reporters.reporter_manager import ReporterManager
except ImportError:
    # Fonction de remplacement si les modules ne sont pas disponibles
    def display_banner():
        print("=" * 60)
        print("ForensicHunter - Outil de forensic avancé pour Windows")
        print("=" * 60)
        print()

    # Classes de remplacement minimales
    class CollectorManager:
        def __init__(self, config):
            self.config = config
        
        def collect_artifacts(self):
            return []
    
    class AnalyzerManager:
        def __init__(self, config):
            self.config = config
        
        def analyze_artifacts(self, artifacts):
            return {}
    
    class ReporterManager:
        def __init__(self, config):
            self.config = config
        
        def generate_reports(self, artifacts, analysis_results):
            return {"placeholder": "report_path"}

__version__ = "1.0.0"


def parse_arguments():
    """Parse les arguments de ligne de commande."""
    parser = argparse.ArgumentParser(
        description="ForensicHunter - Outil de forensic avancé pour Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Options générales
    parser.add_argument("-v", "--version", action="version", version=f"ForensicHunter v{__version__}")
    parser.add_argument("--debug", action="store_true", help="Active le mode debug")
    parser.add_argument("-o", "--output", default="forensichunter_report", help="Répertoire de sortie pour les résultats")
    parser.add_argument("--gui", action="store_true", help="Lance l'interface graphique")
    
    # Options de collecte
    collection_group = parser.add_argument_group("Options de collecte")
    collection_group.add_argument("--full-scan", action="store_true", help="Effectue une collecte complète de tous les artefacts")
    collection_group.add_argument("--collect", type=str, help="Liste des collecteurs à utiliser (séparés par des virgules)")
    collection_group.add_argument("--image-path", type=str, help="Chemin vers une image disque à analyser (VMDK, VHD, etc.)")
    collection_group.add_argument("--no-memory", action="store_true", help="Désactive la collecte de la mémoire RAM")
    
    # Options d'analyse
    analysis_group = parser.add_argument_group("Options d'analyse")
    analysis_group.add_argument("--no-analysis", action="store_true", help="Désactive l'analyse des artefacts collectés")
    analysis_group.add_argument("--threat-intel", action="store_true", help="Active l'enrichissement avec des données de threat intelligence")
    analysis_group.add_argument("--yara-rules", type=str, help="Chemin vers des règles YARA personnalisées")
    
    # Options de rapport
    report_group = parser.add_argument_group("Options de rapport")
    report_group.add_argument("--format", choices=["html", "json", "csv", "all"], default="html", help="Format du rapport")
    report_group.add_argument("--no-report", action="store_true", help="Désactive la génération de rapport")
    
    return parser.parse_args()


def main():
    """Fonction principale de ForensicHunter."""
    start_time = time.time()
    
    # Affichage de la bannière
    display_banner()
    
    # Vérification du système d'exploitation
    if platform.system() != "Windows":
        print("[!] ATTENTION: ForensicHunter est conçu pour Windows. Certaines fonctionnalités peuvent ne pas fonctionner.")
    
    # Parsing des arguments
    args = parse_arguments()
    
    # Lancement de l'interface graphique si demandé
    if args.gui:
        try:
            from gui.main_gui import launch_gui
            return launch_gui()
        except ImportError:
            print("[!] ERREUR: L'interface graphique n'a pas pu être chargée.")
            print("[!] Vérifiez que PyQt5 est installé: pip install PyQt5")
            return 1
    
    # Création du répertoire de sortie
    # Do this early so logs can go into it.
    output_dir = create_output_dir(args.output)

    # Configuration du logger
    log_level = logging.DEBUG if args.debug else logging.INFO
    logger = setup_logger(log_dir=output_dir, level=log_level) # Pass output_dir here
    logger.info(f"ForensicHunter v{__version__} démarré à {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Les résultats seront enregistrés dans: {output_dir}") # Log this after logger is set up with file handler
    
    # Vérification des privilèges administrateur
    if not check_admin_privileges():
        logger.warning("ForensicHunter n'est pas exécuté avec des privilèges administrateur.")
        logger.warning("Certaines fonctionnalités de collecte peuvent être limitées.")
    
    # Initialisation de la configuration
    config = Config(args)
    
    try:
        # Phase de collecte
        logger.info("Démarrage de la phase de collecte...")
        collector_manager = CollectorManager(config)
        artifacts = collector_manager.collect_artifacts()
        logger.info(f"Collecte terminée. {len(artifacts)} artefacts collectés.")
        
        # Phase d'analyse
        if not args.no_analysis:
            logger.info("Démarrage de la phase d'analyse...")
            analyzer_manager = AnalyzerManager(config)
            analysis_results = analyzer_manager.analyze_artifacts(artifacts)
            logger.info("Analyse terminée.")
        else:
            analysis_results = {}
            logger.info("Phase d'analyse ignorée.")
        
        # Phase de génération de rapport
        if not args.no_report:
            logger.info("Génération des rapports...")
            reporter_manager = ReporterManager(config)
            report_paths = reporter_manager.generate_reports(artifacts, analysis_results)
            
            logger.info("Rapports générés avec succès:")
            for report_format, path in report_paths.items():
                logger.info(f"- {report_format.upper()}: {path}")
        else:
            logger.info("Génération de rapport ignorée.")
        
        # Affichage du temps d'exécution
        execution_time = time.time() - start_time
        logger.info(f"Exécution terminée en {execution_time:.2f} secondes.")
        
        return 0
        
    except KeyboardInterrupt:
        logger.warning("Interruption utilisateur. Arrêt de ForensicHunter.")
        return 1
    except Exception as e:
        logger.error(f"Une erreur est survenue: {str(e)}")
        if args.debug:
            logger.exception("Détails de l'erreur:")
        return 1


if __name__ == "__main__":
    sys.exit(main())

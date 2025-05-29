#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion des analyseurs d'artefacts forensiques.

Ce module permet de gérer et d'orchestrer les différents analyseurs
pour l'analyse d'artefacts forensiques.
"""

import os
import logging
import importlib
import inspect
from pathlib import Path

from .base_analyzer import BaseAnalyzer

# Configuration du logger
logger = logging.getLogger("forensichunter.analyzers.manager")

class AnalyzerManager:
    """Gestionnaire d'analyseurs d'artefacts."""
    
    def __init__(self, config=None):
        """
        Initialise un nouveau gestionnaire d'analyseurs.
        
        Args:
            config (dict, optional): Configuration du gestionnaire
        """
        self.config = config or {}
        self.analyzers = {}
        self.available_analyzers = {}
        
        # Charger les analyseurs intégrés
        self._load_builtin_analyzers()
        
        # Charger les analyseurs personnalisés
        custom_analyzers_path = self.config.get("custom_analyzers_path")
        if custom_analyzers_path and os.path.exists(custom_analyzers_path):
            self._load_custom_analyzers(custom_analyzers_path)
    
    def _load_builtin_analyzers(self):
        """Charge les analyseurs intégrés."""
        try:
            # Importer les analyseurs de base
            from .yara_analyzer import YaraAnalyzer
            from .malware_analyzer import MalwareAnalyzer
            from .phishing_analyzer import PhishingAnalyzer
            
            # Importer les analyseurs de logs et CSV
            from .log_analyzer import LogAnalyzer, CSVAnalyzer
            
            # Enregistrer les analyseurs
            self.register_analyzer(YaraAnalyzer)
            self.register_analyzer(MalwareAnalyzer)
            self.register_analyzer(PhishingAnalyzer)
            self.register_analyzer(LogAnalyzer)
            self.register_analyzer(CSVAnalyzer)
            
            # Importer les analyseurs optionnels
            try:
                from .virustotal.virustotal_analyzer import VirusTotalAnalyzer
                self.register_analyzer(VirusTotalAnalyzer)
            except ImportError:
                logger.debug("Analyseur VirusTotal non disponible")
            
            try:
                from .memory.volatility_analyzer import VolatilityAnalyzer
                self.register_analyzer(VolatilityAnalyzer)
            except ImportError:
                logger.debug("Analyseur Volatility non disponible")
            
            try:
                from ..ai.ai_analyzer import AIAnalyzer
                self.register_analyzer(AIAnalyzer)
            except ImportError:
                logger.debug("Analyseur AI non disponible")
            
            try:
                from ..behavioral.behavioral_analyzer import BehavioralAnalyzer
                self.register_analyzer(BehavioralAnalyzer)
            except ImportError:
                logger.debug("Analyseur comportemental non disponible")
            
            try:
                from ..cloud.cloud_analyzer import CloudAnalyzer
                self.register_analyzer(CloudAnalyzer)
            except ImportError:
                logger.debug("Analyseur cloud non disponible")
            
            try:
                from ..remote.remote_analyzer import RemoteAnalyzer
                self.register_analyzer(RemoteAnalyzer)
            except ImportError:
                logger.debug("Analyseur distant non disponible")
            
            logger.info(f"{len(self.analyzers)} analyseurs intégrés chargés")
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement des analyseurs intégrés: {str(e)}")
    
    def _load_custom_analyzers(self, custom_analyzers_path):
        """
        Charge les analyseurs personnalisés depuis un répertoire.
        
        Args:
            custom_analyzers_path (str): Chemin vers le répertoire des analyseurs personnalisés
        """
        try:
            # Ajouter le répertoire au chemin de recherche des modules
            import sys
            sys.path.append(os.path.dirname(custom_analyzers_path))
            
            # Parcourir les fichiers Python du répertoire
            for root, dirs, files in os.walk(custom_analyzers_path):
                for file in files:
                    if file.endswith(".py") and not file.startswith("__"):
                        try:
                            # Construire le nom du module
                            rel_path = os.path.relpath(os.path.join(root, file), custom_analyzers_path)
                            module_name = os.path.splitext(rel_path.replace(os.sep, "."))[0]
                            full_module_name = f"custom_analyzers.{module_name}"
                            
                            # Importer le module
                            module = importlib.import_module(full_module_name)
                            
                            # Rechercher les classes d'analyseurs dans le module
                            for name, obj in inspect.getmembers(module):
                                if (inspect.isclass(obj) and 
                                    issubclass(obj, BaseAnalyzer) and 
                                    obj != BaseAnalyzer):
                                    self.register_analyzer(obj)
                        
                        except Exception as e:
                            logger.error(f"Erreur lors du chargement de l'analyseur personnalisé {file}: {str(e)}")
            
            logger.info(f"{len(self.analyzers)} analyseurs personnalisés chargés")
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement des analyseurs personnalisés: {str(e)}")
    
    def register_analyzer(self, analyzer_class):
        """
        Enregistre un nouvel analyseur.
        
        Args:
            analyzer_class: Classe de l'analyseur à enregistrer
            
        Returns:
            bool: True si l'enregistrement a réussi, False sinon
        """
        try:
            # Créer une instance de l'analyseur
            analyzer = analyzer_class(self.config)
            
            # Vérifier si l'analyseur est disponible
            is_available = True
            if hasattr(analyzer, "is_available"):
                is_available = analyzer.is_available()
            
            # Enregistrer l'analyseur
            name = analyzer.get_name()
            self.analyzers[name] = analyzer_class
            self.available_analyzers[name] = is_available
            
            logger.debug(f"Analyseur {name} enregistré (disponible: {is_available})")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement de l'analyseur {analyzer_class.__name__}: {str(e)}")
            return False
    
    def get_analyzer(self, name):
        """
        Retourne un analyseur par son nom.
        
        Args:
            name (str): Nom de l'analyseur
            
        Returns:
            BaseAnalyzer: Instance de l'analyseur demandé, ou None si non trouvé
        """
        analyzer_class = self.analyzers.get(name)
        if analyzer_class:
            return analyzer_class(self.config)
        return None
    
    def get_all_analyzers(self):
        """
        Retourne tous les analyseurs enregistrés.
        
        Returns:
            list: Liste d'instances d'analyseurs
        """
        return [analyzer_class(self.config) for analyzer_class in self.analyzers.values()]
    
    def get_available_analyzers(self):
        """
        Retourne tous les analyseurs disponibles.
        
        Returns:
            list: Liste d'instances d'analyseurs disponibles
        """
        return [self.analyzers[name](self.config) for name, available in self.available_analyzers.items() if available]
    
    def analyze_artifacts(self, artifacts, analyzer_names=None):
        """
        Analyse les artefacts à l'aide des analyseurs spécifiés.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
            analyzer_names (list, optional): Liste des noms d'analyseurs à utiliser.
                Si None, tous les analyseurs disponibles sont utilisés.
                
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        findings = []
        
        # Déterminer les analyseurs à utiliser
        if analyzer_names:
            analyzers = [self.get_analyzer(name) for name in analyzer_names 
                        if name in self.analyzers and self.available_analyzers.get(name, False)]
        else:
            analyzers = self.get_available_analyzers()
        
        # Analyser les artefacts
        for analyzer in analyzers:
            try:
                logger.info(f"Analyse des artefacts avec {analyzer.get_name()}...")
                analyzer_findings = analyzer.analyze(artifacts)
                findings.extend(analyzer_findings)
                logger.info(f"{len(analyzer_findings)} résultats trouvés avec {analyzer.get_name()}")
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse avec {analyzer.get_name()}: {str(e)}")
        
        return findings
    
    def get_analyzer_info(self):
        """
        Retourne des informations sur les analyseurs enregistrés.
        
        Returns:
            list: Liste de dictionnaires contenant des informations sur les analyseurs
        """
        info = []
        
        for name, analyzer_class in self.analyzers.items():
            try:
                analyzer = analyzer_class(self.config)
                
                # Vérifier si l'analyseur est disponible
                is_available = True
                if hasattr(analyzer, "is_available"):
                    is_available = analyzer.is_available()
                
                # Ajouter les informations sur l'analyseur
                info.append({
                    "name": name,
                    "description": analyzer.get_description(),
                    "available": is_available
                })
                
            except Exception as e:
                logger.error(f"Erreur lors de la récupération des informations sur l'analyseur {name}: {str(e)}")
        
        return info

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion des plugins pour ForensicHunter.

Ce module définit l'architecture des plugins et fournit les mécanismes
pour charger, enregistrer et exécuter des plugins personnalisés.
"""

import os
import sys
import logging
import importlib
import inspect
from typing import Dict, List, Any, Optional, Type, Callable

logger = logging.getLogger("forensichunter")


class PluginInterface:
    """Interface de base pour tous les plugins ForensicHunter."""

    def __init__(self, config):
        """
        Initialise le plugin.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.name = self.__class__.__name__
        self.description = "Plugin ForensicHunter"
        self.version = "1.0.0"
        self.author = "Unknown"
    
    def get_info(self) -> Dict[str, str]:
        """
        Retourne les informations sur le plugin.
        
        Returns:
            Dictionnaire contenant les informations sur le plugin
        """
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author
        }
    
    def initialize(self) -> bool:
        """
        Initialise le plugin.
        
        Returns:
            True si l'initialisation a réussi, False sinon
        """
        return True
    
    def shutdown(self) -> bool:
        """
        Arrête le plugin.
        
        Returns:
            True si l'arrêt a réussi, False sinon
        """
        return True


class CollectorPlugin(PluginInterface):
    """Interface pour les plugins de collecte d'artefacts."""

    def collect(self) -> Dict[str, Any]:
        """
        Collecte des artefacts.
        
        Returns:
            Dictionnaire contenant les artefacts collectés
        """
        raise NotImplementedError("La méthode collect() doit être implémentée par les sous-classes")
    
    def set_image_path(self, image_path: str):
        """
        Configure le chemin vers l'image disque à analyser.
        
        Args:
            image_path: Chemin vers l'image disque
        """
        pass


class AnalyzerPlugin(PluginInterface):
    """Interface pour les plugins d'analyse d'artefacts."""

    def analyze(self, artifacts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse des artefacts.
        
        Args:
            artifacts: Dictionnaire contenant les artefacts à analyser
            
        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        raise NotImplementedError("La méthode analyze() doit être implémentée par les sous-classes")


class ReporterPlugin(PluginInterface):
    """Interface pour les plugins de génération de rapports."""

    def generate(self, artifacts: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
        """
        Génère un rapport.
        
        Args:
            artifacts: Dictionnaire contenant tous les artefacts collectés
            analysis_results: Dictionnaire contenant les résultats d'analyse
            
        Returns:
            Chemin vers le rapport généré
        """
        raise NotImplementedError("La méthode generate() doit être implémentée par les sous-classes")


class PluginManager:
    """Gestionnaire de plugins pour ForensicHunter."""

    def __init__(self, config):
        """
        Initialise le gestionnaire de plugins.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.plugins = {
            "collectors": {},
            "analyzers": {},
            "reporters": {}
        }
        self.plugin_dirs = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "plugins")
        ]
        
        # Ajout du répertoire de plugins personnalisé s'il est spécifié
        if hasattr(config, "plugin_dir") and config.plugin_dir:
            self.plugin_dirs.append(config.plugin_dir)
    
    def discover_plugins(self):
        """
        Découvre et charge tous les plugins disponibles.
        """
        logger.info("Découverte des plugins...")
        
        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                logger.debug(f"Répertoire de plugins non trouvé: {plugin_dir}")
                continue
            
            logger.debug(f"Recherche de plugins dans: {plugin_dir}")
            
            # Ajout du répertoire de plugins au chemin de recherche
            if plugin_dir not in sys.path:
                sys.path.append(plugin_dir)
            
            # Parcours des sous-répertoires
            for category in ["collectors", "analyzers", "reporters"]:
                category_dir = os.path.join(plugin_dir, category)
                if not os.path.exists(category_dir):
                    continue
                
                # Parcours des fichiers Python
                for filename in os.listdir(category_dir):
                    if filename.endswith(".py") and not filename.startswith("__"):
                        module_name = filename[:-3]  # Suppression de l'extension .py
                        self._load_plugin_module(category, module_name, os.path.join(category_dir, filename))
    
    def _load_plugin_module(self, category: str, module_name: str, module_path: str):
        """
        Charge un module de plugin.
        
        Args:
            category: Catégorie du plugin (collectors, analyzers, reporters)
            module_name: Nom du module
            module_path: Chemin vers le fichier du module
        """
        try:
            # Import du module
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Recherche des classes de plugin dans le module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if self._is_valid_plugin(category, obj):
                    try:
                        # Instanciation du plugin
                        plugin = obj(self.config)
                        plugin_info = plugin.get_info()
                        
                        # Enregistrement du plugin
                        self.plugins[category][plugin_info["name"]] = plugin
                        logger.info(f"Plugin chargé: {plugin_info['name']} ({plugin_info['description']}) v{plugin_info['version']} par {plugin_info['author']}")
                    except Exception as e:
                        logger.error(f"Erreur lors de l'instanciation du plugin {name}: {str(e)}")
                        logger.debug("Détails de l'erreur:", exc_info=True)
        
        except Exception as e:
            logger.error(f"Erreur lors du chargement du module {module_name}: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
    
    def _is_valid_plugin(self, category: str, cls) -> bool:
        """
        Vérifie si une classe est un plugin valide pour la catégorie spécifiée.
        
        Args:
            category: Catégorie du plugin (collectors, analyzers, reporters)
            cls: Classe à vérifier
            
        Returns:
            True si la classe est un plugin valide, False sinon
        """
        if category == "collectors":
            return (issubclass(cls, CollectorPlugin) and 
                    cls is not CollectorPlugin and 
                    hasattr(cls, "collect"))
        
        elif category == "analyzers":
            return (issubclass(cls, AnalyzerPlugin) and 
                    cls is not AnalyzerPlugin and 
                    hasattr(cls, "analyze"))
        
        elif category == "reporters":
            return (issubclass(cls, ReporterPlugin) and 
                    cls is not ReporterPlugin and 
                    hasattr(cls, "generate"))
        
        return False
    
    def get_collectors(self) -> Dict[str, CollectorPlugin]:
        """
        Retourne tous les plugins de collecte disponibles.
        
        Returns:
            Dictionnaire des plugins de collecte
        """
        return self.plugins["collectors"]
    
    def get_analyzers(self) -> Dict[str, AnalyzerPlugin]:
        """
        Retourne tous les plugins d'analyse disponibles.
        
        Returns:
            Dictionnaire des plugins d'analyse
        """
        return self.plugins["analyzers"]
    
    def get_reporters(self) -> Dict[str, ReporterPlugin]:
        """
        Retourne tous les plugins de génération de rapports disponibles.
        
        Returns:
            Dictionnaire des plugins de génération de rapports
        """
        return self.plugins["reporters"]
    
    def initialize_plugins(self):
        """
        Initialise tous les plugins chargés.
        """
        for category, plugins in self.plugins.items():
            for name, plugin in plugins.items():
                try:
                    if plugin.initialize():
                        logger.debug(f"Plugin {name} initialisé avec succès")
                    else:
                        logger.warning(f"Échec de l'initialisation du plugin {name}")
                except Exception as e:
                    logger.error(f"Erreur lors de l'initialisation du plugin {name}: {str(e)}")
                    logger.debug("Détails de l'erreur:", exc_info=True)
    
    def shutdown_plugins(self):
        """
        Arrête tous les plugins chargés.
        """
        for category, plugins in self.plugins.items():
            for name, plugin in plugins.items():
                try:
                    if plugin.shutdown():
                        logger.debug(f"Plugin {name} arrêté avec succès")
                    else:
                        logger.warning(f"Échec de l'arrêt du plugin {name}")
                except Exception as e:
                    logger.error(f"Erreur lors de l'arrêt du plugin {name}: {str(e)}")
                    logger.debug("Détails de l'erreur:", exc_info=True)

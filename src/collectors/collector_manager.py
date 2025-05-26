#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion des collecteurs d'artefacts.

Ce module coordonne l'exécution des différents collecteurs d'artefacts
et agrège leurs résultats.
"""

import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any

from src.collectors.event_logs import EventLogCollector
from src.collectors.registry import RegistryCollector
from src.collectors.filesystem import FilesystemCollector
from src.collectors.browser import BrowserHistoryCollector
from src.collectors.process import ProcessCollector
from src.collectors.network import NetworkCollector
from src.collectors.usb import USBCollector
from src.collectors.memory import MemoryCollector
from src.collectors.user_data import UserDataCollector

logger = logging.getLogger("forensichunter")


class CollectorManager:
    """Gestionnaire des collecteurs d'artefacts."""

    def __init__(self, config):
        """
        Initialise le gestionnaire de collecteurs.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.collectors = {}
        self._register_collectors()
        
    def _register_collectors(self):
        """Enregistre les collecteurs disponibles."""
        self.collectors = {
            "eventlogs": EventLogCollector(self.config),
            "registry": RegistryCollector(self.config),
            "filesystem": FilesystemCollector(self.config),
            "browser": BrowserHistoryCollector(self.config),
            "process": ProcessCollector(self.config),
            "network": NetworkCollector(self.config),
            "usb": USBCollector(self.config),
            "memory": MemoryCollector(self.config),
            "userdata": UserDataCollector(self.config)
        }
        
    def get_enabled_collectors(self) -> List:
        """
        Détermine quels collecteurs doivent être exécutés en fonction de la configuration.
        
        Returns:
            Liste des collecteurs à exécuter
        """
        if self.config.args.full_scan:
            enabled_collectors = list(self.collectors.values())
            
            # Si --no-memory est spécifié, on retire le collecteur de mémoire
            if self.config.args.no_memory:
                enabled_collectors = [c for c in enabled_collectors 
                                     if not isinstance(c, MemoryCollector)]
            
            return enabled_collectors
        
        elif self.config.args.collect:
            collector_names = [name.strip().lower() for name in self.config.args.collect.split(',')]
            enabled_collectors = []
            
            for name in collector_names:
                if name in self.collectors:
                    enabled_collectors.append(self.collectors[name])
                else:
                    logger.warning(f"Collecteur inconnu: {name}")
            
            return enabled_collectors
        
        else:
            # Par défaut, on active tous les collecteurs sauf celui de mémoire
            return [c for name, c in self.collectors.items() if name != "memory"]
    
    def collect_artifacts(self) -> Dict[str, Any]:
        """
        Exécute les collecteurs d'artefacts et agrège leurs résultats.
        
        Returns:
            Dictionnaire contenant tous les artefacts collectés
        """
        artifacts = {}
        enabled_collectors = self.get_enabled_collectors()
        
        logger.info(f"Démarrage de la collecte avec {len(enabled_collectors)} collecteurs")
        
        # Si on analyse une image disque, on configure les collecteurs en conséquence
        if self.config.args.image_path:
            image_path = os.path.abspath(self.config.args.image_path)
            logger.info(f"Analyse de l'image disque: {image_path}")
            
            for collector in enabled_collectors:
                collector.set_image_path(image_path)
        
        # Exécution des collecteurs en parallèle
        with ThreadPoolExecutor(max_workers=min(os.cpu_count(), len(enabled_collectors))) as executor:
            future_to_collector = {
                executor.submit(collector.collect): collector for collector in enabled_collectors
            }
            
            for future in as_completed(future_to_collector):
                collector = future_to_collector[future]
                collector_name = collector.__class__.__name__
                
                try:
                    result = future.result()
                    artifacts[collector_name] = result
                    logger.info(f"{collector_name} a collecté {len(result) if isinstance(result, list) else 'des'} artefacts")
                except Exception as e:
                    logger.error(f"Erreur lors de la collecte avec {collector_name}: {str(e)}")
                    logger.debug("Détails de l'erreur:", exc_info=True)
                    artifacts[collector_name] = {"error": str(e)}
        
        return artifacts

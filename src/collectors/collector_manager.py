#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gestionnaire des collecteurs d'artefacts.

Coordonne l'exécution des différents collecteurs en parallèle
et agrège leurs résultats.
"""

import os
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from typing import Dict, Any, List

from src.collectors.event_logs import EventLogCollector
from src.collectors.registry import RegistryCollector
from src.collectors.filesystem import FilesystemCollector
from src.collectors.browser import BrowserHistoryCollector
from src.collectors.process import ProcessCollector, NetworkCollector
from src.collectors.usb import USBCollector
from src.collectors.memory import MemoryCollector
from src.collectors.user_data import UserDataCollector

logger = logging.getLogger("forensichunter")

_COLLECTOR_TIMEOUT = 300  # seconds per collector


class CollectorManager:
    """Gestionnaire des collecteurs d'artefacts."""

    def __init__(self, config):
        self.config = config
        self.collectors: Dict[str, Any] = {}
        self._register_collectors()

    def _register_collectors(self):
        self.collectors = {
            "eventlogs": EventLogCollector(self.config),
            "registry":  RegistryCollector(self.config),
            "filesystem": FilesystemCollector(self.config),
            "browser":   BrowserHistoryCollector(self.config),
            "process":   ProcessCollector(self.config),
            "network":   NetworkCollector(self.config),
            "usb":       USBCollector(self.config),
            "memory":    MemoryCollector(self.config),
            "userdata":  UserDataCollector(self.config),
        }

    def get_enabled_collectors(self) -> List:
        """Détermine la liste des collecteurs à exécuter en fonction de la configuration."""
        args = getattr(self.config, "args", None)

        full_scan  = getattr(args, "full_scan", False)  if args else False
        collect    = getattr(args, "collect",   None)   if args else None
        no_memory  = getattr(args, "no_memory", False)  if args else False

        if full_scan:
            enabled = list(self.collectors.values())
        elif collect:
            names   = [n.strip().lower() for n in collect.split(",")]
            enabled = []
            for name in names:
                if name in self.collectors:
                    enabled.append(self.collectors[name])
                else:
                    logger.warning("Collecteur inconnu ignoré: %s", name)
        else:
            # Par défaut : tout sauf la mémoire RAM (opération lente/risquée)
            enabled = [c for name, c in self.collectors.items() if name != "memory"]

        if no_memory:
            enabled = [c for c in enabled if not isinstance(c, MemoryCollector)]

        return enabled

    def collect_artifacts(self) -> Dict[str, Any]:
        """
        Exécute les collecteurs en parallèle et agrège leurs résultats.

        Returns:
            Dictionnaire {nom_collecteur: résultats}
        """
        artifacts: Dict[str, Any] = {}
        enabled   = self.get_enabled_collectors()
        args      = getattr(self.config, "args", None)
        image_path = getattr(args, "image_path", None) if args else None

        logger.info("Démarrage de la collecte — %d collecteurs actifs", len(enabled))

        if image_path:
            abs_image = os.path.abspath(image_path)
            logger.info("Analyse de l'image disque: %s", abs_image)
            for col in enabled:
                if hasattr(col, "set_image_path"):
                    col.set_image_path(abs_image)

        max_workers = min(os.cpu_count() or 4, len(enabled)) if enabled else 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(col.collect): col for col in enabled}

            for future in as_completed(future_map, timeout=_COLLECTOR_TIMEOUT * len(enabled)):
                col  = future_map[future]
                name = col.__class__.__name__
                try:
                    result = future.result(timeout=_COLLECTOR_TIMEOUT)
                    artifacts[name] = result
                    count = len(result) if isinstance(result, (list, dict)) else "?"
                    logger.info("%s: %s artefacts collectés", name, count)
                except FuturesTimeout:
                    logger.error("%s: timeout dépassé (%ds)", name, _COLLECTOR_TIMEOUT)
                    artifacts[name] = {"error": "timeout"}
                except Exception as exc:
                    logger.error("%s: erreur lors de la collecte: %s", name, exc)
                    logger.debug("Détails:", exc_info=True)
                    artifacts[name] = {"error": str(exc)}

        return artifacts

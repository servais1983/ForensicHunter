#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de support multiplateforme pour ForensicHunter.

Ce module permet à ForensicHunter de fonctionner sur différents systèmes
d'exploitation (Windows, Linux, macOS) en adaptant les méthodes de collecte
et d'analyse.
"""

import os
import platform
import logging
import subprocess
from typing import Dict, List, Any, Optional, Union

from src.utils.security.security_manager import SecurityManager

logger = logging.getLogger("forensichunter")


class MultiPlatformSupport:
    """Classe principale pour le support multiplateforme."""

    def __init__(self, config):
        """
        Initialise le support multiplateforme.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.security_manager = SecurityManager(config)
        self.os_type = self.get_os_type()
        logger.info(f"Système d'exploitation détecté: {self.os_type}")
    
    def get_os_type(self) -> str:
        """
        Détecte le type de système d'exploitation.
        
        Returns:
            Type de système d'exploitation (windows, linux, macos, unknown)
        """
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "linux":
            return "linux"
        elif system == "darwin":
            return "macos"
        else:
            return "unknown"
    
    def adapt_collector(self, collector_name: str, collector_instance: Any) -> Any:
        """
        Adapte un collecteur pour le système d'exploitation actuel.
        
        Args:
            collector_name: Nom du collecteur
            collector_instance: Instance du collecteur
            
        Returns:
            Instance du collecteur adaptée ou None si non supporté
        """
        if self.os_type == "windows":
            # Les collecteurs Windows sont déjà adaptés
            return collector_instance
        elif self.os_type == "linux":
            # Adapter pour Linux
            return self._adapt_for_linux(collector_name, collector_instance)
        elif self.os_type == "macos":
            # Adapter pour macOS
            return self._adapt_for_macos(collector_name, collector_instance)
        else:
            logger.warning(f"Système d'exploitation non supporté: {self.os_type}")
            return None
    
    def _adapt_for_linux(self, collector_name: str, collector_instance: Any) -> Any:
        """
        Adapte un collecteur pour Linux.
        
        Args:
            collector_name: Nom du collecteur
            collector_instance: Instance du collecteur
            
        Returns:
            Instance du collecteur adaptée ou None si non supporté
        """
        logger.info(f"Adaptation du collecteur {collector_name} pour Linux")
        
        # Exemple d'adaptation (à compléter pour chaque collecteur)
        if collector_name == "event_logs":
            # Remplacer par la collecte des logs syslog/journald
            logger.info("Remplacement de la collecte des journaux d'événements par syslog/journald")
            # return LinuxSyslogCollector(self.config)
            return None # Pour l'instant
        elif collector_name == "registry":
            # Non applicable sur Linux
            logger.info("Collecteur de registre non applicable sur Linux")
            return None
        elif collector_name == "browser_history":
            # Adapter les chemins pour Linux
            logger.info("Adaptation des chemins pour l'historique des navigateurs sur Linux")
            # ... modifier les chemins dans l'instance ...
            return collector_instance
        elif collector_name == "processes":
            # Utiliser les commandes Linux (ps, netstat)
            logger.info("Adaptation de la collecte des processus pour Linux")
            # return LinuxProcessCollector(self.config)
            return None # Pour l'instant
        elif collector_name == "usb_devices":
            # Utiliser les commandes Linux (lsusb, dmesg)
            logger.info("Adaptation de la collecte des périphériques USB pour Linux")
            # return LinuxUSBCollector(self.config)
            return None # Pour l'instant
        elif collector_name == "filesystem":
            # Adapter les chemins et commandes Linux
            logger.info("Adaptation de la collecte du système de fichiers pour Linux")
            # ... modifier les chemins et commandes ...
            return collector_instance
        elif collector_name == "memory":
            # Utiliser des outils comme LiME ou fmem
            logger.info("Adaptation de la capture mémoire pour Linux")
            # return LinuxMemoryCollector(self.config)
            return None # Pour l'instant
        elif collector_name == "user_data":
            # Adapter les chemins pour Linux
            logger.info("Adaptation de la collecte des données utilisateur pour Linux")
            # ... modifier les chemins ...
            return collector_instance
        else:
            return collector_instance # Par défaut, retourne l'instance originale
    
    def _adapt_for_macos(self, collector_name: str, collector_instance: Any) -> Any:
        """
        Adapte un collecteur pour macOS.
        
        Args:
            collector_name: Nom du collecteur
            collector_instance: Instance du collecteur
            
        Returns:
            Instance du collecteur adaptée ou None si non supporté
        """
        logger.info(f"Adaptation du collecteur {collector_name} pour macOS")
        
        # Exemple d'adaptation (à compléter pour chaque collecteur)
        if collector_name == "event_logs":
            # Remplacer par la collecte des logs système macOS (ASL, unified logging)
            logger.info("Remplacement de la collecte des journaux d'événements par les logs macOS")
            # return MacOSLogCollector(self.config)
            return None # Pour l'instant
        elif collector_name == "registry":
            # Non applicable sur macOS
            logger.info("Collecteur de registre non applicable sur macOS")
            return None
        elif collector_name == "browser_history":
            # Adapter les chemins pour macOS
            logger.info("Adaptation des chemins pour l'historique des navigateurs sur macOS")
            # ... modifier les chemins dans l'instance ...
            return collector_instance
        elif collector_name == "processes":
            # Utiliser les commandes macOS (ps, netstat, lsof)
            logger.info("Adaptation de la collecte des processus pour macOS")
            # return MacOSProcessCollector(self.config)
            return None # Pour l'instant
        elif collector_name == "usb_devices":
            # Utiliser les commandes macOS (system_profiler)
            logger.info("Adaptation de la collecte des périphériques USB pour macOS")
            # return MacOSUSBCollector(self.config)
            return None # Pour l'instant
        elif collector_name == "filesystem":
            # Adapter les chemins et commandes macOS
            logger.info("Adaptation de la collecte du système de fichiers pour macOS")
            # ... modifier les chemins et commandes ...
            return collector_instance
        elif collector_name == "memory":
            # Utiliser des outils comme OSXPMem
            logger.info("Adaptation de la capture mémoire pour macOS")
            # return MacOSMemoryCollector(self.config)
            return None # Pour l'instant
        elif collector_name == "user_data":
            # Adapter les chemins pour macOS
            logger.info("Adaptation de la collecte des données utilisateur pour macOS")
            # ... modifier les chemins ...
            return collector_instance
        else:
            return collector_instance # Par défaut, retourne l'instance originale
    
    def run_command(self, command: List[str]) -> Optional[str]:
        """
        Exécute une commande système de manière sécurisée.
        
        Args:
            command: Commande à exécuter (liste d'arguments)
            
        Returns:
            Sortie de la commande ou None en cas d'erreur
        """
        # Validation de la commande
        if not self.security_manager.validate_input(command[0], "command"):
            logger.error(f"Commande non autorisée: {command[0]}")
            return None
        
        try:
            # Exécution de la commande
            process = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
            
            if process.returncode != 0:
                logger.error(f"Erreur lors de l'exécution de la commande {' '.join(command)}: {process.stderr}")
                return None
            
            return process.stdout
            
        except FileNotFoundError:
            logger.error(f"Commande introuvable: {command[0]}")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout lors de l'exécution de la commande: {' '.join(command)}")
            return None
        except Exception as e:
            logger.error(f"Erreur inattendue lors de l'exécution de la commande {' '.join(command)}: {str(e)}")
            return None

# --- Classes spécifiques à chaque OS (Exemples à implémenter) ---

# class LinuxSyslogCollector:
#     def __init__(self, config):
#         self.config = config
#     def collect(self):
#         # Logique de collecte pour syslog/journald
#         pass

# class LinuxProcessCollector:
#     def __init__(self, config):
#         self.config = config
#     def collect(self):
#         # Logique de collecte pour les processus Linux
#         pass

# class MacOSLogCollector:
#     def __init__(self, config):
#         self.config = config
#     def collect(self):
#         # Logique de collecte pour les logs macOS
#         pass

# ... etc pour les autres collecteurs spécifiques à chaque OS ...


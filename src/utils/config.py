#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de configuration pour ForensicHunter.

Ce module fournit des classes et fonctions pour gérer la configuration
de l'application ForensicHunter.
"""

import os
import json
import platform
from pathlib import Path

class Config:
    """Classe de gestion de la configuration de ForensicHunter."""
    
    def __init__(self, args=None):
        """
        Initialise la configuration avec les arguments de ligne de commande.
        
        Args:
            args: Arguments de ligne de commande parsés
        """
        self.args = args or {}
        self.config_data = {}
        
        # Chargement de la configuration par défaut
        self._load_default_config()
        
        # Mise à jour avec les arguments de ligne de commande
        if args:
            self._update_from_args()
    
    def _load_default_config(self):
        """Charge la configuration par défaut."""
        self.config_data = {
            "general": {
                "debug": False,
                "output_dir": "forensichunter_report",
                "log_level": "INFO",
                "platform": platform.system()
            },
            "collection": {
                "full_scan": False,
                "collectors": [],
                "image_path": None,
                "memory_dump": True
            },
            "analysis": {
                "enabled": True,
                "threat_intel": False,
                "yara_rules": None
            },
            "reporting": {
                "enabled": True,
                "formats": ["html"]
            }
        }
    
    def _update_from_args(self):
        """Met à jour la configuration avec les arguments de ligne de commande."""
        # Mise à jour des options générales
        if hasattr(self.args, "debug"):
            self.config_data["general"]["debug"] = self.args.debug
            self.config_data["general"]["log_level"] = "DEBUG" if self.args.debug else "INFO"
        
        if hasattr(self.args, "output"):
            self.config_data["general"]["output_dir"] = self.args.output
        
        # Mise à jour des options de collecte
        if hasattr(self.args, "full_scan"):
            self.config_data["collection"]["full_scan"] = self.args.full_scan
        
        if hasattr(self.args, "collect") and self.args.collect:
            self.config_data["collection"]["collectors"] = self.args.collect.split(",")
        
        if hasattr(self.args, "image_path"):
            self.config_data["collection"]["image_path"] = self.args.image_path
        
        if hasattr(self.args, "no_memory"):
            self.config_data["collection"]["memory_dump"] = not self.args.no_memory
        
        # Mise à jour des options d'analyse
        if hasattr(self.args, "no_analysis"):
            self.config_data["analysis"]["enabled"] = not self.args.no_analysis
        
        if hasattr(self.args, "threat_intel"):
            self.config_data["analysis"]["threat_intel"] = self.args.threat_intel
        
        if hasattr(self.args, "yara_rules"):
            self.config_data["analysis"]["yara_rules"] = self.args.yara_rules
        
        # Mise à jour des options de rapport
        if hasattr(self.args, "no_report"):
            self.config_data["reporting"]["enabled"] = not self.args.no_report
        
        if hasattr(self.args, "format"):
            if self.args.format == "all":
                self.config_data["reporting"]["formats"] = ["html", "json", "csv"]
            else:
                self.config_data["reporting"]["formats"] = [self.args.format]
    
    def get(self, section, key=None):
        """
        Récupère une valeur de configuration.
        
        Args:
            section (str): Section de configuration
            key (str, optional): Clé spécifique dans la section
            
        Returns:
            La valeur de configuration demandée
        """
        if key is None:
            return self.config_data.get(section, {})
        return self.config_data.get(section, {}).get(key)
    
    def set(self, section, key, value):
        """
        Définit une valeur de configuration.
        
        Args:
            section (str): Section de configuration
            key (str): Clé dans la section
            value: Valeur à définir
        """
        if section not in self.config_data:
            self.config_data[section] = {}
        self.config_data[section][key] = value
    
    def save_to_file(self, filepath):
        """
        Sauvegarde la configuration dans un fichier JSON.
        
        Args:
            filepath (str): Chemin du fichier de configuration
        """
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.config_data, f, indent=4)
            return True
        except Exception:
            return False
    
    def load_from_file(self, filepath):
        """
        Charge la configuration depuis un fichier JSON.
        
        Args:
            filepath (str): Chemin du fichier de configuration
            
        Returns:
            bool: True si le chargement a réussi, False sinon
        """
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                
                # Mise à jour de la configuration
                for section, values in loaded_config.items():
                    if section in self.config_data:
                        self.config_data[section].update(values)
                    else:
                        self.config_data[section] = values
                
                return True
            return False
        except Exception:
            return False

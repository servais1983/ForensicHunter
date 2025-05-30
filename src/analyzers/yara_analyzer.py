#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'analyse YARA pour la détection de menaces.

Ce module permet d'appliquer des règles YARA aux artefacts collectés
pour détecter des menaces connues.
"""

import os
import sys
import logging
import tempfile
import json
import platform
import re
from pathlib import Path
import shutil

from .base_analyzer import BaseAnalyzer, Finding

# Configuration du logger
logger = logging.getLogger("forensichunter.analyzers.yara")

# Importation conditionnelle de YARA
try:
    import yara  # type: ignore
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("Module YARA non disponible. L'analyseur YARA ne fonctionnera pas.")

class YaraAnalyzer(BaseAnalyzer):
    """Analyseur basé sur des règles YARA."""
    
    def __init__(self, config=None):
        """
        Initialise un nouvel analyseur YARA.
        
        Args:
            config (dict, optional): Configuration de l'analyseur
        """
        super().__init__(config)
        self.rules_dir = self.config.get("rules_dir", os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rules"))
        self.custom_rules = self.config.get("custom_rules", [])
        self.max_file_size = self.config.get("max_file_size", 50 * 1024 * 1024)  # 50 MB
        self.compiled_rules = None
        self.temp_dir = None
        self.yara_available = YARA_AVAILABLE
        self.yara = yara if YARA_AVAILABLE else None
        self.valid_rules_dir = None
        
        # Tentative d'initialisation de YARA
        self._initialize_yara()
    
    def get_name(self):
        """
        Retourne le nom de l'analyseur.
        
        Returns:
            str: Nom de l'analyseur
        """
        return "YaraAnalyzer"
    
    def get_description(self):
        """
        Retourne la description de l'analyseur.
        
        Returns:
            str: Description de l'analyseur
        """
        return "Analyseur basé sur des règles YARA pour la détection de menaces connues"
    
    def is_available(self):
        """
        Vérifie si l'analyseur est disponible.
        
        Returns:
            bool: True si YARA est disponible, False sinon
        """
        return self.yara_available
    
    def _initialize_yara(self):
        """
        Initialise le module YARA et compile les règles.
        
        Returns:
            bool: True si l'initialisation a réussi, False sinon
        """
        if not self.yara_available:
            logger.error("Module YARA non disponible")
            return False
        
        try:
            # Vérifier si le répertoire des règles existe
            if not os.path.exists(self.rules_dir):
                logger.error(f"Répertoire des règles YARA non trouvé: {self.rules_dir}")
                return False
            
            # Compiler les règles
            if not self._compile_rules():
                logger.error("Échec de la compilation des règles YARA")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation de YARA: {str(e)}")
            return False
    
    def _compile_rules(self):
        """
        Compile les règles YARA.
        
        Returns:
            bool: True si la compilation a réussi, False sinon
        """
        if not self.yara_available or not self.yara:
            logger.error("Module YARA non disponible")
            return False
        
        try:
            # Chercher le fichier all_rules.yar (index global)
            all_rules_path = os.path.join(self.rules_dir, "all_rules.yar")
            if not os.path.exists(all_rules_path):
                logger.error(f"Fichier all_rules.yar non trouvé: {all_rules_path}")
                return False
            
            # Compiler toutes les règles via l'index global
            try:
                self.compiled_rules = self.yara.compile(filepath=all_rules_path)
                logger.info("Toutes les règles YARA du projet sont compilées via l'index global.")
                return True
            except Exception as e:
                logger.error(f"Erreur lors de la compilation de l'index global YARA: {str(e)}")
                return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la compilation des règles YARA: {str(e)}")
            return False
    
    def analyze(self, artifacts):
        """
        Analyse les artefacts en utilisant des règles YARA.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
            
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        self.clear_findings()
        
        if not self.yara_available:
            logger.warning("Module YARA non disponible. Analyse ignorée.")
            self.add_finding(
                finding_type="yara_unavailable",
                description="Module YARA non disponible - analyse YARA ignorée",
                severity="info",
                confidence=100,
                artifacts=[],
                metadata={
                    "reason": "yara_module_not_available",
                    "recommendation": "Réinstaller yara-python ou utiliser conda install -c conda-forge yara-python"
                }
            )
            return self.findings
        
        # Vérifier si les règles sont compilées
        if not self.compiled_rules:
            if not self._compile_rules():
                logger.error("Impossible de compiler les règles YARA")
                return self.findings
        
        # Créer un répertoire temporaire si nécessaire
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp(prefix="yara_")
        
        # Analyser chaque artefact
        for artifact in artifacts:
            try:
                # Vérifier la taille du fichier
                if artifact.size > self.max_file_size:
                    logger.warning(f"Fichier trop grand pour l'analyse YARA: {artifact.path}")
                    continue
                
                # Copier le fichier dans un répertoire temporaire
                temp_file_path = os.path.join(self.temp_dir, os.path.basename(artifact.path))
                shutil.copy2(artifact.path, temp_file_path)
                
                try:
                    # Appliquer les règles YARA
                    matches = self.compiled_rules.match(temp_file_path)
                    
                    # Traiter les correspondances
                    for match in matches:
                        try:
                            rule_name = match.rule
                            tags = match.tags
                            meta = match.meta
                            strings = match.strings
                            
                            # Déterminer la sévérité et la confiance
                            severity = meta.get("severity", "medium")
                            confidence = meta.get("confidence", 70)
                            
                            # Créer un résultat
                            description = meta.get("description", f"Règle YARA '{rule_name}' correspondante")
                            
                            self.add_finding(
                                finding_type="yara_match",
                                description=description,
                                severity=severity,
                                confidence=confidence,
                                artifacts=[artifact],
                                metadata={
                                    "rule_name": rule_name,
                                    "tags": list(tags),
                                    "meta": dict(meta),
                                    "strings": [(offset, identifier, data.hex()) for offset, identifier, data in strings],
                                    "file_path": artifact.path,
                                    "file_type": artifact.type
                                }
                            )
                            
                        except Exception as e:
                            logger.error(f"Erreur lors du traitement d'une correspondance YARA: {str(e)}")
                            continue
                    
                except Exception as e:
                    logger.error(f"Erreur lors de l'application des règles YARA: {str(e)}")
                    continue
                
                finally:
                    # Nettoyer le fichier temporaire
                    try:
                        os.remove(temp_file_path)
                    except:
                        pass
                
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse YARA d'un artefact: {str(e)}")
                continue
        
        return self.findings
    
    def cleanup(self):
        """
        Nettoie les ressources utilisées par l'analyseur.
        """
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
            except:
                pass

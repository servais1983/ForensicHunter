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
        self.temp_dir = None
        self.rules = {}
        
        # Charger les règles
        self._load_rules()
    
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
    
    def _load_rules(self):
        """
        Charge les règles YARA depuis les fichiers.
        
        Returns:
            bool: True si le chargement a réussi, False sinon
        """
        try:
            # Vérifier si le répertoire des règles existe
            if not os.path.exists(self.rules_dir):
                logger.error(f"Répertoire des règles YARA non trouvé: {self.rules_dir}")
                return False
            
            # Charger le fichier all_rules.yar
            all_rules_path = os.path.join(self.rules_dir, "all_rules.yar")
            if not os.path.exists(all_rules_path):
                logger.error(f"Fichier all_rules.yar non trouvé: {all_rules_path}")
                return False
            
            # Lire le contenu du fichier
            with open(all_rules_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extraire les règles
            rule_pattern = r'rule\s+(\w+)\s*{([^}]+)}'
            matches = re.finditer(rule_pattern, content, re.DOTALL)
            
            for match in matches:
                rule_name = match.group(1)
                rule_content = match.group(2)
                self.rules[rule_name] = rule_content
            
            logger.info(f"{len(self.rules)} règles YARA chargées avec succès")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement des règles YARA: {str(e)}")
            return False
    
    def _match_rule(self, content, rule_name, rule_content):
        """
        Applique une règle YARA à un contenu.
        
        Args:
            content (str): Contenu à analyser
            rule_name (str): Nom de la règle
            rule_content (str): Contenu de la règle
            
        Returns:
            dict: Résultat de la correspondance ou None
        """
        try:
            # Extraire les chaînes simples et regex
            strings_pattern = r'\$(\w+)\s*=\s*(?:"([^"]+)"|/(.*?)/)'
            strings = re.findall(strings_pattern, rule_content, re.DOTALL)
            
            # Extraire la condition
            condition_pattern = r'condition:\s*(.+)'
            condition_match = re.search(condition_pattern, rule_content)
            if not condition_match:
                return None
            condition = condition_match.group(1).strip()
            
            # Vérifier les correspondances
            matches = []
            for string_name, string_value, regex_value in strings:
                if string_value:
                    if string_value in content:
                        matches.append((string_name, string_value))
                elif regex_value:
                    if re.search(regex_value, content, re.DOTALL):
                        matches.append((string_name, f"/{regex_value}/"))
            # Évaluer la condition
            if "any of them" in condition and matches:
                return {
                    "rule_name": rule_name,
                    "matches": matches,
                    "meta": self._extract_meta(rule_content)
                }
            elif "all of them" in condition and len(matches) == len(strings):
                return {
                    "rule_name": rule_name,
                    "matches": matches,
                    "meta": self._extract_meta(rule_content)
                }
            elif "all of ($protocol*)" in condition and len(matches) >= 3:
                # Cas particulier pour les anciennes règles Zeus
                return {
                    "rule_name": rule_name,
                    "matches": matches,
                    "meta": self._extract_meta(rule_content)
                }
            elif "all of them" in condition and len(matches) >= 1 and len(matches) == len(strings):
                return {
                    "rule_name": rule_name,
                    "matches": matches,
                    "meta": self._extract_meta(rule_content)
                }
            return None
        except Exception as e:
            logger.error(f"Erreur lors de l'application de la règle {rule_name}: {str(e)}")
            return None
    
    def _extract_meta(self, rule_content):
        """
        Extrait les métadonnées d'une règle.
        
        Args:
            rule_content (str): Contenu de la règle
            
        Returns:
            dict: Métadonnées extraites
        """
        meta = {}
        meta_pattern = r'meta:\s*([^}]+)'
        meta_match = re.search(meta_pattern, rule_content)
        
        if meta_match:
            meta_content = meta_match.group(1)
            meta_lines = meta_content.split('\n')
            for line in meta_lines:
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    meta[key.strip()] = value.strip().strip('"')
        
        return meta
    
    def analyze(self, artifacts):
        """
        Analyse les artefacts en utilisant des règles YARA.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
            
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        self.clear_findings()
        
        # Créer un répertoire temporaire si nécessaire
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp(prefix="yara_")
        
        # Analyser chaque artefact
        for artifact in artifacts:
            try:
                # Vérifier la taille du fichier
                size = 0
                if hasattr(artifact, 'metadata') and artifact.metadata:
                    size = artifact.metadata.get('size', 0)
                if size > self.max_file_size:
                    logger.warning(f"Fichier trop grand pour l'analyse YARA: {getattr(artifact, 'source', getattr(artifact, 'path', ''))}")
                    continue

                # Utiliser le contenu déjà présent dans artifact.data
                content = artifact.data if isinstance(artifact.data, str) else ''
                if not content:
                    logger.warning(f"Aucun contenu à analyser pour l'artefact: {getattr(artifact, 'source', getattr(artifact, 'path', ''))}")
                    continue

                # Appliquer chaque règle
                for rule_name, rule_content in self.rules.items():
                    match_result = self._match_rule(content, rule_name, rule_content)
                    if match_result:
                        meta = match_result["meta"]
                        severity = meta.get("severity", "medium")
                        confidence = int(meta.get("confidence", 70))
                        self.add_finding(
                            finding_type="yara_match",
                            description=meta.get("description", f"Règle YARA '{rule_name}' correspondante"),
                            severity=severity,
                            confidence=confidence,
                            artifacts=[artifact],
                            metadata={
                                "rule_name": rule_name,
                                "meta": meta,
                                "matches": match_result["matches"],
                                "file_path": getattr(artifact, 'source', getattr(artifact, 'path', '')),
                                "file_type": getattr(artifact, 'type', None)
                            }
                        )
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

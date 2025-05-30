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
        Initialise le module YARA avec gestion d'erreurs robuste.
        """
        if not YARA_AVAILABLE:
            logger.error("Module YARA non disponible")
            logger.info("Solutions possibles :")
            logger.info("1. Réinstaller yara-python : pip uninstall yara-python && pip install yara-python")
            logger.info("2. Installer les Visual C++ Redistributables")
            logger.info("3. Utiliser conda : conda install -c conda-forge yara-python")
            self.yara_available = False
            return
        
        self.yara_available = True
        logger.info("Module YARA initialisé avec succès")
    
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
            # Chercher les fichiers de règles
            rule_files = []
            for root, dirs, files in os.walk(self.rules_dir):
                for file in files:
                    if file.endswith((".yar", ".yara")):
                        rule_files.append(os.path.join(root, file))
            
            # Ajouter les règles personnalisées
            for rule_path in self.custom_rules:
                if os.path.exists(rule_path):
                    rule_files.append(rule_path)
            
            if not rule_files:
                logger.error("Aucune règle YARA trouvée")
                return False
            
            # Compiler les règles une par une
            compiled_rules = []
            for rule_file in rule_files:
                try:
                    # Vérifier si le fichier existe et est lisible
                    if not os.path.exists(rule_file) or not os.access(rule_file, os.R_OK):
                        logger.warning(f"Fichier de règle inaccessible: {rule_file}")
                        continue
                    
                    # Lire le contenu du fichier
                    with open(rule_file, 'r', encoding='utf-8', errors='ignore') as f:
                        rule_content = f.read().strip()
                    
                    if not rule_content:
                        logger.warning(f"Fichier de règle vide: {rule_file}")
                        continue
                    
                    # Compiler la règle
                    try:
                        rule = self.yara.compile(source=rule_content)
                        compiled_rules.append(rule)
                        logger.debug(f"Règle compilée avec succès: {rule_file}")
                    except Exception as e:
                        logger.warning(f"Erreur lors de la compilation de la règle {rule_file}: {str(e)}")
                        continue
                        
                except Exception as e:
                    logger.warning(f"Erreur lors de la lecture de la règle {rule_file}: {str(e)}")
                    continue
            
            if not compiled_rules:
                logger.error("Aucune règle n'a pu être compilée")
                return False
            
            # Créer un objet Rules qui combine toutes les règles
            try:
                self.compiled_rules = self.yara.Rules()
                for rule in compiled_rules:
                    self.compiled_rules.add_rule(rule)
                logger.info(f"{len(compiled_rules)} règles YARA compilées avec succès")
                return True
            except Exception as e:
                logger.error(f"Erreur lors de la combinaison des règles YARA: {str(e)}")
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
        
        # Créer un répertoire temporaire pour les fichiers à analyser
        if self.temp_dir and os.path.exists(self.temp_dir):
            self._cleanup_temp_dir()
        self.temp_dir = tempfile.mkdtemp(prefix="forensichunter_yara_")
        
        try:
            # Filtrer les artefacts pertinents (fichiers)
            file_artifacts = []
            for artifact in artifacts:
                try:
                    if isinstance(artifact, dict):
                        if artifact.get("type") == "filesystem":
                            file_artifacts.append(artifact)
                    else:
                        if hasattr(artifact, 'type') and artifact.type == "filesystem":
                            if hasattr(artifact, 'data') and artifact.data:
                                if isinstance(artifact.data, dict) and artifact.data.get("type") in ["text", "binary"]:
                                    file_artifacts.append(artifact)
                except Exception as e:
                    logger.warning(f"Erreur lors du filtrage de l'artefact: {str(e)}")
                    continue
            
            if not file_artifacts:
                logger.info("Aucun artefact de type fichier à analyser")
                return self.findings
            
            logger.info(f"Analyse de {len(file_artifacts)} artefacts de type fichier avec YARA...")
            
            # Analyser chaque artefact
            for artifact in file_artifacts:
                try:
                    # Extraire les informations du fichier
                    if isinstance(artifact, dict):
                        file_path = artifact.get("data", {}).get("file_path", "")
                        file_type = artifact.get("data", {}).get("type", "")
                        artifact_id = artifact.get("id", "unknown")
                    else:
                        file_path = artifact.data.get("file_path", "") if hasattr(artifact, 'data') else ""
                        file_type = artifact.data.get("type", "") if hasattr(artifact, 'data') else ""
                        artifact_id = getattr(artifact, 'id', 'unknown')
                    
                    if not file_path or not file_type:
                        continue
                    
                    # Vérifier la taille du fichier
                    if self._get_artifact_size(artifact) > self.max_file_size:
                        logger.debug(f"Fichier {file_path} trop volumineux pour l'analyse YARA")
                        continue
                    
                    # Créer un fichier temporaire pour l'analyse
                    temp_file_path = self._create_temp_file(artifact)
                    if not temp_file_path or not os.path.exists(temp_file_path):
                        continue
                    
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
                                        "file_path": file_path,
                                        "file_type": file_type
                                    }
                                )
                                
                                logger.info(f"Correspondance YARA trouvée: {rule_name} dans {file_path}")
                            except Exception as e:
                                logger.error(f"Erreur lors du traitement de la correspondance YARA: {str(e)}")
                                continue
                    except Exception as e:
                        logger.error(f"Erreur lors de l'analyse YARA du fichier {file_path}: {str(e)}")
                        continue
                
                except Exception as e:
                    logger.error(f"Erreur lors de l'analyse de l'artefact {artifact_id}: {str(e)}")
                    continue
            
            logger.info(f"{len([f for f in self.findings if f.finding_type == 'yara_match'])} correspondances YARA trouvées au total")
            return self.findings
            
        except Exception as e:
            logger.error(f"Erreur générale lors de l'analyse YARA: {str(e)}")
            return self.findings
        finally:
            # Nettoyer le répertoire temporaire
            self._cleanup_temp_dir()
    
    def _get_artifact_size(self, artifact):
        """
        Calcule la taille approximative d'un artefact.
        
        Args:
            artifact: Artefact à mesurer
            
        Returns:
            int: Taille approximative en octets
        """
        try:
            if isinstance(artifact, dict):
                data = artifact.get("data", {})
            else:
                data = artifact.data
            
            if data.get("type") == "text":
                content = data.get("content", "")
                return len(content.encode('utf-8'))
            elif data.get("type") == "binary":
                header_hex = data.get("header_hex", "")
                return len(header_hex) // 2  # 2 caractères hex = 1 octet
            return 0
        except:
            return 0
    
    def _create_temp_file(self, artifact):
        """
        Crée un fichier temporaire à partir d'un artefact.
        
        Args:
            artifact: Artefact à convertir en fichier
            
        Returns:
            str: Chemin vers le fichier temporaire, ou None en cas d'erreur
        """
        try:
            # Extraire les informations du fichier
            if isinstance(artifact, dict):
                data = artifact.get("data", {})
            else:
                data = artifact.data
            
            file_path = data.get("file_path", "")
            file_name = os.path.basename(file_path)
            file_type = data.get("type", "")
            
            # Créer un nom de fichier temporaire
            temp_file_path = os.path.join(self.temp_dir, f"{artifact.id if hasattr(artifact, 'id') else 'unknown'}_{file_name}")
            
            # Écrire le contenu dans le fichier temporaire
            if file_type == "text":
                content = data.get("content", "")
                with open(temp_file_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(content)
            elif file_type == "binary":
                header_hex = data.get("header_hex", "")
                if header_hex:
                    try:
                        binary_data = bytes.fromhex(header_hex)
                        with open(temp_file_path, 'wb') as f:
                            f.write(binary_data)
                    except:
                        logger.error(f"Erreur lors de la conversion de l'hexadécimal en binaire pour {file_path}")
                        return None
                else:
                    logger.warning(f"Pas de données binaires pour {file_path}")
                    return None
            else:
                logger.warning(f"Type de fichier non pris en charge: {file_type}")
                return None
            
            return temp_file_path
            
        except Exception as e:
            logger.error(f"Erreur lors de la création du fichier temporaire: {str(e)}")
            return None
    
    def _cleanup_temp_dir(self):
        """
        Nettoie le répertoire temporaire.
        """
        try:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.debug(f"Répertoire temporaire supprimé: {self.temp_dir}")
        except Exception as e:
            logger.warning(f"Erreur lors du nettoyage du répertoire temporaire: {str(e)}")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de base pour les analyseurs d'artefacts forensiques.

Ce module définit l'interface commune à tous les analyseurs
et fournit des fonctionnalités de base pour l'analyse d'artefacts.
"""

import os
import logging
import datetime
import uuid
from abc import ABC, abstractmethod

# Configuration du logger
logger = logging.getLogger("forensichunter.analyzers")

class Finding:
    """Classe représentant un résultat d'analyse forensique."""
    
    def __init__(self, finding_type, description, severity, confidence=50, artifacts=None, metadata=None):
        """
        Initialise un nouveau résultat d'analyse.
        
        Args:
            finding_type (str): Type de résultat (malware, phishing, backdoor, etc.)
            description (str): Description détaillée du résultat
            severity (str): Sévérité du résultat (info, low, medium, high, critical)
            confidence (int): Niveau de confiance (0-100)
            artifacts (list, optional): Liste des artefacts associés au résultat
            metadata (dict, optional): Métadonnées associées au résultat
        """
        self.id = str(uuid.uuid4())
        self.type = finding_type
        self.description = description
        self.severity = severity
        self.confidence = confidence
        self.timestamp = datetime.datetime.now().isoformat()
        self.artifacts = artifacts or []
        self.metadata = metadata or {}
    
    def to_dict(self):
        """
        Convertit le résultat en dictionnaire.
        
        Returns:
            dict: Représentation du résultat sous forme de dictionnaire
        """
        return {
            "id": self.id,
            "type": self.type,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "artifacts": [artifact.id if hasattr(artifact, 'id') else artifact for artifact in self.artifacts],
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data):
        """
        Crée un résultat à partir d'un dictionnaire.
        
        Args:
            data (dict): Dictionnaire contenant les données du résultat
            
        Returns:
            Finding: Instance de résultat créée à partir du dictionnaire
        """
        finding = cls(
            data["type"],
            data["description"],
            data["severity"],
            data.get("confidence", 50),
            data.get("artifacts", []),
            data.get("metadata")
        )
        finding.id = data["id"]
        finding.timestamp = data["timestamp"]
        return finding


class BaseAnalyzer(ABC):
    """Classe de base pour tous les analyseurs d'artefacts."""
    
    def __init__(self, config=None):
        """
        Initialise un nouvel analyseur.
        
        Args:
            config (dict, optional): Configuration de l'analyseur
        """
        self.config = config or {}
        self.findings = []
    
    @abstractmethod
    def analyze(self, artifacts):
        """
        Analyse les artefacts.
        
        Cette méthode doit être implémentée par les classes dérivées.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
            
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        pass
    
    @abstractmethod
    def get_name(self):
        """
        Retourne le nom de l'analyseur.
        
        Cette méthode doit être implémentée par les classes dérivées.
        
        Returns:
            str: Nom de l'analyseur
        """
        pass
    
    @abstractmethod
    def get_description(self):
        """
        Retourne la description de l'analyseur.
        
        Cette méthode doit être implémentée par les classes dérivées.
        
        Returns:
            str: Description de l'analyseur
        """
        pass
    
    def get_findings(self):
        """
        Retourne les résultats de l'analyse.
        
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        return self.findings
    
    def add_finding(self, finding_type, description, severity, confidence=50, artifacts=None, metadata=None):
        """
        Ajoute un nouveau résultat à la liste des résultats d'analyse.
        
        Args:
            finding_type (str): Type de résultat
            description (str): Description détaillée du résultat
            severity (str): Sévérité du résultat
            confidence (int, optional): Niveau de confiance (0-100)
            artifacts (list, optional): Liste des artefacts associés au résultat
            metadata (dict, optional): Métadonnées associées au résultat
            
        Returns:
            Finding: Résultat créé
        """
        finding = Finding(finding_type, description, severity, confidence, artifacts, metadata)
        self.findings.append(finding)
        return finding
    
    def clear_findings(self):
        """Efface la liste des résultats d'analyse."""
        self.findings = []
    
    def save_findings(self, output_dir):
        """
        Sauvegarde les résultats d'analyse dans un répertoire.
        
        Args:
            output_dir (str): Répertoire de sortie
            
        Returns:
            int: Nombre de résultats sauvegardés
        """
        import json
        
        os.makedirs(output_dir, exist_ok=True)
        
        count = 0
        for finding in self.findings:
            try:
                filename = f"{finding.type}_{finding.id}.json"
                filepath = os.path.join(output_dir, filename)
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(finding.to_dict(), f, indent=2)
                
                count += 1
            except Exception as e:
                logger.error(f"Erreur lors de la sauvegarde du résultat {finding.id}: {str(e)}")
        
        return count


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
    
    def register_analyzer(self, analyzer_class):
        """
        Enregistre un nouvel analyseur.
        
        Args:
            analyzer_class: Classe de l'analyseur à enregistrer
            
        Returns:
            bool: True si l'enregistrement a réussi, False sinon
        """
        try:
            analyzer = analyzer_class(self.config)
            self.analyzers[analyzer.get_name()] = analyzer_class
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
    
    def analyze_artifacts(self, artifacts, analyzer_names=None):
        """
        Analyse les artefacts à l'aide des analyseurs spécifiés.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
            analyzer_names (list, optional): Liste des noms d'analyseurs à utiliser.
                Si None, tous les analyseurs enregistrés sont utilisés.
                
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        findings = []
        
        # Déterminer les analyseurs à utiliser
        if analyzer_names:
            analyzers = [self.get_analyzer(name) for name in analyzer_names if self.get_analyzer(name)]
        else:
            analyzers = self.get_all_analyzers()
        
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

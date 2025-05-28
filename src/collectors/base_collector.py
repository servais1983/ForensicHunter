#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de base pour les collecteurs d'artefacts forensiques.

Ce module définit l'interface commune à tous les collecteurs
et fournit des fonctionnalités de base pour la collecte d'artefacts.
"""

import os
import logging
import datetime
import uuid
from abc import ABC, abstractmethod

# Configuration du logger
logger = logging.getLogger("forensichunter.collectors")

class Artifact:
    """Classe représentant un artefact forensique collecté."""
    
    def __init__(self, artifact_type, source, data, metadata=None):
        """
        Initialise un nouvel artefact.
        
        Args:
            artifact_type (str): Type d'artefact (event_log, registry, browser_history, etc.)
            source (str): Source de l'artefact (chemin du fichier, nom du collecteur, etc.)
            data: Données de l'artefact (contenu du fichier, entrée de registre, etc.)
            metadata (dict, optional): Métadonnées associées à l'artefact
        """
        self.id = str(uuid.uuid4())
        self.type = artifact_type
        self.source = source
        self.timestamp = datetime.datetime.now().isoformat()
        self.data = data
        self.metadata = metadata or {}
    
    def to_dict(self):
        """
        Convertit l'artefact en dictionnaire.
        
        Returns:
            dict: Représentation de l'artefact sous forme de dictionnaire
        """
        return {
            "id": self.id,
            "type": self.type,
            "source": self.source,
            "timestamp": self.timestamp,
            "data": self.data,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data):
        """
        Crée un artefact à partir d'un dictionnaire.
        
        Args:
            data (dict): Dictionnaire contenant les données de l'artefact
            
        Returns:
            Artifact: Instance d'artefact créée à partir du dictionnaire
        """
        artifact = cls(data["type"], data["source"], data["data"], data.get("metadata"))
        artifact.id = data["id"]
        artifact.timestamp = data["timestamp"]
        return artifact


class BaseCollector(ABC):
    """Classe de base pour tous les collecteurs d'artefacts."""
    
    def __init__(self, config=None):
        """
        Initialise un nouveau collecteur.
        
        Args:
            config (dict, optional): Configuration du collecteur
        """
        self.config = config or {}
        self.artifacts = []
    
    @abstractmethod
    def collect(self):
        """
        Collecte les artefacts.
        
        Cette méthode doit être implémentée par les classes dérivées.
        
        Returns:
            list: Liste d'objets Artifact collectés
        """
        pass
    
    @abstractmethod
    def get_name(self):
        """
        Retourne le nom du collecteur.
        
        Cette méthode doit être implémentée par les classes dérivées.
        
        Returns:
            str: Nom du collecteur
        """
        pass
    
    @abstractmethod
    def get_description(self):
        """
        Retourne la description du collecteur.
        
        Cette méthode doit être implémentée par les classes dérivées.
        
        Returns:
            str: Description du collecteur
        """
        pass
    
    def get_artifacts(self):
        """
        Retourne les artefacts collectés.
        
        Returns:
            list: Liste d'objets Artifact collectés
        """
        return self.artifacts
    
    def add_artifact(self, artifact_type, source, data, metadata=None):
        """
        Ajoute un nouvel artefact à la liste des artefacts collectés.
        
        Args:
            artifact_type (str): Type d'artefact
            source (str): Source de l'artefact
            data: Données de l'artefact
            metadata (dict, optional): Métadonnées associées à l'artefact
            
        Returns:
            Artifact: Artefact créé
        """
        artifact = Artifact(artifact_type, source, data, metadata)
        self.artifacts.append(artifact)
        return artifact
    
    def clear_artifacts(self):
        """Efface la liste des artefacts collectés."""
        self.artifacts = []
    
    def save_artifacts(self, output_dir):
        """
        Sauvegarde les artefacts collectés dans un répertoire.
        
        Args:
            output_dir (str): Répertoire de sortie
            
        Returns:
            int: Nombre d'artefacts sauvegardés
        """
        import json
        
        os.makedirs(output_dir, exist_ok=True)
        
        count = 0
        for artifact in self.artifacts:
            try:
                filename = f"{artifact.type}_{artifact.id}.json"
                filepath = os.path.join(output_dir, filename)
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(artifact.to_dict(), f, indent=2)
                
                count += 1
            except Exception as e:
                logger.error(f"Erreur lors de la sauvegarde de l'artefact {artifact.id}: {str(e)}")
        
        return count


class CollectorManager:
    """Gestionnaire de collecteurs d'artefacts."""
    
    def __init__(self, config=None):
        """
        Initialise un nouveau gestionnaire de collecteurs.
        
        Args:
            config (dict, optional): Configuration du gestionnaire
        """
        self.config = config or {}
        self.collectors = {}
    
    def register_collector(self, collector_class):
        """
        Enregistre un nouveau collecteur.
        
        Args:
            collector_class: Classe du collecteur à enregistrer
            
        Returns:
            bool: True si l'enregistrement a réussi, False sinon
        """
        try:
            collector = collector_class(self.config)
            self.collectors[collector.get_name()] = collector_class
            return True
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement du collecteur {collector_class.__name__}: {str(e)}")
            return False
    
    def get_collector(self, name):
        """
        Retourne un collecteur par son nom.
        
        Args:
            name (str): Nom du collecteur
            
        Returns:
            BaseCollector: Instance du collecteur demandé, ou None si non trouvé
        """
        collector_class = self.collectors.get(name)
        if collector_class:
            return collector_class(self.config)
        return None
    
    def get_all_collectors(self):
        """
        Retourne tous les collecteurs enregistrés.
        
        Returns:
            list: Liste d'instances de collecteurs
        """
        return [collector_class(self.config) for collector_class in self.collectors.values()]
    
    def collect_artifacts(self, collector_names=None):
        """
        Collecte les artefacts à l'aide des collecteurs spécifiés.
        
        Args:
            collector_names (list, optional): Liste des noms de collecteurs à utiliser.
                Si None, tous les collecteurs enregistrés sont utilisés.
                
        Returns:
            list: Liste d'objets Artifact collectés
        """
        artifacts = []
        
        # Déterminer les collecteurs à utiliser
        if collector_names:
            collectors = [self.get_collector(name) for name in collector_names if self.get_collector(name)]
        else:
            collectors = self.get_all_collectors()
        
        # Collecter les artefacts
        for collector in collectors:
            try:
                logger.info(f"Collecte des artefacts avec {collector.get_name()}...")
                collector_artifacts = collector.collect()
                artifacts.extend(collector_artifacts)
                logger.info(f"{len(collector_artifacts)} artefacts collectés avec {collector.get_name()}")
            except Exception as e:
                logger.error(f"Erreur lors de la collecte avec {collector.get_name()}: {str(e)}")
        
        return artifacts

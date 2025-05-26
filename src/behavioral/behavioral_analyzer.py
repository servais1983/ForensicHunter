#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'analyse comportementale avancée pour ForensicHunter.

Ce module analyse les artefacts collectés pour détecter des comportements
suspects, des anomalies et des indicateurs de compromission (IOC) basés
sur des modèles comportementaux.
"""

import os
import json
import logging
import datetime
import re
from typing import Dict, List, Any, Optional, Union

from src.utils.security.security_manager import SecurityManager

logger = logging.getLogger("forensichunter")


class BehavioralAnalyzer:
    """Classe principale pour l'analyse comportementale."""

    def __init__(self, config):
        """
        Initialise l'analyseur comportemental.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.security_manager = SecurityManager(config)
        self.rules = self._load_behavioral_rules()
    
    def _load_behavioral_rules(self) -> List[Dict[str, Any]]:
        """
        Charge les règles d'analyse comportementale depuis la configuration ou un fichier.
        
        Returns:
            Liste des règles comportementales
        """
        # Pour l'instant, règles codées en dur (à externaliser)
        rules = [
            {
                "id": "BHV001",
                "name": "Processus suspect lancé depuis un répertoire temporaire",
                "description": "Détecte les processus lancés depuis des répertoires comme %TEMP%, %TMP%, AppData\\Local\\Temp",
                "severity": "High",
                "type": "process",
                "pattern": r"(C:\\Users\\[^\\]+\\AppData\\Local\\Temp\\|C:\\Windows\\Temp\\|%TEMP%\\|%TMP%\\).*\.exe",
                "action": "flag"
            },
            {
                "id": "BHV002",
                "name": "Connexion réseau sortante vers une adresse IP suspecte",
                "description": "Détecte les connexions vers des adresses IP connues pour être malveillantes (liste à maintenir)",
                "severity": "Medium",
                "type": "network",
                "pattern": r"(192\.168\.bad\.ip|10\.0\.evil\.ip)", # Exemple de liste d'IP
                "action": "flag"
            },
            {
                "id": "BHV003",
                "name": "Modification suspecte du registre (persistance)",
                "description": "Détecte les ajouts aux clés de registre Run/RunOnce",
                "severity": "High",
                "type": "registry",
                "pattern": r"(HKLM|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce)",
                "action": "flag"
            },
            {
                "id": "BHV004",
                "name": "Utilisation de PowerShell avec encodage Base64",
                "description": "Détecte l'utilisation de PowerShell avec des commandes encodées, souvent utilisées pour l'obfuscation",
                "severity": "Medium",
                "type": "process",
                "pattern": r"powershell\.exe.*\s+-Enc(odedCommand)?\s+[A-Za-z0-9+/=]+",
                "action": "flag"
            },
            {
                "id": "BHV005",
                "name": "Fichier suspect dans les téléchargements",
                "description": "Détecte les fichiers avec des extensions potentiellement dangereuses (.exe, .scr, .bat) dans le dossier Téléchargements",
                "severity": "Low",
                "type": "filesystem",
                "pattern": r"C:\\Users\\[^\\]+\\Downloads\\.*\.(exe|scr|bat|vbs|ps1)$",
                "action": "flag"
            }
        ]
        logger.info(f"{len(rules)} règles comportementales chargées.")
        return rules

    def analyze(self, collected_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse les données collectées pour détecter des comportements suspects.
        
        Args:
            collected_data: Dictionnaire contenant les artefacts collectés
            
        Returns:
            Dictionnaire contenant les résultats de l'analyse comportementale
        """
        logger.info("Démarrage de l'analyse comportementale")
        behavioral_findings = {
            "timestamp": datetime.datetime.now().isoformat(),
            "findings": []
        }

        # Itérer sur chaque type d'artefact collecté
        for artifact_type, artifacts in collected_data.items():
            if not isinstance(artifacts, list):
                logger.warning(f"Format inattendu pour les artefacts de type {artifact_type}, analyse comportementale ignorée.")
                continue
                
            logger.debug(f"Analyse comportementale des artefacts de type: {artifact_type}")
            
            # Appliquer les règles comportementales pertinentes
            for rule in self.rules:
                if rule["type"] == artifact_type or rule["type"] == "any":
                    for artifact in artifacts:
                        if self._match_rule(rule, artifact):
                            finding = self._create_finding(rule, artifact)
                            behavioral_findings["findings"].append(finding)
                            logger.warning(f"Comportement suspect détecté: {rule['name']} - Artefact: {artifact.get('path', artifact.get('command', artifact))}")

        logger.info(f"Analyse comportementale terminée. {len(behavioral_findings['findings'])} comportements suspects détectés.")
        return behavioral_findings

    def _match_rule(self, rule: Dict[str, Any], artifact: Dict[str, Any]) -> bool:
        """
        Vérifie si un artefact correspond à une règle comportementale.
        
        Args:
            rule: Règle comportementale
            artifact: Artefact à vérifier
            
        Returns:
            True si l'artefact correspond à la règle, False sinon
        """
        try:
            pattern = rule["pattern"]
            # Sécurisation de l'expression régulière
            if not self.security_manager.validate_input(pattern, "regex"):
                logger.error(f"Expression régulière invalide ou dangereuse dans la règle {rule['id']}: {pattern}")
                return False
                
            # Convertir l'artefact en chaîne pour la recherche (simplifié)
            artifact_str = json.dumps(artifact)
            
            # Recherche du motif
            if re.search(pattern, artifact_str, re.IGNORECASE):
                return True
        except re.error as e:
            logger.error(f"Erreur d'expression régulière dans la règle {rule['id']}: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue lors de l'application de la règle {rule['id']}: {e}")
            
        return False

    def _create_finding(self, rule: Dict[str, Any], artifact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Crée un enregistrement de découverte comportementale.
        
        Args:
            rule: Règle comportementale déclenchée
            artifact: Artefact correspondant
            
        Returns:
            Dictionnaire représentant la découverte
        """
        finding = {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "description": rule["description"],
            "severity": rule["severity"],
            "timestamp": datetime.datetime.now().isoformat(),
            "artifact_type": rule["type"],
            "artifact_details": artifact, # Inclure les détails de l'artefact
            "recommended_action": rule.get("action", "investigate")
        }
        return finding

# Exemple d'utilisation (pourrait être intégré dans le flux principal de ForensicHunter)
if __name__ == '__main__':
    # Configuration du logging
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                        handlers=[logging.StreamHandler()])

    # Exemple de données collectées (simplifié)
    mock_collected_data = {
        "process": [
            {"pid": 1234, "name": "svchost.exe", "command": "C:\\Windows\\System32\\svchost.exe -k netsvcs"},
            {"pid": 5678, "name": "malware.exe", "command": "C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe"},
            {"pid": 9012, "name": "powershell.exe", "command": "powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACc="}
        ],
        "registry": [
            {"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "Updater", "data": "C:\\path\\to\\updater.exe"},
            {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "value": "MalwareStart", "data": "C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe"}
        ],
        "network": [
            {"local_ip": "192.168.1.10", "remote_ip": "8.8.8.8", "port": 443, "protocol": "TCP"},
            {"local_ip": "192.168.1.10", "remote_ip": "192.168.bad.ip", "port": 80, "protocol": "TCP"}
        ],
        "filesystem": [
            {"path": "C:\\Users\\Admin\\Downloads\\document.docx", "size": 10240},
            {"path": "C:\\Users\\Admin\\Downloads\\installer.exe", "size": 512000}
        ]
    }

    # Initialisation et analyse
    analyzer = BehavioralAnalyzer(config={}) # Config vide pour l'exemple
    results = analyzer.analyze(mock_collected_data)

    # Affichage des résultats
    print("\n--- Résultats de l'analyse comportementale ---")
    print(json.dumps(results, indent=2))


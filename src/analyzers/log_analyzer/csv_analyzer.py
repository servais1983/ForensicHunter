#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'analyse de fichiers CSV.

Ce module permet d'analyser des fichiers CSV pour détecter
des indicateurs de compromission et des activités suspectes.
"""

import os
import re
import csv
import logging
import io
from pathlib import Path

from ..base_analyzer import BaseAnalyzer

# Configuration du logger
logger = logging.getLogger("forensichunter.analyzers.csv_analyzer")

class CSVAnalyzer(BaseAnalyzer):
    """Analyseur de fichiers CSV."""
    
    def __init__(self, config=None):
        """
        Initialise un nouvel analyseur de fichiers CSV.
        
        Args:
            config (dict, optional): Configuration de l'analyseur
        """
        super().__init__(config)
        self.patterns = self._load_patterns()
        self.whitelist = self._load_whitelist()
        self.max_file_size = self.config.get("max_file_size", 50 * 1024 * 1024)  # 50 MB
        self.max_rows = self.config.get("max_csv_rows", 100000)  # Nombre maximal de lignes à analyser
        
    def _load_patterns(self):
        """
        Charge les patterns de détection pour les fichiers CSV.
        
        Returns:
            dict: Dictionnaire de patterns de détection
        """
        patterns = {
            # Patterns pour les adresses IP malveillantes
            "malicious_ip": {
                "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                "description": "Adresse IP potentiellement malveillante détectée",
                "severity": "medium",
                "confidence": 60,
                "type": "malicious_ip",
                "blacklist": [
                    # Liste d'exemples d'adresses IP malveillantes connues
                    r"^192\.168\.0\.\d{1,3}$",  # Exemple pour les tests, à remplacer par de vraies IOCs
                    r"^10\.0\.0\.\d{1,3}$",     # Exemple pour les tests, à remplacer par de vraies IOCs
                ]
            },
            
            # Patterns pour les domaines malveillants
            "malicious_domain": {
                "pattern": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
                "description": "Domaine potentiellement malveillant détecté",
                "severity": "medium",
                "confidence": 60,
                "type": "malicious_domain",
                "blacklist": [
                    # Liste d'exemples de domaines malveillants connus
                    r"example\.com$",  # Exemple pour les tests, à remplacer par de vraies IOCs
                    r"test\.org$",     # Exemple pour les tests, à remplacer par de vraies IOCs
                ]
            },
            
            # Patterns pour les hashes malveillants
            "malicious_hash": {
                "pattern": r"\b[a-fA-F0-9]{32,64}\b",
                "description": "Hash potentiellement malveillant détecté",
                "severity": "medium",
                "confidence": 60,
                "type": "malicious_hash",
                "blacklist": [
                    # Liste d'exemples de hashes malveillants connus
                    r"^[a-fA-F0-9]{32}$",  # MD5
                    r"^[a-fA-F0-9]{40}$",  # SHA-1
                    r"^[a-fA-F0-9]{64}$",  # SHA-256
                ]
            },
            
            # Patterns pour les URLs malveillantes
            "malicious_url": {
                "pattern": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
                "description": "URL potentiellement malveillante détectée",
                "severity": "medium",
                "confidence": 60,
                "type": "malicious_url",
                "blacklist": [
                    # Liste d'exemples d'URLs malveillantes connues
                    r"example\.com",  # Exemple pour les tests, à remplacer par de vraies IOCs
                    r"test\.org",     # Exemple pour les tests, à remplacer par de vraies IOCs
                ]
            },
            
            # Patterns pour les noms de fichiers malveillants
            "malicious_filename": {
                "pattern": r"\b[\w-]+\.(exe|dll|bat|ps1|vbs|js|hta|cmd|scr|pif)\b",
                "description": "Nom de fichier potentiellement malveillant détecté",
                "severity": "medium",
                "confidence": 60,
                "type": "malicious_filename",
                "blacklist": [
                    # Liste d'exemples de noms de fichiers malveillants connus
                    r"malware\.exe$",  # Exemple pour les tests, à remplacer par de vraies IOCs
                    r"backdoor\.dll$", # Exemple pour les tests, à remplacer par de vraies IOCs
                ]
            },
            
            # Patterns pour les clés de registre malveillantes
            "malicious_registry": {
                "pattern": r"HKLM\\|HKCU\\|HKCR\\|HKU\\|HKCC\\",
                "description": "Clé de registre potentiellement malveillante détectée",
                "severity": "medium",
                "confidence": 60,
                "type": "malicious_registry",
                "blacklist": [
                    # Liste d'exemples de clés de registre malveillantes connues
                    r"\\Run\\",  # Exemple pour les tests, à remplacer par de vraies IOCs
                    r"\\RunOnce\\", # Exemple pour les tests, à remplacer par de vraies IOCs
                ]
            },
            
            # Patterns pour les processus malveillants
            "malicious_process": {
                "pattern": r"\b[\w-]+\.exe\b",
                "description": "Processus potentiellement malveillant détecté",
                "severity": "medium",
                "confidence": 60,
                "type": "malicious_process",
                "blacklist": [
                    # Liste d'exemples de processus malveillants connus
                    r"malware\.exe$",  # Exemple pour les tests, à remplacer par de vraies IOCs
                    r"backdoor\.exe$", # Exemple pour les tests, à remplacer par de vraies IOCs
                ]
            },
            
            # Patterns pour les utilisateurs suspects
            "suspicious_user": {
                "pattern": r"\b(?:admin|administrator|root|system|guest)\b",
                "description": "Utilisateur potentiellement suspect détecté",
                "severity": "low",
                "confidence": 50,
                "type": "suspicious_user"
            },
            
            # Patterns pour les commandes suspectes
            "suspicious_command": {
                "pattern": r"\b(?:cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|rundll32\.exe|regsvr32\.exe|mshta\.exe|certutil\.exe|bitsadmin\.exe|wmic\.exe)\b",
                "description": "Commande potentiellement suspecte détectée",
                "severity": "medium",
                "confidence": 60,
                "type": "suspicious_command"
            }
        }
        
        # Charger des patterns personnalisés depuis la configuration
        custom_patterns = self.config.get("custom_csv_patterns", {})
        patterns.update(custom_patterns)
        
        return patterns
    
    def _load_whitelist(self):
        """
        Charge la liste blanche pour éviter les faux positifs.
        
        Returns:
            dict: Dictionnaire de patterns à ignorer
        """
        # Liste blanche par défaut
        whitelist = {
            # Adresses IP légitimes
            "legitimate_ips": [
                r"^127\.0\.0\.1$",
                r"^0\.0\.0\.0$",
                r"^255\.255\.255\.255$",
                r"^192\.168\.\d{1,3}\.\d{1,3}$",
                r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$",
                r"^169\.254\.\d{1,3}\.\d{1,3}$",
                r"^224\.0\.0\.\d{1,3}$",
                r"^239\.255\.255\.250$",
                r"^255\.255\.255\.255$"
            ],
            
            # Domaines légitimes
            "legitimate_domains": [
                r"\.microsoft\.com$",
                r"\.windows\.com$",
                r"\.windowsupdate\.com$",
                r"\.office\.com$",
                r"\.office365\.com$",
                r"\.live\.com$",
                r"\.msn\.com$",
                r"\.bing\.com$",
                r"\.google\.com$",
                r"\.googleapis\.com$",
                r"\.gstatic\.com$",
                r"\.amazon\.com$",
                r"\.amazonaws\.com$",
                r"\.apple\.com$",
                r"\.icloud\.com$",
                r"\.adobe\.com$",
                r"\.akamai\.net$",
                r"\.cloudfront\.net$",
                r"\.cloudflare\.com$",
                r"\.github\.com$",
                r"\.githubusercontent\.com$",
                r"\.digicert\.com$",
                r"\.verisign\.com$",
                r"\.symantec\.com$",
                r"\.mcafee\.com$",
                r"\.norton\.com$",
                r"\.kaspersky\.com$",
                r"\.avast\.com$",
                r"\.avg\.com$",
                r"\.bitdefender\.com$",
                r"\.eset\.com$",
                r"\.trendmicro\.com$",
                r"\.sophos\.com$"
            ],
            
            # Clés de registre légitimes Windows
            "legitimate_registry_keys": [
                r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                r"HKLM\\SYSTEM\\CurrentControlSet\\Services",
                r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
                r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
                r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication",
                r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication",
                r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx",
                r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx",
                r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
                r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",
                r"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
            ],
            
            # Processus légitimes Windows
            "legitimate_processes": [
                r"svchost\.exe$",
                r"explorer\.exe$",
                r"lsass\.exe$",
                r"services\.exe$",
                r"winlogon\.exe$",
                r"csrss\.exe$",
                r"smss\.exe$",
                r"spoolsv\.exe$",
                r"wininit\.exe$",
                r"taskmgr\.exe$",
                r"msiexec\.exe$",
                r"dllhost\.exe$",
                r"conhost\.exe$",
                r"dwm\.exe$",
                r"taskhost\.exe$",
                r"rundll32\.exe$",
                r"regsvr32\.exe$",
                r"wmiprvse\.exe$",
                r"wuauclt\.exe$",
                r"ctfmon\.exe$",
                r"searchindexer\.exe$",
                r"searchprotocolhost\.exe$",
                r"searchfilterhost\.exe$"
            ]
        }
        
        # Charger des entrées de liste blanche personnalisées depuis la configuration
        custom_whitelist = self.config.get("custom_csv_whitelist", {})
        for category, entries in custom_whitelist.items():
            if category in whitelist:
                whitelist[category].extend(entries)
            else:
                whitelist[category] = entries
        
        return whitelist
    
    def get_name(self):
        """
        Retourne le nom de l'analyseur.
        
        Returns:
            str: Nom de l'analyseur
        """
        return "CSVAnalyzer"
    
    def get_description(self):
        """
        Retourne la description de l'analyseur.
        
        Returns:
            str: Description de l'analyseur
        """
        return "Analyseur de fichiers CSV pour la détection d'indicateurs de compromission"
    
    def is_available(self):
        """
        Vérifie si l'analyseur est disponible.
        
        Returns:
            bool: True si l'analyseur est disponible, False sinon
        """
        return True
    
    def _is_whitelisted(self, value, pattern_type=None):
        """
        Vérifie si une valeur est dans la liste blanche.
        
        Args:
            value (str): Valeur à vérifier
            pattern_type (str, optional): Type de pattern
            
        Returns:
            bool: True si la valeur est dans la liste blanche, False sinon
        """
        # Vérifier toutes les catégories de la liste blanche
        for category, patterns in self.whitelist.items():
            # Si un type de pattern est spécifié, ne vérifier que les catégories pertinentes
            if pattern_type == "malicious_ip" and category != "legitimate_ips":
                continue
            if pattern_type == "malicious_domain" and category != "legitimate_domains":
                continue
            if pattern_type == "malicious_registry" and category != "legitimate_registry_keys":
                continue
            if pattern_type == "malicious_process" and category != "legitimate_processes":
                continue
            
            for pattern in patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    logger.debug(f"Valeur ignorée (liste blanche {category}): {value}")
                    return True
        
        return False
    
    def _is_blacklisted(self, value, pattern_info):
        """
        Vérifie si une valeur est dans la liste noire.
        
        Args:
            value (str): Valeur à vérifier
            pattern_info (dict): Informations sur le pattern
            
        Returns:
            bool: True si la valeur est dans la liste noire, False sinon
        """
        # Vérifier si le pattern a une liste noire
        if "blacklist" not in pattern_info:
            return False
        
        # Vérifier si la valeur correspond à un pattern de la liste noire
        for pattern in pattern_info["blacklist"]:
            if re.search(pattern, value, re.IGNORECASE):
                logger.debug(f"Valeur blacklistée: {value}")
                return True
        
        return False
    
    def analyze(self, artifacts):
        """
        Analyse les artefacts de type fichier CSV.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
            
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        self.clear_findings()
        
        # Filtrer les artefacts pertinents (fichiers CSV)
        csv_artifacts = [a for a in artifacts if a.type == "filesystem" and 
                         (a.data.get("file_path", "").lower().endswith(".csv") or 
                          a.data.get("mime_type") == "text/csv")]
        
        logger.info(f"Analyse de {len(csv_artifacts)} artefacts de type fichier CSV...")
        
        # Analyser chaque artefact
        for artifact in csv_artifacts:
            try:
                # Extraire les informations du fichier
                file_path = artifact.data.get("file_path", "")
                content = artifact.data.get("content", "")
                
                # Vérifier la taille du contenu
                if len(content.encode('utf-8')) > self.max_file_size:
                    logger.warning(f"Fichier {file_path} trop volumineux pour l'analyse complète")
                    continue
                
                # Analyser le fichier CSV
                csv_file = io.StringIO(content)
                
                # Détecter le dialecte CSV
                try:
                    dialect = csv.Sniffer().sniff(csv_file.read(1024))
                    csv_file.seek(0)
                except:
                    # En cas d'échec, utiliser le dialecte par défaut
                    dialect = csv.excel
                    csv_file.seek(0)
                
                # Lire le fichier CSV
                try:
                    reader = csv.reader(csv_file, dialect)
                    headers = next(reader, [])  # Lire les en-têtes
                    
                    # Analyser chaque ligne
                    for row_num, row in enumerate(reader, 1):
                        # Limiter le nombre de lignes analysées
                        if row_num > self.max_rows:
                            logger.warning(f"Nombre maximal de lignes atteint pour {file_path}")
                            break
                        
                        # Analyser chaque cellule
                        for col_num, cell in enumerate(row):
                            # Ignorer les cellules vides
                            if not cell.strip():
                                continue
                            
                            # Appliquer les patterns de détection
                            for pattern_name, pattern_info in self.patterns.items():
                                if re.search(pattern_info["pattern"], cell):
                                    # Vérifier si la valeur est dans la liste blanche
                                    if self._is_whitelisted(cell, pattern_name):
                                        continue
                                    
                                    # Vérifier si la valeur est dans la liste noire (pour augmenter la confiance)
                                    is_blacklisted = self._is_blacklisted(cell, pattern_info)
                                    confidence = pattern_info["confidence"]
                                    if is_blacklisted:
                                        confidence = min(confidence + 20, 100)  # Augmenter la confiance si blacklisté
                                    
                                    # Créer un résultat
                                    header = headers[col_num] if col_num < len(headers) else f"Colonne {col_num+1}"
                                    description = f"{pattern_info['description']} dans {os.path.basename(file_path)}"
                                    
                                    self.add_finding(
                                        finding_type=pattern_info["type"],
                                        description=description,
                                        severity=pattern_info["severity"],
                                        confidence=confidence,
                                        artifacts=[artifact],
                                        metadata={
                                            "pattern": pattern_info["pattern"],
                                            "row": row_num,
                                            "column": col_num + 1,
                                            "header": header,
                                            "value": cell,
                                            "file_path": file_path,
                                            "blacklisted": is_blacklisted
                                        }
                                    )
                                    
                                    logger.info(f"Correspondance trouvée: {pattern_name} dans {file_path} à la ligne {row_num}, colonne {header}")
                
                except Exception as csv_error:
                    logger.error(f"Erreur lors de la lecture du fichier CSV {file_path}: {str(csv_error)}")
                    
                    # Tentative de lecture ligne par ligne en cas d'erreur
                    try:
                        csv_file.seek(0)
                        lines = csv_file.readlines()
                        
                        for line_num, line in enumerate(lines):
                            # Limiter le nombre de lignes analysées
                            if line_num > self.max_rows:
                                break
                            
                            # Ignorer les lignes vides
                            if not line.strip():
                                continue
                            
                            # Vérifier si la ligne est dans la liste blanche
                            if self._is_whitelisted(line):
                                continue
                            
                            # Appliquer les patterns de détection
                            for pattern_name, pattern_info in self.patterns.items():
                                if re.search(pattern_info["pattern"], line):
                                    # Créer un résultat
                                    description = f"{pattern_info['description']} dans {os.path.basename(file_path)}"
                                    
                                    self.add_finding(
                                        finding_type=pattern_info["type"],
                                        description=description,
                                        severity=pattern_info["severity"],
                                        confidence=pattern_info["confidence"],
                                        artifacts=[artifact],
                                        metadata={
                                            "pattern": pattern_info["pattern"],
                                            "line_number": line_num + 1,
                                            "line": line.strip(),
                                            "file_path": file_path
                                        }
                                    )
                                    
                                    logger.info(f"Correspondance trouvée: {pattern_name} dans {file_path} à la ligne {line_num + 1}")
                                    break  # Passer à la ligne suivante après la première correspondance
                    
                    except Exception as line_error:
                        logger.error(f"Erreur lors de l'analyse ligne par ligne du fichier {file_path}: {str(line_error)}")
            
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse du fichier CSV {artifact.id}: {str(e)}")
        
        logger.info(f"{len(self.findings)} correspondances trouvées au total dans les fichiers CSV")
        return self.findings

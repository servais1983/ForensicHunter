#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'analyse de fichiers logs.

Ce module permet d'analyser des fichiers logs pour détecter
des indicateurs de compromission et des activités suspectes.
"""

import os
import re
import logging
import json
from datetime import datetime
from pathlib import Path

from ..base_analyzer import BaseAnalyzer

# Configuration du logger
logger = logging.getLogger("forensichunter.analyzers.log_analyzer")

class LogAnalyzer(BaseAnalyzer):
    """Analyseur de fichiers logs."""
    
    def __init__(self, config=None):
        """
        Initialise un nouvel analyseur de fichiers logs.
        
        Args:
            config (dict, optional): Configuration de l'analyseur
        """
        super().__init__(config)
        self.patterns = self._load_patterns()
        self.whitelist = self._load_whitelist()
        self.max_file_size = self.config.get("max_file_size", 50 * 1024 * 1024)  # 50 MB
        
    def _load_patterns(self):
        """
        Charge les patterns de détection pour les fichiers logs.
        
        Returns:
            dict: Dictionnaire de patterns de détection
        """
        patterns = {
            # Patterns de détection d'authentification
            "failed_login": {
                "pattern": r"(?i)(failed|failure|invalid)\s+(login|password|authentication)",
                "description": "Tentative d'authentification échouée",
                "severity": "medium",
                "confidence": 60,
                "type": "authentication_failure"
            },
            "brute_force": {
                "pattern": r"(?i)(brute\s*force|multiple\s*failed\s*logins|repeated\s*login\s*attempts)",
                "description": "Possible attaque par force brute",
                "severity": "high",
                "confidence": 75,
                "type": "brute_force"
            },
            
            # Patterns de détection d'exploitation
            "sql_injection": {
                "pattern": r"(?i)(sql\s*injection|select\s*from|union\s*select|'--|\%27|\%20or|\%20and)",
                "description": "Possible tentative d'injection SQL",
                "severity": "high",
                "confidence": 70,
                "type": "sql_injection"
            },
            "xss": {
                "pattern": r"(?i)(<script>|javascript:|onerror=|onload=|eval\(|document\.cookie)",
                "description": "Possible tentative de Cross-Site Scripting (XSS)",
                "severity": "high",
                "confidence": 70,
                "type": "xss"
            },
            
            # Patterns de détection de malware
            "webshell": {
                "pattern": r"(?i)(webshell|backdoor|cmd\.php|shell\.php|c99|r57|wso\.php)",
                "description": "Possible webshell détecté",
                "severity": "critical",
                "confidence": 80,
                "type": "webshell"
            },
            "ransomware": {
                "pattern": r"(?i)(ransom|encrypt|decrypt|\.locked|\.crypt|\.enc|lockbit|ryuk|revil|conti)",
                "description": "Possible activité de ransomware",
                "severity": "critical",
                "confidence": 85,
                "type": "ransomware"
            },
            
            # Patterns de détection de mouvement latéral
            "lateral_movement": {
                "pattern": r"(?i)(psexec|wmic|winrm|wmiexec|dcom|pass-the-hash|mimikatz)",
                "description": "Possible mouvement latéral",
                "severity": "high",
                "confidence": 75,
                "type": "lateral_movement"
            },
            
            # Patterns de détection de persistance
            "persistence": {
                "pattern": r"(?i)(scheduled\s*task|new\s*service|registry\s*key|startup\s*folder|run\s*key)",
                "description": "Possible mécanisme de persistance",
                "severity": "high",
                "confidence": 70,
                "type": "persistence"
            },
            
            # Patterns de détection de phishing
            "phishing": {
                "pattern": r"(?i)(phish|credential|harvest|spoof|fake\s*login|impersonat)",
                "description": "Possible activité de phishing",
                "severity": "high",
                "confidence": 70,
                "type": "phishing"
            },
            
            # Patterns de détection d'exfiltration de données
            "data_exfiltration": {
                "pattern": r"(?i)(exfiltration|data\s*leak|upload\s*to\s*external|unusual\s*outbound|large\s*transfer)",
                "description": "Possible exfiltration de données",
                "severity": "high",
                "confidence": 70,
                "type": "data_exfiltration"
            }
        }
        
        # Charger des patterns personnalisés depuis la configuration
        custom_patterns = self.config.get("custom_log_patterns", {})
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
                r"svchost\.exe",
                r"explorer\.exe",
                r"lsass\.exe",
                r"services\.exe",
                r"winlogon\.exe",
                r"csrss\.exe",
                r"smss\.exe",
                r"spoolsv\.exe",
                r"wininit\.exe",
                r"taskmgr\.exe",
                r"msiexec\.exe",
                r"dllhost\.exe",
                r"conhost\.exe",
                r"dwm\.exe",
                r"taskhost\.exe",
                r"rundll32\.exe",
                r"regsvr32\.exe",
                r"wmiprvse\.exe",
                r"wuauclt\.exe",
                r"ctfmon\.exe",
                r"searchindexer\.exe",
                r"searchprotocolhost\.exe",
                r"searchfilterhost\.exe"
            ],
            
            # Faux positifs courants dans les logs
            "common_false_positives": [
                r"Microsoft Windows Security Auditing",
                r"Windows Defender",
                r"Windows Firewall",
                r"Windows Update",
                r"Microsoft Antimalware",
                r"Microsoft Defender",
                r"Microsoft Security Essentials",
                r"Microsoft-Windows-Security-Auditing",
                r"Microsoft-Windows-Windows Defender",
                r"Microsoft-Windows-Windows Firewall",
                r"Microsoft-Windows-WindowsUpdateClient",
                r"Microsoft-Windows-Sysmon",
                r"Microsoft-Windows-PowerShell",
                r"Microsoft-Windows-WMI",
                r"Microsoft-Windows-TaskScheduler",
                r"Microsoft-Windows-TerminalServices-LocalSessionManager",
                r"Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                r"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
                r"Microsoft-Windows-Security-SPP",
                r"Microsoft-Windows-Kernel-General",
                r"Microsoft-Windows-Kernel-PnP",
                r"Microsoft-Windows-Kernel-Power",
                r"Microsoft-Windows-Kernel-Boot",
                r"Microsoft-Windows-Kernel-Processor-Power",
                r"Microsoft-Windows-Kernel-IO",
                r"Microsoft-Windows-Kernel-File",
                r"Microsoft-Windows-Kernel-Registry"
            ]
        }
        
        # Charger des entrées de liste blanche personnalisées depuis la configuration
        custom_whitelist = self.config.get("custom_log_whitelist", {})
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
        return "LogAnalyzer"
    
    def get_description(self):
        """
        Retourne la description de l'analyseur.
        
        Returns:
            str: Description de l'analyseur
        """
        return "Analyseur de fichiers logs pour la détection d'activités suspectes et d'indicateurs de compromission"
    
    def is_available(self):
        """
        Vérifie si l'analyseur est disponible.
        
        Returns:
            bool: True si l'analyseur est disponible, False sinon
        """
        return True
    
    def _is_whitelisted(self, line, artifact_type=None):
        """
        Vérifie si une ligne est dans la liste blanche.
        
        Args:
            line (str): Ligne à vérifier
            artifact_type (str, optional): Type d'artefact
            
        Returns:
            bool: True si la ligne est dans la liste blanche, False sinon
        """
        # Vérifier toutes les catégories de la liste blanche
        for category, patterns in self.whitelist.items():
            # Si un type d'artefact est spécifié, ne vérifier que les catégories pertinentes
            if artifact_type == "registry" and category != "legitimate_registry_keys":
                continue
            if artifact_type == "process" and category != "legitimate_processes":
                continue
            
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    logger.debug(f"Ligne ignorée (liste blanche {category}): {line[:100]}...")
                    return True
        
        return False
    
    def analyze(self, artifacts):
        """
        Analyse les artefacts de type fichier log.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
            
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        self.clear_findings()
        
        # Filtrer les artefacts pertinents (fichiers logs)
        log_artifacts = [a for a in artifacts if a.type == "filesystem" and 
                         (a.data.get("file_path", "").lower().endswith(".log") or 
                          a.data.get("mime_type") == "text/plain")]
        
        logger.info(f"Analyse de {len(log_artifacts)} artefacts de type fichier log...")
        
        # Analyser chaque artefact
        for artifact in log_artifacts:
            try:
                # Extraire les informations du fichier
                file_path = artifact.data.get("file_path", "")
                content = artifact.data.get("content", "")
                
                # Vérifier la taille du contenu
                if len(content.encode('utf-8')) > self.max_file_size:
                    logger.debug(f"Fichier {file_path} trop volumineux pour l'analyse complète, analyse des 10000 premières et dernières lignes")
                    lines = content.splitlines()
                    if len(lines) > 20000:
                        lines = lines[:10000] + lines[-10000:]
                else:
                    lines = content.splitlines()
                
                # Analyser chaque ligne
                for line_num, line in enumerate(lines):
                    # Ignorer les lignes vides
                    if not line.strip():
                        continue
                    
                    # Vérifier si la ligne est dans la liste blanche
                    if self._is_whitelisted(line):
                        continue
                    
                    # Appliquer les patterns de détection
                    for pattern_name, pattern_info in self.patterns.items():
                        if re.search(pattern_info["pattern"], line):
                            # Déterminer le contexte (lignes avant et après)
                            start_idx = max(0, line_num - 5)
                            end_idx = min(len(lines), line_num + 6)
                            context = lines[start_idx:end_idx]
                            
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
                                    "line": line,
                                    "context": context,
                                    "file_path": file_path
                                }
                            )
                            
                            logger.info(f"Correspondance trouvée: {pattern_name} dans {file_path} à la ligne {line_num + 1}")
                            break  # Passer à la ligne suivante après la première correspondance
            
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse du fichier log {artifact.id}: {str(e)}")
        
        logger.info(f"{len(self.findings)} correspondances trouvées au total dans les fichiers logs")
        return self.findings

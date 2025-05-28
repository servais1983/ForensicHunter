#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'analyse YARA pour la détection de menaces.

Ce module permet d'appliquer des règles YARA aux artefacts collectés
pour détecter des menaces connues.
"""

import os
import logging
import tempfile
import json
from pathlib import Path

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
        self.max_file_size = self.config.get("max_file_size", 10 * 1024 * 1024)  # 10 MB
        self.compiled_rules = None
        self.temp_dir = None
    
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
    
    def analyze(self, artifacts):
        """
        Analyse les artefacts en utilisant des règles YARA.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
            
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        self.clear_findings()
        
        # Vérifier si yara-python est disponible
        try:
            import yara
        except ImportError:
            logger.error("Module yara-python non disponible. Veuillez l'installer avec 'pip install yara-python'.")
            return self.findings
        
        # Créer un répertoire temporaire pour les fichiers à analyser
        self.temp_dir = tempfile.mkdtemp(prefix="forensichunter_yara_")
        logger.info(f"Répertoire temporaire créé: {self.temp_dir}")
        
        try:
            # Compiler les règles YARA
            self._compile_rules()
            
            if not self.compiled_rules:
                logger.error("Aucune règle YARA compilée. Impossible de poursuivre l'analyse.")
                return self.findings
            
            # Filtrer les artefacts pertinents (fichiers)
            file_artifacts = [a for a in artifacts if a.type == "filesystem" and a.data and a.data.get("type") in ["text", "binary"]]
            
            logger.info(f"Analyse de {len(file_artifacts)} artefacts de type fichier avec YARA...")
            
            # Analyser chaque artefact
            for artifact in file_artifacts:
                try:
                    # Extraire les informations du fichier
                    file_path = artifact.data.get("file_path", "")
                    file_type = artifact.data.get("type", "")
                    
                    # Créer un fichier temporaire pour l'analyse
                    temp_file_path = self._create_temp_file(artifact)
                    
                    if not temp_file_path:
                        continue
                    
                    # Appliquer les règles YARA
                    matches = self.compiled_rules.match(temp_file_path)
                    
                    # Traiter les correspondances
                    if matches:
                        for match in matches:
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
                                    "tags": tags,
                                    "meta": meta,
                                    "strings": [(offset, identifier, data.hex()) for offset, identifier, data in strings],
                                    "file_path": file_path,
                                    "file_type": file_type
                                }
                            )
                            
                            logger.info(f"Correspondance YARA trouvée: {rule_name} dans {file_path}")
                
                except Exception as e:
                    logger.error(f"Erreur lors de l'analyse YARA de l'artefact {artifact.id}: {str(e)}")
            
            logger.info(f"{len(self.findings)} correspondances YARA trouvées au total")
            return self.findings
            
        finally:
            # Nettoyer le répertoire temporaire
            self._cleanup_temp_dir()
    
    def _compile_rules(self):
        """
        Compile les règles YARA.
        
        Returns:
            bool: True si la compilation a réussi, False sinon
        """
        try:
            import yara
            
            # Vérifier si le répertoire de règles existe
            if not os.path.exists(self.rules_dir):
                logger.warning(f"Le répertoire de règles {self.rules_dir} n'existe pas. Création du répertoire.")
                os.makedirs(self.rules_dir, exist_ok=True)
            
            # Chercher les fichiers de règles
            rule_files = []
            
            for root, dirs, files in os.walk(self.rules_dir):
                for file in files:
                    if file.endswith(".yar") or file.endswith(".yara"):
                        rule_files.append(os.path.join(root, file))
            
            # Ajouter les règles personnalisées
            for rule_path in self.custom_rules:
                if os.path.exists(rule_path):
                    rule_files.append(rule_path)
                else:
                    logger.warning(f"Le fichier de règles personnalisées {rule_path} n'existe pas.")
            
            if not rule_files:
                logger.warning("Aucun fichier de règles YARA trouvé.")
                
                # Créer des règles par défaut si aucune n'est trouvée
                self._create_default_rules()
                
                # Rechercher à nouveau les fichiers de règles
                for root, dirs, files in os.walk(self.rules_dir):
                    for file in files:
                        if file.endswith(".yar") or file.endswith(".yara"):
                            rule_files.append(os.path.join(root, file))
            
            # Compiler les règles
            rules = {}
            
            for rule_file in rule_files:
                try:
                    # Compiler chaque fichier individuellement
                    rule = yara.compile(rule_file)
                    filename = os.path.basename(rule_file)
                    rules[filename] = rule
                    logger.info(f"Règles YARA compilées depuis {rule_file}")
                except Exception as e:
                    logger.error(f"Erreur lors de la compilation des règles YARA depuis {rule_file}: {str(e)}")
            
            if not rules:
                logger.error("Aucune règle YARA n'a pu être compilée.")
                return False
            
            # Fusionner les règles
            try:
                # Créer un fichier temporaire pour chaque ensemble de règles
                temp_files = []
                
                for filename, rule in rules.items():
                    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".yarac")
                    rule.save(temp_file.name)
                    temp_files.append(temp_file.name)
                
                # Charger toutes les règles compilées
                self.compiled_rules = yara.load(temp_files[0]) if len(temp_files) == 1 else None
                
                if not self.compiled_rules and len(temp_files) > 1:
                    # Si plusieurs fichiers, les fusionner manuellement
                    all_rules = {}
                    
                    for temp_file in temp_files:
                        rule = yara.load(temp_file)
                        for r in rule.get_rules():
                            all_rules[r.identifier] = r
                    
                    # Créer un fichier de règles fusionnées
                    merged_file = tempfile.NamedTemporaryFile(delete=False, suffix=".yar")
                    
                    with open(merged_file.name, "w") as f:
                        for rule_id, rule in all_rules.items():
                            f.write(f"rule {rule_id} {{\n")
                            f.write("    meta:\n")
                            f.write(f"        description = \"Merged rule {rule_id}\"\n")
                            f.write("    strings:\n")
                            f.write("        $a = \"YARA rule\"\n")
                            f.write("    condition:\n")
                            f.write("        $a\n")
                            f.write("}\n\n")
                    
                    # Compiler les règles fusionnées
                    self.compiled_rules = yara.compile(merged_file.name)
                    
                    # Nettoyer
                    os.unlink(merged_file.name)
                
                # Nettoyer les fichiers temporaires
                for temp_file in temp_files:
                    os.unlink(temp_file)
                
                logger.info(f"{len(rules)} ensembles de règles YARA compilés avec succès")
                return True
                
            except Exception as e:
                logger.error(f"Erreur lors de la fusion des règles YARA: {str(e)}")
                return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la compilation des règles YARA: {str(e)}")
            return False
    
    def _create_default_rules(self):
        """
        Crée des règles YARA par défaut.
        
        Returns:
            bool: True si la création a réussi, False sinon
        """
        try:
            # Créer le répertoire de règles s'il n'existe pas
            os.makedirs(self.rules_dir, exist_ok=True)
            
            # Règles pour les ransomwares
            ransomware_rules = """
rule LockBit_Ransomware {
    meta:
        description = "Détecte les artefacts du ransomware LockBit 3.0"
        author = "ForensicHunter"
        severity = "critical"
        confidence = 80
    strings:
        $lockbit1 = "LockBit" nocase
        $lockbit2 = ".lockbit" nocase
        $lockbit3 = "LOCKBIT_RANSOMWARE" nocase
        $lockbit4 = "restore-my-files.txt" nocase
        $lockbit5 = "HLJkNskOq" nocase
        $lockbit6 = "LockBit Black" nocase
    condition:
        any of them
}

rule Ryuk_Ransomware {
    meta:
        description = "Détecte les artefacts du ransomware Ryuk"
        author = "ForensicHunter"
        severity = "critical"
        confidence = 80
    strings:
        $ryuk1 = ".RYK" nocase
        $ryuk2 = "RyukReadMe.txt" nocase
        $ryuk3 = "UNIQUE_ID_DO_NOT_REMOVE" nocase
    condition:
        any of them
}

rule WannaCry_Ransomware {
    meta:
        description = "Détecte les artefacts du ransomware WannaCry"
        author = "ForensicHunter"
        severity = "critical"
        confidence = 80
    strings:
        $wannacry1 = ".wncry" nocase
        $wannacry2 = "@WanaDecryptor@" nocase
        $wannacry3 = "tasksche.exe" nocase
        $wannacry4 = "taskdl.exe" nocase
    condition:
        any of them
}
"""
            
            # Règles pour les backdoors
            backdoor_rules = """
rule Generic_Backdoor {
    meta:
        description = "Détecte les artefacts génériques de backdoor"
        author = "ForensicHunter"
        severity = "high"
        confidence = 70
    strings:
        $backdoor1 = "cmd.exe /c net user /add" nocase
        $backdoor2 = "net localgroup administrators" nocase
        $backdoor3 = "netsh firewall add" nocase
        $backdoor4 = "reg add HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
        $backdoor5 = "schtasks /create" nocase
    condition:
        any of them
}

rule Webshell_Detection {
    meta:
        description = "Détecte les webshells PHP, ASP et JSP"
        author = "ForensicHunter"
        severity = "high"
        confidence = 75
    strings:
        $php_shell1 = "<?php" nocase
        $php_shell2 = "system(" nocase
        $php_shell3 = "exec(" nocase
        $php_shell4 = "shell_exec(" nocase
        $php_shell5 = "passthru(" nocase
        $php_shell6 = "eval(" nocase
        $php_shell7 = "base64_decode(" nocase
        
        $asp_shell1 = "<%@" nocase
        $asp_shell2 = "CreateObject(" nocase
        $asp_shell3 = "WScript.Shell" nocase
        $asp_shell4 = "Response.Write" nocase
        $asp_shell5 = "Execute(" nocase
        
        $jsp_shell1 = "<%@" nocase
        $jsp_shell2 = "Runtime.getRuntime(" nocase
        $jsp_shell3 = "ProcessBuilder" nocase
    condition:
        (2 of ($php_shell*)) or
        (2 of ($asp_shell*)) or
        (2 of ($jsp_shell*))
}
"""
            
            # Règles pour les malwares génériques
            malware_rules = """
rule Generic_Malware {
    meta:
        description = "Détecte les artefacts génériques de malware"
        author = "ForensicHunter"
        severity = "medium"
        confidence = 60
    strings:
        $malware1 = "powershell -e " nocase
        $malware2 = "powershell -enc" nocase
        $malware3 = "powershell -nop -w hidden -c" nocase
        $malware4 = "cmd.exe /c powershell" nocase
        $malware5 = "rundll32.exe" nocase
        $malware6 = "regsvr32.exe" nocase
        $malware7 = ".dll,DllRegisterServer" nocase
    condition:
        any of them
}

rule Suspicious_PowerShell {
    meta:
        description = "Détecte les scripts PowerShell suspects"
        author = "ForensicHunter"
        severity = "medium"
        confidence = 65
    strings:
        $ps1 = "Invoke-Expression" nocase
        $ps2 = "IEX" nocase
        $ps3 = "New-Object Net.WebClient" nocase
        $ps4 = "DownloadString" nocase
        $ps5 = "DownloadFile" nocase
        $ps6 = "Start-Process" nocase
        $ps7 = "Hidden" nocase
        $ps8 = "Invoke-Mimikatz" nocase
        $ps9 = "Invoke-Shellcode" nocase
        $ps10 = "ConvertTo-SecureString" nocase
    condition:
        3 of them
}
"""
            
            # Écrire les règles dans des fichiers
            with open(os.path.join(self.rules_dir, "ransomware.yar"), "w") as f:
                f.write(ransomware_rules)
            
            with open(os.path.join(self.rules_dir, "backdoor.yar"), "w") as f:
                f.write(backdoor_rules)
            
            with open(os.path.join(self.rules_dir, "malware.yar"), "w") as f:
                f.write(malware_rules)
            
            logger.info("Règles YARA par défaut créées avec succès")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la création des règles YARA par défaut: {str(e)}")
            return False
    
    def _create_temp_file(self, artifact):
        """
        Crée un fichier temporaire à partir d'un artefact pour l'analyse YARA.
        
        Args:
            artifact (Artifact): Artefact à analyser
            
        Returns:
            str: Chemin du fichier temporaire, ou None en cas d'erreur
        """
        try:
            # Extraire les informations du fichier
            file_path = artifact.data.get("file_path", "")
            file_type = artifact.data.get("type", "")
            
            # Créer un nom de fichier temporaire basé sur le chemin d'origine
            file_name = os.path.basename(file_path)
            temp_file_path = os.path.join(self.temp_dir, f"{artifact.id}_{file_name}")
            
            # Écrire le contenu dans le fichier temporaire
            if file_type == "text":
                content = artifact.data.get("content", "")
                with open(temp_file_path, "w", encoding="utf-8", errors="replace") as f:
                    f.write(content)
            
            elif file_type == "binary":
                header_hex = artifact.data.get("header_hex", "")
                if header_hex:
                    with open(temp_file_path, "wb") as f:
                        f.write(bytes.fromhex(header_hex))
                else:
                    logger.warning(f"Pas de données binaires disponibles pour {file_path}")
                    return None
            
            else:
                logger.warning(f"Type de fichier non pris en charge: {file_type}")
                return None
            
            return temp_file_path
            
        except Exception as e:
            logger.error(f"Erreur lors de la création du fichier temporaire pour l'artefact {artifact.id}: {str(e)}")
            return None
    
    def _cleanup_temp_dir(self):
        """
        Nettoie le répertoire temporaire.
        """
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                import shutil
                shutil.rmtree(self.temp_dir)
                logger.info(f"Répertoire temporaire supprimé: {self.temp_dir}")
            except Exception as e:
                logger.error(f"Erreur lors de la suppression du répertoire temporaire: {str(e)}")

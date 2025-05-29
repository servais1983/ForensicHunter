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
        self.yara_available = False
        self.yara = None
        
        # Tentative d'initialisation de YARA
        self._initialize_yara()
    
    def _initialize_yara(self):
        """
        Initialise le module YARA avec gestion d'erreurs robuste pour Windows.
        """
        try:
            # Tentative d'importation standard
            import yara
            self.yara = yara
            self.yara_available = True
            logger.info("Module YARA initialisé avec succès")
            return
        except ImportError as e:
            logger.warning(f"Échec de l'importation standard de YARA: {str(e)}")
        except Exception as e:
            logger.warning(f"Erreur lors de l'importation de YARA: {str(e)}")
        
        # Tentatives spécifiques pour Windows
        if platform.system() == "Windows":
            self._try_windows_yara_fixes()
        
        if not self.yara_available:
            logger.error("Module YARA non disponible. L'analyseur sera désactivé.")
            logger.info("Solutions possibles :")
            logger.info("1. Réinstaller yara-python : pip uninstall yara-python && pip install yara-python")
            logger.info("2. Installer les Visual C++ Redistributables")
            logger.info("3. Utiliser conda : conda install -c conda-forge yara-python")
    
    def _try_windows_yara_fixes(self):
        """
        Tentatives de correction spécifiques pour Windows.
        """
        logger.info("Tentatives de correction pour Windows...")
        
        # 1. Vérifier les chemins système
        python_path = sys.executable
        python_dir = os.path.dirname(python_path)
        dll_paths = [
            os.path.join(python_dir, "DLLs"),
            os.path.join(python_dir, "Library", "bin"),
            os.path.join(python_dir, "Scripts"),
        ]
        
        # Ajouter temporairement les chemins au PATH
        original_path = os.environ.get("PATH", "")
        for dll_path in dll_paths:
            if os.path.exists(dll_path) and dll_path not in original_path:
                os.environ["PATH"] = dll_path + os.pathsep + os.environ["PATH"]
        
        # 2. Tentative d'importation après modification du PATH
        try:
            import yara
            self.yara = yara
            self.yara_available = True
            logger.info("YARA initialisé après modification du PATH")
            return
        except Exception as e:
            logger.debug(f"Échec après modification du PATH: {str(e)}")
        
        # 3. Tentative avec chargement explicite de la DLL
        try:
            import ctypes
            import site
            
            # Chercher la DLL dans les packages installés
            for site_dir in site.getsitepackages():
                yara_dir = os.path.join(site_dir, "yara")
                if os.path.exists(yara_dir):
                    for root, dirs, files in os.walk(yara_dir):
                        for file in files:
                            if file.lower().endswith('.dll'):
                                dll_path = os.path.join(root, file)
                                try:
                                    ctypes.cdll.LoadLibrary(dll_path)
                                    logger.debug(f"DLL chargée: {dll_path}")
                                except:
                                    pass
            
            # Nouvelle tentative d'importation
            import yara
            self.yara = yara
            self.yara_available = True
            logger.info("YARA initialisé après chargement explicite des DLL")
            return
        except Exception as e:
            logger.debug(f"Échec du chargement explicite: {str(e)}")
        
        # Restaurer le PATH original
        os.environ["PATH"] = original_path
    
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
    
    def analyze(self, artifacts):
        """
        Analyse les artefacts en utilisant des règles YARA.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
            
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        self.clear_findings()
        
        # Vérifier si YARA est disponible
        if not self.yara_available:
            logger.warning("Module YARA non disponible. Analyse ignorée.")
            # Créer un finding informatif
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
        
        # Créer un répertoire temporaire pour les fichiers à analyser
        self.temp_dir = tempfile.mkdtemp(prefix="forensichunter_yara_")
        logger.info(f"Répertoire temporaire créé: {self.temp_dir}")
        
        try:
            # Compiler les règles YARA
            if not self._compile_rules():
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
                    
                    # Vérifier la taille du fichier
                    if self._get_artifact_size(artifact) > self.max_file_size:
                        logger.debug(f"Fichier {file_path} trop volumineux pour l'analyse YARA")
                        continue
                    
                    # Créer un fichier temporaire pour l'analyse
                    temp_file_path = self._create_temp_file(artifact)
                    
                    if not temp_file_path:
                        continue
                    
                    # Appliquer les règles YARA
                    matches = self.compiled_rules.match(temp_file_path)
                    
                    # Traiter les correspondances
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
                                "tags": list(tags),
                                "meta": dict(meta),
                                "strings": [(offset, identifier, data.hex()) for offset, identifier, data in strings],
                                "file_path": file_path,
                                "file_type": file_type
                            }
                        )
                        
                        logger.info(f"Correspondance YARA trouvée: {rule_name} dans {file_path}")
                
                except Exception as e:
                    logger.error(f"Erreur lors de l'analyse YARA de l'artefact {artifact.id}: {str(e)}")
            
            logger.info(f"{len([f for f in self.findings if f.finding_type == 'yara_match'])} correspondances YARA trouvées au total")
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
            if artifact.data.get("type") == "text":
                content = artifact.data.get("content", "")
                return len(content.encode('utf-8'))
            elif artifact.data.get("type") == "binary":
                header_hex = artifact.data.get("header_hex", "")
                return len(header_hex) // 2  # 2 caractères hex = 1 octet
            return 0
        except:
            return 0
    
    def _compile_rules(self):
        """
        Compile les règles YARA.
        
        Returns:
            bool: True si la compilation a réussi, False sinon
        """
        try:
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
                if self._create_default_rules():
                    # Rechercher à nouveau les fichiers de règles
                    for root, dirs, files in os.walk(self.rules_dir):
                        for file in files:
                            if file.endswith(".yar") or file.endswith(".yara"):
                                rule_files.append(os.path.join(root, file))
            
            if not rule_files:
                logger.error("Aucun fichier de règles YARA disponible.")
                return False
            
            # Compiler les règles
            try:
                # Créer un dictionnaire pour toutes les règles
                rules_dict = {}
                
                for i, rule_file in enumerate(rule_files):
                    try:
                        filename = os.path.basename(rule_file)
                        rules_dict[f"rules_{i}_{filename}"] = rule_file
                        logger.debug(f"Règle ajoutée: {rule_file}")
                    except Exception as e:
                        logger.error(f"Erreur lors de l'ajout de la règle {rule_file}: {str(e)}")
                
                if not rules_dict:
                    logger.error("Aucune règle valide trouvée.")
                    return False
                
                # Compiler toutes les règles ensemble
                self.compiled_rules = self.yara.compile(filepaths=rules_dict)
                logger.info(f"{len(rules_dict)} ensembles de règles YARA compilés avec succès")
                return True
                
            except Exception as e:
                logger.error(f"Erreur lors de la compilation des règles YARA: {str(e)}")
                
                # Tentative de compilation individuelle en cas d'échec
                try:
                    logger.info("Tentative de compilation individuelle des règles...")
                    valid_rules = {}
                    
                    for i, rule_file in enumerate(rule_files):
                        try:
                            # Tester la compilation individuelle
                            test_rule = self.yara.compile(rule_file)
                            filename = os.path.basename(rule_file)
                            valid_rules[f"rules_{i}_{filename}"] = rule_file
                            logger.debug(f"Règle valide: {rule_file}")
                        except Exception as rule_error:
                            logger.warning(f"Règle invalide ignorée {rule_file}: {str(rule_error)}")
                    
                    if valid_rules:
                        self.compiled_rules = self.yara.compile(filepaths=valid_rules)
                        logger.info(f"{len(valid_rules)} règles YARA valides compilées")
                        return True
                    else:
                        logger.error("Aucune règle valide n'a pu être compilée")
                        return False
                        
                except Exception as fallback_error:
                    logger.error(f"Échec de la compilation de secours: {str(fallback_error)}")
                    return False
            
        except Exception as e:
            logger.error(f"Erreur critique lors de la compilation des règles YARA: {str(e)}")
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
    condition:
        3 of them
}
"""
            
            # Écrire les règles dans des fichiers
            with open(os.path.join(self.rules_dir, "ransomware.yar"), "w", encoding='utf-8') as f:
                f.write(ransomware_rules)
            
            with open(os.path.join(self.rules_dir, "malware.yar"), "w", encoding='utf-8') as f:
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
            file_name = os.path.basename(file_path) or f"artifact_{artifact.id}"
            # Nettoyer le nom de fichier
            safe_filename = "".join(c for c in file_name if c.isalnum() or c in "._-")
            temp_file_path = os.path.join(self.temp_dir, f"{artifact.id}_{safe_filename}")
            
            # Écrire le contenu dans le fichier temporaire
            if file_type == "text":
                content = artifact.data.get("content", "")
                with open(temp_file_path, "w", encoding="utf-8", errors="replace") as f:
                    f.write(content)
            
            elif file_type == "binary":
                header_hex = artifact.data.get("header_hex", "")
                if header_hex:
                    try:
                        binary_data = bytes.fromhex(header_hex)
                        with open(temp_file_path, "wb") as f:
                            f.write(binary_data)
                    except ValueError as e:
                        logger.warning(f"Données hexadécimales invalides pour {file_path}: {str(e)}")
                        return None
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
                logger.debug(f"Répertoire temporaire supprimé: {self.temp_dir}")
            except Exception as e:
                logger.warning(f"Erreur lors de la suppression du répertoire temporaire: {str(e)}")

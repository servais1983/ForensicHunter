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
        self.max_file_size = self.config.get("max_file_size", 10 * 1024 * 1024)  # 10 MB
        self.compiled_rules = None
        self.temp_dir = None
        self.yara_available = False
        self.yara = None
        self.valid_rules_dir = None
        self.windows_version = None
        
        # Détection de la version de Windows
        if platform.system() == "Windows":
            try:
                self.windows_version = platform.win32_ver()[0]
                logger.info(f"Version de Windows détectée: {self.windows_version}")
            except:
                logger.warning("Impossible de détecter la version de Windows")
        
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
            os.path.join(python_dir, "Lib", "site-packages", "yara"),
            os.path.join(python_dir, "Lib", "site-packages", "yara_python"),
            os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "YARA"),
            os.path.join(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"), "YARA"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "YARA"),
            os.path.join(os.environ.get("APPDATA", ""), "YARA"),
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
        
        # 4. Tentative avec pip install en ligne de commande (pour les anciennes versions de Windows)
        try:
            if self.windows_version and self.windows_version in ["7", "8", "8.1"]:
                logger.info("Tentative d'installation de yara-python pour Windows ancien...")
                import subprocess
                subprocess.call([sys.executable, "-m", "pip", "install", "--upgrade", "yara-python==4.0.5"])
                
                # Nouvelle tentative d'importation
                import yara
                self.yara = yara
                self.yara_available = True
                logger.info("YARA initialisé après installation de version compatible")
                return
        except Exception as e:
            logger.debug(f"Échec de l'installation compatible: {str(e)}")
        
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
    
    def _validate_rule_file(self, rule_path):
        """
        Valide un fichier de règle YARA individuellement.
        
        Args:
            rule_path (str): Chemin vers le fichier de règle
            
        Returns:
            bool: True si la règle est valide, False sinon
        """
        try:
            # Lire le contenu du fichier
            with open(rule_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Vérifier les modules non supportés
            unsupported_modules = ["cuckoo", "magic", "hash", "authenticode", "dotnet", "elf", "math"]
            for module in unsupported_modules:
                if f"import \"{module}\"" in content:
                    logger.debug(f"Module non supporté dans {rule_path}: {module}")
                    return False
            
            # Vérifier les champs non supportés
            unsupported_fields = [
                "sync", "certificate", "url", "service", "receiver", "package_name", 
                "activity", "app_name", "network", "permission"
            ]
            
            for field in unsupported_fields:
                if re.search(r'\b' + field + r'\s*=', content):
                    logger.debug(f"Champ non supporté dans {rule_path}: {field}")
                    return False
            
            # Vérifier les identifiants non définis
            undefined_identifiers = ["is__elf"]
            for identifier in undefined_identifiers:
                if re.search(r'\b' + identifier + r'\b', content):
                    logger.debug(f"Identifiant non défini dans {rule_path}: {identifier}")
                    return False
            
            # Tester la compilation
            self.yara.compile(filepath=rule_path)
            return True
            
        except Exception as e:
            logger.debug(f"Erreur de validation pour {rule_path}: {str(e)}")
            return False
    
    def _create_valid_rules_directory(self):
        """
        Crée un répertoire de règles valides en filtrant les règles incompatibles.
        
        Returns:
            str: Chemin vers le répertoire de règles valides
        """
        # Créer un répertoire temporaire pour les règles valides
        valid_rules_dir = os.path.join(self.temp_dir, "valid_rules")
        os.makedirs(valid_rules_dir, exist_ok=True)
        
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
        
        # Valider et copier les règles valides
        valid_count = 0
        invalid_count = 0
        
        for rule_path in rule_files:
            if self._validate_rule_file(rule_path):
                # Copier la règle valide dans le répertoire temporaire
                dest_path = os.path.join(valid_rules_dir, os.path.basename(rule_path))
                shutil.copy2(rule_path, dest_path)
                valid_count += 1
            else:
                invalid_count += 1
        
        logger.info(f"Règles validées: {valid_count} valides, {invalid_count} invalides")
        
        # Créer un index des règles valides
        self._create_index_file(valid_rules_dir)
        
        return valid_rules_dir
    
    def _create_index_file(self, rules_dir):
        """
        Crée un fichier d'index pour les règles valides.
        
        Args:
            rules_dir (str): Répertoire contenant les règles valides
        """
        index_path = os.path.join(rules_dir, "index.yar")
        
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write('/*\n')
            f.write(' * ForensicHunter - Index des règles YARA valides\n')
            f.write(' * Généré automatiquement\n')
            f.write(' */\n\n')
            
            for root, dirs, files in os.walk(rules_dir):
                for file in files:
                    if (file.endswith(".yar") or file.endswith(".yara")) and file != "index.yar":
                        rel_path = os.path.relpath(os.path.join(root, file), rules_dir)
                        f.write(f'include "./{rel_path}"\n')
    
    def _compile_rules(self):
        """
        Compile les règles YARA.
        
        Returns:
            bool: True si la compilation a réussi, False sinon
        """
        try:
            # Créer un répertoire de règles valides
            self.valid_rules_dir = self._create_valid_rules_directory()
            
            if not os.path.exists(self.valid_rules_dir):
                logger.error("Impossible de créer le répertoire de règles valides")
                return False
            
            # Vérifier si des règles valides existent
            rule_files = []
            for root, dirs, files in os.walk(self.valid_rules_dir):
                for file in files:
                    if file.endswith(".yar") or file.endswith(".yara"):
                        rule_files.append(os.path.join(root, file))
            
            if not rule_files:
                logger.warning("Aucune règle YARA valide trouvée.")
                
                # Créer des règles par défaut si aucune n'est trouvée
                if self._create_default_rules():
                    # Rechercher à nouveau les fichiers de règles
                    for root, dirs, files in os.walk(self.valid_rules_dir):
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
            if not os.path.exists(self.valid_rules_dir):
                os.makedirs(self.valid_rules_dir, exist_ok=True)
            
            # Règles par défaut pour les ransomwares
            ransomware_rule = os.path.join(self.valid_rules_dir, "default_ransomware.yar")
            with open(ransomware_rule, 'w', encoding='utf-8') as f:
                f.write("""
rule Generic_Ransomware {
    meta:
        description = "Détecte des indicateurs génériques de ransomware"
        author = "ForensicHunter"
        severity = "high"
        confidence = 75
    strings:
        $ransom1 = "your files have been encrypted" nocase
        $ransom2 = "pay the ransom" nocase
        $ransom3 = "bitcoin" nocase
        $ransom4 = "decrypt" nocase
        $ransom5 = "README.txt" nocase
        $ransom6 = "HOW_TO_DECRYPT" nocase
        $ransom7 = "DECRYPT_INSTRUCTION" nocase
        $ransom8 = ".locked" nocase
        $ransom9 = ".crypt" nocase
        $ransom10 = ".encrypted" nocase
        $ransom11 = "RECOVERY_KEY" nocase
        $ransom12 = "HELP_DECRYPT" nocase
    condition:
        3 of them
}
                """)
            
            # Règles par défaut pour les backdoors
            backdoor_rule = os.path.join(self.valid_rules_dir, "default_backdoor.yar")
            with open(backdoor_rule, 'w', encoding='utf-8') as f:
                f.write("""
rule Generic_Backdoor {
    meta:
        description = "Détecte des indicateurs génériques de backdoor"
        author = "ForensicHunter"
        severity = "high"
        confidence = 70
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $cmd3 = "netcat" nocase
        $cmd4 = "nc.exe" nocase
        $cmd5 = "reverse shell" nocase
        $cmd6 = "connect-back" nocase
        $cmd7 = "bind shell" nocase
        $cmd8 = "backdoor" nocase
        $cmd9 = "remote access" nocase
        $net1 = "socket(" nocase
        $net2 = "wsock32" nocase
        $net3 = "ws2_32" nocase
        $net4 = "recv(" nocase
        $net5 = "send(" nocase
        $net6 = "connect(" nocase
    condition:
        (2 of ($cmd*)) and (2 of ($net*))
}
                """)
            
            # Règles par défaut pour les webshells
            webshell_rule = os.path.join(self.valid_rules_dir, "default_webshell.yar")
            with open(webshell_rule, 'w', encoding='utf-8') as f:
                f.write("""
rule Generic_Webshell {
    meta:
        description = "Détecte des indicateurs génériques de webshell"
        author = "ForensicHunter"
        severity = "high"
        confidence = 80
    strings:
        $php1 = "<?php" nocase
        $php2 = "eval(" nocase
        $php3 = "system(" nocase
        $php4 = "exec(" nocase
        $php5 = "shell_exec(" nocase
        $php6 = "passthru(" nocase
        $php7 = "base64_decode(" nocase
        $php8 = "preg_replace" nocase
        $php9 = "move_uploaded_file" nocase
        $asp1 = "<%@" nocase
        $asp2 = "Response.Write" nocase
        $asp3 = "CreateObject" nocase
        $asp4 = "WScript.Shell" nocase
        $asp5 = "Server.CreateObject" nocase
        $asp6 = "WSCRIPT.SHELL" nocase
        $asp7 = "ExecuteGlobal" nocase
        $input1 = "$_GET" nocase
        $input2 = "$_POST" nocase
        $input3 = "$_REQUEST" nocase
        $input4 = "Request.Form" nocase
        $input5 = "Request.QueryString" nocase
    condition:
        (2 of ($php*) and 1 of ($input*)) or
        (2 of ($asp*) and 1 of ($input*))
}
                """)
            
            # Règles par défaut pour les malwares
            malware_rule = os.path.join(self.valid_rules_dir, "default_malware.yar")
            with open(malware_rule, 'w', encoding='utf-8') as f:
                f.write("""
rule Generic_Malware {
    meta:
        description = "Détecte des indicateurs génériques de malware"
        author = "ForensicHunter"
        severity = "medium"
        confidence = 65
    strings:
        $packer1 = "UPX" nocase
        $packer2 = "themida" nocase
        $packer3 = "PECompact" nocase
        $packer4 = "ASPack" nocase
        $packer5 = "FSG" nocase
        $packer6 = "NSIS" nocase
        $packer7 = "MPress" nocase
        $inject1 = "VirtualAlloc" nocase
        $inject2 = "WriteProcessMemory" nocase
        $inject3 = "CreateRemoteThread" nocase
        $inject4 = "NtCreateThreadEx" nocase
        $inject5 = "RtlCreateUserThread" nocase
        $persist1 = "CurrentVersion\\Run" nocase
        $persist2 = "CurrentVersion\\RunOnce" nocase
        $persist3 = "Schedule" nocase
        $persist4 = "WinLogon" nocase
        $persist5 = "Startup" nocase
        $persist6 = "MACHINE\\SOFTWARE\\Microsoft" nocase
    condition:
        (2 of ($packer*)) or
        (2 of ($inject*)) or
        (2 of ($persist*))
}
                """)
            
            # Créer un fichier d'index
            self._create_index_file(self.valid_rules_dir)
            
            logger.info("Règles YARA par défaut créées avec succès")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de la création des règles par défaut: {str(e)}")
            return False
    
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
            file_path = artifact.data.get("file_path", "")
            file_name = os.path.basename(file_path)
            file_type = artifact.data.get("type", "")
            
            # Créer un nom de fichier temporaire
            temp_file_path = os.path.join(self.temp_dir, f"{artifact.id}_{file_name}")
            
            # Écrire le contenu dans le fichier temporaire
            if file_type == "text":
                content = artifact.data.get("content", "")
                with open(temp_file_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(content)
            elif file_type == "binary":
                header_hex = artifact.data.get("header_hex", "")
                if header_hex:
                    try:
                        # Convertir l'hexadécimal en binaire
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

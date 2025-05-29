#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module utilitaire pour la gestion d'encodage et d'exécution de commandes système.

Ce module fournit des fonctions utilitaires pour gérer les problèmes d'encodage
rencontrés lors de l'exécution de commandes système sous Windows.
"""

import subprocess
import logging
import os
import platform
from typing import Tuple, Optional, Union, List

logger = logging.getLogger("forensichunter.utils.encoding")

class EncodingError(Exception):
    """Exception levée en cas d'erreur d'encodage."""
    pass

def safe_subprocess_run(
    cmd: Union[str, List[str]], 
    timeout: int = 60,
    shell: Optional[bool] = None,
    cwd: Optional[str] = None,
    env: Optional[dict] = None
) -> Tuple[str, str, int]:
    """
    Exécute une commande subprocess avec gestion d'encodage sécurisée.
    
    Cette fonction tente plusieurs encodages pour résoudre les problèmes
    d'encodage Unicode couramment rencontrés sous Windows.
    
    Args:
        cmd: Commande à exécuter (str ou list)
        timeout: Timeout en secondes (défaut: 60)
        shell: Utiliser le shell (None = auto-détection)
        cwd: Répertoire de travail
        env: Variables d'environnement
        
    Returns:
        tuple: (stdout, stderr, returncode)
        
    Raises:
        EncodingError: Si tous les encodages échouent
        subprocess.TimeoutExpired: Si le timeout est dépassé
    """
    # Auto-détection du shell si non spécifié
    if shell is None:
        shell = isinstance(cmd, str)
    
    # Liste des encodages à essayer (ordre de priorité)
    encodings = ['utf-8', 'cp1252', 'latin1', 'ascii']
    
    # Encodage spécifique par OS
    if platform.system() == "Windows":
        encodings = ['utf-8', 'cp1252', 'cp850', 'latin1']
    elif platform.system() == "Linux":
        encodings = ['utf-8', 'latin1', 'ascii']
    
    last_error = None
    
    for encoding in encodings:
        try:
            logger.debug(f"Tentative d'exécution avec encodage {encoding}")
            
            result = subprocess.run(
                cmd,
                shell=shell,
                capture_output=True,
                text=True,
                encoding=encoding,
                errors='replace',  # Remplacer les caractères invalides
                timeout=timeout,
                cwd=cwd,
                env=env
            )
            
            logger.debug(f"Commande exécutée avec succès (encodage: {encoding})")
            return result.stdout, result.stderr, result.returncode
            
        except UnicodeDecodeError as e:
            last_error = e
            logger.debug(f"Erreur d'encodage {encoding}: {str(e)}")
            continue
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout lors de l'exécution de la commande: {cmd}")
            raise
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution avec encodage {encoding}: {str(e)}")
            last_error = e
            continue
    
    # Si tous les encodages ont échoué
    raise EncodingError(f"Impossible d'exécuter la commande avec tous les encodages testés. Dernière erreur: {last_error}")

def safe_file_read(file_path: str, encodings: Optional[List[str]] = None) -> str:
    """
    Lit un fichier avec gestion d'encodage sécurisée.
    
    Args:
        file_path: Chemin du fichier à lire
        encodings: Liste des encodages à essayer (optionnel)
        
    Returns:
        str: Contenu du fichier
        
    Raises:
        EncodingError: Si tous les encodages échouent
        FileNotFoundError: Si le fichier n'existe pas
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Fichier non trouvé: {file_path}")
    
    if encodings is None:
        if platform.system() == "Windows":
            encodings = ['utf-8', 'cp1252', 'cp850', 'latin1']
        else:
            encodings = ['utf-8', 'latin1', 'ascii']
    
    last_error = None
    
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                content = f.read()
            logger.debug(f"Fichier lu avec succès (encodage: {encoding})")
            return content
            
        except UnicodeDecodeError as e:
            last_error = e
            logger.debug(f"Erreur d'encodage {encoding} pour {file_path}: {str(e)}")
            continue
            
        except Exception as e:
            logger.error(f"Erreur lors de la lecture avec encodage {encoding}: {str(e)}")
            last_error = e
            continue
    
    raise EncodingError(f"Impossible de lire le fichier {file_path} avec tous les encodages testés. Dernière erreur: {last_error}")

def safe_json_loads(json_str: str) -> dict:
    """
    Parse JSON de manière sécurisée avec nettoyage des caractères problématiques.
    
    Args:
        json_str: Chaîne JSON à parser
        
    Returns:
        dict: Données JSON parsées ou None en cas d'erreur
    """
    import json
    
    if not json_str or not json_str.strip():
        return None
    
    try:
        # Nettoyer la chaîne JSON
        json_str = json_str.strip()
        
        # Enlever les caractères de contrôle problématiques (sauf \n, \r, \t)
        json_str = ''.join(char for char in json_str if ord(char) >= 32 or char in '\n\r\t')
        
        # Tentative de parsing JSON
        return json.loads(json_str)
        
    except json.JSONDecodeError as e:
        logger.error(f"Erreur JSON: {str(e)}")
        logger.debug(f"JSON problématique (premiers 200 caractères): {json_str[:200]}")
        return None
        
    except Exception as e:
        logger.error(f"Erreur lors du parsing JSON: {str(e)}")
        return None

def sanitize_string(text: str, max_length: int = None) -> str:
    """
    Nettoie une chaîne de caractères en supprimant les caractères problématiques.
    
    Args:
        text: Texte à nettoyer
        max_length: Longueur maximale (optionnel)
        
    Returns:
        str: Texte nettoyé
    """
    if not isinstance(text, str):
        text = str(text)
    
    # Remplacer les caractères de contrôle par des espaces
    text = ''.join(char if ord(char) >= 32 or char in '\n\r\t' else ' ' for char in text)
    
    # Supprimer les espaces multiples
    import re
    text = re.sub(r'\s+', ' ', text).strip()
    
    # Limiter la longueur si spécifiée
    if max_length and len(text) > max_length:
        text = text[:max_length] + "..."
    
    return text

def get_system_encoding() -> str:
    """
    Détecte l'encodage système recommandé.
    
    Returns:
        str: Nom de l'encodage recommandé
    """
    import locale
    
    # Essayer de détecter l'encodage du système
    try:
        encoding = locale.getpreferredencoding()
        if encoding:
            return encoding
    except Exception:
        pass
    
    # Fallback par OS
    if platform.system() == "Windows":
        return 'cp1252'
    else:
        return 'utf-8'

def create_powershell_command(script: str, execution_policy: str = "Bypass") -> List[str]:
    """
    Crée une commande PowerShell robuste avec gestion d'encodage.
    
    Args:
        script: Script PowerShell à exécuter
        execution_policy: Politique d'exécution (défaut: Bypass)
        
    Returns:
        list: Commande PowerShell formatée
    """
    # Nettoyer le script
    script = script.strip()
    
    # Construire la commande
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", execution_policy,
        "-OutputFormat", "Text",
        "-Command", script
    ]
    
    return cmd

def handle_subprocess_error(e: Exception, cmd: Union[str, List[str]]) -> str:
    """
    Gère les erreurs de subprocess de manière uniforme.
    
    Args:
        e: Exception capturée
        cmd: Commande qui a échoué
        
    Returns:
        str: Message d'erreur formaté
    """
    cmd_str = ' '.join(cmd) if isinstance(cmd, list) else str(cmd)
    
    if isinstance(e, subprocess.TimeoutExpired):
        return f"Timeout lors de l'exécution de: {cmd_str[:100]}..."
    elif isinstance(e, subprocess.CalledProcessError):
        return f"Erreur d'exécution (code {e.returncode}): {cmd_str[:100]}..."
    elif isinstance(e, UnicodeDecodeError):
        return f"Erreur d'encodage lors de l'exécution de: {cmd_str[:100]}..."
    elif isinstance(e, FileNotFoundError):
        return f"Commande non trouvée: {cmd_str[:100]}..."
    else:
        return f"Erreur inconnue lors de l'exécution de {cmd_str[:100]}...: {str(e)}"

class SafeCommandExecutor:
    """
    Exécuteur de commandes avec gestion d'encodage centralisée.
    
    Cette classe encapsule toute la logique de gestion d'encodage
    et fournit une interface simple pour l'exécution de commandes.
    """
    
    def __init__(self, default_timeout: int = 60, logger_name: str = None):
        """
        Initialise l'exécuteur de commandes.
        
        Args:
            default_timeout: Timeout par défaut en secondes
            logger_name: Nom du logger à utiliser
        """
        self.default_timeout = default_timeout
        self.logger = logging.getLogger(logger_name or "forensichunter.utils.safe_executor")
        self.system_encoding = get_system_encoding()
    
    def run(self, cmd: Union[str, List[str]], **kwargs) -> Tuple[str, str, int]:
        """
        Exécute une commande avec gestion d'erreur complète.
        
        Args:
            cmd: Commande à exécuter
            **kwargs: Arguments passés à safe_subprocess_run
            
        Returns:
            tuple: (stdout, stderr, returncode)
        """
        # Paramètres par défaut
        kwargs.setdefault('timeout', self.default_timeout)
        
        try:
            return safe_subprocess_run(cmd, **kwargs)
        except Exception as e:
            error_msg = handle_subprocess_error(e, cmd)
            self.logger.error(error_msg)
            return "", error_msg, 1
    
    def run_powershell(self, script: str, **kwargs) -> Tuple[str, str, int]:
        """
        Exécute un script PowerShell avec gestion d'encodage.
        
        Args:
            script: Script PowerShell à exécuter
            **kwargs: Arguments passés à run()
            
        Returns:
            tuple: (stdout, stderr, returncode)
        """
        cmd = create_powershell_command(script)
        return self.run(cmd, **kwargs)
    
    def run_wmic(self, query: str, **kwargs) -> Tuple[str, str, int]:
        """
        Exécute une requête WMIC avec gestion d'encodage.
        
        Args:
            query: Requête WMIC à exécuter
            **kwargs: Arguments passés à run()
            
        Returns:
            tuple: (stdout, stderr, returncode)
        """
        cmd = f"wmic {query}"
        return self.run(cmd, **kwargs)

# Instance globale pour faciliter l'utilisation
default_executor = SafeCommandExecutor()

# Fonctions de raccourci
def run_command(cmd: Union[str, List[str]], **kwargs) -> Tuple[str, str, int]:
    """Raccourci pour exécuter une commande avec l'exécuteur par défaut."""
    return default_executor.run(cmd, **kwargs)

def run_powershell(script: str, **kwargs) -> Tuple[str, str, int]:
    """Raccourci pour exécuter un script PowerShell avec l'exécuteur par défaut."""
    return default_executor.run_powershell(script, **kwargs)

def run_wmic(query: str, **kwargs) -> Tuple[str, str, int]:
    """Raccourci pour exécuter une requête WMIC avec l'exécuteur par défaut."""
    return default_executor.run_wmic(query, **kwargs)

# Tests unitaires intégrés
if __name__ == "__main__":
    import sys
    
    # Configuration du logging pour les tests
    logging.basicConfig(level=logging.DEBUG)
    
    print("=== Tests du module encoding_utils ===")
    
    # Test 1: Commande simple
    print("\n1. Test commande simple (dir)")
    try:
        stdout, stderr, code = run_command("dir" if platform.system() == "Windows" else "ls")
        print(f"   Code de retour: {code}")
        print(f"   Lignes de sortie: {len(stdout.splitlines())}")
        print("   ✓ Succès")
    except Exception as e:
        print(f"   ✗ Erreur: {e}")
    
    # Test 2: PowerShell (Windows uniquement)
    if platform.system() == "Windows":
        print("\n2. Test PowerShell")
        try:
            stdout, stderr, code = run_powershell("Get-Date | ConvertTo-Json")
            print(f"   Code de retour: {code}")
            print(f"   Contient JSON: {'true' if '{' in stdout else 'false'}")
            print("   ✓ Succès")
        except Exception as e:
            print(f"   ✗ Erreur: {e}")
    
    # Test 3: WMIC (Windows uniquement)
    if platform.system() == "Windows":
        print("\n3. Test WMIC")
        try:
            stdout, stderr, code = run_wmic("computersystem get Name /format:csv")
            print(f"   Code de retour: {code}")
            print(f"   Contient CSV: {',' in stdout}")
            print("   ✓ Succès")
        except Exception as e:
            print(f"   ✗ Erreur: {e}")
    
    # Test 4: Nettoyage JSON
    print("\n4. Test nettoyage JSON")
    test_json = '{"test": "valeur avec caractères \x00\x01 spéciaux"}'
    result = safe_json_loads(test_json)
    if result and "test" in result:
        print("   ✓ JSON parsé avec succès")
    else:
        print("   ✗ Échec du parsing JSON")
    
    # Test 5: Nettoyage de chaîne
    print("\n5. Test nettoyage de chaîne")
    test_string = "Texte avec\x00\x01caractères\x02de contrôle"
    cleaned = sanitize_string(test_string)
    print(f"   Original: {repr(test_string)}")
    print(f"   Nettoyé: {repr(cleaned)}")
    print("   ✓ Chaîne nettoyée")
    
    print("\n=== Fin des tests ===")

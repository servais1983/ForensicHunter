#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion de la sécurité pour ForensicHunter.

Ce module implémente les principes DevSecOps pour garantir la sécurité
de l'application à tous les niveaux : validation des entrées, gestion
des privilèges, chiffrement des données sensibles, etc.
"""

import os
import re
import sys
import hmac
import json
import uuid
import base64
import hashlib
import logging
import tempfile
import platform
import subprocess
from typing import Dict, List, Any, Optional, Union, Callable
from functools import wraps

logger = logging.getLogger("forensichunter")


class SecurityManager:
    """Gestionnaire de sécurité pour ForensicHunter."""

    def __init__(self, config=None):
        """
        Initialise le gestionnaire de sécurité.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config or {}
        self.security_key = self._generate_security_key()
        self.dangerous_patterns = self._load_dangerous_patterns()
        
        # Initialisation du journal de sécurité
        self._setup_security_logger()
        
        # Vérification de l'environnement d'exécution
        self._verify_execution_environment()
    
    def _generate_security_key(self) -> bytes:
        """
        Génère une clé de sécurité unique pour cette instance.
        
        Returns:
            Clé de sécurité
        """
        try:
            return os.urandom(32)
        except Exception:
            # Fallback si os.urandom n'est pas disponible
            seed = f"{uuid.uuid4()}{platform.node()}{os.getpid()}{os.getcwd()}"
            return hashlib.sha256(seed.encode()).digest()
    
    def _load_dangerous_patterns(self) -> Dict[str, List[str]]:
        """
        Charge les patterns dangereux à détecter dans les entrées.
        
        Returns:
            Dictionnaire des patterns dangereux par catégorie
        """
        return {
            "command_injection": [
                r";\s*\w+",
                r"\|\s*\w+",
                r"`.*`",
                r"\$\(.*\)",
                r"&&\s*\w+"
            ],
            "sql_injection": [
                r"(?i)'\s*OR\s*'1'='1",
                r"(?i)'\s*OR\s*1=1",
                r"(?i)--",
                r"(?i);\s*DROP\s+TABLE",
                r"(?i)UNION\s+SELECT"
            ],
            "path_traversal": [
                r"\.\.\/",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e/"
            ],
            "xss": [
                r"<script>",
                r"<\/script>",
                r"javascript:",
                r"onerror=",
                r"onload="
            ]
        }
    
    def _setup_security_logger(self):
        """Configure le logger de sécurité."""
        # Création d'un handler pour le fichier de log de sécurité
        log_dir = os.path.join(os.getcwd(), "security_logs")
        os.makedirs(log_dir, exist_ok=True)
        
        security_file = os.path.join(log_dir, "security.log")
        
        # Configuration du handler de fichier
        file_handler = logging.FileHandler(security_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Format du log de sécurité
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] SECURITY: %(message)s')
        file_handler.setFormatter(formatter)
        
        # Création d'un logger spécifique pour la sécurité
        self.security_logger = logging.getLogger("forensichunter.security")
        self.security_logger.setLevel(logging.INFO)
        self.security_logger.addHandler(file_handler)
        
        # Désactivation de la propagation pour éviter la duplication des logs
        self.security_logger.propagate = False
    
    def _verify_execution_environment(self):
        """Vérifie la sécurité de l'environnement d'exécution."""
        # Vérification des privilèges
        is_admin = self.check_admin_privileges()
        self.security_logger.info(f"Exécution avec privilèges administrateur: {is_admin}")
        
        # Vérification du système d'exploitation
        os_info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version()
        }
        self.security_logger.info(f"Environnement d'exécution: {os_info}")
        
        # Vérification des variables d'environnement sensibles
        self._check_environment_variables()
        
        # Vérification des permissions du répertoire de travail
        self._check_directory_permissions(os.getcwd())
    
    def _check_environment_variables(self):
        """Vérifie les variables d'environnement sensibles."""
        sensitive_vars = ["PATH", "TEMP", "TMP", "PYTHONPATH"]
        
        for var in sensitive_vars:
            if var in os.environ:
                # Ne pas logger la valeur complète pour des raisons de sécurité
                value = os.environ[var]
                masked_value = value[:5] + "..." + value[-5:] if len(value) > 10 else "***"
                self.security_logger.debug(f"Variable d'environnement {var}: {masked_value}")
                
                # Vérification des chemins suspects dans PATH
                if var == "PATH":
                    paths = value.split(os.pathsep)
                    for path in paths:
                        if not os.path.exists(path):
                            continue
                        
                        # Vérification des permissions
                        try:
                            if os.access(path, os.W_OK) and path not in ["/usr/bin", "/bin", "/usr/local/bin"]:
                                self.security_logger.warning(f"Chemin PATH modifiable détecté: {path}")
                        except Exception:
                            pass
    
    def _check_directory_permissions(self, directory: str):
        """
        Vérifie les permissions d'un répertoire.
        
        Args:
            directory: Chemin du répertoire à vérifier
        """
        try:
            # Vérification de l'existence du répertoire
            if not os.path.exists(directory):
                self.security_logger.warning(f"Répertoire inexistant: {directory}")
                return
            
            # Vérification des permissions
            readable = os.access(directory, os.R_OK)
            writable = os.access(directory, os.W_OK)
            executable = os.access(directory, os.X_OK)
            
            self.security_logger.debug(f"Permissions du répertoire {directory}: R={readable}, W={writable}, X={executable}")
            
            # Vérification des permissions trop ouvertes
            if platform.system() != "Windows":
                try:
                    import stat
                    mode = os.stat(directory).st_mode
                    if mode & stat.S_IWOTH:
                        self.security_logger.warning(f"Répertoire accessible en écriture par tous: {directory}")
                except Exception:
                    pass
        except Exception as e:
            self.security_logger.error(f"Erreur lors de la vérification des permissions du répertoire {directory}: {str(e)}")
    
    def validate_input(self, input_data: str, input_type: str = "general") -> bool:
        """
        Valide une entrée utilisateur pour détecter les patterns dangereux.
        
        Args:
            input_data: Données d'entrée à valider
            input_type: Type d'entrée (general, filepath, command, etc.)
            
        Returns:
            True si l'entrée est valide, False sinon
        """
        if input_data is None:
            return False
        
        # Conversion en chaîne si nécessaire
        if not isinstance(input_data, str):
            input_data = str(input_data)
        
        # Validation spécifique selon le type d'entrée
        if input_type == "filepath":
            return self._validate_filepath(input_data)
        elif input_type == "command":
            return self._validate_command(input_data)
        elif input_type == "url":
            return self._validate_url(input_data)
        
        # Validation générale pour détecter les patterns dangereux
        for category, patterns in self.dangerous_patterns.items():
            for pattern in patterns:
                if re.search(pattern, input_data):
                    self.security_logger.warning(f"Pattern dangereux détecté ({category}): {input_data}")
                    return False
        
        return True
    
    def _validate_filepath(self, filepath: str) -> bool:
        """
        Valide un chemin de fichier.
        
        Args:
            filepath: Chemin de fichier à valider
            
        Returns:
            True si le chemin est valide, False sinon
        """
        # Vérification des caractères interdits
        forbidden_chars = ['<', '>', '|', '*', '?', '"', ';']
        if any(char in filepath for char in forbidden_chars):
            self.security_logger.warning(f"Caractères interdits dans le chemin de fichier: {filepath}")
            return False
        
        # Vérification des tentatives de traversée de répertoire
        normalized_path = os.path.normpath(filepath)
        if ".." in normalized_path.split(os.sep):
            self.security_logger.warning(f"Tentative de traversée de répertoire détectée: {filepath}")
            return False
        
        # Vérification des chemins absolus
        if os.path.isabs(filepath):
            # Vérification des répertoires sensibles
            sensitive_dirs = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "C:\\Windows\\System32"]
            for sensitive_dir in sensitive_dirs:
                if normalized_path.startswith(sensitive_dir):
                    self.security_logger.warning(f"Tentative d'accès à un répertoire sensible: {filepath}")
                    return False
        
        return True
    
    def _validate_command(self, command: str) -> bool:
        """
        Valide une commande système.
        
        Args:
            command: Commande à valider
            
        Returns:
            True si la commande est valide, False sinon
        """
        # Liste des commandes autorisées
        allowed_commands = [
            "vol.py", "volatility", "python", "python3",
            "dir", "ls", "find", "grep", "cat", "type"
        ]
        
        # Vérification que la commande commence par une commande autorisée
        command_parts = command.split()
        if not command_parts:
            return False
        
        base_command = os.path.basename(command_parts[0])
        if base_command not in allowed_commands:
            self.security_logger.warning(f"Commande non autorisée: {command}")
            return False
        
        # Vérification des caractères d'échappement et des opérateurs de chaînage
        dangerous_operators = [";", "|", "&", "&&", "||", "`", "$", "(", ")", "<", ">", "\\"]
        for operator in dangerous_operators:
            if operator in command:
                self.security_logger.warning(f"Opérateur dangereux dans la commande: {command}")
                return False
        
        return True
    
    def _validate_url(self, url: str) -> bool:
        """
        Valide une URL.
        
        Args:
            url: URL à valider
            
        Returns:
            True si l'URL est valide, False sinon
        """
        # Vérification du format de l'URL
        url_pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
        if not re.match(url_pattern, url):
            self.security_logger.warning(f"Format d'URL invalide: {url}")
            return False
        
        # Vérification des protocoles autorisés
        allowed_protocols = ["http", "https"]
        protocol = url.split("://")[0].lower()
        if protocol not in allowed_protocols:
            self.security_logger.warning(f"Protocole non autorisé: {protocol}")
            return False
        
        # Vérification des caractères dangereux
        dangerous_chars = ["<", ">", "'", '"', ";", "`", "$", "&", "|", "(", ")"]
        if any(char in url for char in dangerous_chars):
            self.security_logger.warning(f"Caractères dangereux dans l'URL: {url}")
            return False
        
        return True
    
    def sanitize_input(self, input_data: str, input_type: str = "general") -> str:
        """
        Assainit une entrée utilisateur.
        
        Args:
            input_data: Données d'entrée à assainir
            input_type: Type d'entrée (general, filepath, command, etc.)
            
        Returns:
            Entrée assainie
        """
        if input_data is None:
            return ""
        
        # Conversion en chaîne si nécessaire
        if not isinstance(input_data, str):
            input_data = str(input_data)
        
        # Assainissement spécifique selon le type d'entrée
        if input_type == "filepath":
            return self._sanitize_filepath(input_data)
        elif input_type == "command":
            return self._sanitize_command(input_data)
        elif input_type == "html":
            return self._sanitize_html(input_data)
        
        # Assainissement général
        sanitized = input_data
        
        # Suppression des caractères de contrôle
        sanitized = re.sub(r'[\x00-\x1F\x7F]', '', sanitized)
        
        # Échappement des caractères spéciaux
        sanitized = sanitized.replace("&", "&amp;")
        sanitized = sanitized.replace("<", "&lt;")
        sanitized = sanitized.replace(">", "&gt;")
        sanitized = sanitized.replace('"', "&quot;")
        sanitized = sanitized.replace("'", "&#x27;")
        
        return sanitized
    
    def _sanitize_filepath(self, filepath: str) -> str:
        """
        Assainit un chemin de fichier.
        
        Args:
            filepath: Chemin de fichier à assainir
            
        Returns:
            Chemin de fichier assaini
        """
        # Normalisation du chemin
        sanitized = os.path.normpath(filepath)
        
        # Suppression des caractères interdits
        forbidden_chars = ['<', '>', '|', '*', '?', '"', ';']
        for char in forbidden_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Suppression des séquences de traversée de répertoire
        while '..' in sanitized.split(os.sep):
            parts = sanitized.split(os.sep)
            idx = parts.index('..')
            if idx > 0:
                parts.pop(idx)
                parts.pop(idx - 1)
            else:
                parts.pop(idx)
            sanitized = os.sep.join(parts)
        
        return sanitized
    
    def _sanitize_command(self, command: str) -> str:
        """
        Assainit une commande système.
        
        Args:
            command: Commande à assainir
            
        Returns:
            Commande assainie
        """
        # Suppression des opérateurs dangereux
        dangerous_operators = [";", "|", "&", "&&", "||", "`", "$", "(", ")", "<", ">", "\\"]
        sanitized = command
        
        for operator in dangerous_operators:
            sanitized = sanitized.replace(operator, "")
        
        return sanitized
    
    def _sanitize_html(self, html: str) -> str:
        """
        Assainit du contenu HTML.
        
        Args:
            html: Contenu HTML à assainir
            
        Returns:
            Contenu HTML assaini
        """
        # Suppression des balises script
        sanitized = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', html)
        
        # Suppression des attributs dangereux
        dangerous_attrs = ["onload", "onerror", "onclick", "onmouseover", "onmouseout", "onkeydown", "onkeypress", "onkeyup"]
        for attr in dangerous_attrs:
            sanitized = re.sub(rf'{attr}\s*=\s*["\'][^"\']*["\']', '', sanitized)
        
        # Suppression des URLs javascript:
        sanitized = re.sub(r'javascript:', 'void', sanitized)
        
        return sanitized
    
    def encrypt_data(self, data: Union[str, bytes]) -> str:
        """
        Chiffre des données sensibles.
        
        Args:
            data: Données à chiffrer
            
        Returns:
            Données chiffrées en base64
        """
        try:
            # Conversion en bytes si nécessaire
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Génération d'un vecteur d'initialisation aléatoire
            iv = os.urandom(16)
            
            # Chiffrement AES
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            cipher = Cipher(
                algorithms.AES(self.security_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            
            # Concaténation de l'IV et des données chiffrées
            result = iv + encrypted_data
            
            # Encodage en base64
            return base64.b64encode(result).decode('utf-8')
            
        except Exception as e:
            self.security_logger.error(f"Erreur lors du chiffrement des données: {str(e)}")
            return ""
    
    def decrypt_data(self, encrypted_data: str) -> bytes:
        """
        Déchiffre des données sensibles.
        
        Args:
            encrypted_data: Données chiffrées en base64
            
        Returns:
            Données déchiffrées
        """
        try:
            # Décodage base64
            data = base64.b64decode(encrypted_data)
            
            # Extraction de l'IV et des données chiffrées
            iv = data[:16]
            ciphertext = data[16:]
            
            # Déchiffrement AES
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            cipher = Cipher(
                algorithms.AES(self.security_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted_data
            
        except Exception as e:
            self.security_logger.error(f"Erreur lors du déchiffrement des données: {str(e)}")
            return b""
    
    def hash_password(self, password: str) -> str:
        """
        Hache un mot de passe de manière sécurisée.
        
        Args:
            password: Mot de passe à hacher
            
        Returns:
            Hash du mot de passe
        """
        try:
            # Génération d'un sel aléatoire
            salt = os.urandom(16)
            
            # Hachage avec PBKDF2
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            # Dérivation de la clé
            key = kdf.derive(password.encode('utf-8'))
            
            # Concaténation du sel et de la clé
            result = salt + key
            
            # Encodage en base64
            return base64.b64encode(result).decode('utf-8')
            
        except Exception as e:
            self.security_logger.error(f"Erreur lors du hachage du mot de passe: {str(e)}")
            return ""
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Vérifie un mot de passe par rapport à son hash.
        
        Args:
            password: Mot de passe à vérifier
            hashed_password: Hash du mot de passe
            
        Returns:
            True si le mot de passe correspond au hash, False sinon
        """
        try:
            # Décodage base64
            data = base64.b64decode(hashed_password)
            
            # Extraction du sel et du hash
            salt = data[:16]
            stored_key = data[16:]
            
            # Hachage avec PBKDF2
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            # Vérification
            try:
                kdf.verify(password.encode('utf-8'), stored_key)
                return True
            except Exception:
                return False
            
        except Exception as e:
            self.security_logger.error(f"Erreur lors de la vérification du mot de passe: {str(e)}")
            return False
    
    def generate_hmac(self, data: Union[str, bytes]) -> str:
        """
        Génère un HMAC pour vérifier l'intégrité des données.
        
        Args:
            data: Données pour lesquelles générer un HMAC
            
        Returns:
            HMAC en hexadécimal
        """
        try:
            # Conversion en bytes si nécessaire
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Génération du HMAC
            h = hmac.new(self.security_key, data, hashlib.sha256)
            return h.hexdigest()
            
        except Exception as e:
            self.security_logger.error(f"Erreur lors de la génération du HMAC: {str(e)}")
            return ""
    
    def verify_hmac(self, data: Union[str, bytes], hmac_value: str) -> bool:
        """
        Vérifie un HMAC pour confirmer l'intégrité des données.
        
        Args:
            data: Données à vérifier
            hmac_value: HMAC à vérifier
            
        Returns:
            True si le HMAC est valide, False sinon
        """
        try:
            # Conversion en bytes si nécessaire
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Génération du HMAC
            h = hmac.new(self.security_key, data, hashlib.sha256)
            calculated_hmac = h.hexdigest()
            
            # Comparaison en temps constant
            return hmac.compare_digest(calculated_hmac, hmac_value)
            
        except Exception as e:
            self.security_logger.error(f"Erreur lors de la vérification du HMAC: {str(e)}")
            return False
    
    def check_admin_privileges(self) -> bool:
        """
        Vérifie si le processus actuel dispose des privilèges administrateur.
        
        Returns:
            True si le processus dispose des privilèges administrateur, False sinon
        """
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False
    
    def drop_privileges(self) -> bool:
        """
        Abandonne les privilèges élevés si possible.
        
        Returns:
            True si les privilèges ont été abandonnés, False sinon
        """
        if platform.system() != "Windows":
            try:
                # Récupération de l'UID et du GID non privilégiés
                import pwd
                import grp
                
                # Récupération de l'utilisateur nobody
                nobody = pwd.getpwnam("nobody")
                nogroup = grp.getgrnam("nogroup")
                
                # Abandon des privilèges
                os.setgroups([])
                os.setgid(nogroup.gr_gid)
                os.setuid(nobody.pw_uid)
                
                self.security_logger.info("Privilèges abandonnés avec succès")
                return True
            except Exception as e:
                self.security_logger.error(f"Erreur lors de l'abandon des privilèges: {str(e)}")
                return False
        else:
            self.security_logger.warning("L'abandon des privilèges n'est pas supporté sur Windows")
            return False
    
    def create_secure_temp_file(self, prefix: str = "forensichunter_") -> str:
        """
        Crée un fichier temporaire sécurisé.
        
        Args:
            prefix: Préfixe du fichier temporaire
            
        Returns:
            Chemin vers le fichier temporaire
        """
        try:
            # Création du fichier temporaire
            fd, temp_path = tempfile.mkstemp(prefix=prefix)
            os.close(fd)
            
            # Définition des permissions restrictives
            if platform.system() != "Windows":
                import stat
                os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
            
            return temp_path
            
        except Exception as e:
            self.security_logger.error(f"Erreur lors de la création du fichier temporaire sécurisé: {str(e)}")
            return ""
    
    def secure_delete_file(self, filepath: str, passes: int = 3) -> bool:
        """
        Supprime un fichier de manière sécurisée.
        
        Args:
            filepath: Chemin vers le fichier à supprimer
            passes: Nombre de passes d'écrasement
            
        Returns:
            True si le fichier a été supprimé avec succès, False sinon
        """
        if not os.path.isfile(filepath):
            return False
        
        try:
            # Récupération de la taille du fichier
            file_size = os.path.getsize(filepath)
            
            # Écrasement du fichier
            for i in range(passes):
                with open(filepath, "wb") as f:
                    # Écriture de données aléatoires
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Suppression du fichier
            os.unlink(filepath)
            
            return True
            
        except Exception as e:
            self.security_logger.error(f"Erreur lors de la suppression sécurisée du fichier {filepath}: {str(e)}")
            return False
    
    def verify_file_integrity(self, filepath: str, expected_hash: str = None) -> bool:
        """
        Vérifie l'intégrité d'un fichier.
        
        Args:
            filepath: Chemin vers le fichier à vérifier
            expected_hash: Hash attendu (SHA-256)
            
        Returns:
            True si l'intégrité est vérifiée, False sinon
        """
        if not os.path.isfile(filepath):
            return False
        
        try:
            # Calcul du hash SHA-256
            sha256_hash = hashlib.sha256()
            
            with open(filepath, "rb") as f:
                # Lecture par blocs pour éviter de charger tout le fichier en mémoire
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            calculated_hash = sha256_hash.hexdigest()
            
            # Vérification du hash si fourni
            if expected_hash:
                return calculated_hash == expected_hash
            
            # Sinon, on retourne simplement le hash calculé
            self.security_logger.info(f"Hash SHA-256 du fichier {filepath}: {calculated_hash}")
            return True
            
        except Exception as e:
            self.security_logger.error(f"Erreur lors de la vérification de l'intégrité du fichier {filepath}: {str(e)}")
            return False
    
    def verify_binary_signature(self, binary_path: str) -> bool:
        """
        Vérifie la signature d'un binaire.
        
        Args:
            binary_path: Chemin vers le binaire à vérifier
            
        Returns:
            True si la signature est valide, False sinon
        """
        if not os.path.isfile(binary_path):
            return False
        
        try:
            if platform.system() == "Windows":
                # Vérification de la signature avec sigcheck (Sysinternals)
                sigcheck_path = self._find_sigcheck()
                if not sigcheck_path:
                    self.security_logger.warning("Sigcheck non trouvé, impossible de vérifier la signature")
                    return False
                
                cmd = [sigcheck_path, "-a", "-q", binary_path]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                # Vérification du résultat
                return "Signed" in result.stdout and "Verified" in result.stdout
            else:
                # Sur Linux/Unix, on peut utiliser gpg pour vérifier les signatures
                # Mais cela nécessite un fichier de signature séparé
                self.security_logger.warning("Vérification de signature non implémentée pour cette plateforme")
                return False
            
        except Exception as e:
            self.security_logger.error(f"Erreur lors de la vérification de la signature du binaire {binary_path}: {str(e)}")
            return False
    
    def _find_sigcheck(self) -> str:
        """
        Recherche l'outil sigcheck dans le système.
        
        Returns:
            Chemin vers sigcheck ou chaîne vide si non trouvé
        """
        # Recherche dans le PATH
        try:
            result = subprocess.run(["where", "sigcheck.exe"], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        
        # Recherche dans les emplacements courants
        common_locations = [
            r"C:\Program Files\Sysinternals\sigcheck.exe",
            r"C:\Program Files (x86)\Sysinternals\sigcheck.exe",
            os.path.join(os.getcwd(), "tools", "sigcheck.exe")
        ]
        
        for location in common_locations:
            if os.path.isfile(location):
                return location
        
        return ""
    
    def sandbox_function(self, func: Callable, *args, **kwargs) -> Any:
        """
        Exécute une fonction dans un environnement sandbox.
        
        Args:
            func: Fonction à exécuter
            *args: Arguments positionnels
            **kwargs: Arguments nommés
            
        Returns:
            Résultat de la fonction
        """
        # Sauvegarde de l'environnement actuel
        old_env = os.environ.copy()
        old_cwd = os.getcwd()
        
        try:
            # Création d'un répertoire temporaire pour le sandbox
            with tempfile.TemporaryDirectory() as temp_dir:
                # Changement de répertoire
                os.chdir(temp_dir)
                
                # Restriction des variables d'environnement
                restricted_env = {
                    "PATH": os.environ.get("PATH", ""),
                    "TEMP": temp_dir,
                    "TMP": temp_dir
                }
                os.environ.clear()
                os.environ.update(restricted_env)
                
                # Exécution de la fonction
                return func(*args, **kwargs)
                
        finally:
            # Restauration de l'environnement
            os.environ.clear()
            os.environ.update(old_env)
            os.chdir(old_cwd)
    
    def require_admin(self, func: Callable) -> Callable:
        """
        Décorateur pour exiger des privilèges administrateur.
        
        Args:
            func: Fonction à décorer
            
        Returns:
            Fonction décorée
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not self.check_admin_privileges():
                self.security_logger.error(f"Privilèges administrateur requis pour {func.__name__}")
                raise PermissionError(f"Privilèges administrateur requis pour {func.__name__}")
            return func(*args, **kwargs)
        return wrapper
    
    def validate_input_decorator(self, input_type: str = "general") -> Callable:
        """
        Décorateur pour valider les entrées d'une fonction.
        
        Args:
            input_type: Type d'entrée à valider
            
        Returns:
            Décorateur
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Validation des arguments positionnels
                for i, arg in enumerate(args[1:], 1):  # Skip self
                    if isinstance(arg, str) and not self.validate_input(arg, input_type):
                        self.security_logger.error(f"Entrée invalide pour {func.__name__}, argument {i}: {arg}")
                        raise ValueError(f"Entrée invalide pour {func.__name__}, argument {i}")
                
                # Validation des arguments nommés
                for name, value in kwargs.items():
                    if isinstance(value, str) and not self.validate_input(value, input_type):
                        self.security_logger.error(f"Entrée invalide pour {func.__name__}, argument {name}: {value}")
                        raise ValueError(f"Entrée invalide pour {func.__name__}, argument {name}")
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def audit_decorator(self, action: str) -> Callable:
        """
        Décorateur pour auditer les appels de fonction.
        
        Args:
            action: Action à auditer
            
        Returns:
            Décorateur
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Journalisation de l'appel
                self.security_logger.info(f"Audit: {action}, fonction: {func.__name__}")
                
                try:
                    result = func(*args, **kwargs)
                    return result
                except Exception as e:
                    self.security_logger.error(f"Erreur lors de l'exécution de {func.__name__}: {str(e)}")
                    raise
            return wrapper
        return decorator
    
    def perform_security_audit(self) -> Dict[str, Any]:
        """
        Effectue un audit de sécurité complet.
        
        Returns:
            Résultats de l'audit
        """
        audit_results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "system_info": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor()
            },
            "security_checks": [],
            "vulnerabilities": [],
            "recommendations": []
        }
        
        # Vérification des privilèges
        is_admin = self.check_admin_privileges()
        audit_results["security_checks"].append({
            "name": "admin_privileges",
            "description": "Vérification des privilèges administrateur",
            "result": is_admin,
            "details": f"L'application s'exécute {'avec' if is_admin else 'sans'} privilèges administrateur"
        })
        
        if is_admin:
            audit_results["recommendations"].append(
                "Envisager d'exécuter l'application avec des privilèges réduits lorsque possible"
            )
        
        # Vérification des permissions du répertoire de travail
        try:
            cwd = os.getcwd()
            writable_by_others = False
            
            if platform.system() != "Windows":
                import stat
                mode = os.stat(cwd).st_mode
                writable_by_others = bool(mode & stat.S_IWOTH)
            
            audit_results["security_checks"].append({
                "name": "working_directory_permissions",
                "description": "Vérification des permissions du répertoire de travail",
                "result": not writable_by_others,
                "details": f"Le répertoire de travail {'est' if writable_by_others else 'n\'est pas'} accessible en écriture par tous"
            })
            
            if writable_by_others:
                audit_results["vulnerabilities"].append({
                    "name": "insecure_working_directory",
                    "description": "Le répertoire de travail est accessible en écriture par tous",
                    "severity": "high",
                    "mitigation": "Modifier les permissions du répertoire pour restreindre l'accès"
                })
        except Exception as e:
            audit_results["security_checks"].append({
                "name": "working_directory_permissions",
                "description": "Vérification des permissions du répertoire de travail",
                "result": False,
                "details": f"Erreur lors de la vérification: {str(e)}"
            })
        
        # Vérification des variables d'environnement sensibles
        sensitive_vars = ["PATH", "TEMP", "TMP", "PYTHONPATH"]
        for var in sensitive_vars:
            if var in os.environ:
                value = os.environ[var]
                suspicious = False
                
                if var == "PATH":
                    paths = value.split(os.pathsep)
                    for path in paths:
                        if path == "." or path == "":
                            suspicious = True
                            break
                
                audit_results["security_checks"].append({
                    "name": f"env_var_{var.lower()}",
                    "description": f"Vérification de la variable d'environnement {var}",
                    "result": not suspicious,
                    "details": f"La variable {var} {'contient des valeurs suspectes' if suspicious else 'semble correcte'}"
                })
                
                if suspicious:
                    audit_results["vulnerabilities"].append({
                        "name": f"suspicious_env_var_{var.lower()}",
                        "description": f"La variable d'environnement {var} contient des valeurs suspectes",
                        "severity": "medium",
                        "mitigation": f"Vérifier et nettoyer la variable {var}"
                    })
        
        # Vérification des dépendances Python
        try:
            import pkg_resources
            
            for dist in pkg_resources.working_set:
                try:
                    version = dist.version
                    name = dist.project_name
                    
                    # Vérification des versions connues comme vulnérables (exemple)
                    vulnerable = False
                    vulnerability_details = ""
                    
                    if name == "cryptography" and version < "3.4":
                        vulnerable = True
                        vulnerability_details = "Versions < 3.4 vulnérables à CVE-2020-36242"
                    elif name == "requests" and version < "2.20.0":
                        vulnerable = True
                        vulnerability_details = "Versions < 2.20.0 vulnérables à CVE-2018-18074"
                    
                    if vulnerable:
                        audit_results["vulnerabilities"].append({
                            "name": f"vulnerable_dependency_{name}",
                            "description": f"Dépendance vulnérable: {name} {version}",
                            "severity": "high",
                            "details": vulnerability_details,
                            "mitigation": f"Mettre à jour {name} vers une version plus récente"
                        })
                except Exception:
                    pass
        except Exception:
            pass
        
        # Recommandations générales
        audit_results["recommendations"].extend([
            "Maintenir toutes les dépendances à jour",
            "Exécuter régulièrement des audits de sécurité",
            "Utiliser des mécanismes de vérification d'intégrité pour les fichiers critiques",
            "Implémenter une politique de moindre privilège"
        ])
        
        return audit_results

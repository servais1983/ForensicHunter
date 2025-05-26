#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'intégration avec VirusTotal pour l'analyse des artefacts.

Ce module fournit une interface avec l'API VirusTotal pour l'analyse
des fichiers, URLs, hashes et autres indicateurs de compromission.
"""

import os
import json
import time
import hashlib
import logging
import requests
from typing import Dict, List, Any, Optional, Union

from src.utils.security.security_manager import SecurityManager

logger = logging.getLogger("forensichunter")


class VirusTotalAnalyzer:
    """Interface avec VirusTotal pour l'analyse des artefacts."""

    def __init__(self, config):
        """
        Initialise l'analyseur VirusTotal.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.api_key = self._get_api_key()
        self.base_url = "https://www.virustotal.com/api/v3"
        self.security_manager = SecurityManager(config)
        
        # Vérification de la validité de l'API key
        self.api_valid = self._validate_api_key()
    
    def _get_api_key(self) -> str:
        """
        Récupère la clé API VirusTotal.
        
        Returns:
            Clé API VirusTotal
        """
        # Recherche dans la configuration
        api_key = self.config.get("virustotal", {}).get("api_key", "")
        
        # Recherche dans les variables d'environnement
        if not api_key:
            api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        
        return api_key
    
    def _validate_api_key(self) -> bool:
        """
        Valide la clé API VirusTotal.
        
        Returns:
            True si la clé est valide, False sinon
        """
        if not self.api_key:
            logger.warning("Clé API VirusTotal non configurée")
            return False
        
        try:
            # Tentative d'appel à l'API pour vérifier la validité de la clé
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(f"{self.base_url}/users/self", headers=headers)
            
            if response.status_code == 200:
                logger.info("Clé API VirusTotal validée avec succès")
                return True
            else:
                logger.warning(f"Clé API VirusTotal invalide: {response.status_code} - {response.text}")
                return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation de la clé API VirusTotal: {str(e)}")
            return False
    
    def analyze_file(self, file_path: str, wait_for_analysis: bool = False) -> Dict[str, Any]:
        """
        Analyse un fichier avec VirusTotal.
        
        Args:
            file_path: Chemin vers le fichier à analyser
            wait_for_analysis: Attendre la fin de l'analyse
            
        Returns:
            Résultats de l'analyse
        """
        if not self.api_valid:
            return {"error": "Clé API VirusTotal non valide"}
        
        if not os.path.isfile(file_path):
            return {"error": f"Fichier non trouvé: {file_path}"}
        
        # Vérification de la taille du fichier (limite VirusTotal: 32 MB)
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:
            return {"error": f"Fichier trop volumineux pour VirusTotal: {file_size} bytes (max: 32 MB)"}
        
        try:
            # Calcul du hash SHA-256 pour vérifier si le fichier a déjà été analysé
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            file_hash = sha256_hash.hexdigest()
            
            # Vérification si le fichier a déjà été analysé
            existing_report = self.get_file_report(file_hash)
            if "data" in existing_report:
                logger.info(f"Rapport existant trouvé pour le fichier {file_path}")
                return existing_report
            
            # Téléchargement du fichier sur VirusTotal
            logger.info(f"Téléchargement du fichier {file_path} sur VirusTotal")
            
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            files = {"file": (os.path.basename(file_path), open(file_path, "rb"))}
            response = requests.post(f"{self.base_url}/files", headers=headers, files=files)
            
            if response.status_code != 200:
                return {"error": f"Erreur lors du téléchargement du fichier: {response.status_code} - {response.text}"}
            
            # Récupération de l'ID d'analyse
            analysis_id = response.json().get("data", {}).get("id")
            
            if not analysis_id:
                return {"error": "Impossible de récupérer l'ID d'analyse"}
            
            # Attente de la fin de l'analyse si demandé
            if wait_for_analysis:
                return self._wait_for_analysis(analysis_id)
            else:
                # Sinon, retourner l'ID d'analyse
                return {
                    "status": "submitted",
                    "analysis_id": analysis_id,
                    "file_hash": file_hash
                }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du fichier {file_path}: {str(e)}")
            return {"error": str(e)}
    
    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Récupère le rapport d'analyse d'un fichier.
        
        Args:
            file_hash: Hash SHA-256, SHA-1 ou MD5 du fichier
            
        Returns:
            Rapport d'analyse
        """
        if not self.api_valid:
            return {"error": "Clé API VirusTotal non valide"}
        
        # Validation du hash
        if not self._validate_hash(file_hash):
            return {"error": f"Format de hash invalide: {file_hash}"}
        
        try:
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(f"{self.base_url}/files/{file_hash}", headers=headers)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": f"Fichier non trouvé sur VirusTotal: {file_hash}"}
            else:
                return {"error": f"Erreur lors de la récupération du rapport: {response.status_code} - {response.text}"}
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du rapport pour le hash {file_hash}: {str(e)}")
            return {"error": str(e)}
    
    def analyze_url(self, url: str, wait_for_analysis: bool = False) -> Dict[str, Any]:
        """
        Analyse une URL avec VirusTotal.
        
        Args:
            url: URL à analyser
            wait_for_analysis: Attendre la fin de l'analyse
            
        Returns:
            Résultats de l'analyse
        """
        if not self.api_valid:
            return {"error": "Clé API VirusTotal non valide"}
        
        # Validation de l'URL
        if not self.security_manager.validate_input(url, "url"):
            return {"error": f"Format d'URL invalide: {url}"}
        
        try:
            # Vérification si l'URL a déjà été analysée
            url_id = self._get_url_id(url)
            existing_report = self.get_url_report(url_id)
            
            if "data" in existing_report:
                logger.info(f"Rapport existant trouvé pour l'URL {url}")
                return existing_report
            
            # Soumission de l'URL pour analyse
            logger.info(f"Soumission de l'URL {url} pour analyse")
            
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            data = {"url": url}
            response = requests.post(f"{self.base_url}/urls", headers=headers, data=data)
            
            if response.status_code != 200:
                return {"error": f"Erreur lors de la soumission de l'URL: {response.status_code} - {response.text}"}
            
            # Récupération de l'ID d'analyse
            analysis_id = response.json().get("data", {}).get("id")
            
            if not analysis_id:
                return {"error": "Impossible de récupérer l'ID d'analyse"}
            
            # Attente de la fin de l'analyse si demandé
            if wait_for_analysis:
                return self._wait_for_analysis(analysis_id)
            else:
                # Sinon, retourner l'ID d'analyse
                return {
                    "status": "submitted",
                    "analysis_id": analysis_id,
                    "url": url,
                    "url_id": url_id
                }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de l'URL {url}: {str(e)}")
            return {"error": str(e)}
    
    def get_url_report(self, url_id: str) -> Dict[str, Any]:
        """
        Récupère le rapport d'analyse d'une URL.
        
        Args:
            url_id: Identifiant de l'URL (base64 de l'URL)
            
        Returns:
            Rapport d'analyse
        """
        if not self.api_valid:
            return {"error": "Clé API VirusTotal non valide"}
        
        try:
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(f"{self.base_url}/urls/{url_id}", headers=headers)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": f"URL non trouvée sur VirusTotal: {url_id}"}
            else:
                return {"error": f"Erreur lors de la récupération du rapport: {response.status_code} - {response.text}"}
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du rapport pour l'URL {url_id}: {str(e)}")
            return {"error": str(e)}
    
    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Analyse un domaine avec VirusTotal.
        
        Args:
            domain: Domaine à analyser
            
        Returns:
            Résultats de l'analyse
        """
        if not self.api_valid:
            return {"error": "Clé API VirusTotal non valide"}
        
        # Validation du domaine
        if not self._validate_domain(domain):
            return {"error": f"Format de domaine invalide: {domain}"}
        
        try:
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(f"{self.base_url}/domains/{domain}", headers=headers)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": f"Domaine non trouvé sur VirusTotal: {domain}"}
            else:
                return {"error": f"Erreur lors de l'analyse du domaine: {response.status_code} - {response.text}"}
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du domaine {domain}: {str(e)}")
            return {"error": str(e)}
    
    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Analyse une adresse IP avec VirusTotal.
        
        Args:
            ip_address: Adresse IP à analyser
            
        Returns:
            Résultats de l'analyse
        """
        if not self.api_valid:
            return {"error": "Clé API VirusTotal non valide"}
        
        # Validation de l'adresse IP
        if not self._validate_ip(ip_address):
            return {"error": f"Format d'adresse IP invalide: {ip_address}"}
        
        try:
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(f"{self.base_url}/ip_addresses/{ip_address}", headers=headers)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": f"Adresse IP non trouvée sur VirusTotal: {ip_address}"}
            else:
                return {"error": f"Erreur lors de l'analyse de l'adresse IP: {response.status_code} - {response.text}"}
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de l'adresse IP {ip_address}: {str(e)}")
            return {"error": str(e)}
    
    def get_analysis_status(self, analysis_id: str) -> Dict[str, Any]:
        """
        Récupère le statut d'une analyse en cours.
        
        Args:
            analysis_id: Identifiant de l'analyse
            
        Returns:
            Statut de l'analyse
        """
        if not self.api_valid:
            return {"error": "Clé API VirusTotal non valide"}
        
        try:
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(f"{self.base_url}/analyses/{analysis_id}", headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Erreur lors de la récupération du statut: {response.status_code} - {response.text}"}
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du statut pour l'analyse {analysis_id}: {str(e)}")
            return {"error": str(e)}
    
    def _wait_for_analysis(self, analysis_id: str, max_wait_time: int = 300) -> Dict[str, Any]:
        """
        Attend la fin d'une analyse.
        
        Args:
            analysis_id: Identifiant de l'analyse
            max_wait_time: Temps d'attente maximum en secondes
            
        Returns:
            Résultats de l'analyse
        """
        start_time = time.time()
        wait_interval = 5  # Intervalle d'attente en secondes
        
        while time.time() - start_time < max_wait_time:
            # Récupération du statut de l'analyse
            status = self.get_analysis_status(analysis_id)
            
            if "error" in status:
                return status
            
            # Vérification si l'analyse est terminée
            analysis_status = status.get("data", {}).get("attributes", {}).get("status")
            
            if analysis_status == "completed":
                return status
            
            # Attente avant la prochaine vérification
            time.sleep(wait_interval)
        
        return {"error": f"Délai d'attente dépassé pour l'analyse {analysis_id}"}
    
    def _get_url_id(self, url: str) -> str:
        """
        Génère l'identifiant VirusTotal pour une URL.
        
        Args:
            url: URL
            
        Returns:
            Identifiant de l'URL (base64 de l'URL)
        """
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    def _validate_hash(self, file_hash: str) -> bool:
        """
        Valide un hash.
        
        Args:
            file_hash: Hash à valider
            
        Returns:
            True si le hash est valide, False sinon
        """
        # Validation du format du hash (MD5, SHA-1, SHA-256)
        if len(file_hash) == 32:  # MD5
            return bool(re.match(r"^[a-fA-F0-9]{32}$", file_hash))
        elif len(file_hash) == 40:  # SHA-1
            return bool(re.match(r"^[a-fA-F0-9]{40}$", file_hash))
        elif len(file_hash) == 64:  # SHA-256
            return bool(re.match(r"^[a-fA-F0-9]{64}$", file_hash))
        else:
            return False
    
    def _validate_domain(self, domain: str) -> bool:
        """
        Valide un nom de domaine.
        
        Args:
            domain: Nom de domaine à valider
            
        Returns:
            True si le domaine est valide, False sinon
        """
        import re
        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.match(pattern, domain))
    
    def _validate_ip(self, ip_address: str) -> bool:
        """
        Valide une adresse IP.
        
        Args:
            ip_address: Adresse IP à valider
            
        Returns:
            True si l'adresse IP est valide, False sinon
        """
        import re
        # IPv4
        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        # IPv6
        ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)?[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}::$"
        
        return bool(re.match(ipv4_pattern, ip_address)) or bool(re.match(ipv6_pattern, ip_address))
    
    def is_available(self) -> bool:
        """
        Vérifie si l'API VirusTotal est disponible.
        
        Returns:
            True si l'API est disponible, False sinon
        """
        return self.api_valid
    
    def process_file_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Traite un rapport d'analyse de fichier pour en extraire les informations pertinentes.
        
        Args:
            report: Rapport d'analyse brut
            
        Returns:
            Rapport traité
        """
        if "error" in report:
            return report
        
        if "data" not in report:
            return {"error": "Format de rapport invalide"}
        
        try:
            attributes = report["data"]["attributes"]
            
            # Extraction des informations essentielles
            processed_report = {
                "scan_id": report["data"].get("id", ""),
                "scan_date": attributes.get("last_analysis_date", 0),
                "file_name": attributes.get("meaningful_name", ""),
                "file_size": attributes.get("size", 0),
                "file_type": attributes.get("type_description", ""),
                "md5": attributes.get("md5", ""),
                "sha1": attributes.get("sha1", ""),
                "sha256": attributes.get("sha256", ""),
                "detection_rate": {
                    "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                    "undetected": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                    "total": sum(attributes.get("last_analysis_stats", {}).values())
                },
                "detection_names": [],
                "tags": attributes.get("tags", []),
                "first_seen": attributes.get("first_submission_date", 0),
                "last_seen": attributes.get("last_analysis_date", 0),
                "reputation": attributes.get("reputation", 0),
                "threat_score": self._calculate_threat_score(attributes)
            }
            
            # Extraction des noms de détection
            for av, result in attributes.get("last_analysis_results", {}).items():
                if result.get("category") == "malicious" and result.get("result"):
                    processed_report["detection_names"].append({
                        "av": av,
                        "name": result.get("result", "")
                    })
            
            return processed_report
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement du rapport: {str(e)}")
            return {"error": f"Erreur lors du traitement du rapport: {str(e)}"}
    
    def _calculate_threat_score(self, attributes: Dict[str, Any]) -> int:
        """
        Calcule un score de menace basé sur les attributs du rapport.
        
        Args:
            attributes: Attributs du rapport
            
        Returns:
            Score de menace (0-100)
        """
        score = 0
        
        # Facteur 1: Taux de détection
        stats = attributes.get("last_analysis_stats", {})
        total = sum(stats.values()) or 1  # Éviter la division par zéro
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        detection_rate = (malicious + (suspicious * 0.5)) / total
        score += detection_rate * 60  # Max 60 points pour le taux de détection
        
        # Facteur 2: Tags
        tags = attributes.get("tags", [])
        dangerous_tags = ["trojan", "ransomware", "backdoor", "spyware", "keylogger", "rootkit", "exploit", "malware"]
        
        for tag in tags:
            if any(dt in tag.lower() for dt in dangerous_tags):
                score += 5  # +5 points par tag dangereux (max 20 points)
                if score > 80:
                    break
        
        # Facteur 3: Réputation
        reputation = attributes.get("reputation", 0)
        if reputation < 0:
            score += min(20, abs(reputation) / 100)  # Max 20 points pour une mauvaise réputation
        
        # Limitation du score à 100
        return min(100, int(score))

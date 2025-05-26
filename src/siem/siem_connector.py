#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'intégration SIEM pour ForensicHunter.

Ce module permet d'intégrer ForensicHunter avec les SIEM populaires
(Splunk, ELK, QRadar, etc.) pour une analyse centralisée des preuves.
"""

import os
import json
import logging
import datetime
import requests
import socket
import ssl
import time
from typing import Dict, List, Any, Optional, Union

from src.utils.security.security_manager import SecurityManager

logger = logging.getLogger("forensichunter")


class SIEMConnector:
    """Classe principale pour l'intégration avec les SIEM."""

    def __init__(self, config):
        """
        Initialise le connecteur SIEM.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.security_manager = SecurityManager(config)
        self.connectors = {
            "splunk": SplunkConnector(config),
            "elastic": ElasticConnector(config),
            "qradar": QRadarConnector(config),
            "sentinel": SentinelConnector(config),
            "arcsight": ArcSightConnector(config)
        }
    
    def send_data(self, siem_type: str, data: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Envoie des données à un SIEM spécifique.
        
        Args:
            siem_type: Type de SIEM (splunk, elastic, qradar, sentinel, arcsight)
            data: Données à envoyer
            options: Options d'envoi
            
        Returns:
            Résultat de l'envoi
        """
        # Validation du type de SIEM
        if siem_type not in self.connectors:
            logger.error(f"Type de SIEM non supporté: {siem_type}")
            return {"error": f"Type de SIEM non supporté: {siem_type}"}
        
        # Validation des options
        if not self._validate_options(options):
            logger.error("Options d'envoi SIEM invalides")
            return {"error": "Options d'envoi SIEM invalides"}
        
        # Validation des données
        if not self._validate_data(data):
            logger.error("Données SIEM invalides")
            return {"error": "Données SIEM invalides"}
        
        # Envoi des données au SIEM spécifié
        try:
            logger.info(f"Envoi des données au SIEM {siem_type}")
            results = self.connectors[siem_type].send_data(data, options)
            logger.info(f"Envoi des données au SIEM {siem_type} terminé")
            return results
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi des données au SIEM {siem_type}: {str(e)}")
            return {"error": str(e)}
    
    def _validate_options(self, options: Dict[str, Any]) -> bool:
        """
        Valide les options d'envoi SIEM.
        
        Args:
            options: Options à valider
            
        Returns:
            True si les options sont valides, False sinon
        """
        # Vérification des options requises
        required_options = ["host"]
        for option in required_options:
            if option not in options:
                logger.error(f"Option requise manquante: {option}")
                return False
        
        # Validation de l'hôte
        host = options["host"]
        if not self.security_manager.validate_input(host, "hostname"):
            logger.error(f"Hôte SIEM invalide: {host}")
            return False
        
        return True
    
    def _validate_data(self, data: Dict[str, Any]) -> bool:
        """
        Valide les données à envoyer au SIEM.
        
        Args:
            data: Données à valider
            
        Returns:
            True si les données sont valides, False sinon
        """
        # Vérification des données requises
        if not data:
            logger.error("Données SIEM vides")
            return False
        
        # Vérification de la taille des données
        data_size = len(json.dumps(data))
        max_size = 10 * 1024 * 1024  # 10 Mo
        if data_size > max_size:
            logger.error(f"Données SIEM trop volumineuses: {data_size} octets (max: {max_size} octets)")
            return False
        
        return True


class SplunkConnector:
    """Connecteur pour Splunk."""

    def __init__(self, config):
        """
        Initialise le connecteur Splunk.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.security_manager = SecurityManager(config)
    
    def send_data(self, data: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Envoie des données à Splunk.
        
        Args:
            data: Données à envoyer
            options: Options d'envoi
            
        Returns:
            Résultat de l'envoi
        """
        logger.info("Envoi des données à Splunk")
        
        # Vérification des informations d'authentification Splunk
        if not self._check_splunk_credentials(options):
            return {"error": "Informations d'authentification Splunk manquantes ou invalides"}
        
        # Préparation des données pour Splunk
        splunk_data = self._prepare_splunk_data(data)
        
        # Envoi des données à Splunk
        try:
            # Construction de l'URL
            host = options["host"]
            port = options.get("port", 8088)
            endpoint = options.get("endpoint", "/services/collector")
            use_ssl = options.get("use_ssl", True)
            
            protocol = "https" if use_ssl else "http"
            url = f"{protocol}://{host}:{port}{endpoint}"
            
            # Préparation des en-têtes
            headers = {
                "Authorization": f"Splunk {options['token']}",
                "Content-Type": "application/json"
            }
            
            # Envoi des données
            response = requests.post(url, headers=headers, json=splunk_data, verify=options.get("verify_ssl", True))
            
            # Vérification de la réponse
            if response.status_code == 200:
                logger.info("Données envoyées à Splunk avec succès")
                return {"status": "success", "message": "Données envoyées à Splunk avec succès"}
            else:
                logger.error(f"Erreur lors de l'envoi des données à Splunk: {response.status_code} - {response.text}")
                return {"error": f"Erreur lors de l'envoi des données à Splunk: {response.status_code} - {response.text}"}
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi des données à Splunk: {str(e)}")
            return {"error": str(e)}
    
    def _check_splunk_credentials(self, options: Dict[str, Any]) -> bool:
        """
        Vérifie les informations d'authentification Splunk.
        
        Args:
            options: Options d'envoi
            
        Returns:
            True si les informations d'authentification sont valides, False sinon
        """
        # Vérification des informations d'authentification
        if "token" not in options:
            logger.error("Token Splunk manquant")
            return False
        
        # Validation du token
        token = options["token"]
        if not token:
            logger.error("Token Splunk vide")
            return False
        
        return True
    
    def _prepare_splunk_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prépare les données pour Splunk.
        
        Args:
            data: Données à préparer
            
        Returns:
            Données préparées pour Splunk
        """
        # Ajout des métadonnées
        splunk_data = {
            "event": data,
            "time": int(time.time()),
            "source": "forensichunter",
            "sourcetype": "forensichunter:evidence",
            "index": "forensic"
        }
        
        return splunk_data


class ElasticConnector:
    """Connecteur pour Elasticsearch."""

    def __init__(self, config):
        """
        Initialise le connecteur Elasticsearch.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.security_manager = SecurityManager(config)
    
    def send_data(self, data: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Envoie des données à Elasticsearch.
        
        Args:
            data: Données à envoyer
            options: Options d'envoi
            
        Returns:
            Résultat de l'envoi
        """
        logger.info("Envoi des données à Elasticsearch")
        
        # Vérification des informations d'authentification Elasticsearch
        if not self._check_elastic_credentials(options):
            return {"error": "Informations d'authentification Elasticsearch manquantes ou invalides"}
        
        # Préparation des données pour Elasticsearch
        elastic_data = self._prepare_elastic_data(data)
        
        # Envoi des données à Elasticsearch
        try:
            # Construction de l'URL
            host = options["host"]
            port = options.get("port", 9200)
            index = options.get("index", "forensichunter")
            use_ssl = options.get("use_ssl", True)
            
            protocol = "https" if use_ssl else "http"
            url = f"{protocol}://{host}:{port}/{index}/_doc"
            
            # Préparation des en-têtes
            headers = {
                "Content-Type": "application/json"
            }
            
            # Ajout de l'authentification si nécessaire
            auth = None
            if "username" in options and "password" in options:
                auth = (options["username"], options["password"])
            
            # Envoi des données
            response = requests.post(url, headers=headers, json=elastic_data, auth=auth, verify=options.get("verify_ssl", True))
            
            # Vérification de la réponse
            if response.status_code in [200, 201]:
                logger.info("Données envoyées à Elasticsearch avec succès")
                return {"status": "success", "message": "Données envoyées à Elasticsearch avec succès"}
            else:
                logger.error(f"Erreur lors de l'envoi des données à Elasticsearch: {response.status_code} - {response.text}")
                return {"error": f"Erreur lors de l'envoi des données à Elasticsearch: {response.status_code} - {response.text}"}
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi des données à Elasticsearch: {str(e)}")
            return {"error": str(e)}
    
    def _check_elastic_credentials(self, options: Dict[str, Any]) -> bool:
        """
        Vérifie les informations d'authentification Elasticsearch.
        
        Args:
            options: Options d'envoi
            
        Returns:
            True si les informations d'authentification sont valides, False sinon
        """
        # Vérification des informations d'authentification
        if "username" in options and "password" in options:
            # Validation des informations d'authentification
            username = options["username"]
            password = options["password"]
            
            if not username or not password:
                logger.error("Informations d'authentification Elasticsearch vides")
                return False
        
        return True
    
    def _prepare_elastic_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prépare les données pour Elasticsearch.
        
        Args:
            data: Données à préparer
            
        Returns:
            Données préparées pour Elasticsearch
        """
        # Ajout des métadonnées
        elastic_data = data.copy()
        elastic_data["@timestamp"] = datetime.datetime.now().isoformat()
        elastic_data["source"] = "forensichunter"
        elastic_data["type"] = "evidence"
        
        return elastic_data


class QRadarConnector:
    """Connecteur pour IBM QRadar."""

    def __init__(self, config):
        """
        Initialise le connecteur QRadar.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.security_manager = SecurityManager(config)
    
    def send_data(self, data: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Envoie des données à QRadar.
        
        Args:
            data: Données à envoyer
            options: Options d'envoi
            
        Returns:
            Résultat de l'envoi
        """
        logger.info("Envoi des données à QRadar")
        
        # Vérification des informations d'authentification QRadar
        if not self._check_qradar_credentials(options):
            return {"error": "Informations d'authentification QRadar manquantes ou invalides"}
        
        # Préparation des données pour QRadar
        qradar_data = self._prepare_qradar_data(data)
        
        # Envoi des données à QRadar
        try:
            # Construction de l'URL
            host = options["host"]
            port = options.get("port", 443)
            endpoint = options.get("endpoint", "/api/ariel/queries")
            use_ssl = options.get("use_ssl", True)
            
            protocol = "https" if use_ssl else "http"
            url = f"{protocol}://{host}:{port}{endpoint}"
            
            # Préparation des en-têtes
            headers = {
                "SEC": options["token"],
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            # Envoi des données
            response = requests.post(url, headers=headers, json=qradar_data, verify=options.get("verify_ssl", True))
            
            # Vérification de la réponse
            if response.status_code in [200, 201]:
                logger.info("Données envoyées à QRadar avec succès")
                return {"status": "success", "message": "Données envoyées à QRadar avec succès"}
            else:
                logger.error(f"Erreur lors de l'envoi des données à QRadar: {response.status_code} - {response.text}")
                return {"error": f"Erreur lors de l'envoi des données à QRadar: {response.status_code} - {response.text}"}
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi des données à QRadar: {str(e)}")
            return {"error": str(e)}
    
    def _check_qradar_credentials(self, options: Dict[str, Any]) -> bool:
        """
        Vérifie les informations d'authentification QRadar.
        
        Args:
            options: Options d'envoi
            
        Returns:
            True si les informations d'authentification sont valides, False sinon
        """
        # Vérification des informations d'authentification
        if "token" not in options:
            logger.error("Token QRadar manquant")
            return False
        
        # Validation du token
        token = options["token"]
        if not token:
            logger.error("Token QRadar vide")
            return False
        
        return True
    
    def _prepare_qradar_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prépare les données pour QRadar.
        
        Args:
            data: Données à préparer
            
        Returns:
            Données préparées pour QRadar
        """
        # Ajout des métadonnées
        qradar_data = {
            "query_expression": json.dumps(data),
            "query_name": f"ForensicHunter_{int(time.time())}",
            "query_type": "FORENSIC"
        }
        
        return qradar_data


class SentinelConnector:
    """Connecteur pour Microsoft Sentinel."""

    def __init__(self, config):
        """
        Initialise le connecteur Sentinel.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.security_manager = SecurityManager(config)
    
    def send_data(self, data: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Envoie des données à Microsoft Sentinel.
        
        Args:
            data: Données à envoyer
            options: Options d'envoi
            
        Returns:
            Résultat de l'envoi
        """
        logger.info("Envoi des données à Microsoft Sentinel")
        
        # Vérification des informations d'authentification Sentinel
        if not self._check_sentinel_credentials(options):
            return {"error": "Informations d'authentification Microsoft Sentinel manquantes ou invalides"}
        
        # Préparation des données pour Sentinel
        sentinel_data = self._prepare_sentinel_data(data)
        
        # Envoi des données à Sentinel
        try:
            # Construction de l'URL
            workspace_id = options["workspace_id"]
            log_type = options.get("log_type", "ForensicHunter")
            url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            
            # Préparation des en-têtes
            shared_key = options["shared_key"]
            date_rfc1123 = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            content_length = len(json.dumps(sentinel_data))
            
            # Génération de la signature
            signature = self._build_signature(workspace_id, shared_key, date_rfc1123, content_length, "POST", "application/json", "/api/logs")
            
            headers = {
                "Content-Type": "application/json",
                "Log-Type": log_type,
                "Authorization": f"SharedKey {workspace_id}:{signature}",
                "x-ms-date": date_rfc1123
            }
            
            # Envoi des données
            response = requests.post(url, headers=headers, json=sentinel_data, verify=options.get("verify_ssl", True))
            
            # Vérification de la réponse
            if response.status_code in [200, 201]:
                logger.info("Données envoyées à Microsoft Sentinel avec succès")
                return {"status": "success", "message": "Données envoyées à Microsoft Sentinel avec succès"}
            else:
                logger.error(f"Erreur lors de l'envoi des données à Microsoft Sentinel: {response.status_code} - {response.text}")
                return {"error": f"Erreur lors de l'envoi des données à Microsoft Sentinel: {response.status_code} - {response.text}"}
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi des données à Microsoft Sentinel: {str(e)}")
            return {"error": str(e)}
    
    def _check_sentinel_credentials(self, options: Dict[str, Any]) -> bool:
        """
        Vérifie les informations d'authentification Microsoft Sentinel.
        
        Args:
            options: Options d'envoi
            
        Returns:
            True si les informations d'authentification sont valides, False sinon
        """
        # Vérification des informations d'authentification
        if "workspace_id" not in options or "shared_key" not in options:
            logger.error("Informations d'authentification Microsoft Sentinel manquantes")
            return False
        
        # Validation des informations d'authentification
        workspace_id = options["workspace_id"]
        shared_key = options["shared_key"]
        
        if not workspace_id or not shared_key:
            logger.error("Informations d'authentification Microsoft Sentinel vides")
            return False
        
        return True
    
    def _prepare_sentinel_data(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Prépare les données pour Microsoft Sentinel.
        
        Args:
            data: Données à préparer
            
        Returns:
            Données préparées pour Microsoft Sentinel
        """
        # Ajout des métadonnées
        sentinel_data = data.copy()
        sentinel_data["TimeGenerated"] = datetime.datetime.now().isoformat()
        sentinel_data["Source"] = "ForensicHunter"
        sentinel_data["Type"] = "Evidence"
        
        # Sentinel attend un tableau d'objets
        return [sentinel_data]
    
    def _build_signature(self, workspace_id: str, shared_key: str, date: str, content_length: int, method: str, content_type: str, resource: str) -> str:
        """
        Génère la signature pour l'authentification Microsoft Sentinel.
        
        Args:
            workspace_id: ID de l'espace de travail
            shared_key: Clé partagée
            date: Date au format RFC1123
            content_length: Longueur du contenu
            method: Méthode HTTP
            content_type: Type de contenu
            resource: Ressource
            
        Returns:
            Signature générée
        """
        import base64
        import hmac
        import hashlib
        
        x_headers = f"x-ms-date:{date}"
        string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        bytes_to_hash = string_to_hash.encode('utf-8')
        decoded_key = base64.b64decode(shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode('utf-8')
        
        return encoded_hash


class ArcSightConnector:
    """Connecteur pour HP ArcSight."""

    def __init__(self, config):
        """
        Initialise le connecteur ArcSight.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.security_manager = SecurityManager(config)
    
    def send_data(self, data: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Envoie des données à ArcSight.
        
        Args:
            data: Données à envoyer
            options: Options d'envoi
            
        Returns:
            Résultat de l'envoi
        """
        logger.info("Envoi des données à ArcSight")
        
        # Vérification des informations d'authentification ArcSight
        if not self._check_arcsight_credentials(options):
            return {"error": "Informations d'authentification ArcSight manquantes ou invalides"}
        
        # Préparation des données pour ArcSight
        arcsight_data = self._prepare_arcsight_data(data)
        
        # Envoi des données à ArcSight via syslog
        try:
            # Récupération des options
            host = options["host"]
            port = options.get("port", 514)
            use_tcp = options.get("use_tcp", True)
            use_ssl = options.get("use_ssl", False)
            
            # Conversion des données en format CEF
            cef_data = self._convert_to_cef(arcsight_data)
            
            # Envoi des données via syslog
            if use_tcp:
                # Utilisation de TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                if use_ssl:
                    # Utilisation de SSL/TLS
                    context = ssl.create_default_context()
                    if not options.get("verify_ssl", True):
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    
                    sock = context.wrap_socket(sock, server_hostname=host)
                
                sock.connect((host, port))
                sock.sendall(cef_data.encode('utf-8'))
                sock.close()
            else:
                # Utilisation de UDP
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(cef_data.encode('utf-8'), (host, port))
                sock.close()
            
            logger.info("Données envoyées à ArcSight avec succès")
            return {"status": "success", "message": "Données envoyées à ArcSight avec succès"}
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi des données à ArcSight: {str(e)}")
            return {"error": str(e)}
    
    def _check_arcsight_credentials(self, options: Dict[str, Any]) -> bool:
        """
        Vérifie les informations d'authentification ArcSight.
        
        Args:
            options: Options d'envoi
            
        Returns:
            True si les informations d'authentification sont valides, False sinon
        """
        # ArcSight n'a pas besoin d'informations d'authentification spécifiques
        # pour l'envoi via syslog, mais on vérifie quand même les options requises
        if "host" not in options:
            logger.error("Hôte ArcSight manquant")
            return False
        
        return True
    
    def _prepare_arcsight_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prépare les données pour ArcSight.
        
        Args:
            data: Données à préparer
            
        Returns:
            Données préparées pour ArcSight
        """
        # Ajout des métadonnées
        arcsight_data = data.copy()
        arcsight_data["timestamp"] = int(time.time() * 1000)  # Millisecondes
        arcsight_data["source"] = "ForensicHunter"
        arcsight_data["type"] = "Evidence"
        
        return arcsight_data
    
    def _convert_to_cef(self, data: Dict[str, Any]) -> str:
        """
        Convertit les données au format CEF (Common Event Format) pour ArcSight.
        
        Args:
            data: Données à convertir
            
        Returns:
            Données au format CEF
        """
        # Format CEF: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        
        # En-tête CEF
        cef_header = f"CEF:0|ForensicHunter|ForensicHunter|1.0|{data.get('id', '1000')}|{data.get('name', 'Evidence Collection')}|{data.get('severity', '5')}|"
        
        # Extension CEF
        cef_extension = ""
        for key, value in data.items():
            if key not in ["id", "name", "severity"]:
                # Échappement des caractères spéciaux
                if isinstance(value, str):
                    value = value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")
                
                cef_extension += f"{key}={value} "
        
        # Message CEF complet
        cef_message = f"{cef_header}{cef_extension}"
        
        return cef_message

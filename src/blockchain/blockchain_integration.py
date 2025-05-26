#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'intégration blockchain pour ForensicHunter (Phase 3).

Ce module permet de stocker de manière immuable les preuves et les hashes
dans une blockchain pour garantir l'intégrité et la traçabilité des preuves.
"""

import os
import json
import logging
import datetime
import hashlib
import time
import uuid
from typing import Dict, List, Any, Optional, Union

from src.utils.security.security_manager import SecurityManager
from src.utils.integrity.hash_calculator import HashCalculator

logger = logging.getLogger("forensichunter")


class BlockchainIntegration:
    """Classe principale pour l'intégration blockchain."""

    def __init__(self, config):
        """
        Initialise l'intégration blockchain.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.security_manager = SecurityManager(config)
        self.hash_calculator = HashCalculator(config)
        self.blockchain_type = config.get("blockchain", {}).get("type", "local")
        self.blockchain = self._initialize_blockchain()
    
    def _initialize_blockchain(self) -> Dict[str, Any]:
        """
        Initialise la blockchain selon le type configuré.
        
        Returns:
            Instance de blockchain
        """
        logger.info(f"Initialisation de la blockchain de type {self.blockchain_type}")
        
        if self.blockchain_type == "ethereum":
            return self._initialize_ethereum_blockchain()
        elif self.blockchain_type == "hyperledger":
            return self._initialize_hyperledger_blockchain()
        else:
            # Par défaut, blockchain locale
            return self._initialize_local_blockchain()
    
    def _initialize_ethereum_blockchain(self) -> Dict[str, Any]:
        """
        Initialise une connexion à la blockchain Ethereum.
        
        Returns:
            Instance de blockchain Ethereum
        """
        logger.info("Initialisation de la blockchain Ethereum")
        
        # Simulation d'initialisation Ethereum
        # Dans une implémentation réelle, on utiliserait web3.py
        
        ethereum_config = self.config.get("blockchain", {}).get("ethereum", {})
        provider_url = ethereum_config.get("provider_url", "http://localhost:8545")
        contract_address = ethereum_config.get("contract_address", "0x0000000000000000000000000000000000000000")
        
        return {
            "type": "ethereum",
            "provider_url": provider_url,
            "contract_address": contract_address,
            "initialized": True
        }
    
    def _initialize_hyperledger_blockchain(self) -> Dict[str, Any]:
        """
        Initialise une connexion à Hyperledger Fabric.
        
        Returns:
            Instance de blockchain Hyperledger
        """
        logger.info("Initialisation de la blockchain Hyperledger Fabric")
        
        # Simulation d'initialisation Hyperledger
        # Dans une implémentation réelle, on utiliserait le SDK Hyperledger Fabric
        
        hyperledger_config = self.config.get("blockchain", {}).get("hyperledger", {})
        network_profile = hyperledger_config.get("network_profile", "connection.json")
        channel_name = hyperledger_config.get("channel_name", "mychannel")
        chaincode_id = hyperledger_config.get("chaincode_id", "forensic-chaincode")
        
        return {
            "type": "hyperledger",
            "network_profile": network_profile,
            "channel_name": channel_name,
            "chaincode_id": chaincode_id,
            "initialized": True
        }
    
    def _initialize_local_blockchain(self) -> Dict[str, Any]:
        """
        Initialise une blockchain locale (simulée).
        
        Returns:
            Instance de blockchain locale
        """
        logger.info("Initialisation de la blockchain locale")
        
        # Création du répertoire de stockage
        blockchain_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "blockchain")
        os.makedirs(blockchain_dir, exist_ok=True)
        
        # Fichier de la blockchain
        blockchain_file = os.path.join(blockchain_dir, "blockchain.json")
        
        # Vérification si la blockchain existe déjà
        if os.path.exists(blockchain_file):
            try:
                with open(blockchain_file, "r") as f:
                    blockchain_data = json.load(f)
                logger.info(f"Blockchain locale chargée: {len(blockchain_data['blocks'])} blocs")
            except Exception as e:
                logger.error(f"Erreur lors du chargement de la blockchain locale: {str(e)}")
                blockchain_data = self._create_new_blockchain()
        else:
            # Création d'une nouvelle blockchain
            blockchain_data = self._create_new_blockchain()
            self._save_blockchain(blockchain_data, blockchain_file)
        
        return {
            "type": "local",
            "file": blockchain_file,
            "data": blockchain_data,
            "initialized": True
        }
    
    def _create_new_blockchain(self) -> Dict[str, Any]:
        """
        Crée une nouvelle blockchain locale.
        
        Returns:
            Données de la blockchain
        """
        logger.info("Création d'une nouvelle blockchain locale")
        
        # Bloc genesis
        genesis_block = {
            "index": 0,
            "timestamp": datetime.datetime.now().isoformat(),
            "data": {
                "message": "Bloc genesis ForensicHunter"
            },
            "previous_hash": "0",
            "hash": self._calculate_block_hash({
                "index": 0,
                "timestamp": datetime.datetime.now().isoformat(),
                "data": {
                    "message": "Bloc genesis ForensicHunter"
                },
                "previous_hash": "0"
            })
        }
        
        # Blockchain
        blockchain_data = {
            "name": "ForensicHunter Blockchain",
            "created_at": datetime.datetime.now().isoformat(),
            "blocks": [genesis_block]
        }
        
        return blockchain_data
    
    def _save_blockchain(self, blockchain_data: Dict[str, Any], blockchain_file: str):
        """
        Sauvegarde la blockchain locale.
        
        Args:
            blockchain_data: Données de la blockchain
            blockchain_file: Chemin du fichier de la blockchain
        """
        try:
            with open(blockchain_file, "w") as f:
                json.dump(blockchain_data, f, indent=2)
            logger.info(f"Blockchain locale sauvegardée: {blockchain_file}")
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la blockchain locale: {str(e)}")
    
    def _calculate_block_hash(self, block: Dict[str, Any]) -> str:
        """
        Calcule le hash d'un bloc.
        
        Args:
            block: Bloc à hasher
            
        Returns:
            Hash du bloc
        """
        # Conversion du bloc en chaîne JSON
        block_string = json.dumps(block, sort_keys=True)
        
        # Calcul du hash SHA-256
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def store_evidence(self, evidence_id: str, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stocke une preuve dans la blockchain.
        
        Args:
            evidence_id: Identifiant de la preuve
            evidence_data: Données de la preuve
            
        Returns:
            Résultat du stockage
        """
        logger.info(f"Stockage de la preuve {evidence_id} dans la blockchain")
        
        # Validation des données
        if not evidence_data:
            error_msg = "Données de preuve vides"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Calcul du hash de la preuve
        evidence_hash = self.hash_calculator.calculate_hash(evidence_data)
        
        # Préparation des données à stocker
        blockchain_data = {
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "timestamp": datetime.datetime.now().isoformat(),
            "metadata": {
                "type": evidence_data.get("type", "unknown"),
                "source": evidence_data.get("source", "unknown"),
                "collector": evidence_data.get("collector", "unknown")
            }
        }
        
        # Stockage dans la blockchain selon le type
        if self.blockchain["type"] == "ethereum":
            return self._store_in_ethereum(evidence_id, blockchain_data)
        elif self.blockchain["type"] == "hyperledger":
            return self._store_in_hyperledger(evidence_id, blockchain_data)
        else:
            # Blockchain locale
            return self._store_in_local_blockchain(evidence_id, blockchain_data)
    
    def _store_in_ethereum(self, evidence_id: str, blockchain_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stocke des données dans la blockchain Ethereum.
        
        Args:
            evidence_id: Identifiant de la preuve
            blockchain_data: Données à stocker
            
        Returns:
            Résultat du stockage
        """
        logger.info(f"Stockage de la preuve {evidence_id} dans Ethereum")
        
        # Simulation de stockage Ethereum
        # Dans une implémentation réelle, on utiliserait web3.py
        
        try:
            # Simulation de transaction
            transaction_hash = f"0x{uuid.uuid4().hex}"
            
            return {
                "status": "success",
                "blockchain": "ethereum",
                "transaction_hash": transaction_hash,
                "block_number": int(time.time()),
                "timestamp": datetime.datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Erreur lors du stockage dans Ethereum: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def _store_in_hyperledger(self, evidence_id: str, blockchain_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stocke des données dans Hyperledger Fabric.
        
        Args:
            evidence_id: Identifiant de la preuve
            blockchain_data: Données à stocker
            
        Returns:
            Résultat du stockage
        """
        logger.info(f"Stockage de la preuve {evidence_id} dans Hyperledger Fabric")
        
        # Simulation de stockage Hyperledger
        # Dans une implémentation réelle, on utiliserait le SDK Hyperledger Fabric
        
        try:
            # Simulation de transaction
            transaction_id = str(uuid.uuid4())
            
            return {
                "status": "success",
                "blockchain": "hyperledger",
                "transaction_id": transaction_id,
                "channel": self.blockchain["channel_name"],
                "chaincode": self.blockchain["chaincode_id"],
                "timestamp": datetime.datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Erreur lors du stockage dans Hyperledger: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def _store_in_local_blockchain(self, evidence_id: str, blockchain_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stocke des données dans la blockchain locale.
        
        Args:
            evidence_id: Identifiant de la preuve
            blockchain_data: Données à stocker
            
        Returns:
            Résultat du stockage
        """
        logger.info(f"Stockage de la preuve {evidence_id} dans la blockchain locale")
        
        try:
            # Récupération de la blockchain
            blockchain_data_local = self.blockchain["data"]
            blocks = blockchain_data_local["blocks"]
            
            # Récupération du dernier bloc
            last_block = blocks[-1]
            
            # Création du nouveau bloc
            new_block = {
                "index": last_block["index"] + 1,
                "timestamp": datetime.datetime.now().isoformat(),
                "data": blockchain_data,
                "previous_hash": last_block["hash"]
            }
            
            # Calcul du hash du nouveau bloc
            new_block["hash"] = self._calculate_block_hash(new_block)
            
            # Ajout du bloc à la blockchain
            blocks.append(new_block)
            
            # Sauvegarde de la blockchain
            self._save_blockchain(blockchain_data_local, self.blockchain["file"])
            
            return {
                "status": "success",
                "blockchain": "local",
                "block_index": new_block["index"],
                "block_hash": new_block["hash"],
                "timestamp": new_block["timestamp"]
            }
            
        except Exception as e:
            error_msg = f"Erreur lors du stockage dans la blockchain locale: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def verify_evidence(self, evidence_id: str, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Vérifie l'intégrité d'une preuve par rapport à la blockchain.
        
        Args:
            evidence_id: Identifiant de la preuve
            evidence_data: Données de la preuve
            
        Returns:
            Résultat de la vérification
        """
        logger.info(f"Vérification de la preuve {evidence_id} dans la blockchain")
        
        # Calcul du hash de la preuve
        evidence_hash = self.hash_calculator.calculate_hash(evidence_data)
        
        # Vérification selon le type de blockchain
        if self.blockchain["type"] == "ethereum":
            return self._verify_in_ethereum(evidence_id, evidence_hash)
        elif self.blockchain["type"] == "hyperledger":
            return self._verify_in_hyperledger(evidence_id, evidence_hash)
        else:
            # Blockchain locale
            return self._verify_in_local_blockchain(evidence_id, evidence_hash)
    
    def _verify_in_ethereum(self, evidence_id: str, evidence_hash: str) -> Dict[str, Any]:
        """
        Vérifie une preuve dans la blockchain Ethereum.
        
        Args:
            evidence_id: Identifiant de la preuve
            evidence_hash: Hash de la preuve
            
        Returns:
            Résultat de la vérification
        """
        logger.info(f"Vérification de la preuve {evidence_id} dans Ethereum")
        
        # Simulation de vérification Ethereum
        # Dans une implémentation réelle, on utiliserait web3.py
        
        try:
            # Simulation de vérification
            # Ici, on simule une vérification réussie
            is_valid = True
            
            return {
                "status": "success",
                "blockchain": "ethereum",
                "verified": is_valid,
                "timestamp": datetime.datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Erreur lors de la vérification dans Ethereum: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def _verify_in_hyperledger(self, evidence_id: str, evidence_hash: str) -> Dict[str, Any]:
        """
        Vérifie une preuve dans Hyperledger Fabric.
        
        Args:
            evidence_id: Identifiant de la preuve
            evidence_hash: Hash de la preuve
            
        Returns:
            Résultat de la vérification
        """
        logger.info(f"Vérification de la preuve {evidence_id} dans Hyperledger Fabric")
        
        # Simulation de vérification Hyperledger
        # Dans une implémentation réelle, on utiliserait le SDK Hyperledger Fabric
        
        try:
            # Simulation de vérification
            # Ici, on simule une vérification réussie
            is_valid = True
            
            return {
                "status": "success",
                "blockchain": "hyperledger",
                "verified": is_valid,
                "timestamp": datetime.datetime.now().isoformat()
            }
            
        except Exception as e:
            error_msg = f"Erreur lors de la vérification dans Hyperledger: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def _verify_in_local_blockchain(self, evidence_id: str, evidence_hash: str) -> Dict[str, Any]:
        """
        Vérifie une preuve dans la blockchain locale.
        
        Args:
            evidence_id: Identifiant de la preuve
            evidence_hash: Hash de la preuve
            
        Returns:
            Résultat de la vérification
        """
        logger.info(f"Vérification de la preuve {evidence_id} dans la blockchain locale")
        
        try:
            # Récupération de la blockchain
            blockchain_data_local = self.blockchain["data"]
            blocks = blockchain_data_local["blocks"]
            
            # Recherche du bloc contenant la preuve
            found_block = None
            for block in blocks:
                if block["index"] > 0:  # Ignorer le bloc genesis
                    block_data = block["data"]
                    if block_data.get("evidence_id") == evidence_id:
                        found_block = block
                        break
            
            if found_block is None:
                return {
                    "status": "error",
                    "blockchain": "local",
                    "verified": False,
                    "reason": "Preuve non trouvée dans la blockchain",
                    "timestamp": datetime.datetime.now().isoformat()
                }
            
            # Vérification du hash
            stored_hash = found_block["data"].get("evidence_hash")
            is_valid = stored_hash == evidence_hash
            
            return {
                "status": "success",
                "blockchain": "local",
                "verified": is_valid,
                "block_index": found_block["index"],
                "block_hash": found_block["hash"],
                "timestamp": datetime.datetime.now().isoformat(),
                "reason": None if is_valid else "Hash de preuve différent"
            }
            
        except Exception as e:
            error_msg = f"Erreur lors de la vérification dans la blockchain locale: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def get_evidence_history(self, evidence_id: str) -> Dict[str, Any]:
        """
        Récupère l'historique d'une preuve dans la blockchain.
        
        Args:
            evidence_id: Identifiant de la preuve
            
        Returns:
            Historique de la preuve
        """
        logger.info(f"Récupération de l'historique de la preuve {evidence_id}")
        
        # Récupération selon le type de blockchain
        if self.blockchain["type"] == "ethereum":
            return self._get_history_from_ethereum(evidence_id)
        elif self.blockchain["type"] == "hyperledger":
            return self._get_history_from_hyperledger(evidence_id)
        else:
            # Blockchain locale
            return self._get_history_from_local_blockchain(evidence_id)
    
    def _get_history_from_ethereum(self, evidence_id: str) -> Dict[str, Any]:
        """
        Récupère l'historique d'une preuve dans Ethereum.
        
        Args:
            evidence_id: Identifiant de la preuve
            
        Returns:
            Historique de la preuve
        """
        logger.info(f"Récupération de l'historique de la preuve {evidence_id} dans Ethereum")
        
        # Simulation de récupération Ethereum
        # Dans une implémentation réelle, on utiliserait web3.py
        
        try:
            # Simulation d'historique
            history = [
                {
                    "transaction_hash": f"0x{uuid.uuid4().hex}",
                    "block_number": int(time.time()) - 3600,
                    "timestamp": (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat(),
                    "action": "create"
                },
                {
                    "transaction_hash": f"0x{uuid.uuid4().hex}",
                    "block_number": int(time.time()),
                    "timestamp": datetime.datetime.now().isoformat(),
                    "action": "update"
                }
            ]
            
            return {
                "status": "success",
                "blockchain": "ethereum",
                "evidence_id": evidence_id,
                "history": history
            }
            
        except Exception as e:
            error_msg = f"Erreur lors de la récupération de l'historique dans Ethereum: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def _get_history_from_hyperledger(self, evidence_id: str) -> Dict[str, Any]:
        """
        Récupère l'historique d'une preuve dans Hyperledger Fabric.
        
        Args:
            evidence_id: Identifiant de la preuve
            
        Returns:
            Historique de la preuve
        """
        logger.info(f"Récupération de l'historique de la preuve {evidence_id} dans Hyperledger Fabric")
        
        # Simulation de récupération Hyperledger
        # Dans une implémentation réelle, on utiliserait le SDK Hyperledger Fabric
        
        try:
            # Simulation d'historique
            history = [
                {
                    "transaction_id": str(uuid.uuid4()),
                    "timestamp": (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat(),
                    "action": "create"
                },
                {
                    "transaction_id": str(uuid.uuid4()),
                    "timestamp": datetime.datetime.now().isoformat(),
                    "action": "update"
                }
            ]
            
            return {
                "status": "success",
                "blockchain": "hyperledger",
                "evidence_id": evidence_id,
                "history": history
            }
            
        except Exception as e:
            error_msg = f"Erreur lors de la récupération de l'historique dans Hyperledger: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
    
    def _get_history_from_local_blockchain(self, evidence_id: str) -> Dict[str, Any]:
        """
        Récupère l'historique d'une preuve dans la blockchain locale.
        
        Args:
            evidence_id: Identifiant de la preuve
            
        Returns:
            Historique de la preuve
        """
        logger.info(f"Récupération de l'historique de la preuve {evidence_id} dans la blockchain locale")
        
        try:
            # Récupération de la blockchain
            blockchain_data_local = self.blockchain["data"]
            blocks = blockchain_data_local["blocks"]
            
            # Recherche des blocs contenant la preuve
            history = []
            for block in blocks:
                if block["index"] > 0:  # Ignorer le bloc genesis
                    block_data = block["data"]
                    if block_data.get("evidence_id") == evidence_id:
                        history_entry = {
                            "block_index": block["index"],
                            "block_hash": block["hash"],
                            "timestamp": block["timestamp"],
                            "evidence_hash": block_data.get("evidence_hash")
                        }
                        history.append(history_entry)
            
            return {
                "status": "success",
                "blockchain": "local",
                "evidence_id": evidence_id,
                "history": history
            }
            
        except Exception as e:
            error_msg = f"Erreur lors de la récupération de l'historique dans la blockchain locale: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}

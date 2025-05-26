#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des processus en cours et connexions réseau actives.

Ce module est responsable de la collecte des informations sur les processus
en cours d'exécution et les connexions réseau actives pour analyse forensique.
"""

import os
import logging
import datetime
import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Optional

import psutil

logger = logging.getLogger("forensichunter")


class ProcessCollector:
    """Collecteur d'informations sur les processus en cours d'exécution."""

    def __init__(self, config):
        """
        Initialise le collecteur de processus.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "processes")
        self.image_path = None
        
        # Création du répertoire de sortie
        os.makedirs(self.output_dir, exist_ok=True)
    
    def set_image_path(self, image_path: str):
        """
        Configure le chemin vers l'image disque à analyser.
        
        Args:
            image_path: Chemin vers l'image disque
        """
        self.image_path = image_path
        logger.warning("L'analyse des processus à partir d'une image disque n'est pas supportée.")
    
    def _collect_process_info(self) -> List[Dict[str, Any]]:
        """
        Collecte les informations sur les processus en cours d'exécution.
        
        Returns:
            Liste des processus avec leurs informations détaillées
        """
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'exe', 'cwd', 'status', 'create_time', 'cpu_percent', 'memory_percent']):
                try:
                    process_info = proc.info
                    
                    # Ajout d'informations supplémentaires
                    try:
                        process_info['parent'] = proc.parent().pid if proc.parent() else None
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_info['parent'] = None
                    
                    # Conversion de la date de création en format lisible
                    if process_info.get('create_time'):
                        process_info['create_time'] = datetime.datetime.fromtimestamp(
                            process_info['create_time']
                        ).isoformat()
                    
                    # Collecte des fichiers ouverts
                    try:
                        open_files = []
                        for file in proc.open_files():
                            open_files.append(file.path)
                        process_info['open_files'] = open_files
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_info['open_files'] = []
                    
                    # Collecte des connexions réseau
                    try:
                        connections = []
                        for conn in proc.connections():
                            connection_info = {
                                'fd': conn.fd,
                                'family': str(conn.family),
                                'type': str(conn.type),
                                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                'status': conn.status
                            }
                            connections.append(connection_info)
                        process_info['connections'] = connections
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_info['connections'] = []
                    
                    # Ajout du processus à la liste
                    processes.append(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des processus: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
        
        return processes
    
    def collect(self) -> Dict[str, Any]:
        """
        Collecte les informations sur les processus en cours d'exécution.
        
        Returns:
            Dictionnaire contenant les informations sur les processus
        """
        logger.info("Collecte des processus en cours d'exécution...")
        
        # Si on analyse une image disque, cette collecte n'est pas possible
        if self.image_path:
            return {"error": "La collecte des processus n'est pas possible à partir d'une image disque"}
        
        # Collecte des processus
        processes = self._collect_process_info()
        logger.info(f"Collecté {len(processes)} processus en cours d'exécution")
        
        # Sauvegarde des données en JSON
        json_path = os.path.join(self.output_dir, "processes.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(processes, f, indent=4)
        
        # Sauvegarde des données en CSV pour une analyse plus facile
        csv_path = os.path.join(self.output_dir, "processes.csv")
        if processes:
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                # Détermination des champs à inclure
                fields = ['pid', 'name', 'username', 'exe', 'status', 'create_time', 'cpu_percent', 'memory_percent', 'parent']
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                
                for proc in processes:
                    # Extraction des champs pertinents
                    row = {field: proc.get(field, '') for field in fields}
                    writer.writerow(row)
        
        return {
            "processes": processes,
            "count": len(processes),
            "json_path": json_path,
            "csv_path": csv_path
        }


class NetworkCollector:
    """Collecteur d'informations sur les connexions réseau actives."""

    def __init__(self, config):
        """
        Initialise le collecteur de connexions réseau.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "network")
        self.image_path = None
        
        # Création du répertoire de sortie
        os.makedirs(self.output_dir, exist_ok=True)
    
    def set_image_path(self, image_path: str):
        """
        Configure le chemin vers l'image disque à analyser.
        
        Args:
            image_path: Chemin vers l'image disque
        """
        self.image_path = image_path
        logger.warning("L'analyse des connexions réseau à partir d'une image disque n'est pas supportée.")
    
    def _collect_network_connections(self) -> List[Dict[str, Any]]:
        """
        Collecte les informations sur les connexions réseau actives.
        
        Returns:
            Liste des connexions réseau avec leurs informations détaillées
        """
        connections = []
        
        try:
            # Collecte de toutes les connexions
            for conn in psutil.net_connections(kind='all'):
                try:
                    connection_info = {
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    
                    # Ajout d'informations sur le processus associé
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            connection_info['process'] = {
                                'name': proc.name(),
                                'exe': proc.exe(),
                                'username': proc.username()
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            connection_info['process'] = None
                    
                    connections.append(connection_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des connexions réseau: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
        
        return connections
    
    def _collect_network_interfaces(self) -> Dict[str, Any]:
        """
        Collecte les informations sur les interfaces réseau.
        
        Returns:
            Dictionnaire contenant les informations sur les interfaces réseau
        """
        interfaces = {}
        
        try:
            # Collecte des adresses des interfaces
            addrs = psutil.net_if_addrs()
            for interface, addr_list in addrs.items():
                interfaces[interface] = {
                    'addresses': [],
                    'stats': {}
                }
                
                for addr in addr_list:
                    addr_info = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    interfaces[interface]['addresses'].append(addr_info)
            
            # Collecte des statistiques des interfaces
            stats = psutil.net_if_stats()
            for interface, stat in stats.items():
                if interface in interfaces:
                    interfaces[interface]['stats'] = {
                        'isup': stat.isup,
                        'duplex': str(stat.duplex),
                        'speed': stat.speed,
                        'mtu': stat.mtu
                    }
        
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des interfaces réseau: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
        
        return interfaces
    
    def collect(self) -> Dict[str, Any]:
        """
        Collecte les informations sur les connexions réseau actives.
        
        Returns:
            Dictionnaire contenant les informations sur les connexions réseau
        """
        logger.info("Collecte des connexions réseau actives...")
        
        # Si on analyse une image disque, cette collecte n'est pas possible
        if self.image_path:
            return {"error": "La collecte des connexions réseau n'est pas possible à partir d'une image disque"}
        
        # Collecte des connexions réseau
        connections = self._collect_network_connections()
        logger.info(f"Collecté {len(connections)} connexions réseau actives")
        
        # Collecte des interfaces réseau
        interfaces = self._collect_network_interfaces()
        logger.info(f"Collecté {len(interfaces)} interfaces réseau")
        
        # Sauvegarde des données en JSON
        connections_path = os.path.join(self.output_dir, "connections.json")
        with open(connections_path, 'w', encoding='utf-8') as f:
            json.dump(connections, f, indent=4)
        
        interfaces_path = os.path.join(self.output_dir, "interfaces.json")
        with open(interfaces_path, 'w', encoding='utf-8') as f:
            json.dump(interfaces, f, indent=4)
        
        # Sauvegarde des connexions en CSV pour une analyse plus facile
        csv_path = os.path.join(self.output_dir, "connections.csv")
        if connections:
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                # Détermination des champs à inclure
                fields = ['laddr', 'raddr', 'status', 'pid', 'process.name', 'process.exe', 'process.username']
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                
                for conn in connections:
                    # Extraction des champs pertinents
                    row = {
                        'laddr': conn.get('laddr', ''),
                        'raddr': conn.get('raddr', ''),
                        'status': conn.get('status', ''),
                        'pid': conn.get('pid', '')
                    }
                    
                    # Ajout des informations de processus si disponibles
                    if conn.get('process'):
                        row['process.name'] = conn['process'].get('name', '')
                        row['process.exe'] = conn['process'].get('exe', '')
                        row['process.username'] = conn['process'].get('username', '')
                    else:
                        row['process.name'] = ''
                        row['process.exe'] = ''
                        row['process.username'] = ''
                    
                    writer.writerow(row)
        
        return {
            "connections": connections,
            "interfaces": interfaces,
            "connections_count": len(connections),
            "interfaces_count": len(interfaces),
            "connections_path": connections_path,
            "interfaces_path": interfaces_path,
            "csv_path": csv_path
        }

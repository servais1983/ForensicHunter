#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de génération de rapports CSV.

Ce module est responsable de la génération de rapports CSV à partir
des artefacts collectés et des résultats d'analyse.
"""

import os
import logging
import datetime
import csv
from typing import Dict, List, Any, Optional

logger = logging.getLogger("forensichunter")


class CSVReporter:
    """Générateur de rapports CSV."""

    def __init__(self, config, output_dir):
        """
        Initialise le générateur de rapports CSV.
        
        Args:
            config: Configuration de l'application
            output_dir: Répertoire de sortie pour les rapports
        """
        self.config = config
        self.output_dir = output_dir
        
        # Création du répertoire pour les fichiers CSV
        self.csv_dir = os.path.join(output_dir, "csv")
        os.makedirs(self.csv_dir, exist_ok=True)
    
    def generate(self, artifacts: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
        """
        Génère des rapports CSV à partir des artefacts collectés et des résultats d'analyse.
        
        Args:
            artifacts: Dictionnaire contenant tous les artefacts collectés
            analysis_results: Dictionnaire contenant les résultats d'analyse
            
        Returns:
            Chemin vers le répertoire contenant les rapports CSV générés
        """
        # Génération des fichiers CSV pour chaque type d'artefact
        self._generate_system_info_csv(self._get_system_info())
        
        if "EventLogCollector" in artifacts:
            self._generate_eventlogs_csv(artifacts["EventLogCollector"])
        
        if "RegistryCollector" in artifacts:
            self._generate_registry_csv(artifacts["RegistryCollector"])
        
        if "FilesystemCollector" in artifacts:
            self._generate_filesystem_csv(artifacts["FilesystemCollector"])
        
        if "BrowserHistoryCollector" in artifacts:
            self._generate_browser_csv(artifacts["BrowserHistoryCollector"])
        
        if "ProcessCollector" in artifacts:
            self._generate_process_csv(artifacts["ProcessCollector"])
        
        if "NetworkCollector" in artifacts:
            self._generate_network_csv(artifacts["NetworkCollector"])
        
        if "USBCollector" in artifacts:
            self._generate_usb_csv(artifacts["USBCollector"])
        
        if "UserDataCollector" in artifacts:
            self._generate_userdata_csv(artifacts["UserDataCollector"])
        
        if "alerts" in analysis_results:
            self._generate_alerts_csv(analysis_results["alerts"])
        
        # Génération d'un fichier d'index
        index_path = self._generate_index_csv()
        
        return self.csv_dir
    
    def _get_system_info(self) -> Dict[str, Any]:
        """
        Récupère les informations système.
        
        Returns:
            Dictionnaire contenant les informations système
        """
        import platform
        import socket
        import psutil
        
        system_info = {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "user": os.environ.get("USERNAME", "N/A"),
            "boot_time": psutil.boot_time()
        }
        
        return system_info
    
    def _generate_system_info_csv(self, system_info: Dict[str, Any]) -> str:
        """
        Génère un fichier CSV contenant les informations système.
        
        Args:
            system_info: Dictionnaire contenant les informations système
            
        Returns:
            Chemin vers le fichier CSV généré
        """
        csv_path = os.path.join(self.csv_dir, "system_info.csv")
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Propriété", "Valeur"])
            
            for key, value in system_info.items():
                if key == "boot_time" and isinstance(value, (int, float)):
                    value = datetime.datetime.fromtimestamp(value).isoformat()
                writer.writerow([key, value])
        
        return csv_path
    
    def _generate_eventlogs_csv(self, eventlogs_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Génère des fichiers CSV contenant les journaux d'événements.
        
        Args:
            eventlogs_data: Dictionnaire contenant les journaux d'événements
            
        Returns:
            Dictionnaire contenant les chemins des fichiers CSV générés
        """
        csv_paths = {}
        
        for log_name, events in eventlogs_data.items():
            if not isinstance(events, list):
                continue
            
            csv_path = os.path.join(self.csv_dir, f"eventlog_{log_name}.csv")
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                if not events:
                    continue
                
                # Détermination des champs
                fields = ["EventID", "TimeCreated", "Provider", "Computer", "Description"]
                
                # Ajout des champs de données si présents
                if events and "Data" in events[0] and isinstance(events[0]["Data"], dict):
                    for key in events[0]["Data"].keys():
                        fields.append(f"Data.{key}")
                
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                
                for event in events:
                    row = {field: event.get(field, "") for field in fields if "." not in field}
                    
                    # Ajout des données spécifiques
                    if "Data" in event and isinstance(event["Data"], dict):
                        for key, value in event["Data"].items():
                            row[f"Data.{key}"] = value
                    
                    writer.writerow(row)
            
            csv_paths[log_name] = csv_path
        
        return csv_paths
    
    def _generate_registry_csv(self, registry_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Génère des fichiers CSV contenant les données de registre.
        
        Args:
            registry_data: Dictionnaire contenant les données de registre
            
        Returns:
            Dictionnaire contenant les chemins des fichiers CSV générés
        """
        csv_paths = {}
        
        # Fichier CSV pour les ruches
        hives_path = os.path.join(self.csv_dir, "registry_hives.csv")
        with open(hives_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Ruche", "Chemin", "Erreur"])
            
            for hive_name, hive_data in registry_data.items():
                if isinstance(hive_data, dict):
                    writer.writerow([
                        hive_name,
                        hive_data.get("path", ""),
                        hive_data.get("error", "")
                    ])
        
        csv_paths["hives"] = hives_path
        
        # Fichier CSV pour les clés
        keys_path = os.path.join(self.csv_dir, "registry_keys.csv")
        with open(keys_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Ruche", "Clé", "Dernière modification", "Erreur"])
            
            for hive_name, hive_data in registry_data.items():
                if isinstance(hive_data, dict) and "keys" in hive_data:
                    for key_path, key_data in hive_data["keys"].items():
                        writer.writerow([
                            hive_name,
                            key_path,
                            key_data.get("last_modified", ""),
                            key_data.get("error", "")
                        ])
        
        csv_paths["keys"] = keys_path
        
        # Fichier CSV pour les valeurs
        values_path = os.path.join(self.csv_dir, "registry_values.csv")
        with open(values_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Ruche", "Clé", "Nom", "Type", "Valeur"])
            
            for hive_name, hive_data in registry_data.items():
                if isinstance(hive_data, dict) and "keys" in hive_data:
                    for key_path, key_data in hive_data["keys"].items():
                        if "values" in key_data and isinstance(key_data["values"], dict):
                            for value_name, value_data in key_data["values"].items():
                                writer.writerow([
                                    hive_name,
                                    key_path,
                                    value_name,
                                    value_data.get("type", ""),
                                    value_data.get("data", "")
                                ])
        
        csv_paths["values"] = values_path
        
        return csv_paths
    
    def _generate_filesystem_csv(self, filesystem_data: Dict[str, Any]) -> str:
        """
        Génère un fichier CSV contenant les artefacts du système de fichiers.
        
        Args:
            filesystem_data: Dictionnaire contenant les artefacts du système de fichiers
            
        Returns:
            Chemin vers le fichier CSV généré
        """
        csv_path = os.path.join(self.csv_dir, "filesystem_artifacts.csv")
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Nom", "Taille", "Créé", "Modifié", "Accédé", "Chemin"])
            
            if "artifacts" in filesystem_data and isinstance(filesystem_data["artifacts"], dict):
                for artifact_type, artifact_data in filesystem_data["artifacts"].items():
                    if "files" in artifact_data and isinstance(artifact_data["files"], list):
                        for file_info in artifact_data["files"]:
                            writer.writerow([
                                artifact_type,
                                file_info.get("name", ""),
                                file_info.get("size", ""),
                                file_info.get("created", ""),
                                file_info.get("modified", ""),
                                file_info.get("accessed", ""),
                                file_info.get("path", "")
                            ])
        
        return csv_path
    
    def _generate_browser_csv(self, browser_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Génère des fichiers CSV contenant les données de navigation.
        
        Args:
            browser_data: Dictionnaire contenant les données de navigation
            
        Returns:
            Dictionnaire contenant les chemins des fichiers CSV générés
        """
        csv_paths = {}
        
        # Fichier CSV pour l'historique
        history_path = os.path.join(self.csv_dir, "browser_history.csv")
        with open(history_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Navigateur", "URL", "Titre", "Date de visite", "Nombre de visites"])
            
            for browser_name, browser_info in browser_data.items():
                if "history" in browser_info and isinstance(browser_info["history"], list):
                    for entry in browser_info["history"]:
                        writer.writerow([
                            browser_name,
                            entry.get("url", ""),
                            entry.get("title", ""),
                            entry.get("last_visit_time", ""),
                            entry.get("visit_count", "")
                        ])
        
        csv_paths["history"] = history_path
        
        # Fichier CSV pour les favoris
        bookmarks_path = os.path.join(self.csv_dir, "browser_bookmarks.csv")
        with open(bookmarks_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Navigateur", "URL", "Nom", "Date d'ajout", "Dossier"])
            
            for browser_name, browser_info in browser_data.items():
                if "bookmarks" in browser_info and isinstance(browser_info["bookmarks"], list):
                    for bookmark in browser_info["bookmarks"]:
                        writer.writerow([
                            browser_name,
                            bookmark.get("url", ""),
                            bookmark.get("name", ""),
                            bookmark.get("date_added", ""),
                            bookmark.get("folder", "")
                        ])
        
        csv_paths["bookmarks"] = bookmarks_path
        
        return csv_paths
    
    def _generate_process_csv(self, process_data: Dict[str, Any]) -> str:
        """
        Génère un fichier CSV contenant les informations sur les processus.
        
        Args:
            process_data: Dictionnaire contenant les informations sur les processus
            
        Returns:
            Chemin vers le fichier CSV généré
        """
        csv_path = os.path.join(self.csv_dir, "processes.csv")
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["PID", "Nom", "Utilisateur", "Chemin", "Ligne de commande", "Parent", "Créé", "CPU %", "Mémoire %"])
            
            if "processes" in process_data and isinstance(process_data["processes"], list):
                for process in process_data["processes"]:
                    writer.writerow([
                        process.get("pid", ""),
                        process.get("name", ""),
                        process.get("username", ""),
                        process.get("exe", ""),
                        " ".join(process.get("cmdline", [])) if isinstance(process.get("cmdline"), list) else "",
                        process.get("parent", ""),
                        process.get("create_time", ""),
                        process.get("cpu_percent", ""),
                        process.get("memory_percent", "")
                    ])
        
        return csv_path
    
    def _generate_network_csv(self, network_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Génère des fichiers CSV contenant les informations réseau.
        
        Args:
            network_data: Dictionnaire contenant les informations réseau
            
        Returns:
            Dictionnaire contenant les chemins des fichiers CSV générés
        """
        csv_paths = {}
        
        # Fichier CSV pour les connexions
        connections_path = os.path.join(self.csv_dir, "network_connections.csv")
        with open(connections_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["PID", "Processus", "Utilisateur", "Adresse locale", "Adresse distante", "État", "Type"])
            
            if "connections" in network_data and isinstance(network_data["connections"], list):
                for conn in network_data["connections"]:
                    process_name = ""
                    username = ""
                    
                    if "process" in conn and isinstance(conn["process"], dict):
                        process_name = conn["process"].get("name", "")
                        username = conn["process"].get("username", "")
                    
                    writer.writerow([
                        conn.get("pid", ""),
                        process_name,
                        username,
                        conn.get("laddr", ""),
                        conn.get("raddr", ""),
                        conn.get("status", ""),
                        conn.get("type", "")
                    ])
        
        csv_paths["connections"] = connections_path
        
        # Fichier CSV pour les interfaces
        interfaces_path = os.path.join(self.csv_dir, "network_interfaces.csv")
        with open(interfaces_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Interface", "Adresse", "Masque", "Diffusion", "Famille", "État", "MTU", "Vitesse"])
            
            if "interfaces" in network_data and isinstance(network_data["interfaces"], dict):
                for interface_name, interface_data in network_data["interfaces"].items():
                    if "addresses" in interface_data and isinstance(interface_data["addresses"], list):
                        for addr in interface_data["addresses"]:
                            stats = interface_data.get("stats", {})
                            writer.writerow([
                                interface_name,
                                addr.get("address", ""),
                                addr.get("netmask", ""),
                                addr.get("broadcast", ""),
                                addr.get("family", ""),
                                "Actif" if stats.get("isup") else "Inactif",
                                stats.get("mtu", ""),
                                stats.get("speed", "")
                            ])
                    else:
                        stats = interface_data.get("stats", {})
                        writer.writerow([
                            interface_name,
                            "", "", "", "",
                            "Actif" if stats.get("isup") else "Inactif",
                            stats.get("mtu", ""),
                            stats.get("speed", "")
                        ])
        
        csv_paths["interfaces"] = interfaces_path
        
        return csv_paths
    
    def _generate_usb_csv(self, usb_data: Dict[str, Any]) -> str:
        """
        Génère un fichier CSV contenant les informations sur les périphériques USB.
        
        Args:
            usb_data: Dictionnaire contenant les informations sur les périphériques USB
            
        Returns:
            Chemin vers le fichier CSV généré
        """
        csv_path = os.path.join(self.csv_dir, "usb_devices.csv")
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "ID", "Nom", "Description", "Source"])
            
            # Périphériques du registre
            if "registry_devices" in usb_data and isinstance(usb_data["registry_devices"], list):
                for device in usb_data["registry_devices"]:
                    friendly_name = ""
                    device_desc = ""
                    
                    if "properties" in device and isinstance(device["properties"], dict):
                        friendly_name = device["properties"].get("friendly_name", "")
                        device_desc = device["properties"].get("device_desc", "")
                    
                    writer.writerow([
                        device.get("type", ""),
                        device.get("id", ""),
                        friendly_name,
                        device_desc,
                        "Registre"
                    ])
            
            # Périphériques du journal setupapi
            if "setupapi_devices" in usb_data and isinstance(usb_data["setupapi_devices"], list):
                for device in usb_data["setupapi_devices"]:
                    name = ""
                    device_id = ""
                    
                    if "properties" in device and isinstance(device["properties"], dict):
                        name = device["properties"].get("name", "")
                        device_id = device["properties"].get("device_id", "")
                    
                    writer.writerow([
                        "USB",
                        device_id,
                        name,
                        "",
                        "SetupAPI"
                    ])
        
        return csv_path
    
    def _generate_userdata_csv(self, userdata_data: Dict[str, Any]) -> str:
        """
        Génère un fichier CSV contenant les données utilisateur.
        
        Args:
            userdata_data: Dictionnaire contenant les données utilisateur
            
        Returns:
            Chemin vers le fichier CSV généré
        """
        csv_path = os.path.join(self.csv_dir, "userdata.csv")
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Nom", "Taille", "Créé", "Modifié", "Accédé", "Intéressant", "Chemin"])
            
            if "data" in userdata_data and isinstance(userdata_data["data"], dict):
                for data_type, data_info in userdata_data["data"].items():
                    if "files" in data_info and isinstance(data_info["files"], list):
                        for file_info in data_info["files"]:
                            writer.writerow([
                                data_type,
                                file_info.get("name", ""),
                                file_info.get("size", ""),
                                file_info.get("created", ""),
                                file_info.get("modified", ""),
                                file_info.get("accessed", ""),
                                "Oui" if file_info.get("interesting") else "Non",
                                file_info.get("path", "")
                            ])
        
        return csv_path
    
    def _generate_alerts_csv(self, alerts: List[Dict[str, Any]]) -> str:
        """
        Génère un fichier CSV contenant les alertes.
        
        Args:
            alerts: Liste des alertes
            
        Returns:
            Chemin vers le fichier CSV généré
        """
        csv_path = os.path.join(self.csv_dir, "alerts.csv")
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Type", "Description", "Score", "Source", "Détails"])
            
            for alert in alerts:
                writer.writerow([
                    alert.get("type", ""),
                    alert.get("description", ""),
                    alert.get("score", ""),
                    alert.get("source", ""),
                    alert.get("details", "")
                ])
        
        return csv_path
    
    def _generate_index_csv(self) -> str:
        """
        Génère un fichier CSV d'index listant tous les fichiers CSV générés.
        
        Returns:
            Chemin vers le fichier CSV d'index
        """
        csv_path = os.path.join(self.csv_dir, "index.csv")
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Fichier", "Description"])
            
            for filename in os.listdir(self.csv_dir):
                if filename.endswith(".csv") and filename != "index.csv":
                    description = ""
                    
                    if filename == "system_info.csv":
                        description = "Informations système"
                    elif filename.startswith("eventlog_"):
                        log_name = filename[9:-4]  # Extraction du nom du journal
                        description = f"Journal d'événements {log_name}"
                    elif filename == "registry_hives.csv":
                        description = "Ruches de registre"
                    elif filename == "registry_keys.csv":
                        description = "Clés de registre"
                    elif filename == "registry_values.csv":
                        description = "Valeurs de registre"
                    elif filename == "filesystem_artifacts.csv":
                        description = "Artefacts du système de fichiers"
                    elif filename == "browser_history.csv":
                        description = "Historique de navigation"
                    elif filename == "browser_bookmarks.csv":
                        description = "Favoris des navigateurs"
                    elif filename == "processes.csv":
                        description = "Processus en cours d'exécution"
                    elif filename == "network_connections.csv":
                        description = "Connexions réseau"
                    elif filename == "network_interfaces.csv":
                        description = "Interfaces réseau"
                    elif filename == "usb_devices.csv":
                        description = "Périphériques USB"
                    elif filename == "userdata.csv":
                        description = "Données utilisateur"
                    elif filename == "alerts.csv":
                        description = "Alertes détectées"
                    
                    writer.writerow([filename, description])
        
        return csv_path

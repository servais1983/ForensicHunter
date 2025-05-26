#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'intégration avec Volatility pour l'analyse mémoire avancée.

Ce module fournit une interface avec Volatility 3 pour l'analyse avancée
des captures mémoire, permettant d'extraire des informations détaillées
sur les processus, les connexions réseau, les modules chargés, etc.
"""

import os
import sys
import json
import logging
import tempfile
import subprocess
from typing import Dict, List, Any, Optional, Union

logger = logging.getLogger("forensichunter")


class VolatilityAnalyzer:
    """Interface avec Volatility pour l'analyse mémoire avancée."""

    def __init__(self, config):
        """
        Initialise l'analyseur Volatility.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.volatility_path = self._find_volatility()
        self.plugins = self._get_available_plugins()
    
    def _find_volatility(self) -> str:
        """
        Recherche l'exécutable Volatility dans le système.
        
        Returns:
            Chemin vers l'exécutable Volatility ou chaîne vide si non trouvé
        """
        # Recherche dans le PATH
        try:
            # Vérification de vol.py (Volatility 3)
            result = subprocess.run(["where", "vol.py"] if os.name == "nt" else ["which", "vol.py"], 
                                   capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return result.stdout.strip()
            
            # Vérification de volatility (Volatility 2)
            result = subprocess.run(["where", "volatility"] if os.name == "nt" else ["which", "volatility"], 
                                   capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.debug(f"Erreur lors de la recherche de Volatility dans le PATH: {str(e)}")
        
        # Recherche dans les emplacements courants
        common_locations = [
            os.path.join(os.path.dirname(sys.executable), "Scripts", "vol.py"),  # Python Scripts
            os.path.join(os.path.dirname(sys.executable), "vol.py"),  # Python directory
            r"C:\Program Files\Volatility3\vol.py",  # Windows
            r"C:\Program Files (x86)\Volatility3\vol.py",  # Windows 32-bit
            "/usr/local/bin/vol.py",  # Unix/Linux
            "/usr/bin/vol.py",  # Unix/Linux
            os.path.expanduser("~/volatility3/vol.py")  # Home directory
        ]
        
        for location in common_locations:
            if os.path.isfile(location):
                return location
        
        # Vérification de l'installation via pip
        try:
            import volatility3
            return "vol.py"  # Utilisation du module Python directement
        except ImportError:
            pass
        
        logger.warning("Volatility non trouvé dans le système. L'analyse mémoire avancée ne sera pas disponible.")
        return ""
    
    def _get_available_plugins(self) -> List[str]:
        """
        Récupère la liste des plugins Volatility disponibles.
        
        Returns:
            Liste des plugins disponibles
        """
        if not self.volatility_path:
            return []
        
        plugins = []
        
        try:
            # Exécution de Volatility pour lister les plugins
            cmd = [sys.executable, self.volatility_path, "--help"] if self.volatility_path.endswith(".py") else [self.volatility_path, "--help"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                # Analyse de la sortie pour extraire les plugins
                lines = result.stdout.split("\n")
                in_plugins_section = False
                
                for line in lines:
                    if "Plugins" in line and ":" in line:
                        in_plugins_section = True
                        continue
                    
                    if in_plugins_section and line.strip():
                        # Extraction du nom du plugin
                        parts = line.strip().split()
                        if parts:
                            plugins.append(parts[0])
            
            logger.info(f"Plugins Volatility disponibles: {len(plugins)}")
            logger.debug(f"Liste des plugins: {plugins}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des plugins Volatility: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
        
        return plugins
    
    def analyze_memory_dump(self, memory_dump_path: str, plugins: List[str] = None) -> Dict[str, Any]:
        """
        Analyse une capture mémoire avec Volatility.
        
        Args:
            memory_dump_path: Chemin vers la capture mémoire
            plugins: Liste des plugins à utiliser (par défaut: plugins essentiels)
            
        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        if not self.volatility_path:
            logger.error("Volatility non disponible. Impossible d'analyser la capture mémoire.")
            return {"error": "Volatility non disponible"}
        
        if not os.path.isfile(memory_dump_path):
            logger.error(f"Capture mémoire non trouvée: {memory_dump_path}")
            return {"error": f"Capture mémoire non trouvée: {memory_dump_path}"}
        
        # Plugins par défaut si non spécifiés
        if not plugins:
            plugins = [
                "windows.pslist",      # Liste des processus
                "windows.psscan",      # Recherche de processus cachés
                "windows.netscan",     # Connexions réseau
                "windows.malfind",     # Recherche de code injecté
                "windows.dlllist",     # DLLs chargées
                "windows.svcscan",     # Services Windows
                "windows.cmdline",     # Lignes de commande
                "windows.modules",     # Modules du noyau
                "windows.handles",     # Handles de processus
                "windows.mutantscan",  # Mutexes
                "windows.filescan",    # Fichiers ouverts
                "windows.registry.hivelist"  # Ruches de registre
            ]
        
        # Filtrage des plugins disponibles
        plugins = [p for p in plugins if p in self.plugins]
        
        if not plugins:
            logger.warning("Aucun plugin Volatility valide spécifié.")
            return {"error": "Aucun plugin Volatility valide spécifié"}
        
        results = {}
        
        # Création d'un répertoire temporaire pour les résultats
        with tempfile.TemporaryDirectory() as temp_dir:
            for plugin in plugins:
                try:
                    logger.info(f"Exécution du plugin Volatility {plugin}...")
                    
                    # Fichier de sortie JSON
                    output_file = os.path.join(temp_dir, f"{plugin.replace('.', '_')}.json")
                    
                    # Commande Volatility
                    cmd = [sys.executable, self.volatility_path] if self.volatility_path.endswith(".py") else [self.volatility_path]
                    cmd.extend(["-f", memory_dump_path, "-o", "json", "-r", output_file, plugin])
                    
                    # Exécution de la commande
                    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                    
                    if result.returncode != 0:
                        logger.warning(f"Erreur lors de l'exécution du plugin {plugin}: {result.stderr}")
                        results[plugin] = {"error": result.stderr}
                        continue
                    
                    # Lecture des résultats JSON
                    if os.path.isfile(output_file):
                        with open(output_file, 'r') as f:
                            try:
                                plugin_results = json.load(f)
                                results[plugin] = plugin_results
                            except json.JSONDecodeError:
                                logger.warning(f"Erreur de décodage JSON pour le plugin {plugin}")
                                results[plugin] = {"error": "Erreur de décodage JSON"}
                    else:
                        logger.warning(f"Fichier de sortie non trouvé pour le plugin {plugin}")
                        results[plugin] = {"error": "Fichier de sortie non trouvé"}
                
                except Exception as e:
                    logger.error(f"Erreur lors de l'exécution du plugin {plugin}: {str(e)}")
                    logger.debug("Détails de l'erreur:", exc_info=True)
                    results[plugin] = {"error": str(e)}
        
        return self._process_volatility_results(results)
    
    def _process_volatility_results(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Traite les résultats bruts de Volatility pour les rendre plus exploitables.
        
        Args:
            raw_results: Résultats bruts de Volatility
            
        Returns:
            Résultats traités
        """
        processed_results = {
            "processes": [],
            "network_connections": [],
            "loaded_modules": [],
            "injected_code": [],
            "services": [],
            "registry_hives": [],
            "handles": [],
            "mutexes": [],
            "open_files": [],
            "suspicious_items": []
        }
        
        # Traitement des processus (pslist et psscan)
        if "windows.pslist" in raw_results:
            try:
                for process in raw_results["windows.pslist"].get("rows", []):
                    processed_results["processes"].append({
                        "pid": process[0],
                        "ppid": process[1],
                        "name": process[2],
                        "start_time": process[3],
                        "exit_time": process[4],
                        "threads": process[5],
                        "handles": process[6],
                        "session_id": process[7],
                        "wow64": process[8],
                        "base": process[9],
                        "offset": process[10],
                        "source": "pslist"
                    })
            except Exception as e:
                logger.warning(f"Erreur lors du traitement des résultats pslist: {str(e)}")
        
        if "windows.psscan" in raw_results:
            try:
                for process in raw_results["windows.psscan"].get("rows", []):
                    # Vérification si le processus est caché (présent dans psscan mais pas dans pslist)
                    is_hidden = True
                    for p in processed_results["processes"]:
                        if p["pid"] == process[0] and p["offset"] == process[10]:
                            is_hidden = False
                            break
                    
                    proc_info = {
                        "pid": process[0],
                        "ppid": process[1],
                        "name": process[2],
                        "start_time": process[3],
                        "exit_time": process[4],
                        "threads": process[5],
                        "handles": process[6],
                        "session_id": process[7],
                        "wow64": process[8],
                        "base": process[9],
                        "offset": process[10],
                        "source": "psscan",
                        "hidden": is_hidden
                    }
                    
                    processed_results["processes"].append(proc_info)
                    
                    # Ajout aux éléments suspects si caché
                    if is_hidden:
                        processed_results["suspicious_items"].append({
                            "type": "hidden_process",
                            "description": f"Processus caché détecté: {process[2]} (PID: {process[0]})",
                            "details": proc_info
                        })
            except Exception as e:
                logger.warning(f"Erreur lors du traitement des résultats psscan: {str(e)}")
        
        # Traitement des connexions réseau (netscan)
        if "windows.netscan" in raw_results:
            try:
                for conn in raw_results["windows.netscan"].get("rows", []):
                    conn_info = {
                        "offset": conn[0],
                        "protocol": conn[1],
                        "local_addr": conn[2],
                        "local_port": conn[3],
                        "remote_addr": conn[4],
                        "remote_port": conn[5],
                        "state": conn[6],
                        "pid": conn[7],
                        "owner": conn[8],
                        "created": conn[9]
                    }
                    
                    processed_results["network_connections"].append(conn_info)
                    
                    # Détection de connexions suspectes
                    if conn_info["remote_port"] in [4444, 5555, 6666, 7777, 8888, 9999]:
                        processed_results["suspicious_items"].append({
                            "type": "suspicious_connection",
                            "description": f"Connexion réseau suspecte: {conn_info['local_addr']}:{conn_info['local_port']} -> {conn_info['remote_addr']}:{conn_info['remote_port']}",
                            "details": conn_info
                        })
            except Exception as e:
                logger.warning(f"Erreur lors du traitement des résultats netscan: {str(e)}")
        
        # Traitement du code injecté (malfind)
        if "windows.malfind" in raw_results:
            try:
                for item in raw_results["windows.malfind"].get("rows", []):
                    injection_info = {
                        "pid": item[0],
                        "process": item[1],
                        "address": item[2],
                        "vad_tag": item[3],
                        "protection": item[4],
                        "flags": item[5],
                        "hexdump": item[6]
                    }
                    
                    processed_results["injected_code"].append(injection_info)
                    
                    # Ajout aux éléments suspects
                    processed_results["suspicious_items"].append({
                        "type": "code_injection",
                        "description": f"Code injecté détecté dans le processus {item[1]} (PID: {item[0]})",
                        "details": injection_info
                    })
            except Exception as e:
                logger.warning(f"Erreur lors du traitement des résultats malfind: {str(e)}")
        
        # Traitement des DLLs chargées (dlllist)
        if "windows.dlllist" in raw_results:
            try:
                for dll in raw_results["windows.dlllist"].get("rows", []):
                    dll_info = {
                        "pid": dll[0],
                        "process": dll[1],
                        "base": dll[2],
                        "size": dll[3],
                        "name": dll[4],
                        "path": dll[5],
                        "load_time": dll[6]
                    }
                    
                    processed_results["loaded_modules"].append(dll_info)
                    
                    # Détection de DLLs suspectes
                    suspicious_dlls = ["inject", "hook", "spy", "keylog", "stealth", "hide"]
                    if any(s in dll_info["name"].lower() for s in suspicious_dlls):
                        processed_results["suspicious_items"].append({
                            "type": "suspicious_dll",
                            "description": f"DLL suspecte chargée: {dll_info['name']} dans {dll_info['process']} (PID: {dll_info['pid']})",
                            "details": dll_info
                        })
            except Exception as e:
                logger.warning(f"Erreur lors du traitement des résultats dlllist: {str(e)}")
        
        # Traitement des services (svcscan)
        if "windows.svcscan" in raw_results:
            try:
                for service in raw_results["windows.svcscan"].get("rows", []):
                    service_info = {
                        "offset": service[0],
                        "order": service[1],
                        "pid": service[2],
                        "service_name": service[3],
                        "display_name": service[4],
                        "type": service[5],
                        "state": service[6],
                        "binary": service[7]
                    }
                    
                    processed_results["services"].append(service_info)
                    
                    # Détection de services suspects
                    suspicious_services = ["svchost", "lsass", "csrss", "winlogon", "explorer"]
                    if service_info["service_name"] in suspicious_services and service_info["binary"] and "system32" not in service_info["binary"].lower():
                        processed_results["suspicious_items"].append({
                            "type": "suspicious_service",
                            "description": f"Service système suspect avec chemin non standard: {service_info['service_name']}",
                            "details": service_info
                        })
            except Exception as e:
                logger.warning(f"Erreur lors du traitement des résultats svcscan: {str(e)}")
        
        # Traitement des ruches de registre (hivelist)
        if "windows.registry.hivelist" in raw_results:
            try:
                for hive in raw_results["windows.registry.hivelist"].get("rows", []):
                    hive_info = {
                        "offset": hive[0],
                        "name": hive[1]
                    }
                    
                    processed_results["registry_hives"].append(hive_info)
            except Exception as e:
                logger.warning(f"Erreur lors du traitement des résultats hivelist: {str(e)}")
        
        # Calcul des statistiques
        stats = {
            "total_processes": len(processed_results["processes"]),
            "hidden_processes": sum(1 for p in processed_results["processes"] if p.get("hidden", False)),
            "total_connections": len(processed_results["network_connections"]),
            "total_modules": len(processed_results["loaded_modules"]),
            "injected_code_count": len(processed_results["injected_code"]),
            "total_services": len(processed_results["services"]),
            "total_suspicious_items": len(processed_results["suspicious_items"])
        }
        
        processed_results["statistics"] = stats
        
        return processed_results
    
    def extract_timeline(self, memory_dump_path: str) -> Dict[str, Any]:
        """
        Extrait une timeline des événements à partir d'une capture mémoire.
        
        Args:
            memory_dump_path: Chemin vers la capture mémoire
            
        Returns:
            Dictionnaire contenant la timeline des événements
        """
        if not self.volatility_path:
            logger.error("Volatility non disponible. Impossible d'extraire la timeline.")
            return {"error": "Volatility non disponible"}
        
        timeline_data = {
            "events": [],
            "statistics": {}
        }
        
        # Plugins pour la timeline
        timeline_plugins = [
            "windows.pslist",
            "windows.netscan",
            "windows.cmdline",
            "windows.svcscan",
            "windows.registry.userassist"
        ]
        
        # Analyse avec les plugins sélectionnés
        results = self.analyze_memory_dump(memory_dump_path, timeline_plugins)
        
        # Extraction des événements de processus
        for process in results.get("processes", []):
            if process.get("start_time"):
                timeline_data["events"].append({
                    "timestamp": process["start_time"],
                    "type": "process_start",
                    "description": f"Démarrage du processus {process['name']} (PID: {process['pid']})",
                    "details": process
                })
            
            if process.get("exit_time") and process["exit_time"] != "N/A":
                timeline_data["events"].append({
                    "timestamp": process["exit_time"],
                    "type": "process_exit",
                    "description": f"Arrêt du processus {process['name']} (PID: {process['pid']})",
                    "details": process
                })
        
        # Extraction des événements réseau
        for conn in results.get("network_connections", []):
            if conn.get("created"):
                timeline_data["events"].append({
                    "timestamp": conn["created"],
                    "type": "network_connection",
                    "description": f"Connexion réseau {conn['protocol']} {conn['local_addr']}:{conn['local_port']} -> {conn['remote_addr']}:{conn['remote_port']}",
                    "details": conn
                })
        
        # Tri des événements par timestamp
        timeline_data["events"].sort(key=lambda x: x["timestamp"] if x["timestamp"] != "N/A" else "9999-99-99 99:99:99")
        
        # Statistiques
        timeline_data["statistics"] = {
            "total_events": len(timeline_data["events"]),
            "process_events": sum(1 for e in timeline_data["events"] if e["type"] in ["process_start", "process_exit"]),
            "network_events": sum(1 for e in timeline_data["events"] if e["type"] == "network_connection"),
            "earliest_event": timeline_data["events"][0]["timestamp"] if timeline_data["events"] else "N/A",
            "latest_event": timeline_data["events"][-1]["timestamp"] if timeline_data["events"] else "N/A"
        }
        
        return timeline_data
    
    def detect_rootkits(self, memory_dump_path: str) -> Dict[str, Any]:
        """
        Détecte les rootkits et malwares furtifs dans une capture mémoire.
        
        Args:
            memory_dump_path: Chemin vers la capture mémoire
            
        Returns:
            Dictionnaire contenant les résultats de détection
        """
        if not self.volatility_path:
            logger.error("Volatility non disponible. Impossible de détecter les rootkits.")
            return {"error": "Volatility non disponible"}
        
        rootkit_results = {
            "detected_rootkits": [],
            "hidden_processes": [],
            "hidden_modules": [],
            "hooked_functions": [],
            "suspicious_drivers": [],
            "suspicious_memory_regions": [],
            "statistics": {}
        }
        
        # Plugins pour la détection de rootkits
        rootkit_plugins = [
            "windows.pslist",
            "windows.psscan",
            "windows.modules",
            "windows.modscan",
            "windows.ssdt",
            "windows.callbacks",
            "windows.driverirp",
            "windows.malfind"
        ]
        
        # Analyse avec les plugins sélectionnés
        results = self.analyze_memory_dump(memory_dump_path, rootkit_plugins)
        
        # Détection des processus cachés
        pslist_pids = set((p["pid"], p["offset"]) for p in results.get("processes", []) if p.get("source") == "pslist")
        psscan_pids = set((p["pid"], p["offset"]) for p in results.get("processes", []) if p.get("source") == "psscan")
        
        hidden_pids = psscan_pids - pslist_pids
        for pid, offset in hidden_pids:
            for process in results.get("processes", []):
                if process["pid"] == pid and process["offset"] == offset:
                    rootkit_results["hidden_processes"].append(process)
                    
                    rootkit_results["detected_rootkits"].append({
                        "type": "hidden_process",
                        "description": f"Processus caché détecté: {process['name']} (PID: {process['pid']})",
                        "severity": "high",
                        "details": process
                    })
        
        # Détection des modules cachés (si disponible dans les résultats)
        if "windows.modules" in results and "windows.modscan" in results:
            try:
                modules_list = set()
                modscan_list = set()
                
                # Extraction des modules listés
                for module in results["windows.modules"].get("rows", []):
                    modules_list.add(module[3])  # Nom du module
                
                # Extraction des modules scannés
                for module in results["windows.modscan"].get("rows", []):
                    modscan_list.add(module[3])  # Nom du module
                
                # Modules présents dans modscan mais pas dans modules
                hidden_modules = modscan_list - modules_list
                
                for module_name in hidden_modules:
                    module_info = {"name": module_name}
                    rootkit_results["hidden_modules"].append(module_info)
                    
                    rootkit_results["detected_rootkits"].append({
                        "type": "hidden_module",
                        "description": f"Module caché détecté: {module_name}",
                        "severity": "high",
                        "details": module_info
                    })
            except Exception as e:
                logger.warning(f"Erreur lors de la détection des modules cachés: {str(e)}")
        
        # Détection des régions mémoire suspectes (malfind)
        for injection in results.get("injected_code", []):
            rootkit_results["suspicious_memory_regions"].append(injection)
            
            rootkit_results["detected_rootkits"].append({
                "type": "injected_code",
                "description": f"Code injecté détecté dans le processus {injection['process']} (PID: {injection['pid']})",
                "severity": "high",
                "details": injection
            })
        
        # Statistiques
        rootkit_results["statistics"] = {
            "total_detections": len(rootkit_results["detected_rootkits"]),
            "hidden_processes": len(rootkit_results["hidden_processes"]),
            "hidden_modules": len(rootkit_results["hidden_modules"]),
            "suspicious_memory_regions": len(rootkit_results["suspicious_memory_regions"])
        }
        
        return rootkit_results
    
    def is_available(self) -> bool:
        """
        Vérifie si Volatility est disponible.
        
        Returns:
            True si Volatility est disponible, False sinon
        """
        return bool(self.volatility_path)
    
    def get_volatility_version(self) -> str:
        """
        Récupère la version de Volatility.
        
        Returns:
            Version de Volatility ou chaîne vide si non disponible
        """
        if not self.volatility_path:
            return ""
        
        try:
            cmd = [sys.executable, self.volatility_path, "--version"] if self.volatility_path.endswith(".py") else [self.volatility_path, "--version"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                return result.stdout.strip()
            
            return "Unknown"
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la version de Volatility: {str(e)}")
            return "Error"

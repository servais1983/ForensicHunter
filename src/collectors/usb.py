#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte des périphériques USB et informations de stockage.

Ce module est responsable de la collecte des informations sur les périphériques USB
connectés et l'historique des connexions pour analyse forensique.
"""

import os
import logging
import datetime
import json
import csv
import winreg
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger("forensichunter")


class USBCollector:
    """Collecteur d'informations sur les périphériques USB."""

    def __init__(self, config):
        """
        Initialise le collecteur de périphériques USB.
        
        Args:
            config: Configuration de l'application
        """
        self.config = config
        self.output_dir = os.path.join(config.output_dir, "usb")
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
    
    def _get_registry_usb_devices(self) -> List[Dict[str, Any]]:
        """
        Collecte les informations sur les périphériques USB depuis le registre Windows.
        
        Returns:
            Liste des périphériques USB avec leurs informations
        """
        usb_devices = []
        
        try:
            # Si on analyse une image disque, cette collecte nécessite un accès au registre de l'image
            if self.image_path:
                logger.warning("La collecte des périphériques USB depuis une image disque nécessite un accès au registre.")
                return []
            
            # Ouverture de la clé de registre contenant les périphériques USB
            key_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            usb_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            
            # Parcours des périphériques
            i = 0
            while True:
                try:
                    # Récupération du nom de la sous-clé (type de périphérique)
                    device_type = winreg.EnumKey(usb_key, i)
                    device_key = winreg.OpenKey(usb_key, device_type)
                    
                    # Parcours des instances de ce type de périphérique
                    j = 0
                    while True:
                        try:
                            # Récupération du nom de l'instance (identifiant unique)
                            device_id = winreg.EnumKey(device_key, j)
                            instance_key = winreg.OpenKey(device_key, device_id)
                            
                            # Récupération des informations du périphérique
                            device_info = {
                                "type": device_type,
                                "id": device_id,
                                "properties": {}
                            }
                            
                            # Récupération des propriétés
                            try:
                                friendly_name, _ = winreg.QueryValueEx(instance_key, "FriendlyName")
                                device_info["properties"]["friendly_name"] = friendly_name
                            except:
                                pass
                            
                            try:
                                device_desc, _ = winreg.QueryValueEx(instance_key, "DeviceDesc")
                                device_info["properties"]["device_desc"] = device_desc
                            except:
                                pass
                            
                            # Récupération des informations de la sous-clé Properties
                            try:
                                properties_key = winreg.OpenKey(instance_key, "Properties")
                                
                                # Parcours des propriétés
                                k = 0
                                while True:
                                    try:
                                        prop_name = winreg.EnumKey(properties_key, k)
                                        prop_key = winreg.OpenKey(properties_key, prop_name)
                                        
                                        # Récupération des valeurs
                                        l = 0
                                        while True:
                                            try:
                                                value_name = winreg.EnumKey(prop_key, l)
                                                value_key = winreg.OpenKey(prop_key, value_name)
                                                
                                                try:
                                                    data, _ = winreg.QueryValueEx(value_key, "Data")
                                                    device_info["properties"][f"{prop_name}_{value_name}"] = data
                                                except:
                                                    pass
                                                
                                                winreg.CloseKey(value_key)
                                                l += 1
                                            except:
                                                break
                                        
                                        winreg.CloseKey(prop_key)
                                        k += 1
                                    except:
                                        break
                                
                                winreg.CloseKey(properties_key)
                            except:
                                pass
                            
                            # Ajout du périphérique à la liste
                            usb_devices.append(device_info)
                            
                            winreg.CloseKey(instance_key)
                            j += 1
                        except:
                            break
                    
                    winreg.CloseKey(device_key)
                    i += 1
                except:
                    break
            
            winreg.CloseKey(usb_key)
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des périphériques USB depuis le registre: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
        
        return usb_devices
    
    def _get_setupapi_log_devices(self) -> List[Dict[str, Any]]:
        """
        Collecte les informations sur les périphériques USB depuis le journal setupapi.
        
        Returns:
            Liste des périphériques USB avec leurs informations
        """
        usb_devices = []
        
        try:
            # Chemin du journal setupapi
            if self.image_path:
                setupapi_path = os.path.join(self.image_path, "Windows", "INF", "setupapi.dev.log")
            else:
                setupapi_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "INF", "setupapi.dev.log")
            
            if not os.path.exists(setupapi_path):
                logger.warning(f"Journal setupapi non trouvé: {setupapi_path}")
                return []
            
            # Copie du fichier journal pour analyse
            output_path = os.path.join(self.output_dir, "setupapi.dev.log")
            with open(setupapi_path, "r", encoding="utf-16", errors="ignore") as src, open(output_path, "w", encoding="utf-8") as dst:
                dst.write(src.read())
            
            # Analyse du journal pour trouver les périphériques USB
            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()
                
                # Recherche des sections concernant les périphériques USB
                sections = content.split(">>>")
                
                for section in sections:
                    if "USB" in section or "USBSTOR" in section:
                        # Extraction des informations
                        lines = section.strip().split("\n")
                        
                        device_info = {
                            "source": "setupapi",
                            "raw_data": section.strip(),
                            "properties": {}
                        }
                        
                        # Extraction de la date
                        for line in lines:
                            if line.startswith("["):
                                try:
                                    date_str = line.strip("[]")
                                    device_info["date"] = date_str
                                except:
                                    pass
                            
                            # Extraction du nom du périphérique
                            if "Device Install" in line and ":" in line:
                                parts = line.split(":", 1)
                                if len(parts) > 1:
                                    device_info["properties"]["name"] = parts[1].strip()
                            
                            # Extraction de l'ID du périphérique
                            if "Device ID:" in line:
                                parts = line.split(":", 1)
                                if len(parts) > 1:
                                    device_info["properties"]["device_id"] = parts[1].strip()
                        
                        # Ajout du périphérique à la liste s'il contient des informations
                        if "properties" in device_info and device_info["properties"]:
                            usb_devices.append(device_info)
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des périphériques USB depuis le journal setupapi: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
        
        return usb_devices
    
    def collect(self) -> Dict[str, Any]:
        """
        Collecte les informations sur les périphériques USB.
        
        Returns:
            Dictionnaire contenant les informations sur les périphériques USB
        """
        logger.info("Collecte des informations sur les périphériques USB...")
        
        # Collecte des périphériques USB depuis le registre
        registry_devices = self._get_registry_usb_devices()
        logger.info(f"Collecté {len(registry_devices)} périphériques USB depuis le registre")
        
        # Collecte des périphériques USB depuis le journal setupapi
        setupapi_devices = self._get_setupapi_log_devices()
        logger.info(f"Collecté {len(setupapi_devices)} périphériques USB depuis le journal setupapi")
        
        # Fusion des résultats
        all_devices = registry_devices + setupapi_devices
        
        # Sauvegarde des données en JSON
        json_path = os.path.join(self.output_dir, "usb_devices.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(all_devices, f, indent=4)
        
        # Sauvegarde des données en CSV pour une analyse plus facile
        csv_path = os.path.join(self.output_dir, "usb_devices.csv")
        if registry_devices:
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                # Détermination des champs à inclure
                fields = ['type', 'id', 'properties.friendly_name', 'properties.device_desc']
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                
                for device in registry_devices:
                    # Extraction des champs pertinents
                    row = {
                        'type': device.get('type', ''),
                        'id': device.get('id', '')
                    }
                    
                    # Ajout des propriétés si disponibles
                    if 'properties' in device:
                        row['properties.friendly_name'] = device['properties'].get('friendly_name', '')
                        row['properties.device_desc'] = device['properties'].get('device_desc', '')
                    else:
                        row['properties.friendly_name'] = ''
                        row['properties.device_desc'] = ''
                    
                    writer.writerow(row)
        
        return {
            "registry_devices": registry_devices,
            "setupapi_devices": setupapi_devices,
            "total_count": len(all_devices),
            "json_path": json_path,
            "csv_path": csv_path
        }

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de génération de rapports HTML.

Ce module est responsable de la génération de rapports HTML à partir
des artefacts collectés et des résultats d'analyse.
"""

import os
import logging
import datetime
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
import base64
import jinja2

logger = logging.getLogger("forensichunter")


class HTMLReporter:
    """Générateur de rapports HTML."""

    def __init__(self, config, output_dir):
        """
        Initialise le générateur de rapports HTML.
        
        Args:
            config: Configuration de l'application
            output_dir: Répertoire de sortie pour les rapports
        """
        self.config = config
        self.output_dir = output_dir
        
        # Chemin vers les templates
        self.template_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "templates")
        
        # Initialisation de l'environnement Jinja2
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Ajout de filtres personnalisés
        self.jinja_env.filters['format_timestamp'] = self._format_timestamp
        self.jinja_env.filters['format_size'] = self._format_size
        self.jinja_env.filters['to_json'] = self._to_json
    
    def _format_timestamp(self, timestamp):
        """Formate un timestamp en date lisible."""
        if not timestamp:
            return "N/A"
        
        try:
            if isinstance(timestamp, str):
                # Si c'est déjà une chaîne ISO, on la parse
                dt = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                # Sinon, on suppose que c'est un timestamp Unix
                return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except:
            return str(timestamp)
    
    def _format_size(self, size_bytes):
        """Formate une taille en octets en format lisible."""
        if not isinstance(size_bytes, (int, float)):
            return "N/A"
        
        # Conversion en format lisible
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        
        return f"{size_bytes:.2f} PB"
    
    def _to_json(self, data):
        """Convertit des données en JSON formaté."""
        return json.dumps(data, indent=2)
    
    def _create_default_template(self):
        """
        Crée un template HTML par défaut si aucun n'est trouvé.
        
        Returns:
            Chemin vers le template créé
        """
        template_path = os.path.join(self.template_dir, "report.html")
        
        # Création du répertoire des templates s'il n'existe pas
        os.makedirs(self.template_dir, exist_ok=True)
        
        # Contenu du template par défaut
        template_content = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForensicHunter - Rapport d'analyse</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --accent-color: #e74c3c;
            --bg-color: #f9f9f9;
            --text-color: #333;
            --border-color: #ddd;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--bg-color);
            margin: 0;
            padding: 0;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px;
            text-align: center;
            margin-bottom: 30px;
        }
        
        h1, h2, h3, h4 {
            color: var(--primary-color);
            margin-top: 30px;
        }
        
        .summary {
            background-color: white;
            border: 1px solid var(--border-color);
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .card {
            background-color: white;
            border: 1px solid var(--border-color);
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .card h3 {
            margin-top: 0;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        
        table, th, td {
            border: 1px solid var(--border-color);
        }
        
        th, td {
            padding: 12px;
            text-align: left;
        }
        
        th {
            background-color: var(--primary-color);
            color: white;
        }
        
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        
        .alert {
            background-color: #f8d7da;
            color: #721c24;
            padding: 10px;
            border: 1px solid #f5c6cb;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .warning {
            background-color: #fff3cd;
            color: #856404;
            padding: 10px;
            border: 1px solid #ffeeba;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .info {
            background-color: #d1ecf1;
            color: #0c5460;
            padding: 10px;
            border: 1px solid #bee5eb;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .success {
            background-color: #d4edda;
            color: #155724;
            padding: 10px;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .tab {
            overflow: hidden;
            border: 1px solid var(--border-color);
            background-color: #f1f1f1;
            border-radius: 5px 5px 0 0;
        }
        
        .tab button {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
            font-size: 16px;
        }
        
        .tab button:hover {
            background-color: #ddd;
        }
        
        .tab button.active {
            background-color: var(--secondary-color);
            color: white;
        }
        
        .tabcontent {
            display: none;
            padding: 20px;
            border: 1px solid var(--border-color);
            border-top: none;
            border-radius: 0 0 5px 5px;
            animation: fadeEffect 1s;
        }
        
        @keyframes fadeEffect {
            from {opacity: 0;}
            to {opacity: 1;}
        }
        
        .collapsible {
            background-color: #f1f1f1;
            color: var(--primary-color);
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 16px;
            border-radius: 5px;
            margin-bottom: 5px;
        }
        
        .active, .collapsible:hover {
            background-color: #ddd;
        }
        
        .collapsible:after {
            content: '\\002B';
            color: var(--primary-color);
            font-weight: bold;
            float: right;
            margin-left: 5px;
        }
        
        .active:after {
            content: "\\2212";
        }
        
        .content {
            padding: 0 18px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background-color: white;
            border-radius: 0 0 5px 5px;
        }
        
        footer {
            background-color: var(--primary-color);
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 50px;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            table {
                display: block;
                overflow-x: auto;
            }
        }
    </style>
</head>
<body>
    <header>
        <h1>ForensicHunter - Rapport d'analyse forensique</h1>
        <p>Généré le {{ report_date }}</p>
    </header>
    
    <div class="container">
        <div class="summary">
            <h2>Résumé de l'analyse</h2>
            <p><strong>Système analysé:</strong> {{ system_info.hostname }} ({{ system_info.os }})</p>
            <p><strong>Date de l'analyse:</strong> {{ report_date }}</p>
            <p><strong>Durée de l'analyse:</strong> {{ execution_time }} secondes</p>
            <p><strong>Artefacts collectés:</strong> {{ total_artifacts }}</p>
            
            {% if alerts %}
            <div class="alert">
                <h3>Alertes détectées ({{ alerts|length }})</h3>
                <ul>
                {% for alert in alerts %}
                    <li>{{ alert.description }} (Score: {{ alert.score }})</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
        </div>
        
        <h2>Table des matières</h2>
        <ul>
            <li><a href="#system-info">Informations système</a></li>
            {% if eventlogs_data %}
            <li><a href="#eventlogs">Journaux d'événements</a></li>
            {% endif %}
            {% if registry_data %}
            <li><a href="#registry">Registre Windows</a></li>
            {% endif %}
            {% if filesystem_data %}
            <li><a href="#filesystem">Fichiers temporaires et artefacts</a></li>
            {% endif %}
            {% if browser_data %}
            <li><a href="#browsers">Historique des navigateurs</a></li>
            {% endif %}
            {% if process_data %}
            <li><a href="#processes">Processus en cours</a></li>
            {% endif %}
            {% if network_data %}
            <li><a href="#network">Connexions réseau</a></li>
            {% endif %}
            {% if usb_data %}
            <li><a href="#usb">Périphériques USB</a></li>
            {% endif %}
            {% if memory_data %}
            <li><a href="#memory">Capture mémoire</a></li>
            {% endif %}
            {% if userdata_data %}
            <li><a href="#userdata">Données utilisateur</a></li>
            {% endif %}
        </ul>
        
        <h2 id="system-info">Informations système</h2>
        <div class="card">
            <table>
                <tr>
                    <th>Propriété</th>
                    <th>Valeur</th>
                </tr>
                <tr>
                    <td>Nom d'hôte</td>
                    <td>{{ system_info.hostname }}</td>
                </tr>
                <tr>
                    <td>Système d'exploitation</td>
                    <td>{{ system_info.os }}</td>
                </tr>
                <tr>
                    <td>Version</td>
                    <td>{{ system_info.version }}</td>
                </tr>
                <tr>
                    <td>Architecture</td>
                    <td>{{ system_info.architecture }}</td>
                </tr>
                <tr>
                    <td>Utilisateur</td>
                    <td>{{ system_info.user }}</td>
                </tr>
                <tr>
                    <td>Date de démarrage</td>
                    <td>{{ system_info.boot_time|format_timestamp }}</td>
                </tr>
            </table>
        </div>
        
        {% if eventlogs_data %}
        <h2 id="eventlogs">Journaux d'événements</h2>
        <div class="card">
            <h3>Résumé des journaux</h3>
            <table>
                <tr>
                    <th>Journal</th>
                    <th>Nombre d'événements</th>
                </tr>
                {% for log_name, events in eventlogs_data.items() %}
                <tr>
                    <td>{{ log_name }}</td>
                    <td>{{ events|length if events is iterable and events is not string else 'Erreur' }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h3>Événements importants</h3>
            <button class="collapsible">Afficher les événements importants</button>
            <div class="content">
                <table>
                    <tr>
                        <th>ID</th>
                        <th>Date</th>
                        <th>Source</th>
                        <th>Description</th>
                    </tr>
                    {% for log_name, events in eventlogs_data.items() %}
                        {% if events is iterable and events is not string %}
                            {% for event in events[:20] %}
                            <tr>
                                <td>{{ event.EventID }}</td>
                                <td>{{ event.TimeCreated }}</td>
                                <td>{{ event.Provider }}</td>
                                <td>{{ event.Description }}</td>
                            </tr>
                            {% endfor %}
                        {% endif %}
                    {% endfor %}
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if registry_data %}
        <h2 id="registry">Registre Windows</h2>
        <div class="card">
            <h3>Ruches analysées</h3>
            <table>
                <tr>
                    <th>Ruche</th>
                    <th>Chemin</th>
                    <th>Clés analysées</th>
                </tr>
                {% for hive_name, hive_data in registry_data.items() %}
                <tr>
                    <td>{{ hive_name }}</td>
                    <td>{{ hive_data.path }}</td>
                    <td>{{ hive_data.keys|length if hive_data.keys is defined else 'N/A' }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h3>Clés importantes</h3>
            <button class="collapsible">Afficher les clés importantes</button>
            <div class="content">
                {% for hive_name, hive_data in registry_data.items() %}
                    {% if hive_data.keys is defined %}
                        <h4>{{ hive_name }}</h4>
                        {% for key_path, key_data in hive_data.keys.items() %}
                            <div class="info">
                                <strong>{{ key_path }}</strong>
                                <p>Dernière modification: {{ key_data.last_modified }}</p>
                                {% if key_data.values %}
                                <table>
                                    <tr>
                                        <th>Nom</th>
                                        <th>Type</th>
                                        <th>Valeur</th>
                                    </tr>
                                    {% for name, value in key_data.values.items() %}
                                    <tr>
                                        <td>{{ name }}</td>
                                        <td>{{ value.type }}</td>
                                        <td>{{ value.data }}</td>
                                    </tr>
                                    {% endfor %}
                                </table>
                                {% endif %}
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        {% if filesystem_data %}
        <h2 id="filesystem">Fichiers temporaires et artefacts</h2>
        <div class="card">
            <h3>Résumé des artefacts</h3>
            <table>
                <tr>
                    <th>Type d'artefact</th>
                    <th>Nombre de fichiers</th>
                    <th>Taille totale</th>
                </tr>
                {% for artifact_name, artifact_data in filesystem_data.artifacts.items() %}
                <tr>
                    <td>{{ artifact_name }}</td>
                    <td>{{ artifact_data.count }}</td>
                    <td>{{ artifact_data.total_size|format_size }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h3>Fichiers récents</h3>
            <button class="collapsible">Afficher les fichiers récents</button>
            <div class="content">
                <table>
                    <tr>
                        <th>Nom</th>
                        <th>Type</th>
                        <th>Taille</th>
                        <th>Date de modification</th>
                        <th>Chemin</th>
                    </tr>
                    {% for artifact_name, artifact_data in filesystem_data.artifacts.items() %}
                        {% if artifact_data.files is defined %}
                            {% for file in artifact_data.files[:10] %}
                            <tr>
                                <td>{{ file.name }}</td>
                                <td>{{ artifact_name }}</td>
                                <td>{{ file.size|format_size }}</td>
                                <td>{{ file.modified }}</td>
                                <td>{{ file.path }}</td>
                            </tr>
                            {% endfor %}
                        {% endif %}
                    {% endfor %}
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if browser_data %}
        <h2 id="browsers">Historique des navigateurs</h2>
        <div class="card">
            <h3>Résumé des navigateurs</h3>
            <table>
                <tr>
                    <th>Navigateur</th>
                    <th>Entrées d'historique</th>
                    <th>Favoris</th>
                </tr>
                {% for browser_name, browser_info in browser_data.items() %}
                <tr>
                    <td>{{ browser_name }}</td>
                    <td>{{ browser_info.history|length if browser_info.history is defined else 'N/A' }}</td>
                    <td>{{ browser_info.bookmarks|length if browser_info.bookmarks is defined else 'N/A' }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h3>Sites visités récemment</h3>
            <button class="collapsible">Afficher l'historique récent</button>
            <div class="content">
                <table>
                    <tr>
                        <th>Navigateur</th>
                        <th>URL</th>
                        <th>Titre</th>
                        <th>Date de visite</th>
                    </tr>
                    {% for browser_name, browser_info in browser_data.items() %}
                        {% if browser_info.history is defined %}
                            {% for entry in browser_info.history[:20] %}
                            <tr>
                                <td>{{ browser_name }}</td>
                                <td>{{ entry.url }}</td>
                                <td>{{ entry.title }}</td>
                                <td>{{ entry.last_visit_time }}</td>
                            </tr>
                            {% endfor %}
                        {% endif %}
                    {% endfor %}
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if process_data %}
        <h2 id="processes">Processus en cours</h2>
        <div class="card">
            <h3>Résumé des processus</h3>
            <p>Nombre total de processus: {{ process_data.count }}</p>
            
            <button class="collapsible">Afficher les processus</button>
            <div class="content">
                <table>
                    <tr>
                        <th>PID</th>
                        <th>Nom</th>
                        <th>Utilisateur</th>
                        <th>Chemin</th>
                        <th>Démarré le</th>
                        <th>CPU %</th>
                        <th>Mémoire %</th>
                    </tr>
                    {% for process in process_data.processes %}
                    <tr>
                        <td>{{ process.pid }}</td>
                        <td>{{ process.name }}</td>
                        <td>{{ process.username }}</td>
                        <td>{{ process.exe }}</td>
                        <td>{{ process.create_time }}</td>
                        <td>{{ process.cpu_percent }}</td>
                        <td>{{ process.memory_percent }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if network_data %}
        <h2 id="network">Connexions réseau</h2>
        <div class="card">
            <h3>Résumé des connexions</h3>
            <p>Nombre total de connexions: {{ network_data.connections_count }}</p>
            
            <button class="collapsible">Afficher les connexions</button>
            <div class="content">
                <table>
                    <tr>
                        <th>Processus</th>
                        <th>PID</th>
                        <th>Adresse locale</th>
                        <th>Adresse distante</th>
                        <th>État</th>
                    </tr>
                    {% for conn in network_data.connections %}
                    <tr>
                        <td>{{ conn.process.name if conn.process else 'N/A' }}</td>
                        <td>{{ conn.pid }}</td>
                        <td>{{ conn.laddr }}</td>
                        <td>{{ conn.raddr }}</td>
                        <td>{{ conn.status }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            <h3>Interfaces réseau</h3>
            <button class="collapsible">Afficher les interfaces</button>
            <div class="content">
                <table>
                    <tr>
                        <th>Interface</th>
                        <th>Adresses</th>
                        <th>État</th>
                    </tr>
                    {% for interface_name, interface_data in network_data.interfaces.items() %}
                    <tr>
                        <td>{{ interface_name }}</td>
                        <td>
                            {% for addr in interface_data.addresses %}
                                {{ addr.address }}{% if not loop.last %}, {% endif %}
                            {% endfor %}
                        </td>
                        <td>{{ 'Actif' if interface_data.stats.isup else 'Inactif' }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if usb_data %}
        <h2 id="usb">Périphériques USB</h2>
        <div class="card">
            <h3>Résumé des périphériques</h3>
            <p>Nombre total de périphériques: {{ usb_data.total_count }}</p>
            
            <button class="collapsible">Afficher les périphériques</button>
            <div class="content">
                <table>
                    <tr>
                        <th>Type</th>
                        <th>ID</th>
                        <th>Nom</th>
                        <th>Description</th>
                    </tr>
                    {% for device in usb_data.registry_devices %}
                    <tr>
                        <td>{{ device.type }}</td>
                        <td>{{ device.id }}</td>
                        <td>{{ device.properties.friendly_name if device.properties.friendly_name is defined else 'N/A' }}</td>
                        <td>{{ device.properties.device_desc if device.properties.device_desc is defined else 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </div>
        {% endif %}
        
        {% if memory_data %}
        <h2 id="memory">Capture mémoire</h2>
        <div class="card">
            <h3>Résumé de la capture</h3>
            {% if memory_data.capture.success %}
                <div class="success">
                    <p>Capture mémoire réussie</p>
                    <p>Fichier: {{ memory_data.capture.dump_path }}</p>
                    <p>Taille: {{ memory_data.capture.size|format_size }}</p>
                    <p>Date: {{ memory_data.capture.timestamp }}</p>
                </div>
            {% else %}
                <div class="alert">
                    <p>Échec de la capture mémoire</p>
                    <p>Erreur: {{ memory_data.capture.error }}</p>
                </div>
            {% endif %}
        </div>
        {% endif %}
        
        {% if userdata_data %}
        <h2 id="userdata">Données utilisateur</h2>
        <div class="card">
            <h3>Résumé des données</h3>
            <p>Nombre total de fichiers: {{ userdata_data.total_files }}</p>
            <p>Fichiers intéressants: {{ userdata_data.total_interesting_files }}</p>
            
            <h3>Fichiers intéressants</h3>
            <button class="collapsible">Afficher les fichiers intéressants</button>
            <div class="content">
                <table>
                    <tr>
                        <th>Nom</th>
                        <th>Type</th>
                        <th>Taille</th>
                        <th>Date de modification</th>
                        <th>Chemin</th>
                    </tr>
                    {% for data_type, data_info in userdata_data.data.items() %}
                        {% if data_info.files is defined %}
                            {% for file in data_info.files %}
                                {% if file.interesting %}
                                <tr>
                                    <td>{{ file.name }}</td>
                                    <td>{{ data_type }}</td>
                                    <td>{{ file.size|format_size }}</td>
                                    <td>{{ file.modified }}</td>
                                    <td>{{ file.path }}</td>
                                </tr>
                                {% endif %}
                            {% endfor %}
                        {% endif %}
                    {% endfor %}
                </table>
            </div>
        </div>
        {% endif %}
    </div>
    
    <footer>
        <p>Rapport généré par ForensicHunter v1.0.0</p>
        <p>© 2025 ForensicHunter - Outil de forensic avancé pour Windows</p>
    </footer>
    
    <script>
        // Script pour les onglets
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        
        // Script pour les éléments pliables
        var coll = document.getElementsByClassName("collapsible");
        var i;
        
        for (i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                } else {
                    content.style.maxHeight = content.scrollHeight + "px";
                }
            });
        }
    </script>
</body>
</html>
"""
        
        # Écriture du template
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)
        
        return template_path
    
    def generate(self, artifacts: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
        """
        Génère un rapport HTML à partir des artefacts collectés et des résultats d'analyse.
        
        Args:
            artifacts: Dictionnaire contenant tous les artefacts collectés
            analysis_results: Dictionnaire contenant les résultats d'analyse
            
        Returns:
            Chemin vers le rapport HTML généré
        """
        # Vérification de l'existence du template
        template_path = os.path.join(self.template_dir, "report.html")
        if not os.path.exists(template_path):
            template_path = self._create_default_template()
        
        # Chargement du template
        template = self.jinja_env.get_template(os.path.basename(template_path))
        
        # Préparation des données pour le template
        template_data = {
            "report_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system_info": self._get_system_info(),
            "execution_time": getattr(self.config, "execution_time", 0),
            "total_artifacts": self._count_artifacts(artifacts),
            "alerts": analysis_results.get("alerts", []),
            
            # Données des artefacts
            "eventlogs_data": artifacts.get("EventLogCollector", {}),
            "registry_data": artifacts.get("RegistryCollector", {}),
            "filesystem_data": artifacts.get("FilesystemCollector", {}),
            "browser_data": artifacts.get("BrowserHistoryCollector", {}),
            "process_data": artifacts.get("ProcessCollector", {}),
            "network_data": artifacts.get("NetworkCollector", {}),
            "usb_data": artifacts.get("USBCollector", {}),
            "memory_data": artifacts.get("MemoryCollector", {}),
            "userdata_data": artifacts.get("UserDataCollector", {})
        }
        
        # Génération du rapport HTML
        html_content = template.render(**template_data)
        
        # Écriture du rapport dans un fichier
        report_path = os.path.join(self.output_dir, f"forensichunter_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    
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
    
    def _count_artifacts(self, artifacts: Dict[str, Any]) -> int:
        """
        Compte le nombre total d'artefacts collectés.
        
        Args:
            artifacts: Dictionnaire contenant tous les artefacts collectés
            
        Returns:
            Nombre total d'artefacts
        """
        count = 0
        
        for collector_name, collector_data in artifacts.items():
            if isinstance(collector_data, dict):
                # Comptage spécifique selon le type de collecteur
                if collector_name == "EventLogCollector":
                    for log_name, events in collector_data.items():
                        if isinstance(events, list):
                            count += len(events)
                
                elif collector_name == "FilesystemCollector":
                    if "total_files" in collector_data:
                        count += collector_data["total_files"]
                
                elif collector_name == "ProcessCollector":
                    if "count" in collector_data:
                        count += collector_data["count"]
                
                elif collector_name == "NetworkCollector":
                    if "connections_count" in collector_data:
                        count += collector_data["connections_count"]
                
                elif collector_name == "USBCollector":
                    if "total_count" in collector_data:
                        count += collector_data["total_count"]
                
                elif collector_name == "UserDataCollector":
                    if "total_files" in collector_data:
                        count += collector_data["total_files"]
                
                # Pour les autres collecteurs, on essaie de compter les éléments
                else:
                    for key, value in collector_data.items():
                        if isinstance(value, list):
                            count += len(value)
        
        return count

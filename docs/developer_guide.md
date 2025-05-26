#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guide du développeur de ForensicHunter.

Ce document fournit des informations détaillées pour les développeurs
souhaitant contribuer au projet ForensicHunter ou étendre ses fonctionnalités.
"""

# Guide du développeur ForensicHunter

## Introduction

Ce guide est destiné aux développeurs souhaitant contribuer au projet ForensicHunter ou étendre ses fonctionnalités. Il couvre l'architecture du projet, les conventions de codage, le développement de plugins et les procédures de contribution.

## Architecture du projet

ForensicHunter est organisé selon une architecture modulaire qui facilite l'extension et la maintenance :

```
ForensicHunter/
├── src/                    # Code source principal
│   ├── collectors/         # Modules de collecte d'artefacts
│   │   ├── collector_manager.py  # Gestionnaire des collecteurs
│   │   ├── event_logs.py   # Collecteur de journaux d'événements
│   │   ├── registry.py     # Collecteur de registre
│   │   ├── filesystem.py   # Collecteur de fichiers système
│   │   ├── browser.py      # Collecteur d'historique de navigateurs
│   │   ├── process.py      # Collecteur de processus
│   │   ├── network.py      # Collecteur de connexions réseau
│   │   ├── usb.py          # Collecteur de périphériques USB
│   │   ├── memory.py       # Collecteur de mémoire RAM
│   │   └── user_data.py    # Collecteur de données utilisateur
│   ├── analyzers/          # Modules d'analyse et de détection
│   │   ├── analyzer_manager.py  # Gestionnaire des analyseurs
│   │   ├── event_analyzer.py    # Analyseur de journaux d'événements
│   │   ├── registry_analyzer.py # Analyseur de registre
│   │   ├── filesystem_analyzer.py  # Analyseur de fichiers système
│   │   ├── browser_analyzer.py  # Analyseur d'historique de navigateurs
│   │   ├── process_analyzer.py  # Analyseur de processus
│   │   ├── network_analyzer.py  # Analyseur de connexions réseau
│   │   ├── usb_analyzer.py      # Analyseur de périphériques USB
│   │   └── userdata_analyzer.py # Analyseur de données utilisateur
│   ├── reporters/          # Générateurs de rapports
│   │   ├── reporter_manager.py  # Gestionnaire des reporters
│   │   ├── html_reporter.py     # Reporter HTML
│   │   ├── json_reporter.py     # Reporter JSON
│   │   └── csv_reporter.py      # Reporter CSV
│   ├── plugins/            # Système de plugins
│   │   └── plugin_manager.py    # Gestionnaire de plugins
│   ├── utils/              # Utilitaires communs
│   │   ├── config.py       # Gestion de la configuration
│   │   ├── logger.py       # Configuration des journaux
│   │   └── helpers.py      # Fonctions utilitaires diverses
│   └── forensichunter.py   # Point d'entrée principal
├── rules/                  # Règles YARA et IOCs
│   ├── yara/               # Règles YARA
│   └── ioc/                # Indicateurs de compromission
├── templates/              # Templates pour les rapports
│   └── report.html         # Template HTML principal
├── static/                 # Ressources statiques
│   ├── css/                # Feuilles de style
│   ├── js/                 # Scripts JavaScript
│   └── img/                # Images
├── docs/                   # Documentation
│   ├── user_manual.md      # Manuel utilisateur
│   ├── developer_guide.md  # Guide du développeur
│   ├── api_reference.md    # Référence API
│   └── plugin_guide.md     # Guide des plugins
├── plugins/                # Plugins tiers
│   ├── collectors/         # Plugins de collecte
│   ├── analyzers/          # Plugins d'analyse
│   └── reporters/          # Plugins de rapport
├── tests/                  # Tests unitaires et d'intégration
├── install.bat             # Script d'installation Windows
├── requirements.txt        # Dépendances Python
├── LICENSE                 # Licence du projet
└── README.md               # Documentation principale
```

## Conventions de codage

ForensicHunter suit les conventions de codage Python standard (PEP 8) avec quelques spécificités :

1. **Docstrings** : Toutes les fonctions, classes et modules doivent avoir des docstrings au format Google.
2. **Typage** : Utilisez les annotations de type Python pour améliorer la lisibilité et permettre la vérification statique.
3. **Logging** : Utilisez le module de logging intégré plutôt que des prints.
4. **Gestion des erreurs** : Capturez et journalisez les exceptions de manière appropriée.
5. **Tests** : Écrivez des tests unitaires pour toutes les nouvelles fonctionnalités.

Exemple de code conforme :

```python
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger("forensichunter")

def process_artifact(artifact: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Traite un artefact et extrait les informations pertinentes.
    
    Args:
        artifact: Dictionnaire contenant les données de l'artefact
        
    Returns:
        Dictionnaire contenant les informations extraites, ou None en cas d'erreur
    """
    try:
        # Traitement de l'artefact
        result = {"processed": True, "data": artifact.get("data")}
        logger.debug(f"Artefact traité avec succès: {artifact.get('id')}")
        return result
    except Exception as e:
        logger.error(f"Erreur lors du traitement de l'artefact: {str(e)}")
        logger.debug("Détails de l'erreur:", exc_info=True)
        return None
```

## Développement de plugins

ForensicHunter supporte trois types de plugins :

1. **Collecteurs** : Pour collecter de nouveaux types d'artefacts
2. **Analyseurs** : Pour analyser et détecter des anomalies
3. **Reporters** : Pour générer des rapports dans de nouveaux formats

### Structure d'un plugin

Chaque plugin doit être placé dans le répertoire approprié (`plugins/collectors/`, `plugins/analyzers/` ou `plugins/reporters/`) et hériter de la classe d'interface correspondante.

### Exemple de plugin collecteur

```python
from src.plugins.plugin_manager import CollectorPlugin

class CustomLogCollector(CollectorPlugin):
    """Collecteur pour des journaux personnalisés."""

    def __init__(self, config):
        """
        Initialise le collecteur de journaux personnalisés.
        
        Args:
            config: Configuration de l'application
        """
        super().__init__(config)
        self.name = "CustomLogCollector"
        self.description = "Collecte des journaux personnalisés"
        self.version = "1.0.0"
        self.author = "Votre Nom"
        
        # Configuration spécifique au plugin
        self.log_path = config.args.custom_log_path if hasattr(config.args, "custom_log_path") else "C:\\Logs"
    
    def collect(self) -> Dict[str, Any]:
        """
        Collecte des journaux personnalisés.
        
        Returns:
            Dictionnaire contenant les journaux collectés
        """
        import os
        import json
        
        logs = []
        
        try:
            # Vérification de l'existence du répertoire
            if not os.path.exists(self.log_path):
                return {"error": f"Répertoire non trouvé: {self.log_path}"}
            
            # Parcours des fichiers de journaux
            for filename in os.listdir(self.log_path):
                if filename.endswith(".log"):
                    file_path = os.path.join(self.log_path, filename)
                    
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    
                    logs.append({
                        "filename": filename,
                        "path": file_path,
                        "content": content,
                        "size": os.path.getsize(file_path),
                        "modified": os.path.getmtime(file_path)
                    })
            
            return {"logs": logs, "count": len(logs)}
            
        except Exception as e:
            import logging
            logger = logging.getLogger("forensichunter")
            logger.error(f"Erreur lors de la collecte des journaux personnalisés: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            return {"error": str(e)}
```

### Exemple de plugin analyseur

```python
from src.plugins.plugin_manager import AnalyzerPlugin

class CustomLogAnalyzer(AnalyzerPlugin):
    """Analyseur pour des journaux personnalisés."""

    def __init__(self, config):
        """
        Initialise l'analyseur de journaux personnalisés.
        
        Args:
            config: Configuration de l'application
        """
        super().__init__(config)
        self.name = "CustomLogAnalyzer"
        self.description = "Analyse des journaux personnalisés"
        self.version = "1.0.0"
        self.author = "Votre Nom"
        
        # Patterns suspects à rechercher
        self.suspicious_patterns = [
            "error",
            "failed",
            "unauthorized",
            "exception",
            "attack"
        ]
    
    def analyze(self, artifacts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse des journaux personnalisés.
        
        Args:
            artifacts: Dictionnaire contenant les artefacts à analyser
            
        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        import re
        import logging
        
        logger = logging.getLogger("forensichunter")
        alerts = []
        
        try:
            # Vérification de la présence des journaux personnalisés
            if "CustomLogCollector" not in artifacts or "logs" not in artifacts["CustomLogCollector"]:
                return {"alerts": [], "scores": {"custom_logs": 0}}
            
            logs = artifacts["CustomLogCollector"]["logs"]
            
            # Analyse de chaque journal
            for log in logs:
                content = log.get("content", "")
                
                # Recherche des patterns suspects
                for pattern in self.suspicious_patterns:
                    matches = re.finditer(r'\b' + re.escape(pattern) + r'\b', content, re.IGNORECASE)
                    
                    for match in matches:
                        # Extraction du contexte (ligne entière)
                        line_start = content.rfind('\n', 0, match.start()) + 1
                        line_end = content.find('\n', match.end())
                        if line_end == -1:
                            line_end = len(content)
                        
                        line = content[line_start:line_end].strip()
                        
                        # Création d'une alerte
                        alerts.append({
                            "type": "suspicious_log_entry",
                            "description": f"Entrée de journal suspecte contenant '{pattern}'",
                            "severity": "medium",
                            "score": 50,
                            "source": log.get("filename", "unknown"),
                            "details": {
                                "pattern": pattern,
                                "line": line,
                                "file": log.get("path", "")
                            }
                        })
            
            # Calcul du score global
            score = min(100, len(alerts) * 10)
            
            return {
                "alerts": alerts,
                "scores": {"custom_logs": score},
                "summary": {
                    "analyzed_logs": len(logs),
                    "suspicious_entries": len(alerts)
                }
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des journaux personnalisés: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            return {"alerts": [], "scores": {"custom_logs": 0}, "error": str(e)}
```

### Exemple de plugin reporter

```python
from src.plugins.plugin_manager import ReporterPlugin

class MarkdownReporter(ReporterPlugin):
    """Générateur de rapports au format Markdown."""

    def __init__(self, config):
        """
        Initialise le générateur de rapports Markdown.
        
        Args:
            config: Configuration de l'application
        """
        super().__init__(config)
        self.name = "MarkdownReporter"
        self.description = "Génère des rapports au format Markdown"
        self.version = "1.0.0"
        self.author = "Votre Nom"
        
        # Configuration spécifique au plugin
        import os
        self.output_dir = os.path.join(config.output_dir, "reports", "markdown")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate(self, artifacts: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
        """
        Génère un rapport Markdown à partir des artefacts collectés et des résultats d'analyse.
        
        Args:
            artifacts: Dictionnaire contenant tous les artefacts collectés
            analysis_results: Dictionnaire contenant les résultats d'analyse
            
        Returns:
            Chemin vers le rapport Markdown généré
        """
        import os
        import datetime
        import logging
        
        logger = logging.getLogger("forensichunter")
        
        try:
            # Chemin du rapport
            report_path = os.path.join(self.output_dir, f"forensichunter_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
            
            # Génération du contenu Markdown
            content = []
            
            # En-tête
            content.append("# ForensicHunter - Rapport d'analyse forensique")
            content.append(f"*Généré le {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
            content.append("")
            
            # Résumé
            content.append("## Résumé de l'analyse")
            content.append("")
            content.append(f"- **Score global**: {analysis_results.get('global_score', 0)}/100")
            content.append(f"- **Alertes détectées**: {len(analysis_results.get('alerts', []))}")
            content.append("")
            
            # Alertes
            if analysis_results.get('alerts'):
                content.append("## Alertes détectées")
                content.append("")
                content.append("| Type | Description | Sévérité | Score | Source |")
                content.append("| ---- | ----------- | -------- | ----- | ------ |")
                
                for alert in analysis_results['alerts']:
                    content.append(f"| {alert.get('type', 'N/A')} | {alert.get('description', 'N/A')} | {alert.get('severity', 'N/A')} | {alert.get('score', 0)} | {alert.get('source', 'N/A')} |")
                
                content.append("")
            
            # Artefacts collectés
            content.append("## Artefacts collectés")
            content.append("")
            
            for collector_name, collector_data in artifacts.items():
                content.append(f"### {collector_name}")
                content.append("")
                
                # Traitement spécifique selon le type de collecteur
                if collector_name == "EventLogCollector":
                    content.append("#### Journaux d'événements")
                    content.append("")
                    for log_name, events in collector_data.items():
                        if isinstance(events, list):
                            content.append(f"- **{log_name}**: {len(events)} événements")
                    content.append("")
                
                elif collector_name == "ProcessCollector":
                    if "count" in collector_data:
                        content.append(f"- **Processus**: {collector_data['count']} processus en cours d'exécution")
                    content.append("")
                
                # Ajoutez d'autres traitements spécifiques selon les besoins
            
            # Écriture du rapport
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content))
            
            logger.info(f"Rapport Markdown généré: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport Markdown: {str(e)}")
            logger.debug("Détails de l'erreur:", exc_info=True)
            return ""
```

## Procédure de contribution

Pour contribuer au projet ForensicHunter :

1. **Forkez le dépôt** : Créez une copie du dépôt sur votre compte GitHub.
2. **Clonez votre fork** : `git clone https://github.com/votre-username/forensichunter.git`
3. **Créez une branche** : `git checkout -b feature/ma-fonctionnalite`
4. **Développez votre fonctionnalité** : Suivez les conventions de codage et ajoutez des tests.
5. **Testez votre code** : Exécutez les tests unitaires et d'intégration.
6. **Committez vos changements** : `git commit -m "Ajout de ma fonctionnalité"`
7. **Poussez vers votre fork** : `git push origin feature/ma-fonctionnalite`
8. **Créez une Pull Request** : Depuis votre fork sur GitHub, créez une Pull Request vers le dépôt principal.

### Directives pour les Pull Requests

- Assurez-vous que votre code respecte les conventions de codage.
- Incluez des tests pour les nouvelles fonctionnalités.
- Mettez à jour la documentation si nécessaire.
- Expliquez clairement le but et le fonctionnement de votre contribution.
- Répondez aux commentaires et apportez les modifications demandées.

## Tests

ForensicHunter utilise le framework de test `pytest` pour les tests unitaires et d'intégration.

Pour exécuter les tests :

```
cd forensichunter
pytest
```

Pour exécuter un test spécifique :

```
pytest tests/test_specific_module.py
```

Pour exécuter les tests avec couverture de code :

```
pytest --cov=src tests/
```

## Documentation

La documentation est générée à l'aide de Sphinx. Pour générer la documentation :

```
cd docs
make html
```

La documentation générée sera disponible dans le répertoire `docs/_build/html/`.

## Conclusion

Ce guide du développeur devrait vous aider à comprendre l'architecture de ForensicHunter et à contribuer efficacement au projet. Si vous avez des questions ou des suggestions, n'hésitez pas à ouvrir une issue sur GitHub ou à contacter l'équipe de développement.

Merci de contribuer à ForensicHunter !

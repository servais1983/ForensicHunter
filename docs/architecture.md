# Architecture de ForensicHunter

## Vue d'ensemble

ForensicHunter est conçu selon une architecture modulaire qui permet une grande flexibilité et extensibilité. L'application est divisée en trois composants principaux :

1. **Collecteurs** : Modules responsables de la collecte des artefacts forensiques
2. **Analyseurs** : Modules responsables de l'analyse des artefacts et de la détection des menaces
3. **Rapporteurs** : Modules responsables de la génération des rapports

Ces composants interagissent via des interfaces bien définies et un système de plugins qui permet d'ajouter facilement de nouvelles fonctionnalités.

## Diagramme d'architecture

```
+---------------------+     +---------------------+     +---------------------+
|                     |     |                     |     |                     |
|     Collecteurs     |---->|     Analyseurs      |---->|     Rapporteurs     |
|                     |     |                     |     |                     |
+---------------------+     +---------------------+     +---------------------+
         ^                           ^                           ^
         |                           |                           |
         v                           v                           v
+---------------------+     +---------------------+     +---------------------+
|                     |     |                     |     |                     |
|  Système de Plugins |     |  Système de Plugins |     |  Système de Plugins |
|                     |     |                     |     |                     |
+---------------------+     +---------------------+     +---------------------+
         ^                           ^                           ^
         |                           |                           |
         v                           v                           v
+-------------------------------------------------------------------------+
|                                                                         |
|                        Core ForensicHunter                              |
|                                                                         |
+-------------------------------------------------------------------------+
         ^                           ^                           ^
         |                           |                           |
         v                           v                           v
+---------------------+     +---------------------+     +---------------------+
|                     |     |                     |     |                     |
|        CLI          |     |        GUI          |     |      Config         |
|                     |     |                     |     |                     |
+---------------------+     +---------------------+     +---------------------+
```

## Composants principaux

### Core ForensicHunter

Le cœur de l'application qui coordonne l'exécution des différents modules et gère le flux de données entre eux.

Responsabilités :
- Initialisation de l'application
- Chargement des plugins
- Coordination des collecteurs, analyseurs et rapporteurs
- Gestion des erreurs et des exceptions
- Gestion de la configuration

### Collecteurs

Les collecteurs sont responsables de la collecte des artefacts forensiques à partir de différentes sources.

Types de collecteurs :
- **EventLogCollector** : Collecte des journaux d'événements Windows
- **RegistryCollector** : Collecte des fichiers de registre Windows
- **BrowserHistoryCollector** : Collecte de l'historique des navigateurs
- **FileSystemCollector** : Collecte des fichiers temporaires et artefacts système
- **VMDKCollector** : Collecte des artefacts à partir de fichiers VMDK
- **MemoryCollector** : Collecte des artefacts à partir de dumps mémoire

Interface commune :
```python
class BaseCollector:
    def __init__(self, config):
        self.config = config
        
    def collect(self):
        """Collecte les artefacts et retourne une liste d'objets Artifact"""
        pass
        
    def get_name(self):
        """Retourne le nom du collecteur"""
        pass
        
    def get_description(self):
        """Retourne la description du collecteur"""
        pass
```

### Analyseurs

Les analyseurs sont responsables de l'analyse des artefacts collectés et de la détection des menaces.

Types d'analyseurs :
- **MalwareAnalyzer** : Détection de malwares et ransomwares
- **PhishingAnalyzer** : Analyse des traces de phishing
- **BackdoorAnalyzer** : Détection de backdoors et persistance
- **LateralMovementAnalyzer** : Analyse des mouvements latéraux
- **YaraAnalyzer** : Analyse basée sur des règles YARA

Interface commune :
```python
class BaseAnalyzer:
    def __init__(self, config):
        self.config = config
        
    def analyze(self, artifacts):
        """Analyse les artefacts et retourne une liste d'objets Finding"""
        pass
        
    def get_name(self):
        """Retourne le nom de l'analyseur"""
        pass
        
    def get_description(self):
        """Retourne la description de l'analyseur"""
        pass
```

### Rapporteurs

Les rapporteurs sont responsables de la génération des rapports à partir des résultats d'analyse.

Types de rapporteurs :
- **HTMLReporter** : Génération de rapports HTML interactifs
- **JSONReporter** : Exportation des résultats au format JSON
- **CSVReporter** : Exportation des résultats au format CSV

Interface commune :
```python
class BaseReporter:
    def __init__(self, config):
        self.config = config
        
    def generate_report(self, findings):
        """Génère un rapport à partir des résultats d'analyse"""
        pass
        
    def get_name(self):
        """Retourne le nom du rapporteur"""
        pass
        
    def get_description(self):
        """Retourne la description du rapporteur"""
        pass
```

## Système de plugins

Le système de plugins permet d'étendre les fonctionnalités de ForensicHunter sans modifier le code source principal.

Fonctionnalités :
- Découverte automatique des plugins
- Chargement dynamique des plugins
- Validation des interfaces
- Gestion des dépendances entre plugins

## Modèles de données

### Artifact

Représente un artefact forensique collecté.

Attributs :
- `id` : Identifiant unique de l'artefact
- `type` : Type d'artefact (event_log, registry, browser_history, etc.)
- `source` : Source de l'artefact (chemin du fichier, nom du collecteur, etc.)
- `timestamp` : Horodatage de la collecte
- `data` : Données de l'artefact (contenu du fichier, entrée de registre, etc.)
- `metadata` : Métadonnées associées à l'artefact

### Finding

Représente un résultat d'analyse.

Attributs :
- `id` : Identifiant unique du résultat
- `type` : Type de résultat (malware, phishing, backdoor, etc.)
- `severity` : Sévérité du résultat (info, low, medium, high, critical)
- `confidence` : Niveau de confiance (0-100)
- `description` : Description du résultat
- `artifacts` : Liste des artefacts associés au résultat
- `metadata` : Métadonnées associées au résultat

## Flux de données

1. Les collecteurs collectent les artefacts à partir de différentes sources
2. Les artefacts sont transmis aux analyseurs
3. Les analyseurs analysent les artefacts et génèrent des résultats
4. Les résultats sont transmis aux rapporteurs
5. Les rapporteurs génèrent des rapports à partir des résultats

## Interfaces utilisateur

### CLI

Interface en ligne de commande pour l'exécution de ForensicHunter.

Fonctionnalités :
- Exécution de collecteurs spécifiques
- Exécution d'analyseurs spécifiques
- Génération de rapports spécifiques
- Configuration via des arguments en ligne de commande

### GUI

Interface graphique pour l'exécution de ForensicHunter.

Fonctionnalités :
- Sélection des collecteurs à exécuter
- Sélection des analyseurs à exécuter
- Configuration des options d'analyse
- Visualisation des résultats en temps réel
- Génération et visualisation des rapports

## Configuration

La configuration de ForensicHunter est gérée via un système de configuration centralisé.

Sources de configuration :
- Fichier de configuration (JSON, YAML)
- Arguments en ligne de commande
- Interface graphique

## Gestion des erreurs

ForensicHunter implémente un système de gestion des erreurs robuste pour garantir la fiabilité de l'application.

Fonctionnalités :
- Journalisation des erreurs
- Récupération après erreur
- Notification des erreurs à l'utilisateur

## Sécurité

ForensicHunter implémente des mesures de sécurité pour garantir l'intégrité des données et la confidentialité des résultats.

Fonctionnalités :
- Vérification de l'intégrité des artefacts
- Chiffrement des données sensibles
- Contrôle d'accès aux rapports

## Extensibilité

ForensicHunter est conçu pour être facilement extensible.

Mécanismes d'extension :
- Système de plugins
- Interfaces bien définies
- Documentation des API

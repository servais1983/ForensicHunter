![image](ForensicHunter.png)

# 🔍 ForensicHunter

**Outil professionnel d'investigation numérique pour Windows**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)](https://github.com/servais1983/ForensicHunter)

## 📋 Description

ForensicHunter est un outil professionnel d'investigation numérique conçu pour collecter et analyser les artefacts forensiques sur les systèmes Windows. Il permet aux enquêteurs numériques, experts judiciaires et professionnels de la cybersécurité de réaliser des investigations complètes et fiables.

## 🎯 Fonctionnalités principales

### 📁 Collecte d'artefacts
- **Système de fichiers** : Scan exhaustif des répertoires critiques Windows
- **Registre Windows** : Extraction des ruches SAM, SECURITY, SOFTWARE, SYSTEM
- **Journaux d'événements** : Collecte des fichiers .evtx système
- **Navigateurs** : Historique Chrome, Firefox, Edge, Internet Explorer
- **Processus et services** : État du système au moment de l'analyse
- **Réseau** : Connexions actives et configuration réseau

### 🔍 Analyse avancée
- **Moteur YARA** : Détection de malware et d'artefacts suspects
- **Analyse de logs** : Identification d'événements de sécurité critiques
- **Corrélation temporelle** : Reconstitution de la chronologie des événements
- **Filtrage intelligent** : Réduction des faux positifs avec listes blanches

### 📊 Génération de rapports
- **Format HTML** : Rapport interactif avec navigation
- **Format PDF** : Document imprimable pour présentation judiciaire
- **Format CSV/Excel** : Export de données pour analyse statistique
- **Format JSON** : Intégration avec d'autres outils forensiques

## 🚀 Installation

### Prérequis
- Python 3.8 ou supérieur
- Windows 10/11 (privilèges administrateur recommandés)
- 4 GB RAM minimum, 8 GB recommandés
- 10 GB d'espace disque libre

### Installation rapide
```bash
git clone https://github.com/servais1983/ForensicHunter.git
cd ForensicHunter
pip install -r requirements.txt
```

### Vérification de l'installation
```bash
python src/forensichunter.py --version
```

## 💻 Utilisation

### Interface graphique
```bash
python src/gui/main_gui.py
```

### Ligne de commande
```bash
# Scan complet
python src/forensichunter.py --full-scan --output investigation_001

# Scan sélectif
python src/forensichunter.py --collect filesystem,registry --output case_2024_001

# Génération de rapport spécifique
python src/forensichunter.py --collect all --format pdf --output rapport_expertise
```

### Options principales
- `--full-scan` : Collecte exhaustive de tous les artefacts
- `--collect <modules>` : Sélection de collecteurs spécifiques
- `--output <dossier>` : Répertoire de sortie des résultats
- `--format <format>` : Format de rapport (html, pdf, csv, json)
- `--no-analysis` : Collecte uniquement, sans analyse
- `--yara-rules <chemin>` : Utilisation de règles YARA personnalisées

## 📁 Structure des résultats

```
investigation_001/
├── artifacts/              # Artefacts collectés
│   ├── filesystem/         # Fichiers système
│   ├── registry/          # Ruches de registre
│   ├── eventlogs/         # Journaux d'événements
│   └── browser/           # Données navigateurs
├── analysis/              # Résultats d'analyse
│   ├── yara_results.json  # Détections YARA
│   ├── timeline.csv       # Chronologie des événements
│   └── correlations.json  # Corrélations identifiées
├── reports/               # Rapports générés
│   ├── forensic_report.html
│   ├── executive_summary.pdf
│   └── data_export.csv
└── logs/                  # Journaux d'exécution
    └── forensichunter.log
```

## 🔧 Configuration avancée

### Fichier de configuration
Créer un fichier `config.json` :
```json
{
    "collectors": {
        "filesystem": {
            "max_file_size": "100MB",
            "include_deleted": false,
            "custom_paths": []
        },
        "registry": {
            "include_backups": true,
            "export_format": "reg"
        }
    },
    "analysis": {
        "yara_rules_path": "./rules/",
        "whitelist_path": "./config/whitelist.json",
        "correlation_threshold": 0.7
    },
    "reporting": {
        "default_format": "html",
        "include_screenshots": true,
        "compression": "zip"
    }
}
```

### Listes blanches personnalisées
Modifier `config/whitelist.json` :
```json
{
    "registry_keys": [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    ],
    "processes": [
        "explorer.exe",
        "winlogon.exe",
        "services.exe"
    ],
    "files": [
        "C:\\Windows\\System32\\*.dll",
        "C:\\Program Files\\*\\*.exe"
    ]
}
```

## 🎯 Cas d'usage professionnels

### Investigation post-incident
```bash
# Collecte rapide après détection d'intrusion
python src/forensichunter.py --incident-response --output incident_2024_001
```

### Expertise judiciaire
```bash
# Analyse complète pour expertise judiciaire
python src/forensichunter.py --full-scan --format pdf --output expertise_tribunal_001
```

### Audit de sécurité
```bash
# Audit de conformité avec rapport exécutif
python src/forensichunter.py --security-audit --format html,pdf --output audit_2024_Q1
```

## 📊 Performance et limites

### Performances typiques
- **Workstation standard** : 15-30 minutes pour scan complet
- **Serveur Windows** : 45-90 minutes selon la taille
- **Utilisation mémoire** : 2-4 GB pendant l'exécution
- **Espace disque** : 5-20% de l'espace analysé

### Limitations connues
- Nécessite des privilèges administrateur pour l'accès complet
- Certains artefacts peuvent être inaccessibles sur système chiffré
- Performance dépendante de la vitesse du disque
- Analyse limitée des fichiers corrompus

## 🛠️ Architecture technique

### Collecteurs disponibles
- `FileSystemCollector` : Collecte des fichiers et métadonnées
- `RegistryCollector` : Extraction des ruches de registre
- `EventLogCollector` : Analyse des journaux d'événements
- `BrowserCollector` : Artefacts des navigateurs web
- `ProcessCollector` : État des processus et services
- `NetworkCollector` : Configuration et connexions réseau

### Analyseurs intégrés
- `YaraAnalyzer` : Détection de signatures malveillantes
- `LogAnalyzer` : Analyse des fichiers journaux
- `CorrelationEngine` : Établissement de liens entre artefacts
- `TimelineGenerator` : Reconstruction chronologique

## 🔒 Sécurité et intégrité

### Intégrité des preuves
- Calcul automatique de hash MD5/SHA256 pour chaque artefact
- Journal détaillé de toutes les opérations
- Préservation des timestamps originaux
- Vérification de l'intégrité des données collectées

### Confidentialité
- Aucune donnée transmise vers l'extérieur
- Exécution entièrement locale
- Chiffrement optionnel des rapports sensibles
- Suppression sécurisée des fichiers temporaires

## 📞 Support et maintenance

### Documentation
- Guide utilisateur complet : `/docs/user_guide.pdf`
- Documentation technique : `/docs/technical_documentation.md`
- FAQ : `/docs/faq.md`
- Exemples d'utilisation : `/examples/`

### Support technique
- Issues GitHub : [Signalement de bugs](https://github.com/servais1983/ForensicHunter/issues)
- Documentation : [Wiki du projet](https://github.com/servais1983/ForensicHunter/wiki)
- Communauté : [Discussions](https://github.com/servais1983/ForensicHunter/discussions)

## 📋 Conformité et certifications

### Standards respectés
- **NIST SP 800-86** : Guide for Integrating Forensic Techniques into Incident Response
- **ISO/IEC 27037** : Guidelines for identification, collection, acquisition and preservation
- **ACPO Guidelines** : Good Practice Guide for Digital Evidence
- **RFC 3227** : Guidelines for Evidence Collection and Archiving

### Validation
- Tests de régression automatisés
- Validation sur environnements de référence
- Comparaison avec outils forensiques reconnus
- Documentation des procédures de test

## 🔄 Mises à jour et évolution

### Versioning
- Version stable actuelle : 1.0.0
- Mises à jour de sécurité mensuelles
- Nouvelles fonctionnalités trimestrielles
- Support LTS pour versions entreprise

### Roadmap
- **Q1 2025** : Support Linux complet
- **Q2 2025** : Analyse de fichiers macOS
- **Q3 2025** : Interface web pour analyses distantes
- **Q4 2025** : Intégration cloud forensics

## 📄 Licence et conditions

ForensicHunter est distribué sous licence MIT. Utilisation libre pour usage professionnel et commercial. Voir le fichier `LICENSE` pour les détails complets.

### Disclaimer
Cet outil est destiné à un usage légitime par des professionnels autorisés. L'utilisateur est responsable du respect des lois locales et de l'obtention des autorisations nécessaires avant utilisation.

---

**ForensicHunter - Outil professionnel d'investigation numérique**  
*Version 1.0.0 - Développé pour les professionnels de la cybersécurité et de l'expertise judiciaire*
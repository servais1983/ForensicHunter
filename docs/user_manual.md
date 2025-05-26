#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Guide utilisateur de ForensicHunter.

Ce document fournit des instructions détaillées sur l'utilisation de ForensicHunter,
un outil professionnel de forensic pour Windows.
"""

# Manuel utilisateur de ForensicHunter

## Introduction

ForensicHunter est un outil professionnel de forensic pour Windows, conçu pour collecter et analyser l'intégralité des preuves numériques sur un système Windows. Ce manuel vous guidera à travers l'installation, la configuration et l'utilisation de ForensicHunter.

## Installation

### Prérequis

Avant d'installer ForensicHunter, assurez-vous que votre système répond aux exigences suivantes :

- Windows 10/11 ou Windows Server 2016+
- Python 3.8 ou supérieur
- Privilèges administrateur pour la collecte complète
- 4 Go de RAM minimum (8 Go recommandés)
- Espace disque suffisant pour stocker les artefacts collectés

### Installation automatique

1. Téléchargez ou clonez le dépôt ForensicHunter :
   ```
   git clone https://github.com/votre-username/forensichunter.git
   ```

2. Accédez au répertoire ForensicHunter :
   ```
   cd forensichunter
   ```

3. Exécutez le script d'installation :
   ```
   install.bat
   ```

### Installation manuelle

1. Téléchargez ou clonez le dépôt ForensicHunter :
   ```
   git clone https://github.com/votre-username/forensichunter.git
   ```

2. Accédez au répertoire ForensicHunter :
   ```
   cd forensichunter
   ```

3. Installez les dépendances requises :
   ```
   pip install -r requirements.txt
   ```

## Utilisation de base

### Collecte complète

Pour effectuer une collecte complète de tous les artefacts disponibles :

```
python src/forensichunter.py --full-scan --output C:\ForensicHunter\Results
```

Cette commande collectera tous les artefacts disponibles et les stockera dans le répertoire spécifié.

### Collecte sélective

Pour collecter uniquement certains types d'artefacts :

```
python src/forensichunter.py --collect eventlogs,registry,browser --output C:\ForensicHunter\Results
```

Les modules de collecte disponibles sont :
- `eventlogs` : Journaux d'événements Windows
- `registry` : Ruches de registre Windows
- `filesystem` : Fichiers temporaires et artefacts système
- `browser` : Historique des navigateurs
- `process` : Processus en cours d'exécution
- `network` : Connexions réseau actives
- `usb` : Périphériques USB
- `memory` : Capture de la mémoire RAM
- `userdata` : Données utilisateur

### Analyse d'une image disque

Pour analyser une image disque (par exemple, un fichier VMDK) :

```
python src/forensichunter.py --image-path D:\Images\suspect.vmdk --output C:\ForensicHunter\Results
```

## Options avancées

### Format de rapport

Par défaut, ForensicHunter génère un rapport au format HTML. Vous pouvez spécifier d'autres formats :

```
python src/forensichunter.py --full-scan --format json --output C:\ForensicHunter\Results
```

Formats disponibles :
- `html` : Rapport HTML interactif (par défaut)
- `json` : Rapport JSON pour l'intégration avec d'autres outils
- `csv` : Rapport CSV pour l'analyse dans des tableurs
- `all` : Génère tous les formats de rapport

### Désactivation de la collecte mémoire

La collecte de la mémoire RAM peut être désactivée si nécessaire :

```
python src/forensichunter.py --full-scan --no-memory --output C:\ForensicHunter\Results
```

### Utilisation de plugins personnalisés

Pour utiliser des plugins personnalisés :

```
python src/forensichunter.py --full-scan --plugin-dir C:\MesPlugins --output C:\ForensicHunter\Results
```

### Utilisation de règles YARA personnalisées

Pour utiliser des règles YARA personnalisées :

```
python src/forensichunter.py --full-scan --rules-dir C:\MesRegles --output C:\ForensicHunter\Results
```

### Utilisation d'indicateurs de compromission (IOC)

Pour utiliser un fichier d'indicateurs de compromission :

```
python src/forensichunter.py --full-scan --ioc-file C:\IOCs\indicators.json --output C:\ForensicHunter\Results
```

## Interprétation des résultats

### Structure des résultats

Après l'exécution, ForensicHunter crée la structure de répertoires suivante dans le répertoire de sortie spécifié :

```
Results/
├── artifacts/          # Artefacts du système de fichiers
├── browsers/           # Données des navigateurs
├── eventlogs/          # Journaux d'événements
├── memory/             # Capture mémoire
├── network/            # Informations réseau
├── processes/          # Informations sur les processus
├── registry/           # Données de registre
├── reports/            # Rapports générés
│   ├── html/           # Rapports HTML
│   ├── json/           # Rapports JSON
│   └── csv/            # Rapports CSV
└── userdata/           # Données utilisateur
```

### Rapport HTML

Le rapport HTML est le plus complet et le plus facile à interpréter. Il contient :

1. **Résumé de l'analyse** : Vue d'ensemble des résultats, avec le nombre d'artefacts collectés et les alertes détectées.
2. **Informations système** : Détails sur le système analysé.
3. **Sections par type d'artefact** : Chaque type d'artefact a sa propre section avec des tableaux et des graphiques.
4. **Alertes et anomalies** : Liste des comportements suspects détectés, avec un score de criticité.

### Score de criticité

ForensicHunter attribue un score de criticité à chaque alerte détectée :

- **Critique (80-100)** : Indicateurs de compromission confirmés, nécessitant une attention immédiate.
- **Élevé (60-79)** : Comportements très suspects, probablement malveillants.
- **Moyen (40-59)** : Comportements anormaux qui méritent une investigation.
- **Faible (20-39)** : Comportements légèrement inhabituels, à surveiller.
- **Informatif (0-19)** : Informations contextuelles, sans indication de menace.

## Cas d'utilisation courants

### Analyse d'un système potentiellement compromis

```
python src/forensichunter.py --full-scan --output C:\Investigation\Compromis
```

### Collecte de preuves pour une investigation

```
python src/forensichunter.py --collect eventlogs,registry,browser,process,network --output C:\Investigation\Preuves
```

### Analyse de routine pour la maintenance

```
python src/forensichunter.py --collect eventlogs,process,network --no-memory --output C:\Maintenance\Routine
```

## Dépannage

### Erreurs courantes

1. **Privilèges insuffisants** : Assurez-vous d'exécuter ForensicHunter avec des privilèges administrateur.
2. **Dépendances manquantes** : Vérifiez que toutes les dépendances sont installées avec `pip install -r requirements.txt`.
3. **Erreurs de collecte mémoire** : La collecte de mémoire peut échouer sur certains systèmes. Utilisez l'option `--no-memory` si nécessaire.
4. **Espace disque insuffisant** : Assurez-vous d'avoir suffisamment d'espace disque pour stocker les artefacts collectés.

### Journaux de débogage

Pour obtenir des informations de débogage détaillées :

```
python src/forensichunter.py --full-scan --debug --output C:\ForensicHunter\Results
```

Les journaux de débogage sont stockés dans le fichier `forensichunter.log` dans le répertoire de sortie.

## Support et assistance

Si vous rencontrez des problèmes ou avez des questions, vous pouvez :

1. Consulter la [documentation en ligne](https://docs.forensichunter.io)
2. Poser une question sur le [forum de support](https://forum.forensichunter.io)
3. Ouvrir une issue sur [GitHub](https://github.com/votre-username/forensichunter/issues)
4. Contacter l'équipe de support à support@forensichunter.io

## Conclusion

ForensicHunter est un outil puissant pour la collecte et l'analyse de preuves numériques sur les systèmes Windows. En suivant ce manuel, vous devriez être en mesure d'utiliser efficacement ForensicHunter pour vos besoins d'investigation forensique.

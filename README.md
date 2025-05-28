<div align="center">
  <img src="static/logo.png" alt="ForensicHunter Logo" width="200"/>
  <h1>ForensicHunter</h1>
  <p>Outil d'analyse forensique professionnel pour Windows</p>
</div>

## À propos

ForensicHunter est un outil d'analyse forensique professionnel conçu pour les analystes en cybersécurité. Il permet d'analyser des fichiers VMDK, des journaux d'événements Windows, des fichiers de registre et d'autres artefacts système pour détecter des traces de malware, ransomware, phishing, backdoors et autres indicateurs de compromission.

## Fonctionnalités principales

- **Collecte d'artefacts Windows**
  - Journaux d'événements (Event Logs)
  - Fichiers de registre (Registry)
  - Système de fichiers (FileSystem)
  - Fichiers VMDK (jusqu'à 60GB)

- **Analyse de menaces**
  - Détection de malware et ransomware (notamment LockBit 3.0)
  - Analyse de traces de phishing
  - Détection de backdoors et persistance
  - Analyse de mouvements latéraux
  - Intégration de règles YARA

- **Génération de rapports**
  - Rapports HTML interactifs
  - Système de scoring des menaces
  - Visualisations et chronologies
  - Exportation locale sur le PC

## Installation

### Prérequis

- Windows 10/11
- Python 3.8 ou supérieur
- Privilèges administrateur (recommandé)

### Installation rapide

1. Clonez le dépôt :
   ```
   git clone https://github.com/servais1983/ForensicHunter.git
   cd ForensicHunter
   ```

2. Exécutez le script d'installation :
   ```
   install.bat
   ```

3. Lancez l'application :
   ```
   forensichunter_gui.bat
   ```

### Résolution des problèmes d'installation

Si vous rencontrez des erreurs lors de l'installation :

1. **Erreur de permission** : Exécutez l'invite de commande en tant qu'administrateur, puis :
   ```
   rmdir /s /q venv
   install.bat
   ```

2. **Erreur de module** : Assurez-vous que toutes les dépendances sont installées :
   ```
   venv\Scripts\activate
   pip install -r requirements.txt
   deactivate
   ```

## Utilisation

### Interface graphique

1. Lancez l'interface graphique :
   ```
   forensichunter_gui.bat
   ```

2. Sélectionnez les fichiers ou dossiers à analyser
3. Configurez les options d'analyse
4. Cliquez sur "Lancer l'analyse complète"
5. Consultez les résultats dans l'onglet "Rapports"

### Ligne de commande

1. Pour une analyse complète :
   ```
   forensichunter.bat --full-scan --output C:\ForensicHunter\Results
   ```

2. Pour afficher l'aide :
   ```
   forensichunter.bat --help
   ```

## Structure du projet

```
ForensicHunter/
├── docs/               # Documentation
├── rules/              # Règles YARA
├── src/                # Code source
│   ├── analyzers/      # Modules d'analyse
│   ├── collectors/     # Collecteurs d'artefacts
│   ├── gui/            # Interface graphique
│   ├── reporters/      # Générateurs de rapports
│   └── utils/          # Utilitaires
├── static/             # Ressources statiques
├── templates/          # Templates pour les rapports
├── install.bat         # Script d'installation
├── forensichunter.bat  # Lanceur en ligne de commande
└── README.md           # Ce fichier
```

## Mise à jour

Pour mettre à jour ForensicHunter :

1. Récupérez les dernières modifications :
   ```
   git pull origin main
   ```

2. Supprimez les anciens lanceurs :
   ```
   del forensichunter.bat
   del forensichunter_gui.bat
   ```

3. Réexécutez le script d'installation :
   ```
   install.bat
   ```

## Licence

© 2025 ForensicHunter Team - Tous droits réservés

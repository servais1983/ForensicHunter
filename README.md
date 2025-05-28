<div align="center">
  <img src="https://raw.githubusercontent.com/servais1983/ForensicHunter/main/static/logo.png" alt="ForensicHunter Logo" width="200"/>
  <h1>ForensicHunter</h1>
  <p>Outil d'analyse forensique professionnel pour Windows</p>
  
  ![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)
  ![Python](https://img.shields.io/badge/python-3.8+-green.svg)
  ![License](https://img.shields.io/badge/license-Proprietary-red.svg)
  ![Build](https://img.shields.io/badge/build-passing-success.svg)
</div>

## 📋 À propos

ForensicHunter est un outil d'analyse forensique professionnel conçu pour les analystes en cybersécurité. Il permet d'analyser des fichiers VMDK, des journaux d'événements Windows, des fichiers de registre, des disques durs physiques et d'autres artefacts système pour détecter des traces de malware, ransomware, phishing, backdoors et autres indicateurs de compromission.

## ✨ Fonctionnalités principales

- **🔍 Collecte d'artefacts Windows**
  - 📊 Journaux d'événements (Event Logs)
  - 🔑 Fichiers de registre (Registry)
  - 📁 Système de fichiers (FileSystem)
  - 💾 Fichiers VMDK (jusqu'à 60GB)
  - 💿 Disques durs physiques (analyse directe)

- **🛡️ Analyse de menaces**
  - 🦠 Détection de malware et ransomware (notamment LockBit 3.0)
  - 🎣 Analyse de traces de phishing
  - 🚪 Détection de backdoors et persistance
  - 🔄 Analyse de mouvements latéraux
  - 📜 Intégration de règles YARA

- **📊 Génération de rapports**
  - 📱 Rapports HTML interactifs
  - ⭐ Système de scoring des menaces
  - 📈 Visualisations et chronologies
  - 💻 Exportation locale sur le PC

## 🚀 Installation

### ⚠️ IMPORTANT : Exécuter en mode Administrateur

**Toutes les commandes doivent être exécutées dans une invite de commande (CMD) ouverte en mode Administrateur.**

Pour ouvrir CMD en mode Administrateur :
1. Recherchez "cmd" dans le menu Démarrer
2. Faites un clic droit sur "Invite de commandes"
3. Sélectionnez "Exécuter en tant qu'administrateur"

### Prérequis

- Windows 10/11
- Python 3.8 ou supérieur
- Privilèges administrateur (obligatoire)

### Installation rapide

1. Clonez le dépôt :
   ```
   git clone https://github.com/servais1983/ForensicHunter.git
   cd ForensicHunter
   ```

2. Exécutez le script d'installation (en mode Administrateur) :
   ```
   install.bat
   ```

3. Lancez l'application :
   ```
   forensichunter_gui.bat
   ```

### 🔧 Résolution des problèmes d'installation

Si vous rencontrez des erreurs lors de l'installation :

1. **Erreur de permission** : Vérifiez que vous exécutez bien l'invite de commande en tant qu'administrateur, puis :
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

## 📖 Utilisation

### Interface graphique

1. Lancez l'interface graphique (en mode Administrateur) :
   ```
   forensichunter_gui.bat
   ```

2. Sélectionnez les sources à analyser :
   - Fichiers individuels
   - Dossiers complets
   - Fichiers VMDK
   - Disques durs physiques (nouvelle fonctionnalité)

3. Configurez les options d'analyse
4. Cliquez sur "Lancer l'analyse complète"
5. Consultez les résultats dans l'onglet "Rapports"

### Analyse de disques physiques

La nouvelle fonctionnalité d'analyse de disques physiques permet d'analyser directement les disques durs de votre système :

1. Cliquez sur "Sélectionner un disque physique..."
2. Choisissez un ou plusieurs disques dans la liste
3. Les disques sélectionnés apparaîtront dans la liste des sources
4. Assurez-vous que l'option "Disques physiques" est cochée dans les collecteurs
5. Lancez l'analyse

### Ligne de commande

1. Pour une analyse complète (en mode Administrateur) :
   ```
   forensichunter.bat --full-scan --output C:\ForensicHunter\Results
   ```

2. Pour afficher l'aide :
   ```
   forensichunter.bat --help
   ```

## 📂 Structure du projet

```
ForensicHunter/
├── docs/               # Documentation
├── rules/              # Règles YARA
├── src/                # Code source
│   ├── analyzers/      # Modules d'analyse
│   ├── collectors/     # Collecteurs d'artefacts
│   │   ├── disk_collector.py  # Collecteur de disques physiques
│   ├── gui/            # Interface graphique
│   ├── reporters/      # Générateurs de rapports
│   └── utils/          # Utilitaires
├── static/             # Ressources statiques
├── templates/          # Templates pour les rapports
├── install.bat         # Script d'installation
├── forensichunter.bat  # Lanceur en ligne de commande
└── README.md           # Ce fichier
```

## 🔄 Mise à jour

Pour mettre à jour ForensicHunter (en mode Administrateur) :

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

## 📝 Licence

© 2025 ForensicHunter Team - Tous droits réservés

---

<div align="center">
  <p>Développé avec ❤️ par l'équipe ForensicHunter</p>
  
  ![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
  ![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
  ![Security](https://img.shields.io/badge/Security-FF0000?style=for-the-badge&logo=shield&logoColor=white)
</div>

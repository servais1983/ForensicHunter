<div align="center">
  <img src="static/img/logo.svg" alt="ForensicHunter Logo" width="400">
  <h1>ForensicHunter</h1>
  <p>Outil d'analyse forensique avancé pour la détection de menaces dans les fichiers VMDK, logs et autres artefacts Windows</p>
</div>

## 📋 Table des matières

- [Présentation](#-présentation)
- [Fonctionnalités](#-fonctionnalités)
- [Installation](#-installation)
- [Mise à jour](#-mise-à-jour)
- [Utilisation](#-utilisation)
- [Structure du projet](#-structure-du-projet)
- [Dépendances](#-dépendances)
- [Règles YARA](#-règles-yara)
- [Génération de rapports](#-génération-de-rapports)
- [Dépannage](#-dépannage)
- [Licence](#-licence)

## 🔍 Présentation

ForensicHunter est un outil d'analyse forensique professionnel conçu pour les analystes en cybersécurité. Il permet de scanner des fichiers VMDK volumineux (jusqu'à 60GB), des logs, des fichiers CSV et d'autres artefacts Windows pour détecter des traces de malware, ransomware (notamment LockBit 3.0), phishing, backdoors, persistance d'attaquants et mouvements latéraux.

L'application dispose d'une interface graphique intuitive basée sur PyQt5 et d'une interface en ligne de commande pour les analyses automatisées. Les résultats sont présentés dans un rapport HTML détaillé et professionnel.

## 🚀 Fonctionnalités

- **Collecte d'artefacts Windows**
  - Journaux d'événements (Event Logs)
  - Fichiers de registre (Registry)
  - Historique des navigateurs
  - Fichiers temporaires et artefacts système
  - Analyse de fichiers VMDK

- **Détection de menaces**
  - Malwares et ransomwares (LockBit 3.0, etc.)
  - Traces de phishing et ingénierie sociale
  - Backdoors et persistance
  - Mouvements latéraux
  - Intégration de règles YARA personnalisables

- **Rapports professionnels**
  - Rapport HTML interactif unique et consolidé
  - Système de scoring des menaces
  - Visualisations (chronologies, graphiques)
  - Exportation des résultats

## 💻 Installation

### Prérequis

- Windows 10/11
- Python 3.8 ou supérieur
- Droits administrateur recommandés

### Installation automatique

1. Clonez le dépôt GitHub :
   ```
   git clone https://github.com/servais1983/ForensicHunter.git
   cd ForensicHunter
   ```

2. Exécutez le script d'installation :
   ```
   install.bat
   ```

3. Le script va :
   - Vérifier l'installation Python
   - Créer un environnement virtuel
   - Installer les dépendances requises
   - Configurer les lanceurs

### Installation manuelle

Si vous rencontrez des problèmes avec l'installation automatique :

1. Créez un environnement virtuel :
   ```
   python -m venv venv
   ```

2. Activez l'environnement virtuel :
   ```
   venv\Scripts\activate
   ```

3. Installez les dépendances :
   ```
   pip install -r requirements.txt
   ```

4. Créez les lanceurs manuellement :
   ```
   echo @echo off > forensichunter.bat
   echo call venv\Scripts\activate.bat >> forensichunter.bat
   echo set PYTHONPATH=%%CD%% >> forensichunter.bat
   echo python src\forensichunter.py %%* >> forensichunter.bat
   echo deactivate >> forensichunter.bat

   echo @echo off > forensichunter_gui.bat
   echo call venv\Scripts\activate.bat >> forensichunter_gui.bat
   echo set PYTHONPATH=%%CD%% >> forensichunter_gui.bat
   echo python src\gui\main_gui.py >> forensichunter_gui.bat
   echo deactivate >> forensichunter_gui.bat
   ```

## 🔄 Mise à jour

Pour mettre à jour ForensicHunter à la dernière version :

1. Ouvrez une invite de commande dans le répertoire du projet
2. Mettez à jour le dépôt :
   ```
   git pull origin main
   ```
3. Supprimez les anciens lanceurs s'ils existent :
   ```
   del forensichunter.bat
   del forensichunter_gui.bat
   ```
4. Réexécutez le script d'installation :
   ```
   install.bat
   ```

## 📊 Utilisation

### Interface graphique

Pour lancer l'interface graphique :

```
forensichunter_gui.bat
```

L'interface vous permettra de :
- Sélectionner les fichiers à analyser (VMDK, logs, CSV)
- Configurer les options d'analyse
- Lancer l'analyse
- Visualiser les résultats
- Générer des rapports

### Interface en ligne de commande

Pour lancer l'analyse en ligne de commande :

```
forensichunter.bat [options]
```

Options disponibles :
- `--help` : Affiche l'aide
- `--scan <chemin>` : Spécifie le chemin du fichier ou dossier à analyser
- `--output <dossier>` : Spécifie le dossier de sortie pour les résultats
- `--full-scan` : Active l'analyse complète (plus lente mais plus précise)
- `--quick-scan` : Active l'analyse rapide
- `--report-format <format>` : Format du rapport (html, json, csv)
- `--yara-rules <dossier>` : Spécifie un dossier de règles YARA personnalisées

Exemple d'utilisation :
```
forensichunter.bat --scan C:\Evidence\disk.vmdk --output C:\Results --full-scan --report-format html
```

## 📁 Structure du projet

```
ForensicHunter/
├── docs/                   # Documentation
├── rules/                  # Règles YARA
├── src/                    # Code source
│   ├── collectors/         # Collecteurs d'artefacts
│   ├── analyzers/          # Analyseurs de menaces
│   ├── reporters/          # Générateurs de rapports
│   ├── utils/              # Utilitaires
│   ├── gui/                # Interface graphique
│   └── forensichunter.py   # Point d'entrée principal
├── static/                 # Ressources statiques
├── templates/              # Templates de rapports
├── install.bat             # Script d'installation
├── requirements.txt        # Dépendances Python
└── README.md               # Ce fichier
```

## 📦 Dépendances

Les principales dépendances sont :

- **PyQt5** : Interface graphique
- **yara-python** : Moteur de règles YARA
- **python-registry** : Analyse du registre Windows
- **python-evtx** : Analyse des journaux d'événements Windows
- **pytsk3** : Analyse des systèmes de fichiers
- **python-magic** : Détection des types de fichiers
- **matplotlib** et **seaborn** : Visualisation des données
- **jinja2** : Génération de rapports HTML

Toutes les dépendances sont automatiquement installées par le script d'installation.

## 🛡️ Règles YARA

ForensicHunter utilise des règles YARA pour la détection de menaces. Les règles par défaut sont situées dans le dossier `rules/` et comprennent :

- Détection de ransomwares (LockBit 3.0, Ryuk, WannaCry, etc.)
- Détection de backdoors et webshells
- Détection de malwares génériques
- Détection de scripts PowerShell malveillants

Vous pouvez ajouter vos propres règles YARA en les plaçant dans le dossier `rules/` ou en spécifiant un dossier personnalisé avec l'option `--yara-rules`.

## 📝 Génération de rapports

ForensicHunter génère des rapports HTML détaillés et professionnels qui incluent :

- Résumé de l'analyse
- Statistiques sur les menaces détectées
- Liste des menaces classées par sévérité
- Détails des artefacts associés à chaque menace
- Visualisations graphiques
- Recommandations de remédiation

Les rapports sont générés dans le dossier spécifié par l'option `--output` ou dans le dossier par défaut `results/`.

## 🔧 Dépannage

### Problèmes d'installation

**Erreur : ModuleNotFoundError: No module named 'PyQt5'**
- Solution : Supprimez le dossier venv et réexécutez install.bat
- Alternative : Installez PyQt5 manuellement : `pip install PyQt5`

**Erreur : Permission denied lors de la création de l'environnement virtuel**
- Solution : Fermez toutes les instances de ligne de commande qui utilisent l'environnement virtuel
- Alternative : Supprimez le dossier venv et réexécutez install.bat en tant qu'administrateur

### Problèmes d'exécution

**Erreur : ModuleNotFoundError: No module named 'src.utils.logger'**
- Solution : Assurez-vous d'utiliser les lanceurs forensichunter.bat ou forensichunter_gui.bat
- Alternative : Définissez manuellement PYTHONPATH : `set PYTHONPATH=%CD%`

**Erreur : DLL load failed lors du lancement de l'interface graphique**
- Solution : Réinstallez PyQt5 : `pip install --force-reinstall PyQt5`

## 📄 Licence

ForensicHunter est distribué sous licence MIT. Voir le fichier LICENSE pour plus de détails.

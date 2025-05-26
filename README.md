<div align="center">
  <img src="assets/forensichunter_logo.png" alt="ForensicHunter Logo" width="200">
  <h1>ForensicHunter</h1>
  <p>L'outil de forensic Windows ultime pour les professionnels de la cybersécurité</p>
  
  <p>
    <a href="#fonctionnalités"><img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
    <a href="#prérequis"><img src="https://img.shields.io/badge/python-3.7+-red.svg" alt="Python"></a>
    <a href="docs/security_audit.md"><img src="https://img.shields.io/badge/security-audited-success.svg" alt="Security"></a>
    <a href="#compatibilité"><img src="https://img.shields.io/badge/windows-all_versions-lightgrey.svg" alt="Windows"></a>
  </p>
</div>

## 🔍 Vue d'ensemble

**ForensicHunter** est un outil professionnel de forensic pour Windows, conçu pour collecter l'intégralité des preuves numériques sur un système Windows, tout en garantissant leur intégrité et leur recevabilité en justice. Développé selon les principes DevSecOps, il surpasse les outils existants comme Velociraptor, KAPE ou FTK Imager en termes de complétude, de rapidité et d'intelligence.

### 🛡️ Approche DevSecOps

ForensicHunter a été développé avec une approche "security by design", intégrant la sécurité à chaque étape du développement. Un [audit de sécurité complet](docs/security_audit.md) a été réalisé pour garantir la robustesse et la fiabilité de l'outil.

## ✨ Fonctionnalités

### 📊 Collecte complète de preuves

- **Journaux d'événements Windows** - Extraction et analyse de tous les journaux d'événements système, sécurité, application
- **Fichiers de registre** - Capture et analyse des ruches de registre (SYSTEM, SOFTWARE, SECURITY, SAM, etc.)
- **Fichiers temporaires et artefacts** - Collecte des fichiers temporaires, prefetch, et autres artefacts système
- **Historique des navigateurs** - Extraction des données de navigation (Edge, Chrome, Firefox)
- **Processus et connexions** - Capture des processus en cours et des connexions réseau actives
- **Périphériques USB** - Détection et analyse des périphériques USB connectés
- **Capture mémoire** - Dump de la mémoire RAM (lorsque possible)
- **Données utilisateur** - Collecte des fichiers récents, téléchargements et documents

### 🔒 Intégrité des preuves

- **Mode lecture seule** - Toutes les opérations sont effectuées en mode strictement lecture seule
- **Calcul de hashes** - Génération automatique de hashes MD5, SHA-1 et SHA-256 pour chaque artefact
- **Chaîne de custody** - Documentation complète de la chaîne de custody pour chaque preuve
- **Journal d'audit** - Journalisation détaillée de toutes les opérations effectuées

### 🧠 Analyse intelligente

- **Détection d'anomalies** - Identification automatique des comportements suspects
- **Scoring de preuves** - Attribution de scores de pertinence aux artefacts collectés
- **Analyse mémoire avancée** - Intégration avec Volatility pour une analyse mémoire approfondie
- **Détection de rootkits** - Identification des malwares furtifs et rootkits

### 📝 Rapports professionnels

- **Rapports HTML interactifs** - Visualisation claire et interactive des résultats
- **Export JSON/CSV** - Données structurées pour une analyse ultérieure
- **Visualisation avancée** - Graphes de relations, timelines et tableaux de bord
- **Rapports juridiques** - Documentation conforme aux exigences légales

### 🔌 Architecture modulaire

- **Système de plugins** - Extension facile avec de nouveaux modules
- **API documentée** - Intégration avec d'autres outils et workflows
- **Configuration flexible** - Adaptation aux besoins spécifiques de chaque investigation

## 🖥️ Compatibilité

ForensicHunter est compatible avec **toutes les versions de Windows**, des plus anciennes aux plus récentes :

- Windows XP, Vista, 7, 8, 8.1, 10, 11
- Windows Server 2003, 2008, 2012, 2016, 2019, 2022

Le système détecte automatiquement la version et adapte ses méthodes de collecte en conséquence.

## 📋 Prérequis

- Python 3.7 ou supérieur
- Privilèges administrateur sur le système cible
- 4 Go de RAM minimum (8 Go recommandés)
- Espace disque suffisant pour stocker les preuves collectées

## 🚀 Installation

### Installation automatique

```batch
install.bat
```

### Installation manuelle

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/ForensicHunter.git
cd ForensicHunter

# Installer les dépendances
pip install -r requirements.txt

# Vérifier l'installation
python src/forensichunter.py --check
```

## 📖 Utilisation

### Collecte complète

```bash
python src/forensichunter.py --full-scan --output C:\ForensicHunter\Results
```

### Collecte ciblée

```bash
python src/forensichunter.py --collect registry browser_history processes --output C:\ForensicHunter\Results
```

### Analyse mémoire

```bash
python src/forensichunter.py --memory-dump --volatility --output C:\ForensicHunter\Results
```

### Génération de rapport

```bash
python src/forensichunter.py --generate-report --format html --input C:\ForensicHunter\Results --output C:\ForensicHunter\Report.html
```

## 📊 Exemples de rapports

<div align="center">
  <img src="assets/report_example.png" alt="Exemple de rapport" width="800">
</div>

## 🔧 Configuration avancée

ForensicHunter peut être configuré via un fichier de configuration JSON :

```json
{
  "collectors": {
    "event_logs": true,
    "registry": true,
    "browser_history": true,
    "processes": true,
    "network": true,
    "usb_devices": true,
    "memory": true,
    "user_data": true
  },
  "analyzers": {
    "anomaly_detection": true,
    "rootkit_detection": true,
    "malware_scan": true,
    "timeline_generation": true
  },
  "reporters": {
    "html": true,
    "json": true,
    "csv": false
  },
  "security": {
    "hash_algorithms": ["md5", "sha1", "sha256"],
    "chain_of_custody": true,
    "audit_logging": true
  },
  "virustotal": {
    "enabled": false,
    "api_key": ""
  }
}
```

## 🛣️ Roadmap

### Phase 1 (Actuelle)
- ✅ Collecte complète des preuves numériques
- ✅ Intégrité des preuves et chaîne de custody
- ✅ Compatibilité avec toutes les versions de Windows
- ✅ Rapports HTML, JSON et CSV
- ✅ Analyse mémoire avec Volatility
- ✅ Détection de rootkits et malwares

### Phase 2 (Prochaine)
- 🔄 Interface graphique (GUI) pour une utilisation simplifiée

### Phase 3 (Future)
- 📅 Intelligence artificielle pour l'analyse des preuves
- 📅 Reconstruction automatique des incidents
- 📅 Analyse forensique à distance
- 📅 Corrélation multi-sources
- 📅 Blockchain pour la chaîne de custody
=======
Exemple de plugin collecteur :

```python
from src.plugins.plugin_manager import CollectorPlugin

class MyCustomCollector(CollectorPlugin):
    def __init__(self, config):
        super().__init__(config)
        self.name = "MyCustomCollector"
        self.description = "Collecte des artefacts personnalisés"
        self.version = "1.0.0"
        self.author = "Votre Nom"
    
    def collect(self):
        # Logique de collecte
        return {"custom_artifacts": [...]}
```

## 📝 Roadmap

### Version 1.1
- Support de l'analyse de mémoire avancée avec Volatility
- Intégration avec VirusTotal et autres services d'analyse
- Amélioration de la détection des rootkits et malwares furtifs

### Version 1.2
- Interface graphique (GUI) pour une utilisation simplifiée
- Visualisation avancée des données (timeline, graphes de relations)
- Support de l'analyse de disques chiffrés

### Version 2.0
- Analyse comportementale basée sur l'IA
- Corrélation automatique entre différentes sources d'artefacts
- Intégration avec des SIEM et plateformes de threat hunting
>>>>>>> 1bc3bc87f55803125681e8c9da12d27364b731d8

## 🤝 Contribution

Les contributions sont les bienvenues ! Consultez notre [guide de contribution](docs/CONTRIBUTING.md) pour plus d'informations.

## 📜 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 📚 Documentation

- [Manuel utilisateur](docs/user_manual.md)
- [Guide du développeur](docs/developer_guide.md)
- [Audit de sécurité](docs/security_audit.md)
- [API Reference](docs/api_reference.md)

## 🔗 Liens utiles

- [Site officiel](https://forensichunter.io)
- [Documentation en ligne](https://docs.forensichunter.io)
- [Forum de support](https://forum.forensichunter.io)

## 📞 Contact

Pour toute question ou assistance, contactez-nous à support@forensichunter.io

---

<div align="center">
  <p>ForensicHunter - L'outil de forensic Windows ultime pour les professionnels de la cybersécurité</p>
  <p>© 2025 ForensicHunter Team</p>
</div>

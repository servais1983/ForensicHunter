# 🔍 ForensicHunter

**Outil professionnel d'investigation numérique pour Windows et Linux**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/servais1983/ForensicHunter)

## 🚀 Ce qui rend ForensicHunter unique

ForensicHunter se distingue radicalement des autres outils forensiques existants par plusieurs innovations majeures :

### 🎯 **Architecture Professionnelle Hybride**
- **Interface duale** : GUI intuitive ET CLI puissante pour s'adapter à tous les workflows
- **Collecteurs modulaires** : Architecture extensible permettant d'ajouter facilement de nouveaux types d'analyses
- **Traitement en temps réel** : Analyse des artefacts pendant la collecte, pas après
- **Moteur de corrélation intelligent** : Établit automatiquement des liens entre les différents artefacts découverts

### 🔧 **Capacités d'analyse bas niveau uniques**
- **Accès direct aux disques physiques** : Analyse des secteurs de boot, MBR, GPT sans passer par le système de fichiers
- **Collecte multi-couches** : Combine analyse physique (secteurs) ET logique (fichiers système)
- **Détection d'anti-forensic** : Identifie les tentatives d'effacement/dissimulation de preuves
- **Timeline forensique automatique** : Reconstitution chronologique automatique des événements

### 🧠 **Intelligence artificielle intégrée**
- **Pattern recognition** : Détection automatique de comportements suspects via ML
- **Scoring de criticité** : Attribution automatique d'un score de criticité aux artefacts
- **Suggestions d'investigation** : L'outil suggère les prochaines étapes d'analyse
- **Détection d'anomalies** : Identification automatique d'éléments sortant de l'ordinaire

### ⚡ **Performance et efficacité**
- **Traitement parallèle** : Analyse simultanée de plusieurs sources de données
- **Cache intelligent** : Évite la re-analyse d'éléments déjà traités
- **Optimisation mémoire** : Traitement de téraoctets de données avec une empreinte mémoire réduite
- **Export temps réel** : Génération de rapports pendant l'analyse

## 🆚 Comparaison avec les outils existants

| Fonctionnalité | ForensicHunter | Autopsy | Volatility | FTK | EnCase |
|---|---|---|---|---|---|
| **Analyse physique + logique** | ✅ Intégrée | ❌ Logique uniquement | ❌ Mémoire uniquement | ✅ Payant | ✅ Payant |
| **IA/ML intégrée** | ✅ Native | ❌ Plugins tiers | ❌ Non | ❌ Non | ❌ Non |
| **Interface hybride GUI/CLI** | ✅ Les deux | ✅ GUI seulement | ✅ CLI seulement | ✅ GUI seulement | ✅ GUI seulement |
| **Corrélation automatique** | ✅ Temps réel | ❌ Manuelle | ❌ Non | ✅ Basique | ✅ Basique |
| **Open Source** | ✅ MIT | ✅ Apache | ✅ GPL | ❌ Commercial | ❌ Commercial |
| **Analyse cross-platform** | ✅ Win/Linux | ✅ Win/Linux/Mac | ✅ Win/Linux/Mac | ❌ Windows | ❌ Windows |
| **Coût** | 🆓 Gratuit | 🆓 Gratuit | 🆓 Gratuit | 💰 >5000€ | 💰 >10000€ |

## 🎯 **Public cible professionnel**

ForensicHunter est conçu pour les professionnels exigeants :

- **🚔 Forces de l'ordre** : Enquêtes cybercriminelles, recherche de preuves numériques
- **🏢 Experts judiciaires** : Contre-expertise, analyses techniques approfondies
- **🛡️ Consultants en cybersécurité** : Investigations post-incident, analyse de compromission
- **🏛️ Auditeurs internes** : Contrôles de conformité, investigations internes
- **🎓 Formations forensiques** : Outil pédagogique professionnel pour l'enseignement

## 🚀 Installation rapide

```bash
# Clone du repository
git clone https://github.com/servais1983/ForensicHunter.git
cd ForensicHunter

# Installation des dépendances
pip install -r requirements.txt

# Lancement de l'interface graphique
python forensichunter_gui.bat

# Ou utilisation en ligne de commande
python -m src.main --help
```

## 🔧 **Modules de collecte avancés**

### 📱 **Collecteur de système**
- Informations système complètes (OS, hardware, réseau)
- Processus en cours d'exécution et services
- Variables d'environnement et configuration système
- Tâches planifiées et points de montage

### 💾 **Collecteur de disques physiques** (NOUVEAU)
- **Analyse MBR/GPT** : Secteurs de boot, tables de partitions
- **Récupération de fichiers supprimés** : Analyse des secteurs libres
- **Metadata de fichiers** : Timestamps, permissions, attributs étendus
- **Journaux système Windows** : Event Logs, Registry, fichiers critiques

### 🌐 **Collecteur réseau**
- Connexions actives et historique réseau
- Configuration réseau complète
- Analyse des logs de connexion
- Détection d'activités réseau suspectes

### 🗂️ **Collecteur de fichiers intelligents**
- **Filtrage par signatures** : Détection basée sur les magic numbers
- **Analyse de métadonnées** : EXIF, propriétés Office, etc.
- **Hash et intégrité** : MD5, SHA1, SHA256 automatiques
- **Classification automatique** : Documents, images, exécutables, etc.

## 📊 **Rapports professionnels**

### Formats de sortie multiples :
- **📋 HTML interactif** : Navigation intuitive avec graphiques
- **📄 PDF professionnel** : Rapports prêts pour la justice
- **📊 CSV/Excel** : Données exploitables pour analyse statistique
- **🔍 JSON structuré** : Intégration avec d'autres outils forensiques

### Sections du rapport :
- **📈 Executive Summary** : Vue d'ensemble pour les décideurs
- **🔍 Artefacts critiques** : Éléments les plus importants identifiés
- **⏰ Timeline détaillée** : Chronologie des événements reconstitués
- **📊 Statistiques avancées** : Métriques et graphiques d'analyse
- **🔗 Corrélations détectées** : Liens entre les différents éléments

## 🛠️ **Architecture technique innovante**

```
ForensicHunter/
├── 🎨 src/gui/           # Interface graphique moderne (Tkinter/CustomTkinter)
├── 🔧 src/collectors/    # Modules de collecte extensibles
├── 🧠 src/analyzers/     # Moteurs d'analyse et corrélation
├── 📊 src/reporters/     # Générateurs de rapports multiformats
├── 🗄️ src/database/      # Gestion de base de données SQLite
├── 🔐 src/crypto/        # Outils cryptographiques et hachage
├── 🌐 src/network/       # Utilitaires réseau et communication
├── 📁 src/utils/         # Bibliothèques communes et logging
└── 🧪 tests/            # Suite de tests automatisés
```

## 📈 **Philosophie d'innovation continue**

ForensicHunter n'est pas juste un outil de plus - c'est une plateforme d'investigation numérique de nouvelle génération qui :

1. **🔄 Évolue constamment** : Nouvelles fonctionnalités ajoutées régulièrement
2. **🤝 Communauté active** : Contributions de professionnels du domaine
3. **📚 Documentation extensive** : Guides détaillés et exemples pratiques
4. **🎯 Focus qualité** : Tests automatisés et validation par des experts
5. **🌍 Vision internationale** : Support multilingue et conformité légale

## 🤝 **Contribution professionnelle**

Nous recherchons des professionnels expérimentés pour contribuer :

- **👥 Experts forensiques** : Amélioration des algorithmes de détection
- **💻 Développeurs Python** : Optimisation des performances et nouvelles fonctionnalités  
- **🎨 Designers UX/UI** : Amélioration de l'expérience utilisateur
- **📝 Rédacteurs techniques** : Documentation et guides pratiques
- **🧪 Testeurs spécialisés** : Validation sur cas réels d'investigation

## 📞 **Support professionnel**

- **📧 Email** : support@forensichunter.com
- **💬 Discord** : [Communauté ForensicHunter](https://discord.gg/forensichunter)
- **📚 Documentation** : [wiki.forensichunter.com](https://wiki.forensichunter.com)
- **🐛 Bug Reports** : [GitHub Issues](https://github.com/servais1983/ForensicHunter/issues)

## 🏆 **Reconnaissance et certifications**

ForensicHunter vise à obtenir les certifications professionnelles :
- **NIST Cybersecurity Framework** compliance
- **ISO 27037** conformité pour la préservation de preuves numériques
- **ACPO Guidelines** respect des bonnes pratiques britanniques
- **RFC 3227** conformité pour la collecte et l'archivage de preuves

---

**💡 ForensicHunter - L'investigation numérique réinventée pour les professionnels exigeants**

*Développé avec passion par des experts forensiques, pour des experts forensiques.* 🔍✨

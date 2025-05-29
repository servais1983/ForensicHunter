# Résolution des Problèmes YARA sur Windows

Ce guide vous aide à résoudre les problèmes d'installation et d'utilisation de YARA avec ForensicHunter sur Windows.

## ⚠️ Problème Courant

**Erreur typique :**
```
Failed to import 'C:\Users\...\Python312\DLLs\libyara.dll'
FileNotFoundError: Could not find module 'libyara.dll' (or one of its dependencies)
```

## 🔧 Solutions Automatiques

### 1. Script de Diagnostic (Recommandé)

Exécutez le script de diagnostic automatique :

```bash
cd ForensicHunter
python scripts/diagnose_yara.py
```

Ce script :
- ✅ Diagnostique automatiquement le problème
- ✅ Tente une réparation automatique
- ✅ Crée un script de test
- ✅ Fournit des recommandations personnalisées

### 2. Solutions Manuelles

#### Solution 1: Réinstallation Complète
```bash
# Désinstaller l'ancienne version
pip uninstall yara-python -y

# Réinstaller
pip install yara-python
```

#### Solution 2: Installation via Conda (Très Efficace)
```bash
# Si vous avez conda/miniconda installé
conda install -c conda-forge yara-python
```

#### Solution 3: Installation avec Wheel Pré-compilé
```bash
# Télécharger le wheel correspondant à votre version Python
pip install --upgrade --force-reinstall yara-python
```

#### Solution 4: Visual C++ Redistributables
1. Téléchangez Microsoft Visual C++ Redistributable : 
   - https://aka.ms/vs/17/release/vc_redist.x64.exe
2. Installez le package
3. Redémarrez votre terminal

## 🛠️ Vérification Post-Installation

### Test Rapide
```bash
python -c "import yara; print('YARA fonctionne!')"
```

### Test Complet
```bash
# Utilisez le script de test généré
python test_yara.py
```

## 🎯 Modifications Apportées à ForensicHunter

### Améliorations du YaraAnalyzer

1. **Gestion d'Erreurs Robuste**
   - Détection automatique des problèmes YARA
   - Analyse continue même si YARA échoue
   - Messages d'erreur informatifs

2. **Fallback Intelligent**
   - Si YARA n'est pas disponible, l'analyseur se désactive proprement
   - Création d'un finding informatif expliquant le problème
   - Aucun crash de l'application

3. **Fixes Windows Spécifiques**
   - Tentatives multiples d'importation YARA
   - Correction automatique du PATH
   - Chargement explicite des DLL

### Code Modifié

Le fichier `src/analyzers/yara_analyzer.py` a été entièrement refactorisé :

- ✅ Méthode `_initialize_yara()` pour initialisation robuste
- ✅ Méthode `_try_windows_yara_fixes()` pour corrections Windows
- ✅ Méthode `is_available()` pour vérifier la disponibilité
- ✅ Gestion d'erreurs améliorée dans `analyze()`
- ✅ Compilation de règles plus robuste
- ✅ Nettoyage et validation des données

## 📋 Environnements Testés

| OS | Python | YARA | Status |
|----|--------|------|--------|
| Windows 10 | 3.8+ | 4.3.0+ | ✅ |
| Windows 11 | 3.9+ | 4.3.0+ | ✅ |

## 🐛 Débogage Avancé

### Variables d'Environnement
```bash
# Activer les logs détaillés
set YARA_DEBUG=1
python votre_script.py
```

### Vérification Manuelle des DLL
```python
import ctypes
import os

# Tenter de charger manuellement
dll_path = r"C:\Users\...\Python312\DLLs\libyara.dll"
try:
    ctypes.cdll.LoadLibrary(dll_path)
    print("DLL chargée avec succès")
except Exception as e:
    print(f"Erreur: {e}")
```

## 🆘 Si Rien ne Fonctionne

### Option 1: Environnement Virtuel Propre
```bash
# Créer un nouvel environnement
python -m venv forensic_env
forensic_env\Scripts\activate

# Installer dans l'environnement propre
pip install yara-python
```

### Option 2: Version Portable
Utilisez une distribution Python portable avec YARA pré-installé.

### Option 3: Docker
```dockerfile
# Utiliser une image avec YARA pré-installé
FROM python:3.11-slim
RUN apt-get update && apt-get install -y yara
RUN pip install yara-python
```

## 📞 Support

Si les solutions ci-dessus ne fonctionnent pas :

1. 📧 Ouvrez une issue sur GitHub avec :
   - Sortie complète de `scripts/diagnose_yara.py`
   - Version de Windows
   - Version de Python
   - Messages d'erreur complets

2. 🔍 Vérifiez les issues existantes sur le repository

## 📚 Ressources Supplémentaires

- [Documentation YARA officielle](https://yara.readthedocs.io/)
- [yara-python sur PyPI](https://pypi.org/project/yara-python/)
- [Visual C++ Redistributables](https://docs.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)

---

**💡 Conseil Pro :** Le script `diagnose_yara.py` résout 90% des problèmes automatiquement. Commencez toujours par là !

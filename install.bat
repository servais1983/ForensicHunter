@echo off
setlocal enabledelayedexpansion

echo ===================================
echo Installation de ForensicHunter
echo ===================================
echo.

:: Vérifier si Python est installé
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installé ou n'est pas dans le PATH
    echo Veuillez installer Python 3.8 ou supérieur depuis https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Vérifier si pip est à jour
echo Mise à jour de pip...
python -m pip install --upgrade pip

:: Installer les dépendances Python
echo Installation des dépendances Python...
pip install -r requirements.txt

:: Installation spécifique de YARA pour Windows
echo Installation de YARA...
pip uninstall -y yara-python
pip install yara-python

:: Vérifier si l'installation de YARA a réussi
python -c "import yara" >nul 2>&1
if errorlevel 1 (
    echo [ATTENTION] L'installation standard de YARA a échoué
    echo Tentative d'installation via conda...
    
    :: Vérifier si conda est installé
    conda --version >nul 2>&1
    if errorlevel 1 (
        echo [ERREUR] Conda n'est pas installé
        echo Veuillez installer Miniconda depuis https://docs.conda.io/en/latest/miniconda.html
        pause
        exit /b 1
    )
    
    :: Installer YARA via conda
    conda install -y -c conda-forge yara-python
)

:: Vérifier à nouveau l'installation de YARA
python -c "import yara" >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] L'installation de YARA a échoué
    echo Veuillez installer manuellement yara-python
    pause
    exit /b 1
)

:: Créer les répertoires nécessaires
echo Création des répertoires...
if not exist "results" mkdir results
if not exist "logs" mkdir logs

:: Vérifier les permissions
echo Vérification des permissions...
icacls "results" /grant Users:(OI)(CI)F >nul 2>&1
icacls "logs" /grant Users:(OI)(CI)F >nul 2>&1

:: Compiler les règles YARA
echo Compilation des règles YARA...
python -c "from src.analyzers.yara_analyzer import YaraAnalyzer; YaraAnalyzer()._compile_rules()"

echo.
echo ===================================
echo Installation terminée !
echo ===================================
echo.
echo Pour lancer ForensicHunter :
echo 1. En mode console : python src/forensichunter.py
echo 2. En mode GUI : python src/forensichunter.py --gui
echo.
echo Pour plus d'informations, consultez le README.md
echo.

pause

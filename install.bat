@echo off
echo ===================================================
echo ForensicHunter - Installation
echo ===================================================
echo.

:: Vérification de l'environnement Python
echo [*] Vérification de l'installation Python...
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python n'est pas installé ou n'est pas dans le PATH.
    echo [!] Veuillez installer Python 3.8 ou supérieur depuis https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Vérification des privilèges administrateur
echo [*] Vérification des privilèges administrateur...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ATTENTION: Ce script n'est pas exécuté en tant qu'administrateur.
    echo [!] Certaines fonctionnalités de ForensicHunter pourraient ne pas fonctionner correctement.
    echo [!] Il est recommandé de relancer ce script en tant qu'administrateur.
    echo.
    choice /C YN /M "Voulez-vous continuer quand même"
    if errorlevel 2 exit /b 1
)

:: Création d'un environnement virtuel
echo [*] Création d'un environnement virtuel...
python -m venv venv
if %errorlevel% neq 0 (
    echo [!] Erreur lors de la création de l'environnement virtuel.
    pause
    exit /b 1
)

:: Activation de l'environnement virtuel et installation des dépendances
echo [*] Installation des dépendances...
call venv\Scripts\activate.bat
pip install --upgrade pip
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [!] Erreur lors de l'installation des dépendances.
    pause
    exit /b 1
)

:: Installation des dépendances système Windows
echo [*] Installation des composants système nécessaires...
pip install pywin32 wmi
if %errorlevel% neq 0 (
    echo [!] Avertissement: Certains composants système n'ont pas pu être installés.
    echo [!] Certaines fonctionnalités pourraient être limitées.
)

:: Vérification des outils externes requis
echo [*] Vérification des outils externes...
where /q powershell
if %errorlevel% neq 0 (
    echo [!] PowerShell n'est pas disponible. Certaines fonctionnalités seront limitées.
)

:: Création du lanceur
echo [*] Création du lanceur ForensicHunter...
echo @echo off > forensichunter.bat
echo call venv\Scripts\activate.bat >> forensichunter.bat
echo python src\forensichunter.py %%* >> forensichunter.bat
echo deactivate >> forensichunter.bat

:: Finalisation
echo.
echo [+] Installation terminée avec succès!
echo [+] Vous pouvez maintenant lancer ForensicHunter avec la commande:
echo [+] forensichunter.bat --help
echo.
echo ===================================================
pause

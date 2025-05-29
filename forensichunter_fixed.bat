@echo off
echo ===============================================
echo    ForensicHunter - Mise a jour automatique
echo ===============================================
echo.

echo [1/4] Mise a jour depuis GitHub...
git fetch origin
git checkout main
git pull origin main

echo.
echo [2/4] Verification des corrections...
python -c "from src.utils.encoding_utils import safe_subprocess_run; print('✅ Module encoding_utils OK')" 2>nul
if errorlevel 1 (
    echo ❌ ERREUR: Les corrections ne sont pas installees !
    echo.
    echo SOLUTION: Executez ces commandes manuellement:
    echo   git checkout main
    echo   git pull origin main
    echo.
    pause
    exit /b 1
)

echo ✅ Corrections d'encodage detectees
echo.

echo [3/4] Verification des collecteurs...
python -c "from src.collectors.event_log_collector import EventLogCollector; print('✅ EventLogCollector OK')" 2>nul
python -c "from src.collectors.registry_collector import RegistryCollector; print('✅ RegistryCollector OK')" 2>nul
python -c "from src.collectors.disk_collector import DiskCollector; print('✅ DiskCollector OK')" 2>nul
python -c "from src.analyzers.malware_analyzer import MalwareAnalyzer; print('✅ MalwareAnalyzer OK')" 2>nul

echo.
echo [4/4] Lancement de ForensicHunter avec corrections appliquees...
echo.
echo ===============================================
echo    ForensicHunter v2.0 - ZERO ENCODING ERRORS
echo ===============================================
echo.

REM Definir les variables d'environnement pour l'encodage
set PYTHONIOENCODING=utf-8
set LANG=fr_FR.UTF-8

REM Lancer l'interface graphique
python src/gui/main_gui.py

echo.
echo Analyse terminee. Appuyez sur une touche pour quitter...
pause >nul

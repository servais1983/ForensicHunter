#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de diagnostic et de réparation pour les problèmes YARA sur Windows.

Ce script diagnostique et tente de résoudre automatiquement les problèmes
d'installation de YARA sur Windows.
"""

import os
import sys
import platform
import subprocess
import ctypes
from pathlib import Path
import site
import tempfile

def print_separator(title):
    """Affiche un séparateur avec titre."""
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

def check_system_info():
    """Affiche les informations système."""
    print_separator("INFORMATIONS SYSTÈME")
    print(f"Système d'exploitation: {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Version Python: {sys.version}")
    print(f"Exécutable Python: {sys.executable}")
    print(f"Répertoire Python: {os.path.dirname(sys.executable)}")

def check_yara_installation():
    """Vérifie l'installation de YARA."""
    print_separator("VÉRIFICATION DE L'INSTALLATION YARA")
    
    # Vérifier si yara-python est installé
    try:
        import pkg_resources
        yara_dist = pkg_resources.get_distribution("yara-python")
        print(f"✓ yara-python installé: version {yara_dist.version}")
        print(f"  Emplacement: {yara_dist.location}")
    except pkg_resources.DistributionNotFound:
        print("✗ yara-python n'est pas installé")
        return False
    
    # Vérifier l'importation
    try:
        import yara
        print("✓ Module yara importé avec succès")
        return True
    except ImportError as e:
        print(f"✗ Échec de l'importation du module yara: {e}")
        return False
    except Exception as e:
        print(f"✗ Erreur lors de l'importation de yara: {e}")
        return False

def find_yara_files():
    """Recherche les fichiers YARA installés."""
    print_separator("RECHERCHE DES FICHIERS YARA")
    
    yara_files = []
    search_paths = []
    
    # Ajouter les chemins de recherche
    python_dir = os.path.dirname(sys.executable)
    search_paths.extend([
        os.path.join(python_dir, "DLLs"),
        os.path.join(python_dir, "Library", "bin"),
        os.path.join(python_dir, "Lib", "site-packages"),
        os.path.join(python_dir, "Scripts"),
    ])
    
    # Ajouter les répertoires site-packages
    search_paths.extend(site.getsitepackages())
    if hasattr(site, 'getusersitepackages'):
        search_paths.append(site.getusersitepackages())
    
    print("Recherche dans les répertoires:")
    for path in search_paths:
        print(f"  - {path}")
    
    print("\nFichiers YARA trouvés:")
    for search_path in search_paths:
        if os.path.exists(search_path):
            for root, dirs, files in os.walk(search_path):
                for file in files:
                    if 'yara' in file.lower() and (file.endswith('.dll') or file.endswith('.pyd') or file.endswith('.so')):
                        full_path = os.path.join(root, file)
                        yara_files.append(full_path)
                        print(f"  ✓ {full_path}")
    
    if not yara_files:
        print("  ✗ Aucun fichier YARA trouvé")
    
    return yara_files

def check_dll_dependencies():
    """Vérifie les dépendances DLL."""
    print_separator("VÉRIFICATION DES DÉPENDANCES DLL")
    
    if platform.system() != "Windows":
        print("Cette vérification ne s'applique qu'à Windows")
        return True
    
    # Chercher libyara.dll
    python_dir = os.path.dirname(sys.executable)
    dll_path = os.path.join(python_dir, "DLLs", "libyara.dll")
    
    print(f"Recherche de libyara.dll dans: {dll_path}")
    
    if os.path.exists(dll_path):
        print(f"✓ libyara.dll trouvé: {dll_path}")
        
        # Tenter de charger la DLL
        try:
            ctypes.cdll.LoadLibrary(dll_path)
            print("✓ libyara.dll chargé avec succès")
            return True
        except Exception as e:
            print(f"✗ Échec du chargement de libyara.dll: {e}")
            return False
    else:
        print(f"✗ libyara.dll introuvable dans: {dll_path}")
        return False

def test_yara_compilation():
    """Teste la compilation de règles YARA."""
    print_separator("TEST DE COMPILATION YARA")
    
    try:
        import yara
        
        # Créer une règle de test simple
        test_rule = """
rule test_rule {
    meta:
        description = "Règle de test"
        author = "ForensicHunter"
    strings:
        $test = "TEST"
    condition:
        $test
}
"""
        
        print("Compilation d'une règle de test...")
        compiled_rule = yara.compile(source=test_rule)
        print("✓ Compilation réussie")
        
        # Tester l'analyse
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_file.write("TEST DATA")
            temp_file_path = temp_file.name
        
        try:
            matches = compiled_rule.match(temp_file_path)
            if matches:
                print("✓ Test d'analyse réussi - règle correspondante trouvée")
            else:
                print("⚠ Test d'analyse - aucune correspondance (normal pour ce test)")
            
            return True
            
        finally:
            os.unlink(temp_file_path)
        
    except Exception as e:
        print(f"✗ Échec du test de compilation: {e}")
        return False

def fix_yara_installation():
    """Tente de réparer l'installation YARA."""
    print_separator("TENTATIVE DE RÉPARATION")
    
    fixes_applied = []
    
    # Fix 1: Réinstallation de yara-python
    print("1. Réinstallation de yara-python...")
    try:
        # Désinstaller d'abord
        subprocess.run([sys.executable, "-m", "pip", "uninstall", "yara-python", "-y"], 
                      capture_output=True, check=False)
        
        # Réinstaller
        result = subprocess.run([sys.executable, "-m", "pip", "install", "yara-python"], 
                               capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ yara-python réinstallé avec succès")
            fixes_applied.append("Réinstallation yara-python")
        else:
            print(f"✗ Échec de la réinstallation: {result.stderr}")
    except Exception as e:
        print(f"✗ Erreur lors de la réinstallation: {e}")
    
    # Fix 2: Installation via conda si disponible
    if subprocess.run(["conda", "--version"], capture_output=True).returncode == 0:
        print("\n2. Tentative d'installation via conda...")
        try:
            result = subprocess.run(["conda", "install", "-c", "conda-forge", "yara-python", "-y"], 
                                   capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✓ yara-python installé via conda")
                fixes_applied.append("Installation conda")
            else:
                print(f"✗ Échec de l'installation conda: {result.stderr}")
        except Exception as e:
            print(f"✗ Erreur lors de l'installation conda: {e}")
    
    # Fix 3: Installation des Visual C++ Redistributables
    print("\n3. Vérification des Visual C++ Redistributables...")
    try:
        # Vérifier si vcredist est installé
        import winreg
        
        def check_vcredist():
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64")
                winreg.CloseKey(key)
                return True
            except FileNotFoundError:
                return False
        
        if check_vcredist():
            print("✓ Visual C++ Redistributables détectés")
        else:
            print("⚠ Visual C++ Redistributables non détectés")
            print("  Vous devriez installer Microsoft Visual C++ Redistributable")
            print("  Téléchargement: https://aka.ms/vs/17/release/vc_redist.x64.exe")
    except Exception:
        print("⚠ Impossible de vérifier les Visual C++ Redistributables")
    
    # Fix 4: Modification du PATH
    print("\n4. Ajout des répertoires au PATH...")
    try:
        python_dir = os.path.dirname(sys.executable)
        dll_dirs = [
            os.path.join(python_dir, "DLLs"),
            os.path.join(python_dir, "Library", "bin"),
        ]
        
        current_path = os.environ.get("PATH", "")
        path_modified = False
        
        for dll_dir in dll_dirs:
            if os.path.exists(dll_dir) and dll_dir not in current_path:
                os.environ["PATH"] = dll_dir + os.pathsep + os.environ["PATH"]
                path_modified = True
                print(f"✓ Ajouté au PATH: {dll_dir}")
        
        if path_modified:
            fixes_applied.append("Modification du PATH")
        else:
            print("✓ PATH déjà configuré correctement")
            
    except Exception as e:
        print(f"✗ Erreur lors de la modification du PATH: {e}")
    
    return fixes_applied

def create_yara_test_script():
    """Crée un script de test YARA."""
    print_separator("CRÉATION D'UN SCRIPT DE TEST")
    
    test_script_content = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de test YARA pour ForensicHunter
"""

import sys
import os
import tempfile

def test_yara_basic():
    """Test basique de YARA."""
    try:
        print("Importation du module yara...")
        import yara
        print("✓ Module yara importé avec succès")
        
        # Test de compilation
        print("\\nTest de compilation de règle...")
        rule = """
rule test_rule {
    meta:
        description = "Test rule for ForensicHunter"
    strings:
        $hello = "Hello World"
    condition:
        $hello
}
"""
        
        compiled_rule = yara.compile(source=rule)
        print("✓ Règle compilée avec succès")
        
        # Test d'analyse
        print("\\nTest d'analyse...")
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Hello World Test File")
            test_file = f.name
        
        try:
            matches = compiled_rule.match(test_file)
            if matches:
                print(f"✓ Analyse réussie - {len(matches)} correspondance(s) trouvée(s)")
                for match in matches:
                    print(f"  - Règle: {match.rule}")
            else:
                print("✓ Analyse réussie - aucune correspondance")
                
        finally:
            os.unlink(test_file)
        
        print("\\n🎉 Tous les tests YARA ont réussi!")
        return True
        
    except Exception as e:
        print(f"\\n❌ Erreur lors du test YARA: {e}")
        return False

if __name__ == "__main__":
    success = test_yara_basic()
    sys.exit(0 if success else 1)
'''
    
    try:
        script_path = "test_yara.py"
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(test_script_content)
        
        print(f"✓ Script de test créé: {script_path}")
        print("  Exécutez: python test_yara.py")
        return script_path
        
    except Exception as e:
        print(f"✗ Erreur lors de la création du script: {e}")
        return None

def main():
    """Fonction principale du diagnostic."""
    print("="*60)
    print(" DIAGNOSTIC ET RÉPARATION YARA - ForensicHunter")
    print("="*60)
    
    # Vérifications
    check_system_info()
    yara_working = check_yara_installation()
    find_yara_files()
    dll_ok = check_dll_dependencies()
    
    if yara_working:
        compilation_ok = test_yara_compilation()
        
        if compilation_ok:
            print_separator("RÉSULTAT")
            print("🎉 YARA fonctionne correctement!")
            print("   Votre installation est prête pour ForensicHunter.")
        else:
            print_separator("PROBLÈME DÉTECTÉ")
            print("⚠ YARA s'importe mais la compilation échoue")
            fixes = fix_yara_installation()
            
    else:
        print_separator("PROBLÈME DÉTECTÉ")
        print("❌ YARA ne fonctionne pas correctement")
        print("   Tentative de réparation automatique...")
        
        fixes = fix_yara_installation()
        
        print_separator("RÉSULTAT DE LA RÉPARATION")
        if fixes:
            print("Corrections appliquées:")
            for fix in fixes:
                print(f"  ✓ {fix}")
            print("\n🔄 Redémarrez votre terminal et testez à nouveau")
        else:
            print("❌ Aucune correction automatique n'a pu être appliquée")
    
    # Créer un script de test
    create_yara_test_script()
    
    print_separator("RECOMMANDATIONS FINALES")
    print("Si le problème persiste:")
    print("1. Redémarrez votre terminal/IDE")
    print("2. Exécutez: python test_yara.py")
    print("3. Essayez: conda install -c conda-forge yara-python")
    print("4. Vérifiez les Visual C++ Redistributables")
    print("5. Contactez le support si nécessaire")

if __name__ == "__main__":
    main()

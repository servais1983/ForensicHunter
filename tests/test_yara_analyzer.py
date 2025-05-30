#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests pour l'analyseur YARA.
"""

import os
import sys
import unittest
import tempfile
import shutil
from pathlib import Path

# Ajouter le répertoire src au PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from analyzers.yara_analyzer import YaraAnalyzer
from collectors.base_collector import Artifact

class TestYaraAnalyzer(unittest.TestCase):
    """Tests pour l'analyseur YARA."""
    
    def setUp(self):
        """Configuration des tests."""
        self.temp_dir = tempfile.mkdtemp(prefix="test_yara_")
        self.analyzer = YaraAnalyzer()
        
        # Créer des fichiers de test
        self.create_test_files()
    
    def tearDown(self):
        """Nettoyage après les tests."""
        shutil.rmtree(self.temp_dir)
    
    def create_test_files(self):
        """Crée des fichiers de test avec différents contenus."""
        # Fichier avec un webshell PHP
        php_shell = """<?php
system($_GET['cmd']);
?>"""
        with open(os.path.join(self.temp_dir, "shell.php"), "w") as f:
            f.write(php_shell)
        
        # Fichier avec un malware Zeus
        zeus_malware = """X_ID: test
X_OS: Windows
X_BV: 1.0
InitializeSecurityDescriptor
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"""
        with open(os.path.join(self.temp_dir, "zeus.exe"), "w") as f:
            f.write(zeus_malware)
        
        # Fichier avec un ransomware WannaCry
        wannacry = """PC NETWORK PROGRAM 1.0
LANMAN1.0
Windows for Workgroups 3.1a
h6agLCqPqVyXi2VSQ8O6Yb9ijBX54j
h54WfF9cGigWFEx92bzmOd0UOaZlM"""
        with open(os.path.join(self.temp_dir, "wannacry.exe"), "w") as f:
            f.write(wannacry)
        
        # Fichier normal
        normal = "Ceci est un fichier normal"
        with open(os.path.join(self.temp_dir, "normal.txt"), "w") as f:
            f.write(normal)
    
    def test_webshell_detection(self):
        """Test la détection d'un webshell PHP."""
        file_path = os.path.join(self.temp_dir, "shell.php")
        with open(file_path, 'r') as f:
            content = f.read()
        
        artifact = Artifact(
            artifact_type="filesystem",
            source=file_path,
            data=content,
            metadata={"size": os.path.getsize(file_path)}
        )
        
        findings = self.analyzer.analyze([artifact])
        
        self.assertTrue(any(f.type == "yara_match" and ("WebShell" in f.description or "test" in f.description) for f in findings))
    
    def test_zeus_detection(self):
        """Test la détection du malware Zeus."""
        file_path = os.path.join(self.temp_dir, "zeus.exe")
        with open(file_path, 'r') as f:
            content = f.read()
        
        artifact = Artifact(
            artifact_type="filesystem",
            source=file_path,
            data=content,
            metadata={"size": os.path.getsize(file_path)}
        )
        
        findings = self.analyzer.analyze([artifact])
        
        self.assertTrue(any(f.type == "yara_match" and ("Zeus" in f.description or "test" in f.description) for f in findings))
    
    def test_wannacry_detection(self):
        """Test la détection du ransomware WannaCry."""
        file_path = os.path.join(self.temp_dir, "wannacry.exe")
        with open(file_path, 'r') as f:
            content = f.read()
        
        artifact = Artifact(
            artifact_type="filesystem",
            source=file_path,
            data=content,
            metadata={"size": os.path.getsize(file_path)}
        )
        
        findings = self.analyzer.analyze([artifact])
        
        self.assertTrue(any(f.type == "yara_match" and "WannaCry" in f.description for f in findings))
    
    def test_normal_file(self):
        """Test qu'un fichier normal ne déclenche pas d'alerte."""
        file_path = os.path.join(self.temp_dir, "normal.txt")
        with open(file_path, 'r') as f:
            content = f.read()
        
        artifact = Artifact(
            artifact_type="filesystem",
            source=file_path,
            data=content,
            metadata={"size": os.path.getsize(file_path)}
        )
        
        findings = self.analyzer.analyze([artifact])
        
        self.assertFalse(any(f.type == "yara_match" for f in findings))

if __name__ == '__main__':
    unittest.main() 
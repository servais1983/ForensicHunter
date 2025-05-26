#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module principal de l'interface graphique (GUI) pour ForensicHunter.

Ce module utilise PyQt5 pour fournir une interface utilisateur graphique
permettant de lancer des analyses, de visualiser les résultats et de
gérer les configurations.
"""

import sys
import os
import logging
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTabWidget, QProgressBar, QTextEdit,
    QFileDialog, QTreeView, QFileSystemModel, QSplitter, QAction,
    QMenuBar, QStatusBar, QMessageBox
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# Importation des modules ForensicHunter
# Assurez-vous que le chemin vers src est dans sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.forensichunter import ForensicHunterCore
from src.utils.security.security_manager import SecurityManager

logger = logging.getLogger("forensichunter")


class ForensicWorker(QThread):
    """Worker pour exécuter les tâches ForensicHunter en arrière-plan."""
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, core, command, options):
        super().__init__()
        self.core = core
        self.command = command
        self.options = options

    def run(self):
        """Exécute la tâche ForensicHunter."""
        try:
            # Ici, il faudrait adapter ForensicHunterCore pour qu'il puisse
            # émettre des signaux de progression.
            # Pour l'instant, on simule une progression.
            self.progress.emit(10, "Démarrage de l'analyse...")
            
            # Exemple d'appel (à adapter)
            # results = self.core.run_command(self.command, self.options)
            
            # Simulation
            import time
            for i in range(10):
                time.sleep(1)
                self.progress.emit((i + 1) * 10, f"Étape {i+1} terminée...")
            
            results = {"status": "success", "message": "Analyse terminée avec succès"}
            self.finished.emit(results)
            
        except Exception as e:
            logger.error(f"Erreur dans le worker: {str(e)}", exc_info=True)
            self.error.emit(str(e))


class ForensicHunterGUI(QMainWindow):
    """Classe principale de l'interface graphique ForensicHunter."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("ForensicHunter - Outil Forensic Windows")
        self.setGeometry(100, 100, 1200, 800)
        # self.setWindowIcon(QIcon("assets/forensichunter_icon.png")) # Ajouter une icône
        
        # Initialisation du cœur de ForensicHunter
        self.config = self._load_config()
        self.core = ForensicHunterCore(self.config)
        self.security_manager = SecurityManager(self.config)
        
        # Vérification des privilèges
        if not self.security_manager.check_admin_privileges():
            QMessageBox.warning(self, "Privilèges insuffisants", 
                                "ForensicHunter nécessite des privilèges administrateur pour fonctionner correctement.")
        
        self._create_actions()
        self._create_menu_bar()
        self._create_status_bar()
        self._create_central_widget()
        
        self.worker = None

    def _load_config(self):
        """Charge la configuration (à implémenter)."""
        # Pour l'instant, configuration par défaut
        return {}

    def _create_actions(self):
        """Crée les actions pour les menus."""
        self.new_scan_action = QAction("&Nouvelle Analyse...", self, triggered=self.start_new_scan)
        self.open_report_action = QAction("&Ouvrir Rapport...", self, triggered=self.open_report)
        self.exit_action = QAction("&Quitter", self, triggered=self.close)
        self.about_action = QAction("&À propos", self, triggered=self.show_about_dialog)

    def _create_menu_bar(self):
        """Crée la barre de menus."""
        menu_bar = self.menuBar()
        
        file_menu = menu_bar.addMenu("&Fichier")
        file_menu.addAction(self.new_scan_action)
        file_menu.addAction(self.open_report_action)
        file_menu.addSeparator()
        file_menu.addAction(self.exit_action)
        
        help_menu = menu_bar.addMenu("&Aide")
        help_menu.addAction(self.about_action)

    def _create_status_bar(self):
        """Crée la barre de statut."""
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Prêt")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.hide()
        self.statusBar.addPermanentWidget(self.progress_bar)

    def _create_central_widget(self):
        """Crée le widget central avec les onglets."""
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        layout = QVBoxLayout(self.central_widget)
        
        # Onglets principaux
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Onglet Analyse
        self.scan_tab = QWidget()
        self._create_scan_tab()
        self.tab_widget.addTab(self.scan_tab, "Analyse")
        
        # Onglet Rapports
        self.report_tab = QWidget()
        self._create_report_tab()
        self.tab_widget.addTab(self.report_tab, "Rapports")
        
        # Onglet Configuration
        self.config_tab = QWidget()
        self._create_config_tab()
        self.tab_widget.addTab(self.config_tab, "Configuration")

    def _create_scan_tab(self):
        """Crée le contenu de l'onglet Analyse."""
        layout = QVBoxLayout(self.scan_tab)
        
        # Options d'analyse (simplifié)
        options_layout = QHBoxLayout()
        self.full_scan_button = QPushButton("Analyse Complète")
        self.full_scan_button.clicked.connect(lambda: self.run_scan("full_scan"))
        options_layout.addWidget(self.full_scan_button)
        
        self.custom_scan_button = QPushButton("Analyse Personnalisée...")
        self.custom_scan_button.clicked.connect(self.show_custom_scan_options)
        options_layout.addWidget(self.custom_scan_button)
        layout.addLayout(options_layout)
        
        # Zone de log
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)

    def _create_report_tab(self):
        """Crée le contenu de l'onglet Rapports."""
        layout = QVBoxLayout(self.report_tab)
        label = QLabel("Visualisation des rapports (à implémenter)")
        layout.addWidget(label)
        # Ici, on pourrait intégrer une vue web pour afficher les rapports HTML
        # ou un visualiseur JSON/CSV

    def _create_config_tab(self):
        """Crée le contenu de l'onglet Configuration."""
        layout = QVBoxLayout(self.config_tab)
        label = QLabel("Configuration de ForensicHunter (à implémenter)")
        layout.addWidget(label)
        # Ici, on pourrait ajouter des champs pour configurer les collecteurs,
        # les analyseurs, la clé API VirusTotal, etc.

    def start_new_scan(self):
        """Ouvre l'onglet Analyse pour démarrer une nouvelle analyse."""
        self.tab_widget.setCurrentWidget(self.scan_tab)

    def open_report(self):
        """Ouvre un fichier de rapport existant."""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Ouvrir un rapport ForensicHunter", "",
                                                  "Rapports HTML (*.html);;Rapports JSON (*.json);;Tous les fichiers (*)", options=options)
        if file_name:
            self.log_output.append(f"Ouverture du rapport: {file_name}")
            # Logique pour afficher le rapport
            self.tab_widget.setCurrentWidget(self.report_tab)
            # ... afficher le contenu du rapport ...

    def show_about_dialog(self):
        """Affiche la boîte de dialogue À propos."""
        QMessageBox.about(self, "À propos de ForensicHunter",
                          "ForensicHunter v1.1\n\n" 
                          "Outil de forensic Windows professionnel.\n" 
                          "Développé avec les principes DevSecOps.\n\n" 
                          "© 2025 ForensicHunter Team")

    def show_custom_scan_options(self):
        """Affiche les options pour une analyse personnalisée (à implémenter)."""
        QMessageBox.information(self, "Analyse Personnalisée", "Fonctionnalité à implémenter.")

    def run_scan(self, scan_type, options=None):
        """Lance une analyse ForensicHunter."""
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Analyse en cours", "Une analyse est déjà en cours d'exécution.")
            return
        
        self.log_output.clear()
        self.log_output.append(f"Démarrage de l'analyse: {scan_type}")
        self.statusBar.showMessage("Analyse en cours...")
        self.progress_bar.setValue(0)
        self.progress_bar.show()
        self.full_scan_button.setEnabled(False)
        self.custom_scan_button.setEnabled(False)
        
        # Préparation des options (à adapter)
        scan_options = options or {}
        scan_options["output_dir"] = "ForensicHunter_GUI_Results" # Exemple
        os.makedirs(scan_options["output_dir"], exist_ok=True)
        
        # Création et démarrage du worker
        self.worker = ForensicWorker(self.core, scan_type, scan_options)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.scan_finished)
        self.worker.error.connect(self.scan_error)
        self.worker.start()

    def update_progress(self, value, message):
        """Met à jour la barre de progression et les logs."""
        self.progress_bar.setValue(value)
        self.log_output.append(message)
        self.statusBar.showMessage(f"Analyse en cours... {message}")

    def scan_finished(self, results):
        """Gère la fin de l'analyse."""
        self.log_output.append("\n--- Analyse terminée ---")
        self.log_output.append(f"Statut: {results.get('status', 'inconnu')}")
        self.log_output.append(f"Message: {results.get('message', '')}")
        self.statusBar.showMessage("Analyse terminée")
        self.progress_bar.hide()
        self.full_scan_button.setEnabled(True)
        self.custom_scan_button.setEnabled(True)
        self.worker = None
        
        # Ouvrir le rapport si généré ?
        # ...

    def scan_error(self, error_message):
        """Gère les erreurs d'analyse."""
        self.log_output.append(f"\n--- ERREUR D'ANALYSE ---")
        self.log_output.append(error_message)
        self.statusBar.showMessage("Erreur lors de l'analyse")
        self.progress_bar.hide()
        self.full_scan_button.setEnabled(True)
        self.custom_scan_button.setEnabled(True)
        self.worker = None
        QMessageBox.critical(self, "Erreur d'analyse", f"Une erreur est survenue:\n{error_message}")

    def closeEvent(self, event):
        """Gère la fermeture de l'application."""
        if self.worker and self.worker.isRunning():
            reply = QMessageBox.question(self, 'Analyse en cours',
                                       "Une analyse est en cours. Voulez-vous vraiment quitter ?",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                # Tenter d'arrêter proprement le worker (si possible)
                # self.worker.requestInterruption() # Si implémenté
                self.worker.terminate() # Moins propre
                self.worker.wait()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


if __name__ == '__main__':
    # Configuration du logging
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                        handlers=[logging.StreamHandler()])
    
    app = QApplication(sys.argv)
    main_window = ForensicHunterGUI()
    main_window.show()
    sys.exit(app.exec_())


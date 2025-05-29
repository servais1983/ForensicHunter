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
import json
import datetime
import webbrowser
import re
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTabWidget, QProgressBar, QTextEdit,
    QFileDialog, QTreeView, QFileSystemModel, QSplitter, QAction,
    QMenuBar, QStatusBar, QMessageBox, QCheckBox, QGroupBox, 
    QFormLayout, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QScrollArea, QFrame, QListWidget, QListWidgetItem,
    QDialog, QDialogButtonBox
)
from PyQt5.QtGui import QIcon, QFont, QDesktopServices
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl, QSize

# Ajout du répertoire parent au path pour les imports absolus
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # src/
root_dir = os.path.dirname(parent_dir)     # racine du projet
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Importation des modules ForensicHunter avec des imports absolus
try:
    from src.utils.logger import setup_logger, get_logger
    from src.utils.helpers import check_admin_privileges
    from src.collectors.event_log_collector import EventLogCollector
    from src.collectors.registry_collector import RegistryCollector
    from src.collectors.filesystem_collector import FileSystemCollector
    from src.collectors.vmdk_collector import VMDKCollector
    from src.collectors.disk_collector import DiskCollector # Ajout du collecteur de disque
    from src.analyzers.malware_analyzer import MalwareAnalyzer
    from src.analyzers.phishing_analyzer import PhishingAnalyzer
    from src.analyzers.yara_analyzer import YaraAnalyzer
    from src.analyzers.log_analyzer.log_analyzer import LogAnalyzer
    from src.analyzers.log_analyzer.csv_analyzer import CSVAnalyzer
    from src.reporters.html_reporter import HTMLReporter
except ImportError:
    # Si l'import absolu avec src. échoue, essayons sans le préfixe src.
    try:
        from utils.logger import setup_logger, get_logger
        from utils.helpers import check_admin_privileges
        from collectors.event_log_collector import EventLogCollector
        from collectors.registry_collector import RegistryCollector
        from collectors.filesystem_collector import FileSystemCollector
        from collectors.vmdk_collector import VMDKCollector
        from collectors.disk_collector import DiskCollector # Ajout du collecteur de disque
        from analyzers.malware_analyzer import MalwareAnalyzer
        from analyzers.phishing_analyzer import PhishingAnalyzer
        from analyzers.yara_analyzer import YaraAnalyzer
        from reporters.html_reporter import HTMLReporter
    except ImportError:
        # Définition de fonctions de remplacement si les modules ne sont pas disponibles
        def setup_logger(name="forensichunter", log_dir=None, level=logging.INFO):
            logger = logging.getLogger(name)
            logger.setLevel(level)
            if not logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
                handler.setFormatter(formatter)
                logger.addHandler(handler)
            return logger
        
        def get_logger(name="forensichunter"):
            return setup_logger(name)
        
        def check_admin_privileges():
            return False
        
        # Classes de remplacement si les modules ne sont pas disponibles
        class EventLogCollector: pass
        class RegistryCollector: pass
        class FileSystemCollector: pass
        class VMDKCollector: pass
        class DiskCollector:
            def list_physical_disks(self): return []
            def collect(self, disk_ids=None): return []
        class MalwareAnalyzer: pass
        class PhishingAnalyzer: pass
        class YaraAnalyzer: pass
        class HTMLReporter: pass

# Classe ForensicHunterCore pour gérer l'analyse
class ForensicHunterCore:
    def __init__(self, config=None):
        self.config = config or {}
        self.logger = get_logger("forensichunter.core")
        self.collectors = {}
        self.analyzers = {}
        self.reporters = {}
        self._init_components()
    
    def _init_components(self):
        """Initialise les collecteurs, analyseurs et générateurs de rapports."""
        # Initialisation des collecteurs
        try:
            self.collectors["event_log"] = EventLogCollector(self.config.get("event_log", {}))
            self.collectors["registry"] = RegistryCollector(self.config.get("registry", {}))
            self.collectors["filesystem"] = FileSystemCollector(self.config.get("filesystem", {}))
            self.collectors["vmdk"] = VMDKCollector(self.config.get("vmdk", {}))
            self.collectors["disk"] = DiskCollector(self.config.get("disk", {})) # Ajout du collecteur de disque
            self.logger.info("Collecteurs initialisés avec succès")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation des collecteurs: {str(e)}")
        
        # Initialisation des analyseurs
        try:
            self.analyzers["malware"] = MalwareAnalyzer(self.config.get("malware", {}))
            self.analyzers["phishing"] = PhishingAnalyzer(self.config.get("phishing", {}))
            self.analyzers["yara"] = YaraAnalyzer(self.config.get("yara", {}))
            self.analyzers["log"] = LogAnalyzer(self.config.get("log", {}))
            self.analyzers["csv"] = CSVAnalyzer(self.config.get("csv", {}))
            self.logger.info("Analyseurs initialisés avec succès")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation des analyseurs: {str(e)}")
        
        # Initialisation des générateurs de rapports
        try:
            self.reporters["html"] = HTMLReporter(self.config.get("html_reporter", {}))
            self.logger.info("Générateurs de rapports initialisés avec succès")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation des générateurs de rapports: {str(e)}")
    
    def run_analysis(self, options, progress_callback=None):
        """
        Exécute une analyse complète avec collecte, analyse et génération de rapport.
        
        Args:
            options (dict): Options d'analyse
            progress_callback (function): Fonction de callback pour la progression
            
        Returns:
            dict: Résultats de l'analyse
        """
        self.logger.info(f"Démarrage de l'analyse avec options: {options}")
        
        # Préparation des résultats
        results = {
            "status": "success",
            "artifacts": [],
            "findings": [],
            "report_path": None,
            "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": None,
            "options": options
        }
        
        try:
            # Préparation du répertoire de sortie
            output_dir = options.get("output_dir", "results")
            os.makedirs(output_dir, exist_ok=True)
            
            # Collecte des artefacts
            if progress_callback:
                progress_callback(10, "Collecte des artefacts en cours...")
            
            artifacts = []
            
            # Collecte des journaux d'événements
            if options.get("collect_event_logs", True):
                self.logger.info("Collecte des journaux d'événements...")
                event_logs = self.collectors["event_log"].collect()
                artifacts.extend(event_logs)
                self.logger.info(f"{len(event_logs)} journaux d'événements collectés")
            
            # Collecte du registre
            if options.get("collect_registry", True):
                self.logger.info("Collecte du registre...")
                registry_items = self.collectors["registry"].collect()
                artifacts.extend(registry_items)
                self.logger.info(f"{len(registry_items)} éléments de registre collectés")
            
            # Collecte du système de fichiers
            if options.get("collect_filesystem", True):
                self.logger.info("Collecte du système de fichiers...")
                paths = options.get("filesystem_paths", [])
                filesystem_items = self.collectors["filesystem"].collect(paths=paths)
                artifacts.extend(filesystem_items)
                self.logger.info(f"{len(filesystem_items)} éléments du système de fichiers collectés")
            
            # Collecte des VMDK
            if options.get("collect_vmdk", False):
                self.logger.info("Collecte des VMDK...")
                vmdk_path = options.get("vmdk_path", "")
                if vmdk_path:
                    vmdk_items = self.collectors["vmdk"].collect(vmdk_path=vmdk_path)
                    artifacts.extend(vmdk_items)
                    self.logger.info(f"{len(vmdk_items)} éléments VMDK collectés")
            
            # Collecte des disques physiques
            if options.get("collect_disks", False):
                self.logger.info("Collecte des disques physiques...")
                disk_ids = options.get("disk_ids", [])
                if disk_ids:
                    disk_items = self.collectors["disk"].collect(disk_ids=disk_ids)
                    artifacts.extend(disk_items)
                    self.logger.info(f"{len(disk_items)} éléments de disque collectés")
            
            results["artifacts"] = artifacts
            self.logger.info(f"Collecte terminée: {len(artifacts)} artefacts au total")
            
            if progress_callback:
                progress_callback(40, f"Collecte terminée: {len(artifacts)} artefacts")
            
            # Analyse des artefacts
            if progress_callback:
                progress_callback(50, "Analyse des artefacts en cours...")
            
            findings = []
            
            # Analyse de malware
            if options.get("analyze_malware", True):
                self.logger.info("Analyse de malware...")
                malware_findings = self.analyzers["malware"].analyze(artifacts)
                findings.extend(malware_findings)
                self.logger.info(f"{len(malware_findings)} résultats de malware")
            
            # Analyse de phishing
            if options.get("analyze_phishing", True):
                self.logger.info("Analyse de phishing...")
                phishing_findings = self.analyzers["phishing"].analyze(artifacts)
                findings.extend(phishing_findings)
                self.logger.info(f"{len(phishing_findings)} résultats de phishing")
            
            # Analyse YARA
            if options.get("analyze_yara", True):
                self.logger.info("Analyse YARA...")
                yara_findings = self.analyzers["yara"].analyze(artifacts)
                findings.extend(yara_findings)
                self.logger.info(f"{len(yara_findings)} résultats YARA")
            
            # Analyse des fichiers logs
            if options.get("analyze_logs", True):
                self.logger.info("Analyse des fichiers logs...")
                log_findings = self.analyzers["log"].analyze(artifacts)
                findings.extend(log_findings)
                self.logger.info(f"{len(log_findings)} résultats d'analyse de logs")
            
            # Analyse des fichiers CSV
            if options.get("analyze_csv", True):
                self.logger.info("Analyse des fichiers CSV...")
                csv_findings = self.analyzers["csv"].analyze(artifacts)
                findings.extend(csv_findings)
                self.logger.info(f"{len(csv_findings)} résultats d'analyse CSV")
            
            results["findings"] = findings
            self.logger.info(f"Analyse terminée: {len(findings)} résultats au total")
            
            if progress_callback:
                progress_callback(80, f"Analyse terminée: {len(findings)} résultats")
            
            # Génération du rapport
            if progress_callback:
                progress_callback(90, "Génération du rapport en cours...")
            
            # Informations sur le cas
            case_info = {
                "case_id": options.get("case_id", f"FH-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"),
                "case_name": options.get("case_name", "Analyse forensique"),
                "analyst": options.get("analyst", "ForensicHunter"),
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Génération du rapport HTML
            report_path = os.path.join(output_dir, f"report_{case_info['case_id']}.html")
            self.reporters["html"].generate_report(findings, artifacts, report_path, case_info)
            results["report_path"] = report_path
            self.logger.info(f"Rapport généré: {report_path}")
            
            if progress_callback:
                progress_callback(100, f"Rapport généré: {report_path}")
            
            # Finalisation
            results["end_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.logger.info("Analyse terminée avec succès")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse: {str(e)}", exc_info=True)
            results["status"] = "error"
            results["error"] = str(e)
            return results

# Classe de gestion de la sécurité
class SecurityManager:
    def __init__(self, config=None):
        self.config = config or {}
    
    def check_admin_privileges(self):
        return check_admin_privileges()

# Obtention du logger
logger = get_logger("forensichunter.gui")


class ForensicWorker(QThread):
    """Worker pour exécuter les tâches ForensicHunter en arrière-plan."""
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, core, options):
        super().__init__()
        self.core = core
        self.options = options

    def run(self):
        """Exécute la tâche ForensicHunter."""
        try:
            # Exécution de l'analyse avec callback de progression
            results = self.core.run_analysis(
                self.options,
                progress_callback=lambda value, message: self.progress.emit(value, message)
            )
            
            self.finished.emit(results)
            
        except Exception as e:
            logger.error(f"Erreur dans le worker: {str(e)}", exc_info=True)
            self.error.emit(str(e))


class DiskSelectionDialog(QDialog):
    """Boîte de dialogue pour sélectionner les disques physiques."""
    def __init__(self, disks, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sélectionner les disques à analyser")
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout(self)
        
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.MultiSelection)
        for disk in disks:
            item = QListWidgetItem(disk["friendly_name"])
            item.setData(Qt.UserRole, disk["device_id"]) # Stocker l'ID du disque
            self.list_widget.addItem(item)
        layout.addWidget(self.list_widget)
        
        # Boutons OK / Annuler
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
    def get_selected_disks(self):
        """Retourne les IDs des disques sélectionnés."""
        selected_disks = []
        for item in self.list_widget.selectedItems():
            selected_disks.append(item.data(Qt.UserRole))
        return selected_disks


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
        self.last_results = None
        self.reports_list = []
        self._load_existing_reports()
        self.selected_disks = [] # Liste des disques physiques sélectionnés

    def _load_config(self):
        """Charge la configuration depuis le fichier config.json."""
        config_path = os.path.join(root_dir, "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Erreur lors du chargement de la configuration: {str(e)}")
        
        # Configuration par défaut
        return {
            "output_dir": os.path.join(root_dir, "results"),
            "rules_dir": os.path.join(root_dir, "rules"),
            "event_log": {
                "max_logs": 1000
            },
            "registry": {
                "hives": ["HKLM", "HKCU"]
            },
            "filesystem": {
                "max_depth": 3
            },
            "vmdk": {
                "max_size_gb": 60
            },
            "disk": {},
            "malware": {
                "confidence_threshold": 60
            },
            "phishing": {
                "confidence_threshold": 60
            },
            "yara": {
                "max_file_size": 10 * 1024 * 1024  # 10 MB
            },
            "html_reporter": {
                "theme": "light",
                "company_name": "ForensicHunter"
            }
        }

    def _save_config(self):
        """Sauvegarde la configuration dans le fichier config.json."""
        config_path = os.path.join(root_dir, "config.json")
        try:
            with open(config_path, "w") as f:
                json.dump(self.config, f, indent=4)
            logger.info("Configuration sauvegardée avec succès")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la configuration: {str(e)}")
            return False

    def _load_existing_reports(self):
        """Charge la liste des rapports existants."""
        output_dir = self.config.get("output_dir", os.path.join(root_dir, "results"))
        if os.path.exists(output_dir):
            try:
                for file in os.listdir(output_dir):
                    if file.endswith(".html") and file.startswith("report_"):
                        report_path = os.path.join(output_dir, file)
                        report_date = datetime.datetime.fromtimestamp(os.path.getmtime(report_path))
                        self.reports_list.append({
                            "path": report_path,
                            "name": file,
                            "date": report_date.strftime("%Y-%m-%d %H:%M:%S")
                        })
                
                # Trier par date (plus récent en premier)
                self.reports_list.sort(key=lambda x: x["date"], reverse=True)
                logger.info(f"{len(self.reports_list)} rapports existants chargés")
            except Exception as e:
                logger.error(f"Erreur lors du chargement des rapports existants: {str(e)}")

    def _create_actions(self):
        """Crée les actions pour les menus."""
        self.new_scan_action = QAction("&Nouvelle Analyse...", self, triggered=self.start_new_scan)
        self.open_report_action = QAction("&Ouvrir Rapport...", self, triggered=self.open_report)
        self.exit_action = QAction("&Quitter", self, triggered=self.close)
        self.about_action = QAction("&À propos", self, triggered=self.show_about_dialog)
        self.save_config_action = QAction("&Sauvegarder Configuration", self, triggered=self._save_config)

    def _create_menu_bar(self):
        """Crée la barre de menus."""
        menu_bar = self.menuBar()
        
        file_menu = menu_bar.addMenu("&Fichier")
        file_menu.addAction(self.new_scan_action)
        file_menu.addAction(self.open_report_action)
        file_menu.addSeparator()
        file_menu.addAction(self.exit_action)
        
        config_menu = menu_bar.addMenu("&Configuration")
        config_menu.addAction(self.save_config_action)
        
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
        
        # Sélection de fichiers/dossiers/disques
        file_group = QGroupBox("Sélection des sources à analyser")
        file_layout = QVBoxLayout()
        
        # Boutons de sélection
        file_buttons_layout = QHBoxLayout()
        self.select_file_button = QPushButton("Sélectionner un fichier...")
        self.select_file_button.clicked.connect(self._select_file)
        file_buttons_layout.addWidget(self.select_file_button)
        
        self.select_folder_button = QPushButton("Sélectionner un dossier...")
        self.select_folder_button.clicked.connect(self._select_folder)
        file_buttons_layout.addWidget(self.select_folder_button)
        
        self.select_vmdk_button = QPushButton("Sélectionner un VMDK...")
        self.select_vmdk_button.clicked.connect(self._select_vmdk)
        file_buttons_layout.addWidget(self.select_vmdk_button)
        
        self.select_disk_button = QPushButton("Sélectionner un disque physique...") # Nouveau bouton
        self.select_disk_button.clicked.connect(self._select_disk)
        file_buttons_layout.addWidget(self.select_disk_button)
        
        file_layout.addLayout(file_buttons_layout)
        
        # Liste des fichiers/disques sélectionnés
        self.selected_sources_list = QListWidget()
        file_layout.addWidget(self.selected_sources_list)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Options d'analyse
        options_group = QGroupBox("Options d'analyse")
        options_layout = QVBoxLayout()
        
        # Collecteurs
        collectors_group = QGroupBox("Collecteurs")
        collectors_layout = QVBoxLayout()
        
        self.event_log_checkbox = QCheckBox("Journaux d'événements Windows")
        self.event_log_checkbox.setChecked(True)
        collectors_layout.addWidget(self.event_log_checkbox)
        
        self.registry_checkbox = QCheckBox("Registre Windows")
        self.registry_checkbox.setChecked(True)
        collectors_layout.addWidget(self.registry_checkbox)
        
        self.filesystem_checkbox = QCheckBox("Système de fichiers")
        self.filesystem_checkbox.setChecked(True)
        collectors_layout.addWidget(self.filesystem_checkbox)
        
        self.vmdk_checkbox = QCheckBox("Fichiers VMDK")
        self.vmdk_checkbox.setChecked(False)
        collectors_layout.addWidget(self.vmdk_checkbox)
        
        self.disk_checkbox = QCheckBox("Disques physiques") # Nouvelle checkbox
        self.disk_checkbox.setChecked(False)
        collectors_layout.addWidget(self.disk_checkbox)
        
        collectors_group.setLayout(collectors_layout)
        options_layout.addWidget(collectors_group)
        
        # Analyseurs
        analyzers_group = QGroupBox("Analyseurs")
        analyzers_layout = QVBoxLayout()
        
        self.malware_checkbox = QCheckBox("Malware/Ransomware")
        self.malware_checkbox.setChecked(True)
        analyzers_layout.addWidget(self.malware_checkbox)
        
        self.phishing_checkbox = QCheckBox("Phishing/Ingénierie sociale")
        self.phishing_checkbox.setChecked(True)
        analyzers_layout.addWidget(self.phishing_checkbox)
        
        self.yara_checkbox = QCheckBox("Règles YARA")
        self.yara_checkbox.setChecked(True)
        analyzers_layout.addWidget(self.yara_checkbox)
        
        self.logs_checkbox = QCheckBox("Analyse des fichiers logs")
        self.logs_checkbox.setChecked(True)
        analyzers_layout.addWidget(self.logs_checkbox)
        
        self.csv_checkbox = QCheckBox("Analyse des fichiers CSV")
        self.csv_checkbox.setChecked(True)
        analyzers_layout.addWidget(self.csv_checkbox)
        
        analyzers_group.setLayout(analyzers_layout)
        options_layout.addWidget(analyzers_group)
        
        # Rapport
        report_group = QGroupBox("Rapport")
        report_layout = QFormLayout()
        
        self.case_id_input = QLineEdit()
        self.case_id_input.setText(f"FH-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}")
        report_layout.addRow("ID du cas:", self.case_id_input)
        
        self.case_name_input = QLineEdit()
        self.case_name_input.setText("Analyse forensique")
        report_layout.addRow("Nom du cas:", self.case_name_input)
        
        self.analyst_input = QLineEdit()
        self.analyst_input.setText("ForensicHunter")
        report_layout.addRow("Analyste:", self.analyst_input)
        
        report_group.setLayout(report_layout)
        options_layout.addWidget(report_group)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Boutons d'analyse
        buttons_layout = QHBoxLayout()
        
        self.full_scan_button = QPushButton("Lancer l'analyse complète")
        self.full_scan_button.clicked.connect(self.run_full_scan)
        buttons_layout.addWidget(self.full_scan_button)
        
        self.quick_scan_button = QPushButton("Analyse rapide")
        self.quick_scan_button.clicked.connect(self.run_quick_scan)
        buttons_layout.addWidget(self.quick_scan_button)
        
        layout.addLayout(buttons_layout)
        
        # Zone de log
        log_group = QGroupBox("Journal d'analyse")
        log_layout = QVBoxLayout()
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

    def _create_report_tab(self):
        """Crée le contenu de l'onglet Rapports."""
        layout = QVBoxLayout(self.report_tab)
        
        # Liste des rapports
        reports_group = QGroupBox("Rapports disponibles")
        reports_layout = QVBoxLayout()
        
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(3)
        self.reports_table.setHorizontalHeaderLabels(["Nom", "Date", "Actions"])
        self.reports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.reports_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.reports_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        reports_layout.addWidget(self.reports_table)
        
        reports_group.setLayout(reports_layout)
        layout.addWidget(reports_group)
        
        # Boutons d'action
        buttons_layout = QHBoxLayout()
        
        self.refresh_reports_button = QPushButton("Actualiser la liste")
        self.refresh_reports_button.clicked.connect(self._refresh_reports_list)
        buttons_layout.addWidget(self.refresh_reports_button)
        
        self.open_report_folder_button = QPushButton("Ouvrir le dossier des rapports")
        self.open_report_folder_button.clicked.connect(self._open_report_folder)
        buttons_layout.addWidget(self.open_report_folder_button)
        
        layout.addLayout(buttons_layout)
        
        # Aperçu du rapport
        preview_group = QGroupBox("Aperçu du rapport")
        preview_layout = QVBoxLayout()
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        preview_layout.addWidget(self.report_preview)
        
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)
        
        # Initialiser la liste des rapports
        self._refresh_reports_list()

    def _create_config_tab(self):
        """Crée le contenu de l'onglet Configuration."""
        layout = QVBoxLayout(self.config_tab)
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        
        # Configuration générale
        general_group = QGroupBox("Configuration générale")
        general_layout = QFormLayout()
        
        self.output_dir_input = QLineEdit()
        self.output_dir_input.setText(self.config.get("output_dir", os.path.join(root_dir, "results")))
        output_dir_layout = QHBoxLayout()
        output_dir_layout.addWidget(self.output_dir_input)
        output_dir_button = QPushButton("...")
        output_dir_button.clicked.connect(self._select_output_dir)
        output_dir_layout.addWidget(output_dir_button)
        general_layout.addRow("Dossier de sortie:", output_dir_layout)
        
        self.rules_dir_input = QLineEdit()
        self.rules_dir_input.setText(self.config.get("rules_dir", os.path.join(root_dir, "rules")))
        rules_dir_layout = QHBoxLayout()
        rules_dir_layout.addWidget(self.rules_dir_input)
        rules_dir_button = QPushButton("...")
        rules_dir_button.clicked.connect(self._select_rules_dir)
        rules_dir_layout.addWidget(rules_dir_button)
        general_layout.addRow("Dossier des règles YARA:", rules_dir_layout)
        
        general_group.setLayout(general_layout)
        scroll_layout.addWidget(general_group)
        
        # Configuration des collecteurs
        collectors_group = QGroupBox("Configuration des collecteurs")
        collectors_layout = QFormLayout()
        
        # Event Log
        self.max_logs_input = QLineEdit()
        self.max_logs_input.setText(str(self.config.get("event_log", {}).get("max_logs", 1000)))
        collectors_layout.addRow("Nombre maximum de journaux d'événements:", self.max_logs_input)
        
        # Registry
        self.registry_hives_input = QLineEdit()
        self.registry_hives_input.setText(",".join(self.config.get("registry", {}).get("hives", ["HKLM", "HKCU"])))
        collectors_layout.addRow("Ruches de registre à analyser:", self.registry_hives_input)
        
        # Filesystem
        self.max_depth_input = QLineEdit()
        self.max_depth_input.setText(str(self.config.get("filesystem", {}).get("max_depth", 3)))
        collectors_layout.addRow("Profondeur maximale de recherche:", self.max_depth_input)
        
        # VMDK
        self.max_size_input = QLineEdit()
        self.max_size_input.setText(str(self.config.get("vmdk", {}).get("max_size_gb", 60)))
        collectors_layout.addRow("Taille maximale VMDK (GB):", self.max_size_input)
        
        collectors_group.setLayout(collectors_layout)
        scroll_layout.addWidget(collectors_group)
        
        # Configuration des analyseurs
        analyzers_group = QGroupBox("Configuration des analyseurs")
        analyzers_layout = QFormLayout()
        
        # Malware
        self.malware_threshold_input = QLineEdit()
        self.malware_threshold_input.setText(str(self.config.get("malware", {}).get("confidence_threshold", 60)))
        analyzers_layout.addRow("Seuil de confiance malware (%):", self.malware_threshold_input)
        
        # Phishing
        self.phishing_threshold_input = QLineEdit()
        self.phishing_threshold_input.setText(str(self.config.get("phishing", {}).get("confidence_threshold", 60)))
        analyzers_layout.addRow("Seuil de confiance phishing (%):", self.phishing_threshold_input)
        
        # YARA
        self.yara_max_size_input = QLineEdit()
        self.yara_max_size_input.setText(str(self.config.get("yara", {}).get("max_file_size", 10 * 1024 * 1024) // (1024 * 1024)))
        analyzers_layout.addRow("Taille maximale fichier YARA (MB):", self.yara_max_size_input)
        
        analyzers_group.setLayout(analyzers_layout)
        scroll_layout.addWidget(analyzers_group)
        
        # Configuration du rapport
        report_group = QGroupBox("Configuration du rapport")
        report_layout = QFormLayout()
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["light", "dark"])
        self.theme_combo.setCurrentText(self.config.get("html_reporter", {}).get("theme", "light"))
        report_layout.addRow("Thème du rapport:", self.theme_combo)
        
        self.company_name_input = QLineEdit()
        self.company_name_input.setText(self.config.get("html_reporter", {}).get("company_name", "ForensicHunter"))
        report_layout.addRow("Nom de l'entreprise:", self.company_name_input)
        
        report_group.setLayout(report_layout)
        scroll_layout.addWidget(report_group)
        
        # Boutons de configuration
        buttons_layout = QHBoxLayout()
        
        self.save_config_button = QPushButton("Sauvegarder la configuration")
        self.save_config_button.clicked.connect(self._save_config_from_ui)
        buttons_layout.addWidget(self.save_config_button)
        
        self.reset_config_button = QPushButton("Réinitialiser")
        self.reset_config_button.clicked.connect(self._reset_config)
        buttons_layout.addWidget(self.reset_config_button)
        
        scroll_layout.addLayout(buttons_layout)
        
        scroll_area.setWidget(scroll_content)
        layout.addWidget(scroll_area)

    def _select_file(self):
        """Ouvre une boîte de dialogue pour sélectionner un fichier."""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Sélectionner un fichier à analyser", "",
                                                  "Tous les fichiers (*)", options=options)
        if file_name:
            self.selected_sources_list.addItem(file_name)
            self.log_output.append(f"Fichier sélectionné: {file_name}")

    def _select_folder(self):
        """Ouvre une boîte de dialogue pour sélectionner un dossier."""
        options = QFileDialog.Options()
        folder_name = QFileDialog.getExistingDirectory(self, "Sélectionner un dossier à analyser", "", options=options)
        if folder_name:
            self.selected_sources_list.addItem(folder_name)
            self.log_output.append(f"Dossier sélectionné: {folder_name}")

    def _select_vmdk(self):
        """Ouvre une boîte de dialogue pour sélectionner un fichier VMDK."""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Sélectionner un fichier VMDK", "",
                                                  "Fichiers VMDK (*.vmdk);;Tous les fichiers (*)", options=options)
        if file_name:
            self.selected_sources_list.addItem(file_name)
            self.vmdk_checkbox.setChecked(True)
            self.log_output.append(f"Fichier VMDK sélectionné: {file_name}")

    def _select_disk(self):
        """Ouvre une boîte de dialogue pour sélectionner des disques physiques."""
        try:
            disks = self.core.collectors["disk"].list_physical_disks()
            if not disks:
                QMessageBox.information(self, "Aucun disque trouvé", "Aucun disque physique n'a été détecté.")
                return
            
            dialog = DiskSelectionDialog(disks, self)
            if dialog.exec_() == QDialog.Accepted:
                selected_disks = dialog.get_selected_disks()
                if selected_disks:
                    self.selected_disks = selected_disks
                    # Ajouter les disques sélectionnés à la liste des sources
                    for disk_id in selected_disks:
                        # Trouver le nom convivial
                        friendly_name = disk_id
                        for disk in disks:
                            if disk["device_id"] == disk_id:
                                friendly_name = disk["friendly_name"]
                                break
                        self.selected_sources_list.addItem(f"Disque: {friendly_name}")
                    self.disk_checkbox.setChecked(True)
                    self.log_output.append(f"Disques physiques sélectionnés: {', '.join(selected_disks)}")
        except Exception as e:
            logger.error(f"Erreur lors de la sélection des disques: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la sélection des disques: {str(e)}")

    def _select_output_dir(self):
        """Ouvre une boîte de dialogue pour sélectionner le dossier de sortie."""
        options = QFileDialog.Options()
        folder_name = QFileDialog.getExistingDirectory(self, "Sélectionner le dossier de sortie", "", options=options)
        if folder_name:
            self.output_dir_input.setText(folder_name)

    def _select_rules_dir(self):
        """Ouvre une boîte de dialogue pour sélectionner le dossier des règles YARA."""
        options = QFileDialog.Options()
        folder_name = QFileDialog.getExistingDirectory(self, "Sélectionner le dossier des règles YARA", "", options=options)
        if folder_name:
            self.rules_dir_input.setText(folder_name)

    def _save_config_from_ui(self):
        """Sauvegarde la configuration depuis l'interface utilisateur."""
        try:
            # Configuration générale
            self.config["output_dir"] = self.output_dir_input.text()
            self.config["rules_dir"] = self.rules_dir_input.text()
            
            # Configuration des collecteurs
            if "event_log" not in self.config:
                self.config["event_log"] = {}
            self.config["event_log"]["max_logs"] = int(self.max_logs_input.text())
            
            if "registry" not in self.config:
                self.config["registry"] = {}
            self.config["registry"]["hives"] = [h.strip() for h in self.registry_hives_input.text().split(",")]
            
            if "filesystem" not in self.config:
                self.config["filesystem"] = {}
            self.config["filesystem"]["max_depth"] = int(self.max_depth_input.text())
            
            if "vmdk" not in self.config:
                self.config["vmdk"] = {}
            self.config["vmdk"]["max_size_gb"] = int(self.max_size_input.text())
            
            # Configuration des analyseurs
            if "malware" not in self.config:
                self.config["malware"] = {}
            self.config["malware"]["confidence_threshold"] = int(self.malware_threshold_input.text())
            
            if "phishing" not in self.config:
                self.config["phishing"] = {}
            self.config["phishing"]["confidence_threshold"] = int(self.phishing_threshold_input.text())
            
            if "yara" not in self.config:
                self.config["yara"] = {}
            self.config["yara"]["max_file_size"] = int(self.yara_max_size_input.text()) * 1024 * 1024
            
            # Configuration du rapport
            if "html_reporter" not in self.config:
                self.config["html_reporter"] = {}
            self.config["html_reporter"]["theme"] = self.theme_combo.currentText()
            self.config["html_reporter"]["company_name"] = self.company_name_input.text()
            
            # Sauvegarde dans le fichier
            if self._save_config():
                QMessageBox.information(self, "Configuration", "Configuration sauvegardée avec succès.")
            else:
                QMessageBox.warning(self, "Configuration", "Erreur lors de la sauvegarde de la configuration.")
                
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la configuration: {str(e)}")
            QMessageBox.critical(self, "Erreur", f"Erreur lors de la sauvegarde de la configuration: {str(e)}")

    def _reset_config(self):
        """Réinitialise la configuration aux valeurs par défaut."""
        reply = QMessageBox.question(self, 'Réinitialisation', 
                                   "Voulez-vous vraiment réinitialiser la configuration aux valeurs par défaut ?",
                                   QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.config = self._load_config()
            self._update_config_ui()
            QMessageBox.information(self, "Configuration", "Configuration réinitialisée aux valeurs par défaut.")

    def _update_config_ui(self):
        """Met à jour l'interface utilisateur avec les valeurs de configuration."""
        # Configuration générale
        self.output_dir_input.setText(self.config.get("output_dir", os.path.join(root_dir, "results")))
        self.rules_dir_input.setText(self.config.get("rules_dir", os.path.join(root_dir, "rules")))
        
        # Configuration des collecteurs
        self.max_logs_input.setText(str(self.config.get("event_log", {}).get("max_logs", 1000)))
        self.registry_hives_input.setText(",".join(self.config.get("registry", {}).get("hives", ["HKLM", "HKCU"])))
        self.max_depth_input.setText(str(self.config.get("filesystem", {}).get("max_depth", 3)))
        self.max_size_input.setText(str(self.config.get("vmdk", {}).get("max_size_gb", 60)))
        
        # Configuration des analyseurs
        self.malware_threshold_input.setText(str(self.config.get("malware", {}).get("confidence_threshold", 60)))
        self.phishing_threshold_input.setText(str(self.config.get("phishing", {}).get("confidence_threshold", 60)))
        self.yara_max_size_input.setText(str(self.config.get("yara", {}).get("max_file_size", 10 * 1024 * 1024) // (1024 * 1024)))
        
        # Configuration du rapport
        self.theme_combo.setCurrentText(self.config.get("html_reporter", {}).get("theme", "light"))
        self.company_name_input.setText(self.config.get("html_reporter", {}).get("company_name", "ForensicHunter"))

    def _refresh_reports_list(self):
        """Actualise la liste des rapports."""
        # Recharger la liste des rapports
        self.reports_list = []
        output_dir = self.config.get("output_dir", os.path.join(root_dir, "results"))
        if os.path.exists(output_dir):
            try:
                for file in os.listdir(output_dir):
                    if file.endswith(".html") and file.startswith("report_"):
                        report_path = os.path.join(output_dir, file)
                        report_date = datetime.datetime.fromtimestamp(os.path.getmtime(report_path))
                        self.reports_list.append({
                            "path": report_path,
                            "name": file,
                            "date": report_date.strftime("%Y-%m-%d %H:%M:%S")
                        })
                
                # Trier par date (plus récent en premier)
                self.reports_list.sort(key=lambda x: x["date"], reverse=True)
                logger.info(f"{len(self.reports_list)} rapports existants chargés")
            except Exception as e:
                logger.error(f"Erreur lors du chargement des rapports existants: {str(e)}")
        
        # Mettre à jour la table
        self.reports_table.setRowCount(0)
        for i, report in enumerate(self.reports_list):
            self.reports_table.insertRow(i)
            self.reports_table.setItem(i, 0, QTableWidgetItem(report["name"]))
            self.reports_table.setItem(i, 1, QTableWidgetItem(report["date"]))
            
            # Bouton d'action
            actions_widget = QWidget()
            actions_layout = QHBoxLayout()
            actions_layout.setContentsMargins(0, 0, 0, 0)
            
            view_button = QPushButton("Voir")
            view_button.clicked.connect(lambda checked, path=report["path"]: self._view_report(path))
            actions_layout.addWidget(view_button)
            
            actions_widget.setLayout(actions_layout)
            self.reports_table.setCellWidget(i, 2, actions_widget)

    def _open_report_folder(self):
        """Ouvre le dossier des rapports."""
        output_dir = self.config.get("output_dir", os.path.join(root_dir, "results"))
        if os.path.exists(output_dir):
            QDesktopServices.openUrl(QUrl.fromLocalFile(output_dir))
        else:
            QMessageBox.warning(self, "Dossier introuvable", f"Le dossier {output_dir} n'existe pas.")

    def _view_report(self, report_path):
        """Affiche un rapport HTML."""
        if os.path.exists(report_path):
            # Ouvrir le rapport dans le navigateur par défaut
            QDesktopServices.openUrl(QUrl.fromLocalFile(report_path))
            
            # Afficher un aperçu dans l'interface
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    # Extraire le titre et le début du contenu
                    title_match = re.search(r"<title>(.*?)</title>", content)
                    title = title_match.group(1) if title_match else "Rapport ForensicHunter"
                    
                    # Afficher un aperçu simplifié
                    self.report_preview.setHtml(f"""
                    <h2>{title}</h2>
                    <p>Rapport généré le {datetime.datetime.fromtimestamp(os.path.getmtime(report_path)).strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p>Chemin: {report_path}</p>
                    <p><i>Le rapport complet est ouvert dans votre navigateur.</i></p>
                    """)
            except Exception as e:
                logger.error(f"Erreur lors de la lecture du rapport: {str(e)}")
                self.report_preview.setPlainText(f"Erreur lors de la lecture du rapport: {str(e)}")
        else:
            QMessageBox.warning(self, "Rapport introuvable", f"Le rapport {report_path} n'existe pas.")

    def start_new_scan(self):
        """Ouvre l'onglet Analyse pour démarrer une nouvelle analyse."""
        self.tab_widget.setCurrentWidget(self.scan_tab)

    def open_report(self):
        """Ouvre un fichier de rapport existant."""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Ouvrir un rapport ForensicHunter", "",
                                                  "Rapports HTML (*.html);;Rapports JSON (*.json);;Tous les fichiers (*)", options=options)
        if file_name:
            self._view_report(file_name)
            self.tab_widget.setCurrentWidget(self.report_tab)

    def show_about_dialog(self):
        """Affiche la boîte de dialogue À propos."""
        QMessageBox.about(self, "À propos de ForensicHunter",
                          "ForensicHunter v1.1\n\n" 
                          "Outil de forensic Windows professionnel.\n" 
                          "Analyse de fichiers VMDK, logs, et artefacts Windows.\n"
                          "Détection de malware, ransomware, phishing, et backdoors.\n\n" 
                          "© 2025 ForensicHunter Team")

    def run_full_scan(self):
        """Lance une analyse complète."""
        self._run_scan(quick=False)

    def run_quick_scan(self):
        """Lance une analyse rapide."""
        self._run_scan(quick=True)

    def _run_scan(self, quick=False):
        """Lance une analyse ForensicHunter."""
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Analyse en cours", "Une analyse est déjà en cours d'exécution.")
            return
        
        # Vérifier qu'au moins une source est sélectionnée
        if self.selected_sources_list.count() == 0:
            QMessageBox.warning(self, "Aucune source sélectionnée", "Veuillez sélectionner au moins un fichier, dossier ou disque à analyser.")
            return
        
        # Préparer les options d'analyse
        scan_options = {
           # Préparation des options d'analyse
        options = {
            "case_id": self.case_id_input.text(),
            "case_name": self.case_name_input.text(),
            "analyst": self.analyst_input.text(),
            "output_dir": output_dir,
            "collect_event_logs": self.event_log_checkbox.isChecked(),
            "collect_registry": self.registry_checkbox.isChecked(),
            "collect_filesystem": self.filesystem_checkbox.isChecked(),
            "filesystem_paths": selected_paths,
            "collect_vmdk": self.vmdk_checkbox.isChecked(),
            "vmdk_path": vmdk_path,
            "collect_disks": self.disk_checkbox.isChecked(),
            "disk_ids": selected_disks,
            "analyze_malware": self.malware_checkbox.isChecked(),
            "analyze_phishing": self.phishing_checkbox.isChecked(),
            "analyze_yara": self.yara_checkbox.isChecked(),
            "analyze_logs": self.logs_checkbox.isChecked(),
            "analyze_csv": self.csv_checkbox.isChecked()
        }    
            # Fichiers/Disques à analyser
            "filesystem_paths": [],
            "vmdk_path": None,
            "disk_ids": self.selected_disks # Ajout des IDs des disques sélectionnés
        }
        
        # Ajouter les fichiers/dossiers sélectionnés
        for i in range(self.selected_sources_list.count()):
            item = self.selected_sources_list.item(i)
            source_text = item.text()
            
            if source_text.startswith("Disque:"):
                # C'est un disque, déjà géré par self.selected_disks
                continue
            elif source_text.lower().endswith(".vmdk"):
                scan_options["vmdk_path"] = source_text
            else:
                scan_options["filesystem_paths"].append(source_text)
        
        # Créer le répertoire de sortie s'il n'existe pas
        os.makedirs(scan_options["output_dir"], exist_ok=True)
        
        # Préparer l'interface
        self.log_output.clear()
        self.log_output.append(f"Démarrage de l'analyse {'rapide' if quick else 'complète'}...")
        self.statusBar.showMessage("Analyse en cours...")
        self.progress_bar.setValue(0)
        self.progress_bar.show()
        self.full_scan_button.setEnabled(False)
        self.quick_scan_button.setEnabled(False)
        
        # Création et démarrage du worker
        self.worker = ForensicWorker(self.core, scan_options)
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
        
        if results.get("status") == "success":
            self.log_output.append(f"Artefacts collectés: {len(results.get('artifacts', []))}")
            self.log_output.append(f"Menaces détectées: {len(results.get('findings', []))}")
            
            # Afficher le chemin du rapport
            report_path = results.get("report_path")
            if report_path and os.path.exists(report_path):
                self.log_output.append(f"Rapport généré: {report_path}")
                
                # Proposer d'ouvrir le rapport
                reply = QMessageBox.question(self, 'Rapport généré',
                                           f"L'analyse est terminée et le rapport a été généré.\n\nVoulez-vous ouvrir le rapport maintenant ?",
                                           QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
                if reply == QMessageBox.Yes:
                    self._view_report(report_path)
                    self.tab_widget.setCurrentWidget(self.report_tab)
        else:
            self.log_output.append(f"Erreur: {results.get('error', 'Erreur inconnue')}")
        
        self.statusBar.showMessage("Analyse terminée")
        self.progress_bar.hide()
        self.full_scan_button.setEnabled(True)
        self.quick_scan_button.setEnabled(True)
        self.worker = None
        self.last_results = results
        
        # Actualiser la liste des rapports
        self._refresh_reports_list()

    def scan_error(self, error_message):
        """Gère les erreurs d'analyse."""
        self.log_output.append(f"\n--- ERREUR D'ANALYSE ---")
        self.log_output.append(error_message)
        self.statusBar.showMessage("Erreur lors de l'analyse")
        self.progress_bar.hide()
        self.full_scan_button.setEnabled(True)
        self.quick_scan_button.setEnabled(True)
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


def launch_gui():
    """Lance l'interface graphique."""
    # Configuration du logging
    setup_logger(name="forensichunter.gui", level=logging.INFO)
    
    app = QApplication(sys.argv)
    main_window = ForensicHunterGUI()
    main_window.show()
    return app.exec_()


if __name__ == '__main__':
    sys.exit(launch_gui())


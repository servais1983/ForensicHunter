#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de visualisation des artefacts pour ForensicHunter.

Ce module fournit une interface pour explorer, visualiser et exporter
les artefacts collectés lors des analyses forensiques.
"""

import os
import sys
import json
import datetime
import csv
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QTreeWidget, QTreeWidgetItem, QSplitter, QTextEdit, 
    QFileDialog, QMenu, QAction, QMessageBox, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QCheckBox, QGroupBox, QFormLayout
)
from PyQt5.QtGui import QIcon, QFont, QColor, QBrush
from PyQt5.QtCore import Qt, pyqtSignal, QSize

class ArtifactsView(QWidget):
    """Widget pour visualiser et explorer les artefacts collectés."""
    
    def __init__(self, parent=None):
        """Initialise la vue des artefacts."""
        super().__init__(parent)
        self.parent = parent
        self.artifacts = []
        self.current_artifact = None
        self.setup_ui()
    
    def setup_ui(self):
        """Configure l'interface utilisateur."""
        layout = QVBoxLayout(self)
        
        # Titre et description
        title_layout = QHBoxLayout()
        title = QLabel("<h2>Explorateur d'artefacts</h2>")
        title.setStyleSheet("font-weight: bold; color: #2c3e50;")
        title_layout.addWidget(title)
        
        # Boutons d'action
        self.export_button = QPushButton("Exporter les artefacts")
        self.export_button.setIcon(QIcon.fromTheme("document-save"))
        self.export_button.clicked.connect(self.export_artifacts)
        self.export_button.setEnabled(False)
        title_layout.addWidget(self.export_button)
        
        self.refresh_button = QPushButton("Actualiser")
        self.refresh_button.setIcon(QIcon.fromTheme("view-refresh"))
        self.refresh_button.clicked.connect(self.refresh_artifacts)
        title_layout.addWidget(self.refresh_button)
        
        layout.addLayout(title_layout)
        
        description = QLabel("Explorez et analysez tous les artefacts collectés lors des analyses forensiques.")
        description.setStyleSheet("font-size: 12px; color: #34495e; margin-bottom: 10px;")
        layout.addWidget(description)
        
        # Splitter principal
        splitter = QSplitter(Qt.Horizontal)
        
        # Arbre des artefacts
        self.artifacts_tree = QTreeWidget()
        self.artifacts_tree.setHeaderLabels(["Artefacts"])
        self.artifacts_tree.setMinimumWidth(300)
        self.artifacts_tree.itemClicked.connect(self.on_artifact_selected)
        self.artifacts_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.artifacts_tree.customContextMenuRequested.connect(self.show_context_menu)
        splitter.addWidget(self.artifacts_tree)
        
        # Panneau de détails
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        # Onglets de détails
        self.details_tabs = QTabWidget()
        
        # Onglet Aperçu
        self.overview_tab = QWidget()
        overview_layout = QVBoxLayout(self.overview_tab)
        self.artifact_info = QTextEdit()
        self.artifact_info.setReadOnly(True)
        self.artifact_info.setStyleSheet("font-family: 'Courier New'; font-size: 12px; background-color: #f8f9fa; color: #212529;")
        overview_layout.addWidget(self.artifact_info)
        self.details_tabs.addTab(self.overview_tab, "Aperçu")
        
        # Onglet Contenu
        self.content_tab = QWidget()
        content_layout = QVBoxLayout(self.content_tab)
        self.artifact_content = QTextEdit()
        self.artifact_content.setReadOnly(True)
        self.artifact_content.setStyleSheet("font-family: 'Courier New'; font-size: 12px; background-color: #f8f9fa; color: #212529;")
        content_layout.addWidget(self.artifact_content)
        self.details_tabs.addTab(self.content_tab, "Contenu")
        
        # Onglet Métadonnées
        self.metadata_tab = QWidget()
        metadata_layout = QVBoxLayout(self.metadata_tab)
        self.metadata_table = QTableWidget()
        self.metadata_table.setColumnCount(2)
        self.metadata_table.setHorizontalHeaderLabels(["Propriété", "Valeur"])
        self.metadata_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        metadata_layout.addWidget(self.metadata_table)
        self.details_tabs.addTab(self.metadata_tab, "Métadonnées")
        
        details_layout.addWidget(self.details_tabs)
        splitter.addWidget(details_widget)
        
        # Définir les proportions du splitter
        splitter.setSizes([300, 700])
        layout.addWidget(splitter)
        
        # Barre d'état
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Prêt")
        status_layout.addWidget(self.status_label)
        
        # Filtres
        filter_group = QGroupBox("Filtres")
        filter_layout = QHBoxLayout()
        
        self.filter_type = QComboBox()
        self.filter_type.addItem("Tous les types", "all")
        self.filter_type.addItem("Fichiers", "filesystem")
        self.filter_type.addItem("Registre", "registry")
        self.filter_type.addItem("Journaux d'événements", "eventlog")
        self.filter_type.addItem("VMDK", "vmdk")
        self.filter_type.addItem("Disques", "disk")
        self.filter_type.currentIndexChanged.connect(self.apply_filters)
        filter_layout.addWidget(QLabel("Type:"))
        filter_layout.addWidget(self.filter_type)
        
        self.show_suspicious = QCheckBox("Afficher uniquement les éléments suspects")
        self.show_suspicious.stateChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.show_suspicious)
        
        filter_group.setLayout(filter_layout)
        status_layout.addWidget(filter_group)
        
        layout.addLayout(status_layout)
    
    def set_artifacts(self, artifacts):
        """
        Définit la liste des artefacts à afficher.
        
        Args:
            artifacts (list): Liste des objets Artifact
        """
        self.artifacts = artifacts
        self.export_button.setEnabled(len(artifacts) > 0)
        self.populate_tree()
    
    def populate_tree(self):
        """Remplit l'arbre des artefacts avec les données."""
        self.artifacts_tree.clear()
        
        # Créer des catégories principales
        filesystem_root = QTreeWidgetItem(self.artifacts_tree, ["Système de fichiers"])
        filesystem_root.setIcon(0, QIcon.fromTheme("folder"))
        
        registry_root = QTreeWidgetItem(self.artifacts_tree, ["Registre Windows"])
        registry_root.setIcon(0, QIcon.fromTheme("text-x-generic"))
        
        eventlog_root = QTreeWidgetItem(self.artifacts_tree, ["Journaux d'événements"])
        eventlog_root.setIcon(0, QIcon.fromTheme("text-x-log"))
        
        vmdk_root = QTreeWidgetItem(self.artifacts_tree, ["VMDK"])
        vmdk_root.setIcon(0, QIcon.fromTheme("drive-harddisk"))
        
        disk_root = QTreeWidgetItem(self.artifacts_tree, ["Disques physiques"])
        disk_root.setIcon(0, QIcon.fromTheme("drive-harddisk"))
        
        other_root = QTreeWidgetItem(self.artifacts_tree, ["Autres"])
        other_root.setIcon(0, QIcon.fromTheme("dialog-question"))
        
        # Remplir l'arbre avec les artefacts
        for artifact in self.artifacts:
            if artifact.type == "filesystem":
                parent = filesystem_root
                icon = QIcon.fromTheme("text-x-generic")
                if artifact.data.get("is_directory", False):
                    icon = QIcon.fromTheme("folder")
                elif artifact.data.get("file_path", "").lower().endswith((".exe", ".dll")):
                    icon = QIcon.fromTheme("application-x-executable")
                elif artifact.data.get("file_path", "").lower().endswith((".log", ".txt")):
                    icon = QIcon.fromTheme("text-x-log")
            elif artifact.type == "registry":
                parent = registry_root
                icon = QIcon.fromTheme("text-x-generic")
            elif artifact.type == "eventlog":
                parent = eventlog_root
                icon = QIcon.fromTheme("text-x-log")
            elif artifact.type == "vmdk":
                parent = vmdk_root
                icon = QIcon.fromTheme("drive-harddisk")
            elif artifact.type == "disk":
                parent = disk_root
                icon = QIcon.fromTheme("drive-harddisk")
            else:
                parent = other_root
                icon = QIcon.fromTheme("dialog-question")
            
            # Créer l'élément d'arbre
            item = QTreeWidgetItem(parent)
            
            # Définir le texte et l'icône
            if artifact.type == "filesystem":
                item.setText(0, os.path.basename(artifact.data.get("file_path", "Inconnu")))
            elif artifact.type == "registry":
                item.setText(0, artifact.data.get("key_path", "Inconnu"))
            elif artifact.type == "eventlog":
                item.setText(0, artifact.data.get("log_name", "Inconnu"))
            elif artifact.type == "vmdk":
                item.setText(0, os.path.basename(artifact.data.get("vmdk_path", "Inconnu")))
            elif artifact.type == "disk":
                item.setText(0, artifact.data.get("disk_name", "Inconnu"))
            else:
                item.setText(0, artifact.id)
            
            item.setIcon(0, icon)
            
            # Stocker l'ID de l'artefact dans les données de l'élément
            item.setData(0, Qt.UserRole, artifact.id)
            
            # Marquer les éléments suspects
            if hasattr(artifact, "is_suspicious") and artifact.is_suspicious:
                item.setForeground(0, QBrush(QColor("#e74c3c")))
                item.setFont(0, QFont("Sans Serif", -1, QFont.Bold))
        
        # Développer les catégories principales
        self.artifacts_tree.expandAll()
        
        # Mettre à jour le statut
        self.status_label.setText(f"{len(self.artifacts)} artefacts chargés")
    
    def on_artifact_selected(self, item, column):
        """
        Gère la sélection d'un artefact dans l'arbre.
        
        Args:
            item: Élément d'arbre sélectionné
            column: Colonne sélectionnée
        """
        artifact_id = item.data(0, Qt.UserRole)
        if not artifact_id:
            return
        
        # Trouver l'artefact correspondant
        for artifact in self.artifacts:
            if artifact.id == artifact_id:
                self.current_artifact = artifact
                self.display_artifact(artifact)
                break
    
    def display_artifact(self, artifact):
        """
        Affiche les détails d'un artefact.
        
        Args:
            artifact: Objet Artifact à afficher
        """
        # Onglet Aperçu
        info_html = f"<h3>Artefact: {artifact.id}</h3>"
        info_html += f"<p><strong>Type:</strong> {artifact.type}</p>"
        
        if artifact.type == "filesystem":
            file_path = artifact.data.get("file_path", "Inconnu")
            file_type = artifact.data.get("type", "Inconnu")
            file_size = artifact.data.get("size", 0)
            
            info_html += f"<p><strong>Chemin:</strong> {file_path}</p>"
            info_html += f"<p><strong>Type:</strong> {file_type}</p>"
            info_html += f"<p><strong>Taille:</strong> {self.format_size(file_size)}</p>"
            
            if "creation_time" in artifact.data:
                info_html += f"<p><strong>Créé le:</strong> {artifact.data['creation_time']}</p>"
            if "modification_time" in artifact.data:
                info_html += f"<p><strong>Modifié le:</strong> {artifact.data['modification_time']}</p>"
            if "access_time" in artifact.data:
                info_html += f"<p><strong>Accédé le:</strong> {artifact.data['access_time']}</p>"
            
        elif artifact.type == "registry":
            key_path = artifact.data.get("key_path", "Inconnu")
            value_name = artifact.data.get("value_name", "")
            value_type = artifact.data.get("value_type", "")
            value_data = artifact.data.get("value_data", "")
            
            info_html += f"<p><strong>Chemin de clé:</strong> {key_path}</p>"
            if value_name:
                info_html += f"<p><strong>Nom de valeur:</strong> {value_name}</p>"
                info_html += f"<p><strong>Type de valeur:</strong> {value_type}</p>"
                info_html += f"<p><strong>Données:</strong> {value_data}</p>"
            
        elif artifact.type == "eventlog":
            log_name = artifact.data.get("log_name", "Inconnu")
            event_id = artifact.data.get("event_id", "")
            time_created = artifact.data.get("time_created", "")
            level = artifact.data.get("level", "")
            
            info_html += f"<p><strong>Journal:</strong> {log_name}</p>"
            info_html += f"<p><strong>ID d'événement:</strong> {event_id}</p>"
            info_html += f"<p><strong>Créé le:</strong> {time_created}</p>"
            info_html += f"<p><strong>Niveau:</strong> {level}</p>"
            
        elif artifact.type == "vmdk":
            vmdk_path = artifact.data.get("vmdk_path", "Inconnu")
            vmdk_size = artifact.data.get("size", 0)
            
            info_html += f"<p><strong>Chemin VMDK:</strong> {vmdk_path}</p>"
            info_html += f"<p><strong>Taille:</strong> {self.format_size(vmdk_size)}</p>"
            
        elif artifact.type == "disk":
            disk_name = artifact.data.get("disk_name", "Inconnu")
            disk_size = artifact.data.get("size", 0)
            
            info_html += f"<p><strong>Nom du disque:</strong> {disk_name}</p>"
            info_html += f"<p><strong>Taille:</strong> {self.format_size(disk_size)}</p>"
        
        # Ajouter des informations sur les résultats associés
        if hasattr(artifact, "findings") and artifact.findings:
            info_html += f"<h4>Résultats associés ({len(artifact.findings)})</h4>"
            info_html += "<ul>"
            for finding in artifact.findings:
                severity_color = "#2ecc71"  # Vert pour info
                if finding.severity == "medium":
                    severity_color = "#f39c12"  # Orange pour medium
                elif finding.severity == "high":
                    severity_color = "#e74c3c"  # Rouge pour high
                
                info_html += f'<li><span style="color: {severity_color}; font-weight: bold;">[{finding.severity.upper()}]</span> {finding.description}</li>'
            info_html += "</ul>"
        
        self.artifact_info.setHtml(info_html)
        
        # Onglet Contenu
        content_html = "<pre style='white-space: pre-wrap; word-wrap: break-word;'>"
        if artifact.type == "filesystem" and artifact.data.get("type") == "text":
            content = artifact.data.get("content", "")
            content_html += self.escape_html(content)
        elif artifact.type == "eventlog":
            message = artifact.data.get("message", "")
            content_html += self.escape_html(message)
        elif artifact.type == "registry" and "value_data" in artifact.data:
            content_html += self.escape_html(str(artifact.data["value_data"]))
        else:
            content_html += "Contenu non disponible ou non affichable."
        content_html += "</pre>"
        self.artifact_content.setHtml(content_html)
        
        # Onglet Métadonnées
        self.metadata_table.setRowCount(0)
        row = 0
        
        # Ajouter toutes les métadonnées disponibles
        for key, value in artifact.data.items():
            self.metadata_table.insertRow(row)
            self.metadata_table.setItem(row, 0, QTableWidgetItem(key))
            
            # Formater la valeur selon son type
            if isinstance(value, (dict, list)):
                value_str = json.dumps(value, indent=2)
            else:
                value_str = str(value)
            
            self.metadata_table.setItem(row, 1, QTableWidgetItem(value_str))
            row += 1
    
    def escape_html(self, text):
        """
        Échappe les caractères spéciaux HTML.
        
        Args:
            text (str): Texte à échapper
            
        Returns:
            str: Texte échappé
        """
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    def format_size(self, size_bytes):
        """
        Formate une taille en octets en une chaîne lisible.
        
        Args:
            size_bytes (int): Taille en octets
            
        Returns:
            str: Taille formatée
        """
        if size_bytes < 1024:
            return f"{size_bytes} octets"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} Ko"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} Mo"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} Go"
    
    def show_context_menu(self, position):
        """
        Affiche un menu contextuel pour l'artefact sélectionné.
        
        Args:
            position: Position du clic
        """
        item = self.artifacts_tree.itemAt(position)
        if not item:
            return
        
        artifact_id = item.data(0, Qt.UserRole)
        if not artifact_id:
            return
        
        # Créer le menu contextuel
        menu = QMenu()
        
        export_action = QAction("Exporter cet artefact", self)
        export_action.triggered.connect(lambda: self.export_single_artifact(artifact_id))
        menu.addAction(export_action)
        
        view_action = QAction("Voir les détails", self)
        view_action.triggered.connect(lambda: self.on_artifact_selected(item, 0))
        menu.addAction(view_action)
        
        # Afficher le menu
        menu.exec_(self.artifacts_tree.viewport().mapToGlobal(position))
    
    def export_artifacts(self):
        """Exporte tous les artefacts dans un fichier."""
        if not self.artifacts:
            QMessageBox.warning(self, "Aucun artefact", "Aucun artefact à exporter.")
            return
        
        # Demander le répertoire de destination
        export_dir = QFileDialog.getExistingDirectory(
            self, "Sélectionner le répertoire d'exportation", 
            os.path.expanduser("~"),
            QFileDialog.ShowDirsOnly
        )
        
        if not export_dir:
            return
        
        try:
            # Créer un sous-répertoire pour l'exportation
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            export_subdir = os.path.join(export_dir, f"forensichunter_artifacts_{timestamp}")
            os.makedirs(export_subdir, exist_ok=True)
            
            # Exporter les métadonnées des artefacts en CSV
            metadata_path = os.path.join(export_subdir, "artifacts_metadata.csv")
            with open(metadata_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['id', 'type', 'path', 'size', 'creation_time', 'modification_time']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for artifact in self.artifacts:
                    row = {
                        'id': artifact.id,
                        'type': artifact.type,
                        'path': artifact.data.get('file_path', artifact.data.get('key_path', '')),
                        'size': artifact.data.get('size', ''),
                        'creation_time': artifact.data.get('creation_time', ''),
                        'modification_time': artifact.data.get('modification_time', '')
                    }
                    writer.writerow(row)
            
            # Exporter le contenu des artefacts textuels
            content_dir = os.path.join(export_subdir, "contents")
            os.makedirs(content_dir, exist_ok=True)
            
            for artifact in self.artifacts:
                if artifact.type == "filesystem" and artifact.data.get("type") == "text":
                    content = artifact.data.get("content", "")
                    if content:
                        filename = f"{artifact.id}_{os.path.basename(artifact.data.get('file_path', 'unknown'))}"
                        with open(os.path.join(content_dir, filename), 'w', encoding='utf-8') as f:
                            f.write(content)
                elif artifact.type == "eventlog":
                    message = artifact.data.get("message", "")
                    if message:
                        filename = f"{artifact.id}_{artifact.data.get('log_name', 'unknown')}.txt"
                        with open(os.path.join(content_dir, filename), 'w', encoding='utf-8') as f:
                            f.write(message)
            
            # Exporter toutes les métadonnées en JSON
            json_path = os.path.join(export_subdir, "artifacts_full.json")
            with open(json_path, 'w', encoding='utf-8') as f:
                artifacts_data = []
                for artifact in self.artifacts:
                    artifact_dict = {
                        'id': artifact.id,
                        'type': artifact.type,
                        'data': artifact.data
                    }
                    artifacts_data.append(artifact_dict)
                json.dump(artifacts_data, f, indent=2)
            
            QMessageBox.information(
                self, 
                "Exportation réussie", 
                f"Les artefacts ont été exportés avec succès dans:\n{export_subdir}"
            )
            
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Erreur d'exportation", 
                f"Une erreur s'est produite lors de l'exportation des artefacts:\n{str(e)}"
            )
    
    def export_single_artifact(self, artifact_id):
        """
        Exporte un seul artefact.
        
        Args:
            artifact_id (str): ID de l'artefact à exporter
        """
        # Trouver l'artefact correspondant
        artifact = None
        for a in self.artifacts:
            if a.id == artifact_id:
                artifact = a
                break
        
        if not artifact:
            return
        
        # Demander le répertoire de destination
        export_dir = QFileDialog.getExistingDirectory(
            self, "Sélectionner le répertoire d'exportation", 
            os.path.expanduser("~"),
            QFileDialog.ShowDirsOnly
        )
        
        if not export_dir:
            return
        
        try:
            # Exporter les métadonnées en JSON
            json_path = os.path.join(export_dir, f"artifact_{artifact.id}.json")
            with open(json_path, 'w', encoding='utf-8') as f:
                artifact_dict = {
                    'id': artifact.id,
                    'type': artifact.type,
                    'data': artifact.data
                }
                json.dump(artifact_dict, f, indent=2)
            
            # Exporter le contenu si disponible
            if artifact.type == "filesystem" and artifact.data.get("type") == "text":
                content = artifact.data.get("content", "")
                if content:
                    filename = f"content_{artifact.id}_{os.path.basename(artifact.data.get('file_path', 'unknown'))}"
                    with open(os.path.join(export_dir, filename), 'w', encoding='utf-8') as f:
                        f.write(content)
            elif artifact.type == "eventlog":
                message = artifact.data.get("message", "")
                if message:
                    filename = f"content_{artifact.id}_{artifact.data.get('log_name', 'unknown')}.txt"
                    with open(os.path.join(export_dir, filename), 'w', encoding='utf-8') as f:
                        f.write(message)
            
            QMessageBox.information(
                self, 
                "Exportation réussie", 
                f"L'artefact {artifact.id} a été exporté avec succès dans:\n{export_dir}"
            )
            
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Erreur d'exportation", 
                f"Une erreur s'est produite lors de l'exportation de l'artefact:\n{str(e)}"
            )
    
    def refresh_artifacts(self):
        """Actualise l'affichage des artefacts."""
        if hasattr(self.parent, "last_scan_results") and self.parent.last_scan_results:
            artifacts = self.parent.last_scan_results.get("artifacts", [])
            self.set_artifacts(artifacts)
        else:
            QMessageBox.information(
                self, 
                "Aucun résultat", 
                "Aucun résultat d'analyse disponible. Veuillez effectuer une analyse pour collecter des artefacts."
            )
    
    def apply_filters(self):
        """Applique les filtres sélectionnés."""
        if not self.artifacts:
            return
        
        # Récupérer les filtres
        filter_type = self.filter_type.currentData()
        show_suspicious = self.show_suspicious.isChecked()
        
        # Filtrer les artefacts
        filtered_artifacts = []
        for artifact in self.artifacts:
            # Filtrer par type
            if filter_type != "all" and artifact.type != filter_type:
                continue
            
            # Filtrer par suspicion
            if show_suspicious and not (hasattr(artifact, "is_suspicious") and artifact.is_suspicious):
                continue
            
            filtered_artifacts.append(artifact)
        
        # Mettre à jour l'affichage
        self.artifacts_tree.clear()
        self.set_artifacts(filtered_artifacts)
        
        # Mettre à jour le statut
        self.status_label.setText(f"{len(filtered_artifacts)} artefacts affichés sur {len(self.artifacts)} au total")

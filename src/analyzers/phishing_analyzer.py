#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'analyse de phishing et d'ingénierie sociale.

Ce module permet de détecter les signes de phishing et d'ingénierie sociale
dans les artefacts collectés.
"""

import os
import logging
import re
import json
from pathlib import Path
import urllib.parse

from .base_analyzer import BaseAnalyzer, Finding

# Configuration du logger
logger = logging.getLogger("forensichunter.analyzers.phishing")

class PhishingAnalyzer(BaseAnalyzer):
    """Analyseur de phishing et d'ingénierie sociale."""
    
    def __init__(self, config=None):
        """
        Initialise un nouvel analyseur de phishing.
        
        Args:
            config (dict, optional): Configuration de l'analyseur
        """
        super().__init__(config)
        self.phishing_signatures = self.config.get("phishing_signatures", [
            # Signatures de phishing génériques
            {
                "name": "Generic Phishing",
                "type": "phishing",
                "patterns": [
                    r"password.*expired",
                    r"account.*verify",
                    r"unusual.*activity",
                    r"security.*alert",
                    r"login.*attempt",
                    r"click.*here.*to.*confirm",
                    r"update.*your.*information",
                    r"verify.*your.*account",
                    r"suspicious.*activity",
                    r"limited.*access"
                ],
                "severity": "medium",
                "confidence": 60
            },
            # Signatures de phishing spécifiques
            {
                "name": "Banking Phishing",
                "type": "phishing_banking",
                "patterns": [
                    r"bank.*account.*suspended",
                    r"confirm.*transaction",
                    r"unusual.*transaction",
                    r"banking.*security",
                    r"account.*blocked",
                    r"credit.*card.*expired",
                    r"payment.*failed"
                ],
                "severity": "high",
                "confidence": 70
            },
            {
                "name": "Corporate Credentials Phishing",
                "type": "phishing_corporate",
                "patterns": [
                    r"office365.*login",
                    r"sharepoint.*access",
                    r"onedrive.*shared",
                    r"teams.*meeting",
                    r"corporate.*password",
                    r"company.*portal",
                    r"VPN.*access",
                    r"IT.*support.*request"
                ],
                "severity": "high",
                "confidence": 70
            },
            # Signatures d'ingénierie sociale
            {
                "name": "Social Engineering",
                "type": "social_engineering",
                "patterns": [
                    r"urgent.*action",
                    r"immediate.*attention",
                    r"prize.*won",
                    r"lottery.*winner",
                    r"inheritance",
                    r"million.*dollars",
                    r"Nigerian.*prince",
                    r"investment.*opportunity",
                    r"limited.*time.*offer"
                ],
                "severity": "medium",
                "confidence": 60
            }
        ])
        self.suspicious_domains = self.config.get("suspicious_domains", [
            r".*\.tk$",
            r".*\.xyz$",
            r".*\.top$",
            r".*\.gq$",
            r".*\.ml$",
            r".*\.ga$",
            r".*\.cf$",
            r".*-secure-.*\.com$",
            r".*-verify-.*\.com$",
            r".*-login-.*\.com$",
            r".*-account-.*\.com$",
            r".*-support-.*\.com$",
            r".*-update-.*\.com$",
            r".*-service-.*\.com$",
            r".*-confirm-.*\.com$"
        ])
        self.legitimate_domains = self.config.get("legitimate_domains", [
            "google.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
            "facebook.com",
            "twitter.com",
            "linkedin.com",
            "instagram.com",
            "paypal.com",
            "chase.com",
            "bankofamerica.com",
            "wellsfargo.com",
            "citibank.com",
            "amex.com"
        ])
        self.max_url_length = self.config.get("max_url_length", 100)
        self.max_domain_length = self.config.get("max_domain_length", 50)
        self.max_subdomain_count = self.config.get("max_subdomain_count", 3)
    
    def get_name(self):
        """
        Retourne le nom de l'analyseur.
        
        Returns:
            str: Nom de l'analyseur
        """
        return "PhishingAnalyzer"
    
    def get_description(self):
        """
        Retourne la description de l'analyseur.
        
        Returns:
            str: Description de l'analyseur
        """
        return "Analyseur de phishing et d'ingénierie sociale (emails, sites web, documents)"
    
    def analyze(self, artifacts):
        """
        Analyse les artefacts pour détecter des signes de phishing et d'ingénierie sociale.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
            
        Returns:
            list: Liste d'objets Finding résultant de l'analyse
        """
        self.clear_findings()
        
        # Regrouper les artefacts par type
        artifact_groups = {}
        for artifact in artifacts:
            if artifact.type not in artifact_groups:
                artifact_groups[artifact.type] = []
            artifact_groups[artifact.type].append(artifact)
        
        # Analyser les artefacts par type
        for artifact_type, artifacts_of_type in artifact_groups.items():
            logger.info(f"Analyse de {len(artifacts_of_type)} artefacts de type {artifact_type}...")
            
            if artifact_type == "filesystem":
                self._analyze_filesystem_artifacts(artifacts_of_type)
            elif artifact_type == "browser_history":
                self._analyze_browser_artifacts(artifacts_of_type)
            elif artifact_type == "email":
                self._analyze_email_artifacts(artifacts_of_type)
            else:
                # Pour les autres types d'artefacts, chercher des URLs et des motifs de phishing
                self._analyze_generic_artifacts(artifacts_of_type)
        
        # Analyser les corrélations entre les résultats
        self._analyze_correlations()
        
        logger.info(f"{len(self.findings)} résultats trouvés au total")
        return self.findings
    
    def _analyze_filesystem_artifacts(self, artifacts):
        """
        Analyse les artefacts du système de fichiers.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
        """
        for artifact in artifacts:
            try:
                # Vérifier si l'artefact contient des données
                if not artifact.data:
                    continue
                
                # Extraire les informations du fichier
                file_path = artifact.data.get("file_path", "")
                file_type = artifact.data.get("type", "")
                content = None
                
                if file_type == "text":
                    content = artifact.data.get("content", "")
                elif file_type == "binary":
                    # Pour les fichiers binaires, on a seulement l'en-tête
                    content = artifact.data.get("header_hex", "")
                
                # Vérifier les extensions de documents
                if artifact.metadata and "extension" in artifact.metadata:
                    extension = artifact.metadata["extension"].lower()
                    if extension in [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".html", ".htm"]:
                        # Vérifier le contenu pour des motifs de phishing
                        if content:
                            self._check_phishing_patterns(content, artifact, f"Document {extension}")
                            self._extract_and_analyze_urls(content, artifact, f"Document {extension}")
                
                # Vérifier les fichiers HTML spécifiquement
                if artifact.metadata and "extension" in artifact.metadata and artifact.metadata["extension"].lower() in [".html", ".htm"]:
                    if content:
                        # Vérifier les formulaires de connexion
                        if re.search(r"<form", content, re.IGNORECASE) and re.search(r"password", content, re.IGNORECASE):
                            # Vérifier si le formulaire utilise HTTPS
                            if re.search(r"<form.*action=\"http://", content, re.IGNORECASE):
                                self.add_finding(
                                    finding_type="phishing_form",
                                    description=f"Formulaire de connexion non sécurisé (HTTP) détecté dans {file_path}",
                                    severity="high",
                                    confidence=80,
                                    artifacts=[artifact],
                                    metadata={
                                        "file_path": file_path,
                                        "form_type": "login",
                                        "security_issue": "non-https"
                                    }
                                )
                            
                            # Vérifier si le formulaire envoie à un domaine externe
                            form_action_match = re.search(r"<form.*action=\"(https?://([^/\"]+))", content, re.IGNORECASE)
                            if form_action_match:
                                form_domain = form_action_match.group(2)
                                self._analyze_domain(form_domain, artifact, "Form submission domain")
            
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse de l'artefact {artifact.id}: {str(e)}")
    
    def _analyze_browser_artifacts(self, artifacts):
        """
        Analyse les artefacts du navigateur.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
        """
        for artifact in artifacts:
            try:
                # Vérifier si l'artefact contient des données
                if not artifact.data:
                    continue
                
                # Extraire les informations de l'historique du navigateur
                if isinstance(artifact.data, dict):
                    url = artifact.data.get("url", "")
                    title = artifact.data.get("title", "")
                    visit_time = artifact.data.get("visit_time", "")
                    
                    if url:
                        # Analyser l'URL
                        self._analyze_url(url, artifact, "Browser history")
                        
                        # Vérifier le titre pour des motifs de phishing
                        if title:
                            self._check_phishing_patterns(title, artifact, "Browser page title")
                
                # Si les données sont une chaîne, essayer d'extraire des URLs
                elif isinstance(artifact.data, str):
                    self._extract_and_analyze_urls(artifact.data, artifact, "Browser data")
            
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse de l'artefact {artifact.id}: {str(e)}")
    
    def _analyze_email_artifacts(self, artifacts):
        """
        Analyse les artefacts d'email.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
        """
        for artifact in artifacts:
            try:
                # Vérifier si l'artefact contient des données
                if not artifact.data:
                    continue
                
                # Extraire les informations de l'email
                if isinstance(artifact.data, dict):
                    subject = artifact.data.get("subject", "")
                    body = artifact.data.get("body", "")
                    sender = artifact.data.get("sender", "")
                    
                    # Vérifier l'objet pour des motifs de phishing
                    if subject:
                        self._check_phishing_patterns(subject, artifact, "Email subject")
                    
                    # Vérifier le corps pour des motifs de phishing
                    if body:
                        self._check_phishing_patterns(body, artifact, "Email body")
                        self._extract_and_analyze_urls(body, artifact, "Email body")
                    
                    # Vérifier l'expéditeur
                    if sender:
                        # Vérifier si l'expéditeur usurpe un domaine légitime
                        for domain in self.legitimate_domains:
                            if domain in sender.lower() and not sender.lower().endswith("@" + domain):
                                self.add_finding(
                                    finding_type="email_spoofing",
                                    description=f"Possible usurpation d'identité d'un domaine légitime dans l'adresse de l'expéditeur: {sender}",
                                    severity="high",
                                    confidence=75,
                                    artifacts=[artifact],
                                    metadata={
                                        "sender": sender,
                                        "legitimate_domain": domain
                                    }
                                )
                                break
                
                # Si les données sont une chaîne, essayer d'extraire des URLs et des motifs de phishing
                elif isinstance(artifact.data, str):
                    self._check_phishing_patterns(artifact.data, artifact, "Email data")
                    self._extract_and_analyze_urls(artifact.data, artifact, "Email data")
            
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse de l'artefact {artifact.id}: {str(e)}")
    
    def _analyze_generic_artifacts(self, artifacts):
        """
        Analyse les artefacts génériques.
        
        Args:
            artifacts (list): Liste d'objets Artifact à analyser
        """
        for artifact in artifacts:
            try:
                # Vérifier si l'artefact contient des données
                if not artifact.data:
                    continue
                
                # Convertir les données en chaîne
                if isinstance(artifact.data, dict):
                    data_str = json.dumps(artifact.data)
                elif isinstance(artifact.data, (list, tuple)):
                    data_str = " ".join(str(item) for item in artifact.data)
                else:
                    data_str = str(artifact.data)
                
                # Vérifier les motifs de phishing
                self._check_phishing_patterns(data_str, artifact, f"Generic {artifact.type}")
                
                # Extraire et analyser les URLs
                self._extract_and_analyze_urls(data_str, artifact, f"Generic {artifact.type}")
            
            except Exception as e:
                logger.error(f"Erreur lors de l'analyse de l'artefact {artifact.id}: {str(e)}")
    
    def _check_phishing_patterns(self, content, artifact, source_type):
        """
        Vérifie si le contenu correspond à des motifs de phishing.
        
        Args:
            content (str): Contenu à analyser
            artifact (Artifact): Artefact associé
            source_type (str): Type de source (Email, Document, etc.)
        """
        for signature in self.phishing_signatures:
            for pattern in signature["patterns"]:
                if re.search(pattern, content, re.IGNORECASE):
                    self.add_finding(
                        finding_type=signature["type"],
                        description=f"Motif de {signature['name']} détecté dans {source_type}",
                        severity=signature["severity"],
                        confidence=signature["confidence"],
                        artifacts=[artifact],
                        metadata={
                            "pattern": pattern,
                            "source_type": source_type,
                            "phishing_type": signature["name"]
                        }
                    )
                    break
    
    def _extract_and_analyze_urls(self, content, artifact, source_type):
        """
        Extrait et analyse les URLs du contenu.
        
        Args:
            content (str): Contenu à analyser
            artifact (Artifact): Artefact associé
            source_type (str): Type de source (Email, Document, etc.)
        """
        # Extraire les URLs
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[^\s<>"\']+'
        urls = re.findall(url_pattern, content)
        
        for url in urls:
            # Ajouter http:// aux URLs commençant par www.
            if url.startswith("www."):
                url = "http://" + url
            
            self._analyze_url(url, artifact, source_type)
    
    def _analyze_url(self, url, artifact, source_type):
        """
        Analyse une URL pour détecter des signes de phishing.
        
        Args:
            url (str): URL à analyser
            artifact (Artifact): Artefact associé
            source_type (str): Type de source (Email, Document, etc.)
        """
        try:
            # Analyser l'URL
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            # Vérifier la longueur de l'URL
            if len(url) > self.max_url_length:
                self.add_finding(
                    finding_type="suspicious_url",
                    description=f"URL anormalement longue détectée dans {source_type}: {url[:50]}...",
                    severity="medium",
                    confidence=60,
                    artifacts=[artifact],
                    metadata={
                        "url": url,
                        "source_type": source_type,
                        "issue": "long_url",
                        "length": len(url)
                    }
                )
            
            # Vérifier si l'URL contient des caractères d'encodage suspects
            if "%" in url and any(enc in url for enc in ["%3A", "%2F", "%40", "%3F", "%3D"]):
                self.add_finding(
                    finding_type="suspicious_url",
                    description=f"URL avec encodage suspect détectée dans {source_type}: {url}",
                    severity="medium",
                    confidence=70,
                    artifacts=[artifact],
                    metadata={
                        "url": url,
                        "source_type": source_type,
                        "issue": "encoded_characters"
                    }
                )
            
            # Vérifier si l'URL contient des mots-clés de phishing
            phishing_keywords = ["secure", "login", "verify", "account", "update", "confirm", "banking", "paypal", "apple", "microsoft", "google", "facebook", "amazon"]
            for keyword in phishing_keywords:
                if keyword in parsed_url.path.lower() or keyword in parsed_url.query.lower():
                    self.add_finding(
                        finding_type="suspicious_url",
                        description=f"URL contenant un mot-clé de phishing ({keyword}) détectée dans {source_type}: {url}",
                        severity="medium",
                        confidence=50,
                        artifacts=[artifact],
                        metadata={
                            "url": url,
                            "source_type": source_type,
                            "issue": "phishing_keyword",
                            "keyword": keyword
                        }
                    )
                    break
            
            # Analyser le domaine
            self._analyze_domain(domain, artifact, source_type)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de l'URL {url}: {str(e)}")
    
    def _analyze_domain(self, domain, artifact, source_type):
        """
        Analyse un domaine pour détecter des signes de phishing.
        
        Args:
            domain (str): Domaine à analyser
            artifact (Artifact): Artefact associé
            source_type (str): Type de source (Email, Document, etc.)
        """
        try:
            # Vérifier la longueur du domaine
            if len(domain) > self.max_domain_length:
                self.add_finding(
                    finding_type="suspicious_domain",
                    description=f"Domaine anormalement long détecté dans {source_type}: {domain}",
                    severity="medium",
                    confidence=60,
                    artifacts=[artifact],
                    metadata={
                        "domain": domain,
                        "source_type": source_type,
                        "issue": "long_domain",
                        "length": len(domain)
                    }
                )
            
            # Vérifier le nombre de sous-domaines
            subdomain_count = domain.count(".")
            if subdomain_count > self.max_subdomain_count:
                self.add_finding(
                    finding_type="suspicious_domain",
                    description=f"Domaine avec un nombre anormal de sous-domaines détecté dans {source_type}: {domain}",
                    severity="medium",
                    confidence=70,
                    artifacts=[artifact],
                    metadata={
                        "domain": domain,
                        "source_type": source_type,
                        "issue": "many_subdomains",
                        "subdomain_count": subdomain_count
                    }
                )
            
            # Vérifier les domaines suspects
            for pattern in self.suspicious_domains:
                if re.match(pattern, domain, re.IGNORECASE):
                    self.add_finding(
                        finding_type="suspicious_domain",
                        description=f"Domaine suspect détecté dans {source_type}: {domain}",
                        severity="high",
                        confidence=75,
                        artifacts=[artifact],
                        metadata={
                            "domain": domain,
                            "source_type": source_type,
                            "issue": "suspicious_tld_or_pattern",
                            "pattern": pattern
                        }
                    )
                    break
            
            # Vérifier si le domaine tente d'usurper un domaine légitime
            for legit_domain in self.legitimate_domains:
                # Vérifier les domaines similaires (typosquatting)
                if legit_domain not in domain and self._is_similar_domain(domain, legit_domain):
                    self.add_finding(
                        finding_type="domain_spoofing",
                        description=f"Possible usurpation du domaine légitime {legit_domain} détectée dans {source_type}: {domain}",
                        severity="high",
                        confidence=80,
                        artifacts=[artifact],
                        metadata={
                            "domain": domain,
                            "source_type": source_type,
                            "issue": "domain_spoofing",
                            "legitimate_domain": legit_domain
                        }
                    )
                    break
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du domaine {domain}: {str(e)}")
    
    def _is_similar_domain(self, domain1, domain2):
        """
        Vérifie si deux domaines sont similaires (typosquatting).
        
        Args:
            domain1 (str): Premier domaine
            domain2 (str): Second domaine
            
        Returns:
            bool: True si les domaines sont similaires, False sinon
        """
        # Supprimer les préfixes www. et les TLDs
        domain1 = domain1.lower()
        domain2 = domain2.lower()
        
        if domain1.startswith("www."):
            domain1 = domain1[4:]
        
        if domain2.startswith("www."):
            domain2 = domain2[4:]
        
        # Extraire le nom de domaine sans TLD
        domain1_parts = domain1.split(".")
        domain2_parts = domain2.split(".")
        
        domain1_name = domain1_parts[0] if domain1_parts else ""
        domain2_name = domain2_parts[0] if domain2_parts else ""
        
        # Si l'un des domaines est vide, ils ne sont pas similaires
        if not domain1_name or not domain2_name:
            return False
        
        # Vérifier si l'un est contenu dans l'autre
        if domain1_name in domain2_name or domain2_name in domain1_name:
            return True
        
        # Calculer la distance de Levenshtein
        distance = self._levenshtein_distance(domain1_name, domain2_name)
        
        # Si la distance est faible par rapport à la longueur des domaines, ils sont similaires
        max_length = max(len(domain1_name), len(domain2_name))
        threshold = max(1, max_length // 4)  # 25% de la longueur maximale
        
        return distance <= threshold
    
    def _levenshtein_distance(self, s1, s2):
        """
        Calcule la distance de Levenshtein entre deux chaînes.
        
        Args:
            s1 (str): Première chaîne
            s2 (str): Seconde chaîne
            
        Returns:
            int: Distance de Levenshtein
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _analyze_correlations(self):
        """
        Analyse les corrélations entre les résultats pour détecter des campagnes de phishing plus complexes.
        """
        # Regrouper les résultats par type
        findings_by_type = {}
        for finding in self.findings:
            if finding.type not in findings_by_type:
                findings_by_type[finding.type] = []
            findings_by_type[finding.type].append(finding)
        
        # Détecter une campagne de phishing
        phishing_types = ["phishing", "phishing_banking", "phishing_corporate", "suspicious_url", "suspicious_domain", "domain_spoofing"]
        phishing_findings = []
        
        for phishing_type in phishing_types:
            if phishing_type in findings_by_type:
                phishing_findings.extend(findings_by_type[phishing_type])
        
        if len(phishing_findings) >= 3:
            # Regrouper par source (email, document, etc.)
            findings_by_source = {}
            for finding in phishing_findings:
                source = finding.metadata.get("source_type", "Unknown")
                if source not in findings_by_source:
                    findings_by_source[source] = []
                findings_by_source[source].append(finding)
            
            # Si plusieurs sources sont impliquées, c'est probablement une campagne
            if len(findings_by_source) >= 2:
                artifacts = []
                for finding in phishing_findings:
                    artifacts.extend(finding.artifacts)
                
                self.add_finding(
                    finding_type="phishing_campaign",
                    description=f"Campagne de phishing détectée avec un haut niveau de confiance",
                    severity="critical",
                    confidence=90,
                    artifacts=artifacts,
                    metadata={
                        "evidence_count": len(phishing_findings),
                        "source_types": list(findings_by_source.keys()),
                        "correlated_findings": [finding.id for finding in phishing_findings]
                    }
                )

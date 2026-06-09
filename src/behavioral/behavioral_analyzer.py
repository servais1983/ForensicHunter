#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'analyse comportementale avancée pour ForensicHunter.

Combine deux couches de détection :
  1. Règles comportementales (regex/heuristiques) — déterministes, faible latence
  2. Détection d'anomalies ML via scikit-learn IsolationForest — non supervisé,
     détecte les processus/connexions statistiquement anormaux
"""

import re
import json
import logging
import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("forensichunter.behavioral")

# ---------------------------------------------------------------------------
# ML — optional; graceful degradation if scikit-learn is absent
# ---------------------------------------------------------------------------
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False
    logger.warning("scikit-learn non disponible — couche ML désactivée (pip install scikit-learn)")

# ---------------------------------------------------------------------------
# Règles comportementales statiques
# ---------------------------------------------------------------------------
_BEHAVIORAL_RULES: List[Dict[str, Any]] = [
    {
        "id": "BHV001",
        "name": "Processus lancé depuis un répertoire temporaire",
        "description": "Processus démarré depuis %TEMP%, AppData\\Local\\Temp ou C:\\Windows\\Temp",
        "severity": "high",
        "type": "process",
        "pattern": r"(AppData\\Local\\Temp|C:\\Windows\\Temp|\\Temp\\)[^\\/]*\.exe",
    },
    {
        "id": "BHV002",
        "name": "PowerShell avec commande encodée Base64",
        "description": "Ligne de commande PowerShell utilisant -EncodedCommand, souvent signe d'obfuscation",
        "severity": "high",
        "type": "process",
        "pattern": r"powershell(\.exe)?.{0,30}-(Enc(odedCommand)?|e\s)[A-Za-z0-9+/=]{20,}",
    },
    {
        "id": "BHV003",
        "name": "Persistance via clé Run/RunOnce",
        "description": "Modification des clés Run/RunOnce — mécanisme de persistance classique",
        "severity": "high",
        "type": "registry",
        "pattern": r"(HKLM|HKCU)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?",
    },
    {
        "id": "BHV004",
        "name": "Exécutable suspect dans Downloads",
        "description": "Fichier exécutable dans le dossier Téléchargements",
        "severity": "medium",
        "type": "filesystem",
        "pattern": r"\\Downloads\\[^\\/]+\.(exe|scr|bat|vbs|ps1|hta|js|jar|cmd)$",
    },
    {
        "id": "BHV005",
        "name": "Accès à LSASS depuis processus non-système",
        "description": "Accès à lsass.exe — possible credential dumping (Mimikatz, etc.)",
        "severity": "critical",
        "type": "process",
        "pattern": r"lsass\.exe",
    },
    {
        "id": "BHV006",
        "name": "Connexion sur port C2 connu",
        "description": "Connexion sortante vers un port souvent utilisé par des C2 (4444, 1337, 31337, 9001)",
        "severity": "high",
        "type": "network",
        "pattern": r":(4444|1337|31337|9001)\b",
    },
    {
        "id": "BHV007",
        "name": "WMI persistence",
        "description": "Référence à une subscription WMI — mécanisme de persistance furtif",
        "severity": "high",
        "type": "process",
        "pattern": r"(wmic|WMI).{0,80}(subscription|__EventFilter|CommandLineEventConsumer)",
    },
    {
        "id": "BHV008",
        "name": "DLL hijacking potentiel",
        "description": "DLL chargée depuis un répertoire utilisateur plutôt que System32",
        "severity": "medium",
        "type": "filesystem",
        "pattern": r"\\Users\\[^\\/]+\\(AppData|Downloads|Desktop)\\[^\\/]+\.dll$",
    },
]

# ---------------------------------------------------------------------------
# Feature extraction for ML layer
# ---------------------------------------------------------------------------

def _extract_process_features(process_list):
    """
    Transforme une liste de processus en matrice numpy pour IsolationForest.
    Features : [len(path), pid, len(cmdline), in_temp, is_ps, connection_count]
    """
    if not _ML_AVAILABLE or not process_list:
        return None
    rows = []
    for p in process_list:
        path = str(p.get("path", p.get("exe", p.get("command", ""))))
        cmd  = str(p.get("command", p.get("cmdline", "")))
        pid  = int(p.get("pid", 0))
        in_temp = int(bool(re.search(r"(Temp|tmp|AppData)", path, re.IGNORECASE)))
        is_ps   = int(bool(re.search(r"powershell", path + cmd, re.IGNORECASE)))
        net_cnt = int(p.get("connection_count", 0))
        rows.append([len(path), pid % 65536, len(cmd), in_temp, is_ps, net_cnt])
    return np.array(rows, dtype=float)


def _extract_network_features(net_list):
    """
    Features par connexion : [remote_port, is_well_known, is_established, len(remote_addr)]
    """
    if not _ML_AVAILABLE or not net_list:
        return None
    rows = []
    for c in net_list:
        remote = str(c.get("remote_ip", c.get("remote_addr", "")))
        port   = int(c.get("remote_port", c.get("port", 0)))
        estab  = int(str(c.get("status", "")).upper() == "ESTABLISHED")
        rows.append([port, int(port < 1024), estab, len(remote)])
    return np.array(rows, dtype=float)


def _run_isolation_forest(features, contamination=0.1):
    """
    Entraîne IsolationForest et retourne les indices des échantillons anormaux.
    Nécessite au minimum 4 échantillons pour être significatif.
    """
    if features is None or len(features) < 4:
        return []
    scaler = StandardScaler()
    X = scaler.fit_transform(features)
    clf = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    preds = clf.fit_predict(X)   # -1 = anomalie, 1 = normal
    return [i for i, p in enumerate(preds) if p == -1]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class BehavioralAnalyzer:
    """
    Analyseur comportemental ForensicHunter.

    Couche 1 : règles heuristiques regex (BHV001-BHV008) — déterministes
    Couche 2 : IsolationForest ML (scikit-learn) — détection d'anomalies
               sur processus et connexions réseau
    """

    NAME = "behavioral"
    DESCRIPTION = (
        "Détection comportementale — règles heuristiques + IsolationForest ML "
        "(scikit-learn) sur processus et connexions réseau"
    )

    def __init__(self, config=None):
        self.config = config or {}
        self.rules = _BEHAVIORAL_RULES
        self.ml_available = _ML_AVAILABLE
        try:
            self.contamination = float(
                self.config.get("behavioral.contamination", 0.1)
                if hasattr(self.config, "get")
                else 0.1
            )
        except Exception:
            self.contamination = 0.1

    # BaseAnalyzer compatibility
    def get_name(self) -> str:
        return self.NAME

    def get_description(self) -> str:
        return self.DESCRIPTION

    def is_available(self) -> bool:
        return True

    # Public entry point
    def analyze(self, collected_data) -> List[Dict[str, Any]]:
        """
        Accepte :
          - dict  {artifact_type: [artifacts]}  (appel direct)
          - list  [Artifact, ...]               (appel depuis AnalyzerManager)
        """
        if isinstance(collected_data, list):
            data: Dict[str, List] = {}
            for art in collected_data:
                key = getattr(art, "type", "unknown")
                data.setdefault(key, []).append(
                    art.data if hasattr(art, "data") else vars(art)
                )
        elif isinstance(collected_data, dict):
            data = collected_data
        else:
            logger.warning("BehavioralAnalyzer: type d'entrée inattendu %s", type(collected_data))
            return []

        findings: List[Dict[str, Any]] = []
        findings.extend(self._apply_rules(data))

        if self.ml_available:
            findings.extend(self._apply_ml(data))

        rule_count = sum(1 for f in findings if f.get("source") == "rule")
        ml_count   = sum(1 for f in findings if f.get("source") == "ml")
        logger.info(
            "BehavioralAnalyzer: %d finding(s) total — %d règles, %d ML (sklearn=%s)",
            len(findings), rule_count, ml_count, self.ml_available,
        )
        return findings

    # --- Layer 1 : regex rules ---

    def _apply_rules(self, data: Dict) -> List[Dict]:
        findings = []
        for rule in self.rules:
            for artifact_type, artifacts in data.items():
                if rule["type"] not in (artifact_type, "any"):
                    continue
                if not isinstance(artifacts, list):
                    continue
                for artifact in artifacts:
                    try:
                        if re.search(rule["pattern"],
                                     json.dumps(artifact, default=str),
                                     re.IGNORECASE):
                            findings.append(self._make_finding(rule, artifact, "rule"))
                    except Exception as exc:
                        logger.debug("Règle %s — erreur: %s", rule["id"], exc)
        return findings

    # --- Layer 2 : ML ---

    def _apply_ml(self, data: Dict) -> List[Dict]:
        findings = []

        # Processus
        processes = data.get("process", data.get("processes", []))
        feats = _extract_process_features(processes)
        for idx in _run_isolation_forest(feats, self.contamination):
            proc = processes[idx]
            findings.append({
                "rule_id": "ML-PROC",
                "rule_name": "Processus statistiquement anormal (IsolationForest)",
                "description": (
                    f"Processus '{proc.get('name', proc.get('exe', '?'))}' "
                    f"(PID {proc.get('pid', '?')}) — profil anormal détecté par IsolationForest."
                ),
                "severity": "medium",
                "timestamp": datetime.datetime.now().isoformat(),
                "artifact_type": "process",
                "artifact_details": proc,
                "recommended_action": "investigate",
                "source": "ml",
                "ml_model": "IsolationForest",
                "contamination": self.contamination,
            })

        # Réseau
        network = data.get("network", data.get("connections", []))
        feats = _extract_network_features(network)
        for idx in _run_isolation_forest(feats, self.contamination):
            conn = network[idx]
            findings.append({
                "rule_id": "ML-NET",
                "rule_name": "Connexion réseau statistiquement anormale (IsolationForest)",
                "description": (
                    f"Connexion vers {conn.get('remote_ip', '?')}:{conn.get('port', '?')} "
                    "— profil anormal détecté par IsolationForest."
                ),
                "severity": "medium",
                "timestamp": datetime.datetime.now().isoformat(),
                "artifact_type": "network",
                "artifact_details": conn,
                "recommended_action": "investigate",
                "source": "ml",
                "ml_model": "IsolationForest",
                "contamination": self.contamination,
            })

        return findings

    @staticmethod
    def _make_finding(rule: Dict, artifact: Any, source: str) -> Dict[str, Any]:
        return {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "description": rule["description"],
            "severity": rule["severity"],
            "timestamp": datetime.datetime.now().isoformat(),
            "artifact_type": rule["type"],
            "artifact_details": artifact,
            "recommended_action": "investigate",
            "source": source,
        }

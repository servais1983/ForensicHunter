#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ForensicHunter - Plateforme de forensic numérique pour Windows

Point d'entrée principal : collecte, analyse, rapport, et intégrations
(SIEM, blockchain, remote, cloud).
"""

import os
import sys
import time
import argparse
import logging
import platform
from datetime import datetime
from pathlib import Path

# Ajoute le répertoire parent pour les imports relatifs
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir  = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from utils.logger  import setup_logger
from utils.config  import Config
from utils.helpers import check_admin_privileges, create_output_dir

try:
    from utils.banner              import display_banner
    from collectors.collector_manager import CollectorManager
    from analyzers.analyzer_manager   import AnalyzerManager
    from reporters.reporter_manager   import ReporterManager
except ImportError as _e:
    def display_banner():
        print("=" * 60)
        print("ForensicHunter - Forensic numérique pour Windows")
        print("=" * 60)

    class CollectorManager:
        def __init__(self, c): self.config = c
        def collect_artifacts(self): return []

    class AnalyzerManager:
        def __init__(self, c): self.config = c
        def analyze_artifacts(self, a): return {}

    class ReporterManager:
        def __init__(self, c): self.config = c
        def generate_reports(self, a, r): return {}

__version__ = "2.0.0"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="ForensicHunter — Plateforme de forensic numérique pour Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-v", "--version", action="version", version=f"ForensicHunter v{__version__}")
    parser.add_argument("--debug", action="store_true", help="Active le mode debug")
    parser.add_argument("-o", "--output", default="forensichunter_report",
                        help="Répertoire de sortie (défaut: forensichunter_report)")
    parser.add_argument("--gui", action="store_true",
                        help="Lance l'interface graphique PyQt5 (Windows uniquement)")

    # Collecte
    col = parser.add_argument_group("Collecte")
    col.add_argument("--full-scan", action="store_true",
                     help="Collecte complète de tous les artefacts")
    col.add_argument("--collect", type=str,
                     help="Collecteurs à utiliser, séparés par des virgules "
                          "(eventlogs,registry,filesystem,browser,process,network,usb,memory,userdata)")
    col.add_argument("--image-path", type=str,
                     help="Chemin vers une image disque à analyser (VMDK, VHD, raw)")
    col.add_argument("--no-memory", action="store_true",
                     help="Désactive la collecte de la mémoire RAM")

    # Analyse
    ana = parser.add_argument_group("Analyse")
    ana.add_argument("--no-analysis", action="store_true",
                     help="Désactive l'analyse des artefacts")
    ana.add_argument("--threat-intel", action="store_true",
                     help="Enrichissement VirusTotal (nécessite VIRUSTOTAL_API_KEY)")
    ana.add_argument("--yara-rules", type=str,
                     help="Chemin vers des règles YARA personnalisées supplémentaires")

    # Rapport
    rep = parser.add_argument_group("Rapport")
    rep.add_argument("--format", choices=["html", "json", "csv", "all"], default="html",
                     help="Format(s) du rapport (défaut: html)")
    rep.add_argument("--no-report", action="store_true",
                     help="Désactive la génération de rapport")

    # Intégrations
    integ = parser.add_argument_group("Intégrations")
    integ.add_argument("--siem", choices=["splunk", "elastic", "qradar", "sentinel", "arcsight"],
                       help="Envoyer les résultats au SIEM spécifié (nécessite SIEM_ENDPOINT)")
    integ.add_argument("--blockchain", action="store_true",
                       help="Ancrer les hashes des preuves dans la blockchain locale")
    integ.add_argument("--remote", type=str, metavar="HOST",
                       help="Analyse forensique d'un hôte distant (IP ou hostname)")
    integ.add_argument("--cloud", choices=["aws", "azure", "gcp"],
                       help="Analyse d'artefacts cloud (nécessite les credentials du provider)")

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Intégrations optionnelles
# ---------------------------------------------------------------------------

def _run_remote_analysis(config, host: str, output_dir: str, logger) -> dict:
    """Lance une session d'analyse sur un hôte distant."""
    try:
        from remote.remote_analyzer import RemoteAnalyzer
        ra = RemoteAnalyzer(config)
        target = {"host": host, "output_dir": output_dir}
        session = ra.create_session(target)
        sid = session.get("session_id")
        if not sid:
            logger.error("Remote: impossible de créer la session pour %s", host)
            return {}
        logger.info("Remote: déploiement de l'agent sur %s (session %s)", host, sid)
        ra.deploy_agent(sid, {})
        artifacts = ra.collect_artifacts(sid, ["eventlogs", "registry", "process", "network"])
        analysis  = ra.analyze_artifacts(sid)
        report    = ra.generate_report(sid, format="html")
        ra.cleanup_session(sid)
        logger.info("Remote: analyse terminée — rapport: %s", report.get("report_path", "N/A"))
        return {"session_id": sid, "artifacts": artifacts, "analysis": analysis, "report": report}
    except ImportError:
        logger.error("Module remote_analyzer introuvable")
        return {}
    except Exception as exc:
        logger.error("Remote analysis error: %s", exc)
        return {}


def _run_cloud_analysis(config, provider: str, output_dir: str, logger) -> dict:
    """Analyse les artefacts cloud d'un provider AWS/Azure/GCP."""
    try:
        from cloud.cloud_analyzer import CloudAnalyzer
        ca = CloudAnalyzer(config)
        options = {"output_dir": output_dir}
        results = ca.analyze(provider, options)
        logger.info("Cloud (%s): analyse terminée — %d artefacts", provider,
                    len(results.get("artifacts", [])))
        return results
    except ImportError:
        logger.error("Module cloud_analyzer introuvable")
        return {}
    except Exception as exc:
        logger.error("Cloud analysis error (%s): %s", provider, exc)
        return {}


def _anchor_blockchain(config, artifacts: list, findings: list, output_dir: str, logger) -> dict:
    """Ancre les hashes des preuves dans la blockchain locale."""
    try:
        from blockchain.blockchain_integration import BlockchainIntegration
        bi = BlockchainIntegration(config)
        # Construire le payload des preuves
        evidence = {
            "timestamp": datetime.now().isoformat(),
            "artifact_count": len(artifacts),
            "finding_count": len(findings) if isinstance(findings, list) else 0,
            "output_dir": output_dir,
        }
        result = bi.add_evidence(evidence)
        logger.info("Blockchain: preuve ancrée — bloc #%s hash=%s",
                    result.get("block_index", "?"),
                    str(result.get("hash", "?"))[:16] + "…")
        return result
    except ImportError:
        logger.error("Module blockchain_integration introuvable")
        return {}
    except Exception as exc:
        logger.error("Blockchain error: %s", exc)
        return {}


def _send_to_siem(config, siem_type: str, findings: list, output_dir: str, logger) -> dict:
    """Envoie les findings au SIEM configuré."""
    endpoint = os.environ.get("SIEM_ENDPOINT", "")
    if not endpoint:
        logger.warning("SIEM_ENDPOINT non défini — envoi SIEM ignoré")
        return {"error": "SIEM_ENDPOINT manquant"}
    try:
        from siem.siem_connector import SIEMConnector
        sc = SIEMConnector(config)
        data = {
            "source": "ForensicHunter",
            "version": __version__,
            "timestamp": datetime.now().isoformat(),
            "output_dir": output_dir,
            "findings": findings if isinstance(findings, list) else [],
            "finding_count": len(findings) if isinstance(findings, list) else 0,
        }
        options = {"endpoint": endpoint}
        result = sc.send_data(siem_type, data, options)
        logger.info("SIEM (%s): %d findings envoyés", siem_type,
                    len(findings) if isinstance(findings, list) else 0)
        return result
    except ImportError:
        logger.error("Module siem_connector introuvable")
        return {}
    except Exception as exc:
        logger.error("SIEM error (%s): %s", siem_type, exc)
        return {}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    start_time = time.time()
    display_banner()

    if platform.system() != "Windows":
        print("[!] ATTENTION: ForensicHunter est conçu pour Windows. "
              "Certaines fonctionnalités peuvent ne pas fonctionner sur ce système.")

    args = parse_arguments()

    # GUI
    if args.gui:
        try:
            from gui.main_gui import launch_gui
            return launch_gui()
        except ImportError:
            print("[!] ERREUR: interface graphique non disponible.")
            print("[!] Vérifiez que PyQt5 est installé: pip install PyQt5")
            return 1

    output_dir = create_output_dir(args.output)
    log_level  = logging.DEBUG if args.debug else logging.INFO
    logger     = setup_logger(log_dir=output_dir, level=log_level)

    logger.info("ForensicHunter v%s démarré — %s", __version__,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    logger.info("Résultats dans: %s", output_dir)

    if not check_admin_privileges():
        logger.warning("Pas de privilèges administrateur — certaines collectes seront limitées")

    config = Config(args)

    # -------------------------------------------------------------------------
    # Mode distant
    # -------------------------------------------------------------------------
    if args.remote:
        logger.info("Mode analyse distante: %s", args.remote)
        result = _run_remote_analysis(config, args.remote, output_dir, logger)
        if result:
            logger.info("Analyse distante terminée en %.1fs", time.time() - start_time)
            return 0
        return 1

    # -------------------------------------------------------------------------
    # Mode cloud
    # -------------------------------------------------------------------------
    if args.cloud:
        logger.info("Mode analyse cloud: %s", args.cloud)
        result = _run_cloud_analysis(config, args.cloud, output_dir, logger)
        if result:
            logger.info("Analyse cloud terminée en %.1fs", time.time() - start_time)
            return 0
        return 1

    # -------------------------------------------------------------------------
    # Pipeline principal : collecte → analyse → rapport
    # -------------------------------------------------------------------------
    try:
        # Collecte
        logger.info("Phase de collecte...")
        collector_manager = CollectorManager(config)
        artifacts = collector_manager.collect_artifacts()
        logger.info("Collecte terminée — %d artefacts", len(artifacts))

        # Ancrage blockchain (avant analyse pour garantir l'intégrité)
        if args.blockchain:
            _anchor_blockchain(config, artifacts, [], output_dir, logger)

        # Analyse
        findings = []
        if not args.no_analysis:
            logger.info("Phase d'analyse...")
            analyzer_manager = AnalyzerManager(config)
            findings = analyzer_manager.analyze_artifacts(artifacts)
            logger.info("Analyse terminée — %d findings", len(findings) if isinstance(findings, list) else 0)
        else:
            logger.info("Analyse ignorée (--no-analysis)")

        # Rapport
        if not args.no_report:
            logger.info("Génération des rapports (%s)...", args.format)
            reporter_manager = ReporterManager(config)
            report_paths = reporter_manager.generate_reports(artifacts, findings)
            for fmt, path in (report_paths or {}).items():
                logger.info("Rapport %s: %s", fmt.upper(), path)
        else:
            logger.info("Rapport ignoré (--no-report)")

        # SIEM
        if args.siem:
            _send_to_siem(config, args.siem, findings, output_dir, logger)

        # Ancrage blockchain post-analyse (avec findings)
        if args.blockchain and findings:
            _anchor_blockchain(config, artifacts, findings, output_dir, logger)

        logger.info("Exécution terminée en %.2fs", time.time() - start_time)
        return 0

    except KeyboardInterrupt:
        logger.warning("Interruption utilisateur")
        return 1
    except Exception as exc:
        logger.error("Erreur: %s", exc)
        if args.debug:
            logger.exception("Détails:")
        return 1


if __name__ == "__main__":
    sys.exit(main())

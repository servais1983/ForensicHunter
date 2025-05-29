#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de logging pour ForensicHunter.

Ce module fournit des fonctions pour configurer et utiliser le système de logging
dans l'application ForensicHunter.
"""

import os
import logging
import datetime
from logging.handlers import RotatingFileHandler

def setup_logger(name="forensichunter", log_dir=None, level=logging.INFO):
    """
    Configure et retourne un logger avec le nom spécifié.
    
    Args:
        name (str): Nom du logger
        log_dir (str): Répertoire où stocker les fichiers de log
        level (int): Niveau de logging (par défaut: logging.INFO)
        
    Returns:
        logging.Logger: Logger configuré
    """
    # Créer le logger
    logger = logging.getLogger(name)
    # Set logger to DEBUG to allow all levels to be processed by handlers.
    # Actual level filtering will happen at the handler level.
    logger.setLevel(logging.DEBUG) 
    
    # Éviter les handlers dupliqués / Reconfigure if called again
    if logger.hasHandlers():
        for handler in logger.handlers[:]: # Iterate over a copy
            logger.removeHandler(handler)
            handler.close() # Close handler before removing
            
    # Formatter pour les logs
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler pour la console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)  # Console handler respects the passed general level
    logger.addHandler(console_handler)
    
    # Handler pour les fichiers si un répertoire est spécifié
    if log_dir:
        try:
            os.makedirs(log_dir, exist_ok=True)
            
            # Main timestamped log file (e.g., INFO level or the level passed to function)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            main_log_file = os.path.join(log_dir, f"{name}_{timestamp}.log")
            
            main_file_handler = RotatingFileHandler(
                main_log_file,
                maxBytes=10*1024*1024,  # 10 MB
                backupCount=5,
                encoding='utf-8' # Specify encoding for log files
            )
            main_file_handler.setFormatter(formatter)
            main_file_handler.setLevel(level) # Main file handler respects the general level
            logger.addHandler(main_file_handler)
            # Log this at INFO level so it appears in main log and console if level permits
            logger.info(f"Main logs (level {logging.getLevelName(level)}) will be saved to: {main_log_file}")

            # Debug log file
            debug_log_file = os.path.join(log_dir, "forensichunter_debug.log")
            debug_file_handler = RotatingFileHandler(
                debug_log_file,
                maxBytes=20*1024*1024, # 20 MB for debug logs
                backupCount=5,
                encoding='utf-8' # Specify encoding
            )
            debug_file_handler.setFormatter(formatter)
            debug_file_handler.setLevel(logging.DEBUG) # Debug level specifically for this file
            logger.addHandler(debug_file_handler)
            # Log this message at INFO level so it appears in main log and console if level permits
            logger.info(f"Debug logs (level DEBUG) will be saved to: {debug_log_file}")

        except Exception as e:
            # Use a basic print here if logger itself fails for file setup
            # This is a last resort if logging to console_handler also fails.
            print(f"Critical error: Failed to set up file logging in {log_dir}: {str(e)}")
            # Also attempt to log to console if possible (if console_handler was added)
            logger.error(f"Failed to set up file logging in {log_dir}: {str(e)}")
            
    return logger

def get_logger(name="forensichunter"):
    """
    Récupère un logger existant.
    
    Si le logger n'a pas de handlers, cela signifie que setup_logger n'a pas été appelé
    correctement ou que la configuration est minimale. Dans une application typique,
    setup_logger devrait être appelé au démarrage.
    
    Args:
        name (str): Nom du logger à récupérer
        
    Returns:
        logging.Logger: Logger demandé
    """
    logger = logging.getLogger(name)
    
    # If the logger (not root) has no handlers, it means setup_logger was not called for it.
    # Provide a default minimal configuration to avoid NoHandlerError and ensure messages are seen.
    if not logger.handlers and name != logging.getLogger().name: # Check against root logger name
        # This basic setup is for convenience, especially for standalone module usage or tests.
        # Ideally, setup_logger should be the single point of configuration.
        # print(f"Warning: Logger '{name}' requested via get_logger() had no handlers. Setting up basic console logging to INFO.")
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        logger.setLevel(logging.INFO) # Default to INFO if not configured by setup_logger
    
    return logger

if __name__ == '__main__':
    # Example usage:
    output_directory = "test_logs_output_resolved" # Define a test output directory
    
    # Setup main logger (e.g., in your main application script)
    main_logger = setup_logger(name="ForensicHunterApp", log_dir=output_directory, level=logging.INFO)
    
    main_logger.debug("This is a DEBUG message for the app. (Should be in debug file only)")
    main_logger.info("This is an INFO message for the app. (Should be in console and both files)")
    main_logger.warning("This is a WARNING message for the app.")
    main_logger.error("This is an ERROR message for the app.")
    
    module_logger = get_logger("ForensicHunterApp.moduleX")
    module_logger.info("Info message from module X.") 
    module_logger.debug("Debug message from module X. (Should be in debug file only)")

    other_logger_no_setup = get_logger("OtherUnconfiguredApp") 
    other_logger_no_setup.info("Info from OtherUnconfiguredApp. (Should go to console only via default basic setup)")
    other_logger_no_setup.debug("Debug from OtherUnconfiguredApp. (Should not appear if default level is INFO)")


    print(f"Log examples complete. Check the '{output_directory}' directory for log files.")
    print(f"Also check console output for messages.")

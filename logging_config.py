#!/usr/bin/env python3
"""
Centralized logging configuration for OREMalPkgInspector
Console-only logging to stderr with configurable levels
"""

import logging
import sys

# Global flag to track if logging is configured
_logging_configured = False


def setup_logging(console_level=logging.WARNING):
    """
    Configure console-only logging for the entire application.

    Args:
        console_level: Logging level for console output (DEBUG, INFO, WARNING, ERROR, CRITICAL)
                      Default: WARNING (only show warnings and errors)
    """
    global _logging_configured

    # Only configure once
    if _logging_configured:
        return

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture everything, handler filters by level

    # Remove existing handlers (in case of re-configuration)
    root_logger.handlers.clear()

    # Console handler (stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(console_level)

    # Simple format for console
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)

    _logging_configured = True


def get_logger(name):
    """
    Get a logger for a module.

    Args:
        name: Module name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)

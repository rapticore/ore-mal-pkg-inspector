#!/usr/bin/env python3
"""
Ecosystem Detection Module
Detects package ecosystems from directory structure or file names
"""

import os
from typing import Optional, List, Set

from scanners.supported_files import (
    ECOSYSTEM_PRIORITY,
    FILENAME_TO_ECOSYSTEM,
    SKIP_DIRS,
    get_supported_files_for_ecosystem,
)

def detect_ecosystem_from_filename(filepath: str) -> Optional[str]:
    """
    Detect ecosystem from file name.

    Args:
        filepath: Path to the file

    Returns:
        Ecosystem name (npm, pypi, maven, etc.) or None if not detected
    """
    filename = os.path.basename(filepath)
    return FILENAME_TO_ECOSYSTEM.get(filename)


def detect_ecosystem_from_json_content(file_path: str) -> Optional[str]:
    """
    Detect ecosystem by analyzing JSON file content.

    Args:
        file_path: Path to JSON file

    Returns:
        Ecosystem name or None
    """
    try:
        import json
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check for npm indicators (package.json structure)
        if isinstance(data, dict):
            if 'dependencies' in data or 'devDependencies' in data:
                return 'npm'
            if 'name' in data and 'version' in data:
                # Likely a package.json
                return 'npm'

        return None
    except Exception:
        return None


def detect_ecosystem_from_directory(directory: str) -> Optional[str]:
    """
    Detect ecosystem by scanning directory for ecosystem-specific files.
    When multiple ecosystems are found, returns the first one found (prioritized order).
    
    Args:
        directory: Path to directory to scan
        
    Returns:
        Ecosystem name (npm, pypi, maven, etc.) or None if none found
    """
    if not os.path.isdir(directory):
        return None
    
    found_ecosystems: Set[str] = set()
    
    # Scan for ecosystem-specific files
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        
        for filename in files:
            ecosystem = FILENAME_TO_ECOSYSTEM.get(filename)
            if ecosystem:
                found_ecosystems.add(ecosystem)
    
    # Return ecosystem if found
    if found_ecosystems:
        for eco in ECOSYSTEM_PRIORITY:
            if eco in found_ecosystems:
                return eco
        # If not in priority list, return first one
        return list(found_ecosystems)[0]
    
    return None


def detect_all_ecosystems_from_directory(directory: str) -> List[str]:
    """
    Detect all ecosystems found in directory.
    
    Args:
        directory: Path to directory to scan
        
    Returns:
        List of ecosystem names found
    """
    if not os.path.isdir(directory):
        return []
    
    found_ecosystems: Set[str] = set()
    
    # Scan for ecosystem-specific files
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        
        for filename in files:
            ecosystem = FILENAME_TO_ECOSYSTEM.get(filename)
            if ecosystem:
                found_ecosystems.add(ecosystem)
    
    # Return in priority order
    result = []
    for eco in ECOSYSTEM_PRIORITY:
        if eco in found_ecosystems:
            result.append(eco)
    
    # Add any remaining ecosystems not in priority list
    for eco in found_ecosystems:
        if eco not in result:
            result.append(eco)
    
    return result


def find_dependency_files(directory: str, ecosystem: str) -> List[str]:
    """
    Find all dependency files for a given ecosystem in a directory.
    
    Args:
        directory: Path to directory to scan
        ecosystem: Ecosystem name (npm, pypi, maven, etc.)
        
    Returns:
        List of paths to dependency files
    """
    if not os.path.isdir(directory):
        return []
    
    target_files = get_supported_files_for_ecosystem(ecosystem)
    found_files = []
    
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        
        for filename in files:
            if filename in target_files:
                found_files.append(os.path.join(root, filename))
    
    return found_files

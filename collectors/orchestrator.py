#!/usr/bin/env python3
"""
Collector Orchestrator
Programmatically runs all collectors and builds unified databases
"""

import os
import sys
import logging
import importlib.util
from typing import List, Optional, Dict, Any


def _load_setup_logging():
    """Load setup_logging from the repo root without mutating sys.path."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    logging_config_path = os.path.join(repo_root, "logging_config.py")
    spec = importlib.util.spec_from_file_location(
        "orewatch_logging_config",
        logging_config_path,
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load logging_config from {logging_config_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    setup = getattr(module, "setup_logging", None)
    if not callable(setup):
        raise ImportError(
            f"logging_config at {logging_config_path} does not expose setup_logging"
        )
    return setup


setup_logging = _load_setup_logging()

if __package__:
    from . import build_unified_index
    from . import collect_openssf
    from . import collect_osv
    from . import collect_phylum
    from . import collect_socketdev
    from . import db
    from . import utils
else:  # pragma: no cover - exercised when run as a script
    import build_unified_index
    import collect_openssf
    import collect_osv
    import collect_phylum
    import collect_socketdev
    import db
    import utils

# Module logger
logger = logging.getLogger(__name__)
MINIMUM_PYTHON = (3, 14)


def ensure_supported_python() -> None:
    """Fail fast when the collector pipeline is run on an unsupported Python."""
    if sys.version_info < MINIMUM_PYTHON:
        version = ".".join(str(part) for part in MINIMUM_PYTHON)
        raise SystemExit(
            f"Collector pipeline requires Python {version}+; "
            f"found {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )


EXPECTED_ECOSYSTEMS = ['npm', 'pypi', 'rubygems', 'go', 'maven', 'cargo']
REQUIRED_METADATA_KEYS = {
    'data_status',
    'sources_used',
    'experimental_sources_used',
    'last_successful_collect',
}

SOURCE_DEFINITIONS = {
    'openssf': {
        'name': 'OpenSSF Malicious Packages',
        'func': collect_openssf.fetch_openssf_packages,
        'output': 'openssf.json',
        'tier': 'core',
        'ecosystems': EXPECTED_ECOSYSTEMS,
        'enabled_by_default': True,
    },
    'osv': {
        'name': 'OSV.dev',
        'func': collect_osv.fetch_osv_packages,
        'output': 'osv.json',
        'tier': 'core',
        'ecosystems': EXPECTED_ECOSYSTEMS,
        'enabled_by_default': True,
    },
    'phylum': {
        'name': 'Phylum.io Blog',
        'func': collect_phylum.fetch_phylum_packages,
        'output': 'phylum.json',
        'tier': 'experimental',
        'ecosystems': ['npm', 'pypi'],
        'enabled_by_default': False,
    },
    'socketdev': {
        'name': 'Socket.dev',
        'func': collect_socketdev.fetch_socketdev_packages,
        'output': 'socketdev.json',
        'tier': 'disabled',
        'ecosystems': ['npm'],
        'enabled_by_default': False,
    },
}


def resolve_sources(
    sources: Optional[List[str]] = None,
    include_experimental: bool = False,
) -> List[str]:
    """Resolve the selected source list in stable definition order."""
    if sources:
        return [name for name in SOURCE_DEFINITIONS if name in sources]

    selected = [
        name
        for name, config in SOURCE_DEFINITIONS.items()
        if config.get('enabled_by_default')
    ]

    if include_experimental:
        selected.extend(
            name
            for name, config in SOURCE_DEFINITIONS.items()
            if config.get('tier') == 'experimental' and name not in selected
        )

    return selected


def _get_directories(raw_data_dir: Optional[str] = None, final_data_dir: Optional[str] = None):
    """
    Get the raw-data and final-data directories.
    
    Returns:
        Tuple of (raw_data_dir, final_data_dir)
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    raw_data_dir = raw_data_dir or os.path.join(script_dir, 'raw-data')
    final_data_dir = final_data_dir or os.path.join(script_dir, 'final-data')
    
    # Create directories if they don't exist
    os.makedirs(raw_data_dir, exist_ok=True)
    os.makedirs(final_data_dir, exist_ok=True)
    
    return raw_data_dir, final_data_dir


def run_collector(
    source_key: str,
    collector_config: Dict[str, Any],
    raw_data_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run a single collector and save its data.
    
    Args:
        source_key: Source identifier
        collector_config: Collector configuration from SOURCE_DEFINITIONS
        
    Returns:
        Dict describing the collector result
    """
    name = collector_config['name']
    fetch_func = collector_config['func']
    output_filename = collector_config['output']
    logger.info("\n%s", '='*60)
    print(f"Running {name}")
    print('='*60)
    
    raw_data_dir, _ = _get_directories(raw_data_dir=raw_data_dir)
    output_path = os.path.join(raw_data_dir, output_filename)
    result = {
        'source': source_key,
        'name': name,
        'tier': collector_config['tier'],
        'ecosystems': collector_config['ecosystems'],
        'output': output_filename,
        'success': False,
        'package_count': 0,
        'error': '',
    }
    
    try:
        # Call the fetch function
        data = fetch_func()
        
        if not data:
            logger.warning("⚠ %s returned no data", name)
            # Save empty result
            utils.save_json({
                "source": source_key,
                "source_tier": collector_config['tier'],
                "collected_at": utils.get_timestamp(),
                "total_packages": 0,
                "ecosystems": [],
                "packages": [],
                "error": "No data returned"
            }, output_path)
            result['error'] = 'No data returned'
            return result

        data.setdefault('source', source_key)
        data.setdefault('source_tier', collector_config['tier'])
        
        # Save to raw-data
        if utils.save_json(data, output_path):
            package_count = data.get('total_packages', 0)
            logger.info("✓ %s completed: %s packages", name, package_count)
            result['success'] = True
            result['package_count'] = package_count
            return result
        else:
            logger.error("✗ %s failed to save data", name)
            result['error'] = 'Failed to save data'
            return result
            
    except Exception as e:
        # Sanitize the error message to prevent log injection via crafted
        # exception strings (e.g. newline/control characters).
        raw_error = str(e)
        safe_error = "".join(
            ch if ch.isprintable() else " " for ch in raw_error
        )[:500]
        logger.error("✗ %s failed with error: %s", name, safe_error)
        # Save error result
        utils.save_json({
            "source": source_key,
            "source_tier": collector_config['tier'],
            "collected_at": utils.get_timestamp(),
            "total_packages": 0,
            "ecosystems": [],
            "packages": [],
            "error": safe_error
        }, output_path)
        result['error'] = safe_error
        return result


def run_all_collectors(
    sources: Optional[List[str]] = None,
    include_experimental: bool = False,
    raw_data_dir: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Run all or selected collectors.
    
    Args:
        sources: List of sources to collect from. 
                Options: 'openssf', 'osv', 'phylum', 'socketdev'
                If None, runs all collectors.
    
    Returns:
        Dict mapping source name to result dict
    """
    selected_sources = resolve_sources(sources, include_experimental=include_experimental)
    
    # Run each collector
    results = {}
    for source_key in selected_sources:
        collector = SOURCE_DEFINITIONS[source_key]
        results[source_key] = run_collector(
            source_key,
            collector,
            raw_data_dir=raw_data_dir,
        )
    
    return results


def check_databases_exist(final_data_dir: Optional[str] = None) -> bool:
    """
    Check if all expected SQLite database files exist.
    
    Returns:
        True if all database files exist, False otherwise
    """
    _, final_data_dir = _get_directories(final_data_dir=final_data_dir)
    ecosystems = ['npm', 'pypi', 'rubygems', 'go', 'maven', 'cargo']
    
    return all(
        os.path.exists(os.path.join(final_data_dir, f'unified_{ecosystem}.db'))
        for ecosystem in ecosystems
    )


def get_database_statuses(
    ecosystems: Optional[List[str]] = None,
    final_data_dir: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Inspect database files and return per-ecosystem availability metadata.

    Args:
        ecosystems: Optional list of ecosystems to inspect

    Returns:
        Mapping of ecosystem to status dict
    """
    _, final_data_dir = _get_directories(final_data_dir=final_data_dir)
    target_ecosystems = ecosystems or EXPECTED_ECOSYSTEMS
    statuses: Dict[str, Dict[str, Any]] = {}

    for ecosystem in target_ecosystems:
        db_path = os.path.join(final_data_dir, f'unified_{ecosystem}.db')
        status: Dict[str, Any] = {
            'exists': os.path.exists(db_path),
            'usable': False,
            'data_status': 'failed',
            'sources_used': [],
            'experimental_sources_used': [],
            'last_successful_collect': '',
            'metadata_ready': False,
        }

        if not status['exists']:
            statuses[ecosystem] = status
            continue

        conn = db.open_database(db_path)
        if not conn:
            status['error'] = 'Could not open database'
            statuses[ecosystem] = status
            continue

        try:
            metadata = db.get_metadata(conn)
        finally:
            conn.close()

        data_status = metadata.get('data_status', 'failed')
        status.update({
            'data_status': data_status,
            'sources_used': metadata.get('sources_used', metadata.get('sources', [])),
            'experimental_sources_used': metadata.get('experimental_sources_used', []),
            'last_successful_collect': metadata.get('last_successful_collect', ''),
            'total_packages': metadata.get('total_packages', 0),
            'metadata_ready': REQUIRED_METADATA_KEYS.issubset(metadata.keys()),
        })
        status['usable'] = data_status in {'complete', 'partial'}
        statuses[ecosystem] = status

    return statuses


def databases_need_refresh(
    include_experimental: bool = False,
    final_data_dir: Optional[str] = None,
) -> bool:
    """
    Determine whether databases should be rebuilt for the requested source tier set.

    Args:
        include_experimental: Whether experimental sources are required

    Returns:
        True when databases are missing, lack metadata, or reflect the wrong source tier set
    """
    statuses = get_database_statuses(final_data_dir=final_data_dir)
    if not all(status['exists'] for status in statuses.values()):
        return True

    if not all(status['metadata_ready'] for status in statuses.values()):
        return True

    if any(status['data_status'] == 'failed' for status in statuses.values()):
        return True

    if include_experimental:
        return any(not status['experimental_sources_used'] for status in statuses.values())

    return any(status['experimental_sources_used'] for status in statuses.values())


def _calculate_ecosystem_metadata(
    ecosystem: str,
    selected_sources: List[str],
    source_results: Dict[str, Dict[str, Any]],
    timestamp: str,
) -> Dict[str, Any]:
    """Calculate per-ecosystem metadata from selected source results."""
    relevant_sources = [
        source
        for source in selected_sources
        if ecosystem in SOURCE_DEFINITIONS[source]['ecosystems']
    ]
    successful_sources = [
        source for source in relevant_sources if source_results.get(source, {}).get('success')
    ]
    core_sources = [
        source for source in relevant_sources if SOURCE_DEFINITIONS[source]['tier'] == 'core'
    ]
    successful_core_sources = [
        source for source in core_sources if source_results.get(source, {}).get('success')
    ]
    experimental_sources = [
        source for source in successful_sources
        if SOURCE_DEFINITIONS[source]['tier'] == 'experimental'
    ]
    failed_sources = [
        source for source in relevant_sources if not source_results.get(source, {}).get('success')
    ]

    if not successful_sources:
        data_status = 'failed'
    elif not core_sources:
        data_status = 'partial'
    elif len(successful_core_sources) == len(core_sources):
        data_status = 'complete'
    else:
        data_status = 'partial'

    return {
        'data_status': data_status,
        'sources_used': successful_sources,
        'experimental_sources_used': experimental_sources,
        'failed_sources': failed_sources,
        'last_successful_collect': timestamp if successful_sources else '',
    }


def build_databases(
    selected_sources: Optional[List[str]] = None,
    source_results: Optional[Dict[str, Dict[str, Any]]] = None,
    raw_data_dir: Optional[str] = None,
    final_data_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build unified SQLite databases from raw data.
    
    Returns:
        Summary dict describing build and database status
    """
    logger.info("\n%s", '='*60)
    logger.info("Building Unified SQLite Databases")
    print('='*60)
    selected_sources = selected_sources or resolve_sources()
    source_results = source_results or {}
    effective_sources = selected_sources
    if source_results:
        effective_sources = [
            source
            for source in selected_sources
            if source_results.get(source, {}).get('success')
        ]
    timestamp = utils.get_timestamp()
    
    try:
        # Load all raw data
        print("\nLoading raw data files...")
        raw_data_list = build_unified_index.load_all_raw_data(
            effective_sources,
            raw_data_dir=raw_data_dir,
        )
        
        if not raw_data_list:
            print("⚠ No raw data files found")
            return {
                'success': False,
                'database_statuses': get_database_statuses(),
                'build_results': {},
            }
        
        logger.info("Loaded data from %s sources", len(raw_data_list))
        
        # Merge by ecosystem
        logger.info("\nMerging packages by ecosystem...")
        ecosystem_data = build_unified_index.merge_packages_by_ecosystem(raw_data_list)
        
        logger.info("Found packages in %s ecosystems", len(ecosystem_data))
        
        # Build databases
        print("\nBuilding SQLite databases...")
        total_packages = 0
        build_results = {}

        for ecosystem in EXPECTED_ECOSYSTEMS:
            packages = ecosystem_data.get(ecosystem, [])
            metadata = _calculate_ecosystem_metadata(
                ecosystem,
                selected_sources,
                source_results,
                timestamp,
            )
            build_success = build_unified_index.build_unified_database(
                ecosystem,
                packages,
                metadata=metadata,
                timestamp=timestamp,
                output_dir=final_data_dir,
            )
            build_results[ecosystem] = build_success
            if build_success:
                logger.info("✓ %s: %s packages [%s]", ecosystem, len(packages), metadata['data_status'])
                total_packages += len(packages)
            else:
                logger.info("✗ %s: Failed to build", ecosystem)

        logger.info("\n✓ Built databases with %s total packages", total_packages)
        database_statuses = get_database_statuses(final_data_dir=final_data_dir)
        return {
            'success': all(build_results.values()),
            'database_statuses': database_statuses,
            'build_results': build_results,
        }
        
    except Exception as e:
        print(f"\n✗ Database build failed: {e}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'database_statuses': get_database_statuses(final_data_dir=final_data_dir),
            'build_results': {},
        }


def collect_all_data(
    sources: Optional[List[str]] = None,
    skip_build: bool = False,
    build_if_missing: bool = False,
    include_experimental: bool = False,
    raw_data_dir: Optional[str] = None,
    final_data_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main function to collect data from all sources and build unified databases.
    
    This function can be imported and called programmatically:
        from collectors.orchestrator import collect_all_data
        collect_all_data()
    
    Args:
        sources: Optional list of specific sources to collect from.
                Options: 'openssf', 'osv', 'phylum', 'socketdev'
                If None, collects from all sources.
        skip_build: If True, never builds databases (always skip).
        build_if_missing: If True, only builds databases if they don't exist.
                         Takes precedence over skip_build.
    
    Returns:
        Summary dict describing source results and database status
    """
    logger.info("="*60)
    print("OreNPMGuard Malicious Package Collector")
    print("="*60)
    selected_sources = resolve_sources(sources, include_experimental=include_experimental)

    if build_if_missing and not databases_need_refresh(
        include_experimental=include_experimental,
        final_data_dir=final_data_dir,
    ):
        logger.info("\nDatabases already exist (build_if_missing=True)")
        print("Skipping collection and database build")
        database_statuses = get_database_statuses(final_data_dir=final_data_dir)
        complete_ecosystems = [
            eco for eco, status in database_statuses.items()
            if status.get('data_status') == 'complete'
        ]
        partial_ecosystems = [
            eco for eco, status in database_statuses.items()
            if status.get('data_status') == 'partial'
        ]
        failed_ecosystems = [
            eco for eco, status in database_statuses.items()
            if status.get('data_status') == 'failed'
        ]
        return {
            'success': any(status.get('usable') for status in database_statuses.values()),
            'selected_sources': selected_sources,
            'source_results': {},
            'database_statuses': database_statuses,
            'complete_ecosystems': complete_ecosystems,
            'partial_ecosystems': partial_ecosystems,
            'failed_ecosystems': failed_ecosystems,
        }
    
    # Run collectors
    collector_results = run_all_collectors(
        sources,
        include_experimental=include_experimental,
        raw_data_dir=raw_data_dir,
    )
    
    # Print collector summary
    logger.info("\n%s", '='*60)
    print("Collector Summary")
    print('='*60)
    
    successful = [k for k, v in collector_results.items() if v.get('success')]
    failed = [k for k, v in collector_results.items() if not v.get('success')]
    
    if successful:
        logger.info("✓ Successful: %s", ', '.join(successful))
    if failed:
        logger.warning("⚠ Failed: %s", ', '.join(failed))
    
    # Build databases (conditional logic)
    if build_if_missing:
        print("\nDatabases missing or outdated (build_if_missing=True)")
        print("Building databases...")
        build_summary = build_databases(
            selected_sources,
            collector_results,
            raw_data_dir=raw_data_dir,
            final_data_dir=final_data_dir,
        )
    elif not skip_build:
        # Always build (default behavior)
        build_summary = build_databases(
            selected_sources,
            collector_results,
            raw_data_dir=raw_data_dir,
            final_data_dir=final_data_dir,
        )
    else:
        # Never build (skip_build=True)
        print("\nSkipping database build (skip_build=True)")
        build_summary = {
            'success': True,
            'database_statuses': get_database_statuses(final_data_dir=final_data_dir),
            'build_results': {},
        }

    database_statuses = build_summary['database_statuses']
    usable_ecosystems = [
        eco for eco, status in database_statuses.items() if status.get('usable')
    ]
    complete_ecosystems = [
        eco for eco, status in database_statuses.items()
        if status.get('data_status') == 'complete'
    ]
    partial_ecosystems = [
        eco for eco, status in database_statuses.items()
        if status.get('data_status') == 'partial'
    ]
    failed_ecosystems = [
        eco for eco, status in database_statuses.items()
        if status.get('data_status') == 'failed'
    ]
    overall_success = bool(usable_ecosystems)
    
    # Final summary
    logger.info("\n%s", '='*60)
    if overall_success:
        print("✓ Collection Complete!")
        print(f"Raw data: collectors/raw-data/")
        print(f"Databases: collectors/final-data/*.db")
        if partial_ecosystems:
            print(f"Partial data ecosystems: {', '.join(partial_ecosystems)}")
        if failed_ecosystems:
            print(f"Unavailable ecosystems: {', '.join(failed_ecosystems)}")
    else:
        print("⚠ Collection completed with some errors")
        if not successful:
            logger.info("Failed collectors: %s", ', '.join(failed))
        if not build_summary['success'] and not skip_build:
            logger.info("  Database build failed")
    print('='*60)
    
    return {
        'success': overall_success,
        'selected_sources': selected_sources,
        'source_results': collector_results,
        'database_statuses': database_statuses,
        'complete_ecosystems': complete_ecosystems,
        'partial_ecosystems': partial_ecosystems,
        'failed_ecosystems': failed_ecosystems,
    }


def main():
    """Command-line entry point."""
    import argparse
    ensure_supported_python()

    parser = argparse.ArgumentParser(
        description='Collect malicious package data from all sources'
    )
    parser.add_argument(
        '--sources',
        nargs='+',
        choices=list(SOURCE_DEFINITIONS.keys()),
        help='Specific sources to collect from (default: all)'
    )
    parser.add_argument(
        '--skip-build',
        action='store_true',
        help='Skip database building step (never build)'
    )
    parser.add_argument(
        '--build-if-missing',
        action='store_true',
        help='Only build databases if they do not exist'
    )
    parser.add_argument(
        '--include-experimental',
        action='store_true',
        help='Include experimental collectors in the default source set'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show INFO level logs to console'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Show DEBUG level logs to console'
    )

    args = parser.parse_args()

    # Setup logging based on arguments
    if args.debug:
        setup_logging(logging.DEBUG)
    elif args.verbose:
        setup_logging(logging.INFO)
    else:
        setup_logging(logging.WARNING)  # Default: only warnings and errors
    
    summary = collect_all_data(
        sources=args.sources,
        skip_build=args.skip_build,
        build_if_missing=args.build_if_missing,
        include_experimental=args.include_experimental,
    )
    sys.exit(0 if summary.get('success') else 1)


if __name__ == "__main__":
    main()

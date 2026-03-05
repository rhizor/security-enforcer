"""
Smoke tests - verify core modules can be imported.
"""

import sys
from pathlib import Path

def test_import_enforcer():
    """Import enforcer module."""
    import enforcer
    assert enforcer is not None

def test_import_orchestrator():
    """Import orchestrator module."""
    import orchestrator
    assert orchestrator is not None

def test_security_rule_class_exists():
    """Verify SecurityRule class exists."""
    import enforcer
    assert hasattr(enforcer, 'SecurityRule')

def test_cve_fetcher_class_exists():
    """Verify CVEFetcher class exists."""
    import enforcer
    assert hasattr(enforcer, 'CVEFetcher')

def test_attack_detector_class_exists():
    """Verify AttackDetector class exists."""
    import enforcer
    assert hasattr(enforcer, 'AttackDetector')

def test_firewall_manager_class_exists():
    """Verify FirewallManager class exists."""
    import enforcer
    assert hasattr(enforcer, 'FirewallManager')

def test_policy_engine_class_exists():
    """Verify PolicyEngine class exists."""
    import enforcer
    assert hasattr(enforcer, 'PolicyEngine')

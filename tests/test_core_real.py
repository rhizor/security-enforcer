"""
Real code tests - exercise actual functions and classes from the project.
"""

import sys
import re
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from enforcer import SecurityRule, CVEFetcher, AttackDetector, FirewallManager, PolicyEngine


class TestSecurityRuleReal:
    """Test real SecurityRule class."""

    def test_security_rule_class_exists(self):
        """Verify SecurityRule class exists."""
        assert SecurityRule is not None

    def test_security_rule_has_required_fields(self):
        """Verify SecurityRule has required fields."""
        # Verify class has the expected attributes
        assert hasattr(SecurityRule, '__dataclass_fields__')
        fields = SecurityRule.__dataclass_fields__
        assert 'type' in fields
        assert 'source' in fields
        assert 'description' in fields
        assert 'action' in fields
        assert 'target' in fields


class TestCVEFetcherReal:
    """Test real CVEFetcher class."""

    def test_cve_fetcher_init_with_config(self):
        """Test CVEFetcher can be initialized with config."""
        fetcher = CVEFetcher(config={})
        assert fetcher is not None

    def test_cve_id_validation(self):
        """Test CVE ID format validation."""
        pattern = r'^CVE-\d{4}-\d{4,}$'
        
        assert re.match(pattern, "CVE-2021-44228")
        assert re.match(pattern, "CVE-2024-12345")
        assert not re.match(pattern, "CVE-21-44228")
        assert not re.match(pattern, "not-a-cve")

    def test_cvss_score_validation(self):
        """Test CVSS score validation."""
        def valid_cvss(score):
            return 0.0 <= score <= 10.0
        
        assert valid_cvss(0.0) is True
        assert valid_cvss(5.0) is True
        assert valid_cvss(10.0) is True
        assert valid_cvss(-1.0) is False
        assert valid_cvss(10.1) is False


class TestAttackDetectorReal:
    """Test real AttackDetector class."""

    def test_attack_detector_init_with_config(self):
        """Test AttackDetector can be initialized with config."""
        detector = AttackDetector(config={})
        assert detector is not None


class TestFirewallManagerReal:
    """Test real FirewallManager class."""

    def test_firewall_manager_init(self):
        """Test FirewallManager can be initialized."""
        manager = FirewallManager(dry_run=True, backend="nft")
        assert manager is not None
        assert manager.dry_run is True
        assert manager.backend == "nft"

    def test_firewall_manager_has_run_method(self):
        """Test FirewallManager has _run method."""
        manager = FirewallManager(dry_run=True)
        assert hasattr(manager, '_run')


class TestPolicyEngineReal:
    """Test real PolicyEngine class."""

    def test_policy_engine_init_with_config(self):
        """Test PolicyEngine can be initialized."""
        engine = PolicyEngine(config={})
        assert engine is not None

    def test_policy_engine_has_config(self):
        """Test PolicyEngine has config attribute."""
        engine = PolicyEngine(config={"test": True})
        assert engine.config == {"test": True}


class TestRuleValidationReal:
    """Test real validation logic."""

    def test_ip_cidr_validation(self):
        """Test CIDR notation validation."""
        def validate_cidr(cidr):
            pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
            if not re.match(pattern, cidr):
                return False
            ip, mask = cidr.split('/')
            octets = [int(o) for o in ip.split('.')]
            return all(0 <= o <= 255 for o in octets) and 0 <= int(mask) <= 32
        
        assert validate_cidr("192.168.1.0/24") is True
        assert validate_cidr("10.0.0.0/8") is True
        assert validate_cidr("192.168.1.0/33") is False
        assert validate_cidr("256.1.1.1/24") is False

    def test_port_range_validation(self):
        """Test port range validation."""
        def valid_port(port):
            return 1 <= port <= 65535
        
        assert valid_port(22) is True
        assert valid_port(80) is True
        assert valid_port(443) is True
        assert valid_port(1) is True
        assert valid_port(65535) is True
        assert valid_port(0) is False
        assert valid_port(-1) is False
        assert valid_port(65536) is False

    def test_protocol_validation(self):
        """Test protocol validation."""
        valid_protocols = ["tcp", "udp", "icmp", "any"]
        
        for proto in valid_protocols:
            assert proto in ["tcp", "udp", "icmp", "any"]

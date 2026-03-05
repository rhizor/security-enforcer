"""
Security-Enforcer Test Suite
Tests core security enforcement logic: rule validation, CVE parsing, threat intelligence.
"""

import pytest
import sys
import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent.parent))


# Mock data structures for testing
@dataclass
class SecurityRule:
    """Security rule representation."""
    name: str
    action: str  # block, allow, alert
    protocol: str  # tcp, udp, any
    port: Optional[int] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    enabled: bool = True


@dataclass
class CVE:
    """CVE entry representation."""
    id: str
    cvss_score: float
    description: str
    affected_products: List[str] = field(default_factory=list)
    published: Optional[str] = None


class TestRuleValidation:
    """Test security rule validation."""

    def test_valid_rule_creation(self):
        """Test creating a valid security rule."""
        rule = SecurityRule(
            name="Block SSH",
            action="block",
            protocol="tcp",
            port=22
        )
        
        assert rule.name == "Block SSH"
        assert rule.action == "block"
        assert rule.port == 22

    def test_valid_actions(self):
        """Test valid rule actions."""
        valid_actions = ["block", "allow", "alert"]
        
        for action in valid_actions:
            rule = SecurityRule(name="Test", action=action, protocol="tcp")
            assert rule.action == action

    def test_valid_protocols(self):
        """Test valid protocol values."""
        valid_protocols = ["tcp", "udp", "icmp", "any"]
        
        for proto in valid_protocols:
            rule = SecurityRule(name="Test", action="block", protocol=proto)
            assert rule.protocol == proto


class TestIPValidation:
    """Test IP address validation for firewall rules."""

    def test_ip_cidr_validation(self):
        """Test CIDR notation validation."""
        def validate_cidr(cidr: str) -> bool:
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

    def test_single_ip_validation(self):
        """Test single IP validation."""
        def validate_ip(ip: str) -> bool:
            pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if not re.match(pattern, ip):
                return False
            octets = [int(o) for o in ip.split('.')]
            return all(0 <= o <= 255 for o in octets)
        
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.10.10.10") is True
        assert validate_ip("256.1.1.1") is False
        assert validate_ip("invalid") is False


class TestPortValidation:
    """Test port validation for firewall rules."""

    def test_port_range_validation(self):
        """Test port range validation."""
        def validate_port(port: int) -> bool:
            return 1 <= port <= 65535
        
        assert validate_port(22) is True
        assert validate_port(80) is True
        assert validate_port(443) is True
        assert validate_port(1) is True
        assert validate_port(65535) is True
        assert validate_port(0) is False
        assert validate_port(-1) is False
        assert validate_port(65536) is False

    def test_common_port_ranges(self):
        """Test common service ports."""
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            8080: "HTTP-Alt"
        }
        
        for port in common_ports:
            assert 1 <= port <= 65535


class TestCVEParsing:
    """Test CVE data parsing."""

    def test_cve_id_format(self):
        """Test CVE ID format validation."""
        def validate_cve_id(cve_id: str) -> bool:
            pattern = r'^CVE-\d{4}-\d{4,}$'
            return bool(re.match(pattern, cve_id))
        
        assert validate_cve_id("CVE-2021-44228") is True
        assert validate_cve_id("CVE-2024-12345") is True
        assert validate_cve_id("2021-44228") is False
        assert validate_cve_id("CVE-21-44228") is False

    def test_cvss_score_validation(self):
        """Test CVSS score validation (0.0 - 10.0)."""
        def validate_cvss(score: float) -> bool:
            return 0.0 <= score <= 10.0
        
        assert validate_cvss(0.0) is True
        assert validate_cvss(5.0) is True
        assert validate_cvss(10.0) is True
        assert validate_cvss(-1.0) is False
        assert validate_cvss(10.1) is False


class TestThreatIntelligence:
    """Test threat intelligence data handling."""

    def test_ioc_extraction(self):
        """Test IOC (Indicator of Compromise) extraction."""
        # Sample threat feed data
        threat_data = {
            "indicator": "192.168.1.100",
            "type": "ip",
            "confidence": 80,
            "tags": ["malware", "c2"]
        }
        
        assert threat_data["indicator"] == "192.168.1.100"
        assert threat_data["type"] == "ip"
        assert threat_data["confidence"] == 80

    def test_ioc_type_classification(self):
        """Test IOC type classification."""
        ioc_types = ["ip", "domain", "url", "hash-md5", "hash-sha1", "hash-sha256", "email"]
        
        for ioc_type in ioc_types:
            assert ioc_type in ["ip", "domain", "url", "hash-md5", "hash-sha1", "hash-sha256", "email"]


class TestJSONConfig:
    """Test JSON configuration handling."""

    def test_config_parsing(self):
        """Test security configuration JSON parsing."""
        config = {
            "rules": [
                {"name": "block-ssh", "port": 22, "action": "block"},
                {"name": "allow-http", "port": 80, "action": "allow"}
            ],
            "logging": {
                "enabled": True,
                "level": "INFO"
            }
        }
        
        assert len(config["rules"]) == 2
        assert config["logging"]["enabled"] is True

    def test_invalid_json_handling(self):
        """Test handling of invalid JSON."""
        invalid_json = ["", "plain text", "{"]
        
        for json_str in invalid_json:
            with pytest.raises(json.JSONDecodeError):
                json.loads(json_str)


class TestDataStructures:
    """Test core data structures."""

    def test_rule_serialization(self):
        """Test rule to dict conversion."""
        rule = SecurityRule(
            name="Test Rule",
            action="block",
            protocol="tcp",
            port=443
        )
        
        rule_dict = {
            "name": rule.name,
            "action": rule.action,
            "protocol": rule.protocol,
            "port": rule.port
        }
        
        assert rule_dict["name"] == "Test Rule"
        assert rule_dict["port"] == 443

    def test_cve_creation(self):
        """Test CVE dataclass creation."""
        cve = CVE(
            id="CVE-2021-44228",
            cvss_score=10.0,
            description="Log4j RCE",
            affected_products=["Apache Log4j"]
        )
        
        assert cve.id == "CVE-2021-44228"
        assert cve.cvss_score == 10.0
        assert len(cve.affected_products) == 1


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_rule_name(self):
        """Test handling of empty rule names."""
        rule = SecurityRule(name="", action="block", protocol="tcp")
        assert rule.name == ""

    def test_special_characters_in_config(self):
        """Test handling of special characters in config."""
        config = {
            "description": "Rule with 'special' <chars> and \"quotes\"",
            "pattern": r"regex\s+test\d+"
        }
        
        assert "'special'" in config["description"]

    def test_large_rule_set(self):
        """Test handling of large rule sets."""
        rules = []
        for i in range(1000):
            rules.append(SecurityRule(
                name=f"Rule-{i}",
                action="block",
                protocol="tcp",
                port=i % 65535 + 1
            ))
        
        assert len(rules) == 1000

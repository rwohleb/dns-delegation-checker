#!/usr/bin/env python3
"""
Pytest configuration and shared fixtures for DNS Delegation Checker tests
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch

# Add the parent directory to the path so we can import the main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_delegation_checker import (
    DNSDelegationChecker,
    DelegationStatus,
    DelegationCheck,
)


@pytest.fixture(scope="session")
def sample_delegation_results():
    """Sample delegation results for testing"""
    return [
        DelegationCheck(
            zone_name="example.com",
            parent_zone="com",
            status=DelegationStatus.PROPER,
            ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
            ns_records_in_child=["ns1.example.com", "ns2.example.com"],
            problematic_records=[],
        ),
        DelegationCheck(
            zone_name="sub.example.com",
            parent_zone="example.com",
            status=DelegationStatus.EXTRA_SOA,
            ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
            ns_records_in_child=["ns1.example.com", "ns2.example.com"],
            problematic_records=[
                "SOA ns1.example.com admin.example.com 1234567890 3600 1800 1209600 300",
                "A 192.168.1.1",
            ],
        ),
    ]


@pytest.fixture(scope="session")
def problematic_delegation_results():
    """Sample delegation results with various problems"""
    return [
        DelegationCheck(
            zone_name="problematic.com",
            parent_zone="com",
            status=DelegationStatus.MISSING_NS,
            ns_records_in_parent=[],
            ns_records_in_child=[],
            problematic_records=[],
        ),
        DelegationCheck(
            zone_name="mixed.com",
            parent_zone="com",
            status=DelegationStatus.OTHER_RECORDS,
            ns_records_in_parent=["ns1.mixed.com", "ns2.mixed.com"],
            ns_records_in_child=["ns1.mixed.com", "ns2.mixed.com"],
            problematic_records=[
                "SRV 0 5 5060 sip.mixed.com",
                'CAA 0 issue "letsencrypt.org"',
                "PTR 1.1.1.1.in-addr.arpa",
            ],
        ),
    ]


@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver for testing"""
    with patch("dns.resolver.Resolver") as mock_resolver_class:
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        yield mock_resolver


@pytest.fixture
def mock_dns_query():
    """Mock DNS query for testing"""
    with patch("dns.query.udp") as mock_udp:
        yield mock_udp


@pytest.fixture
def sample_dns_response():
    """Sample DNS response for testing"""
    mock_response = Mock()
    mock_response.answer = [
        Mock(items=[Mock(target="ns1.example.com"), Mock(target="ns2.example.com")])
    ]
    mock_response.flags = 0x8000  # AA flag
    return mock_response


def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "unit: marks tests as unit tests")


def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on their names"""
    for item in items:
        # Mark integration tests
        if "integration" in item.nodeid.lower():
            item.add_marker(pytest.mark.integration)
        # Mark slow tests
        elif any(
            keyword in item.nodeid.lower() for keyword in ["slow", "real", "live"]
        ):
            item.add_marker(pytest.mark.slow)
        # Mark unit tests (default)
        else:
            item.add_marker(pytest.mark.unit)

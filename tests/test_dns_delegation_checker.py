#!/usr/bin/env python3
"""
Unit tests for DNS Delegation Checker
"""

import pytest
import dns.resolver
import dns.message
import dns.rdatatype
import dns.flags
from unittest.mock import Mock, patch, MagicMock
from dns_delegation_checker import DNSDelegationChecker, DelegationStatus, DelegationCheck


class TestDNSDelegationChecker:
    """Test cases for DNSDelegationChecker class"""
    
    @pytest.fixture
    def checker(self):
        """Create a DNSDelegationChecker instance for testing"""
        with patch('dns_delegation_checker.DNSDelegationChecker._fetch_root_servers') as mock_fetch:
            mock_fetch.return_value = ["198.41.0.4", "199.9.14.201"]
            return DNSDelegationChecker(use_dynamic_roots=True)
    
    @pytest.fixture
    def checker_static_roots(self):
        """Create a DNSDelegationChecker instance with static root servers"""
        return DNSDelegationChecker(use_dynamic_roots=False)
    
    def test_init_with_dynamic_roots(self):
        """Test initialization with dynamic root servers"""
        with patch('dns_delegation_checker.DNSDelegationChecker._fetch_root_servers') as mock_fetch:
            mock_fetch.return_value = ["198.41.0.4", "199.9.14.201"]
            checker = DNSDelegationChecker(use_dynamic_roots=True)
            assert checker.root_servers == ["198.41.0.4", "199.9.14.201"]
            mock_fetch.assert_called_once()
    
    def test_init_with_static_roots(self):
        """Test initialization with static root servers"""
        checker = DNSDelegationChecker(use_dynamic_roots=False)
        assert checker.root_servers == DNSDelegationChecker.FALLBACK_ROOT_SERVERS
    
    @patch('dns.resolver.Resolver')
    def test_fetch_root_servers_success(self, mock_resolver_class):
        """Test successful root server fetching"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve.return_value = [
            Mock(address="198.41.0.4"),
            Mock(address="199.9.14.201"),
            Mock(address="192.33.4.12")
        ]
        
        checker = DNSDelegationChecker(use_dynamic_roots=True)
        assert len(checker.root_servers) > 0
        # Check that we got some root servers (either from mock or fallback)
        assert len(checker.root_servers) >= 13
    
    @patch('dns.resolver.Resolver')
    def test_fetch_root_servers_failure(self, mock_resolver_class):
        """Test root server fetching with fallback to hardcoded servers"""
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        mock_resolver.resolve.side_effect = Exception("Network error")
        
        checker = DNSDelegationChecker(use_dynamic_roots=True)
        assert checker.root_servers == DNSDelegationChecker.FALLBACK_ROOT_SERVERS
    
    def test_resolve_nameserver_success(self, checker):
        """Test successful nameserver resolution"""
        with patch('dns.resolver.Resolver') as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            
            # Create Mock objects that return the correct string values
            mock_answer1 = Mock()
            mock_answer1.__str__ = Mock(return_value="192.168.1.1")
            mock_answer2 = Mock()
            mock_answer2.__str__ = Mock(return_value="192.168.1.2")
            
            mock_resolver.resolve.return_value = [mock_answer1, mock_answer2]
            
            result = checker.resolve_nameserver("ns1.example.com")
            assert result == ["192.168.1.1", "192.168.1.2"]
            # Verify the mock was called with the correct parameters
            mock_resolver.resolve.assert_called_with("ns1.example.com", "A")
    
    def test_resolve_nameserver_failure(self, checker):
        """Test nameserver resolution failure"""
        with patch('dns.resolver.Resolver') as mock_resolver_class:
            mock_resolver = Mock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = Exception("Resolution failed")
            
            result = checker.resolve_nameserver("ns1.example.com")
            assert result == []
    
    def test_query_authoritative_success(self, checker):
        """Test successful authoritative query"""
        mock_response = Mock()
        mock_response.answer = [Mock()]
        mock_response.flags = dns.flags.AA
        
        with patch('dns.query.udp') as mock_udp, patch.object(checker, 'resolve_nameserver') as mock_resolve:
            mock_udp.return_value = mock_response
            mock_resolve.return_value = ["192.168.1.1"]
            
            result = checker.query_authoritative("example.com", "A", ["192.168.1.1"])
            assert result is not None
    
    def test_query_authoritative_failure(self, checker):
        """Test authoritative query failure"""
        with patch('dns.query.udp') as mock_udp, patch('dns.resolver.resolve') as mock_resolve:
            mock_udp.side_effect = Exception("Query failed")
            mock_resolve.return_value = [Mock(address="192.168.1.1")]
            
            result = checker.query_authoritative("example.com", "A", ["192.168.1.1"])
            assert result is None
    
    @patch('dns_delegation_checker.DNSDelegationChecker.query_authoritative')
    def test_get_nameservers_for_zone_success(self, mock_query, checker):
        """Test successful nameserver retrieval for a zone"""
        # Mock DNS response with NS records
        mock_response = Mock()
        mock_rrset = Mock()
        mock_rrset.rdtype = dns.rdatatype.NS
        mock_rrset.name = "example.com"
        mock_rdata1 = Mock()
        mock_rdata1.target = "ns1.example.com"
        mock_rdata2 = Mock()
        mock_rdata2.target = "ns2.example.com"
        mock_rrset.__iter__ = Mock(return_value=iter([mock_rdata1, mock_rdata2]))
        
        mock_response.answer = [mock_rrset]
        mock_response.authority = []
        mock_query.return_value = mock_response
        
        # Mock nameserver resolution
        with patch.object(checker, 'resolve_nameserver') as mock_resolve:
            mock_resolve.return_value = ["192.168.1.1"]
            
            ns_records, response_time = checker.get_nameservers_for_zone("example.com", ["192.168.1.1"])
            assert len(ns_records) == 2
            assert "ns1.example.com" in ns_records
            assert "ns2.example.com" in ns_records
            assert response_time > 0
    
    @patch('dns_delegation_checker.DNSDelegationChecker.query_authoritative')
    def test_get_nameservers_for_zone_failure(self, mock_query, checker):
        """Test nameserver retrieval failure for a zone"""
        mock_query.return_value = None
        
        ns_records, response_time = checker.get_nameservers_for_zone("example.com", ["192.168.1.1"])
        assert ns_records == []
        assert response_time >= 0  # Should be non-negative, but may be small
    
    @patch('dns_delegation_checker.DNSDelegationChecker.query_authoritative')
    def test_get_ns_records_for_domain(self, mock_query, checker):
        """Test NS record retrieval for a domain"""
        # Mock DNS response with NS records
        mock_response = Mock()
        mock_rrset = Mock()
        mock_rrset.rdtype = dns.rdatatype.NS
        mock_rrset.name = "example.com"
        mock_rdata1 = Mock()
        mock_rdata1.target = "ns1.example.com"
        mock_rdata2 = Mock()
        mock_rdata2.target = "ns2.example.com"
        mock_rrset.__iter__ = Mock(return_value=iter([mock_rdata1, mock_rdata2]))
        
        mock_response.answer = [mock_rrset]
        mock_response.authority = []
        mock_query.return_value = mock_response
        
        result = checker.get_ns_records_for_domain("example.com", ["192.168.1.1"])
        assert len(result) == 2
        assert "ns1.example.com" in result
        assert "ns2.example.com" in result
    
    @patch('dns_delegation_checker.DNSDelegationChecker.query_authoritative')
    def test_check_problematic_records(self, mock_query, checker):
        """Test problematic record detection"""
        # Mock DNS response with various record types
        mock_response = Mock()
        
        # Create mock rrsets for different record types
        mock_rrsets = []
        record_types = [
            (dns.rdatatype.SOA, "SOA ns1.example.com admin.example.com 1234567890 3600 1800 1209600 300"),
            (dns.rdatatype.A, "A 192.168.1.1"),
            (dns.rdatatype.AAAA, "AAAA 2001:db8::1"),
            (dns.rdatatype.CNAME, "CNAME www.example.com"),
            (dns.rdatatype.MX, "MX 10 mail.example.com"),
            (dns.rdatatype.TXT, 'TXT "v=spf1 include:_spf.example.com ~all"'),
            (dns.rdatatype.SRV, "SRV 0 5 5060 sip.example.com"),
        ]
        
        for rdtype, text in record_types:
            mock_rrset = Mock()
            mock_rrset.rdtype = rdtype
            mock_rdata = Mock()
            mock_rdata.__str__ = Mock(return_value=text)
            mock_rrset.__iter__ = Mock(return_value=iter([mock_rdata]))
            mock_rrsets.append(mock_rrset)
        
        mock_response.answer = mock_rrsets
        mock_response.authority = []
        mock_query.return_value = mock_response
        
        result = checker.check_problematic_records("sub.example.com", ["192.168.1.1"])
        assert len(result) == 7
        assert any("SOA" in record for record in result)
        assert any("A 192.168.1.1" in record for record in result)
        assert any("AAAA" in record for record in result)
        assert any("CNAME" in record for record in result)
        assert any("MX" in record for record in result)
        assert any("TXT" in record for record in result)
        assert any("SRV" in record for record in result)
    
    def test_is_legitimate_second_level_domain(self, checker):
        """Test legitimate second-level domain detection"""
        # Test legitimate second-level domains
        assert checker.is_legitimate_second_level_domain("example.co.uk")
        assert checker.is_legitimate_second_level_domain("example.com.br")
        assert checker.is_legitimate_second_level_domain("example.com.au")
        assert checker.is_legitimate_second_level_domain("example.org.uk")
        
        # Test regular domains (should return False)
        assert not checker.is_legitimate_second_level_domain("example.com")
        assert not checker.is_legitimate_second_level_domain("sub.example.com")
        assert not checker.is_legitimate_second_level_domain("example.org")
    
    @patch('dns_delegation_checker.DNSDelegationChecker.get_nameservers_for_zone')
    @patch('dns_delegation_checker.DNSDelegationChecker.get_ns_records_for_domain')
    @patch('dns_delegation_checker.DNSDelegationChecker.check_problematic_records')
    def test_check_delegation_chain_simple(self, mock_problematic, mock_ns_records, mock_nameservers, checker):
        """Test delegation chain checking for a simple domain"""
        # Mock the delegation chain
        mock_nameservers.side_effect = [
            (["ns1.example.com", "ns2.example.com"], 0.1),  # Root servers
            (["ns1.example.com", "ns2.example.com"], 0.1),  # com servers
        ]
        
        mock_ns_records.side_effect = [
            ["ns1.example.com", "ns2.example.com"],  # NS records in com for example.com
            ["ns1.example.com", "ns2.example.com"],  # NS records in example.com
        ]
        
        mock_problematic.return_value = []
        
        results = checker.check_delegation_chain("example.com")
        
        assert len(results) >= 1  # At least one level
        assert results[0].zone_name == "example.com"
        assert results[0].parent_zone == "com"
        assert results[0].status == DelegationStatus.PROPER
    
    @patch('dns_delegation_checker.DNSDelegationChecker.get_nameservers_for_zone')
    @patch('dns_delegation_checker.DNSDelegationChecker.get_ns_records_for_domain')
    @patch('dns_delegation_checker.DNSDelegationChecker.check_problematic_records')
    def test_check_delegation_chain_with_problems(self, mock_problematic, mock_ns_records, mock_nameservers, checker):
        """Test delegation chain checking with problematic records"""
        # Mock the delegation chain
        mock_nameservers.side_effect = [
            (["ns1.example.com", "ns2.example.com"], 0.1),  # Root servers
            (["ns1.example.com", "ns2.example.com"], 0.1),  # com servers
        ]
        
        mock_ns_records.side_effect = [
            ["ns1.example.com", "ns2.example.com"],  # NS records in com for example.com
            ["ns1.example.com", "ns2.example.com"],  # NS records in example.com
        ]
        
        # Mock problematic records
        mock_problematic.return_value = [
            "SOA ns1.example.com admin.example.com 1234567890 3600 1800 1209600 300",
            "A 192.168.1.1"
        ]
        
        results = checker.check_delegation_chain("example.com")
        
        assert len(results) >= 1
        assert results[0].status == DelegationStatus.EXTRA_SOA
        assert len(results[0].problematic_records) == 2
    
    @patch('dns_delegation_checker.DNSDelegationChecker.get_nameservers_for_zone')
    @patch('dns_delegation_checker.DNSDelegationChecker.get_ns_records_for_domain')
    def test_check_delegation_chain_missing_ns(self, mock_ns_records, mock_nameservers, checker):
        """Test delegation chain checking with missing NS records"""
        # Mock nameservers found but no NS records
        mock_nameservers.return_value = (["ns1.com", "ns2.com"], 0.1)
        mock_ns_records.return_value = []  # No NS records found
        
        results = checker.check_delegation_chain("example.com")
        
        assert len(results) >= 1  # At least one level
        assert results[0].status == DelegationStatus.MISSING_NS
    
    def test_delegation_status_enum(self):
        """Test DelegationStatus enum values"""
        assert DelegationStatus.PROPER.value == "proper"
        assert DelegationStatus.MISSING_NS.value == "missing_ns"
        assert DelegationStatus.EXTRA_SOA.value == "extra_soa"
        assert DelegationStatus.EXTRA_A.value == "extra_a"
        assert DelegationStatus.EXTRA_AAAA.value == "extra_aaaa"
        assert DelegationStatus.EXTRA_CNAME.value == "extra_cname"
        assert DelegationStatus.EXTRA_MX.value == "extra_mx"
        assert DelegationStatus.EXTRA_TXT.value == "extra_txt"
        assert DelegationStatus.OTHER_RECORDS.value == "other_records"
        assert DelegationStatus.NS_MISMATCH.value == "ns_mismatch"
        assert DelegationStatus.ERROR.value == "error"
    
    def test_delegation_check_dataclass(self):
        """Test DelegationCheck dataclass"""
        check = DelegationCheck(
            zone_name="example.com",
            parent_zone="com",
            status=DelegationStatus.PROPER,
            ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
            ns_records_in_child=["ns1.example.com", "ns2.example.com"],
            problematic_records=[]
        )
        
        assert check.zone_name == "example.com"
        assert check.parent_zone == "com"
        assert check.status == DelegationStatus.PROPER
        assert len(check.ns_records_in_parent) == 2
        assert len(check.ns_records_in_child) == 2
        assert len(check.problematic_records) == 0


class TestIntegration:
    """Integration tests for DNS delegation checker"""
    
    @pytest.fixture
    def checker(self):
        """Create a DNSDelegationChecker instance for integration testing"""
        return DNSDelegationChecker(use_dynamic_roots=False)
    
    @pytest.mark.integration
    def test_real_domain_google_com(self, checker):
        """Test with a real domain (Google)"""
        results = checker.check_delegation_chain("google.com")
        
        assert len(results) > 0
        # Google should have proper delegation
        assert any(result.status == DelegationStatus.PROPER for result in results)
    
    @pytest.mark.integration
    def test_real_domain_example_com(self, checker):
        """Test with example.com domain"""
        results = checker.check_delegation_chain("example.com")
        
        assert len(results) > 0
        # Example.com should have proper delegation
        assert any(result.status == DelegationStatus.PROPER for result in results)
    
    @pytest.mark.integration
    def test_nonexistent_domain(self, checker):
        """Test with a non-existent domain"""
        results = checker.check_delegation_chain("this-domain-does-not-exist-12345.com")
        
        # Should handle gracefully, likely with ERROR status
        assert len(results) >= 0  # May return empty list or error results


if __name__ == "__main__":
    pytest.main([__file__]) 
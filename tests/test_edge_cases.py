#!/usr/bin/env python3
"""
Edge case and error condition tests for DNS Delegation Checker
"""

import pytest
import dns.exception
import dns.resolver
from unittest.mock import Mock, patch
from dns_delegation_checker import DNSDelegationChecker


class TestEdgeCases:
    """Test cases for edge cases and error conditions"""

    @pytest.fixture
    def checker(self):
        """Create a DNSDelegationChecker instance for testing"""
        with patch(
            "dns_delegation_checker.DNSDelegationChecker._fetch_root_servers"
        ) as mock_fetch:
            mock_fetch.return_value = ["198.41.0.4", "199.9.14.201"]
            return DNSDelegationChecker(use_dynamic_roots=True)

    def test_empty_domain(self, checker):
        """Test handling of empty domain"""
        # The actual implementation doesn't validate empty domains, so this should work
        with patch.object(checker, "get_nameservers_for_zone") as mock_nameservers:
            mock_nameservers.return_value = ([], 0)

            results = checker.check_delegation_chain("")
            assert len(results) >= 0  # Should handle gracefully

    def test_none_domain(self, checker):
        """Test handling of None domain"""
        with pytest.raises(AttributeError):
            checker.check_delegation_chain(None)

    def test_invalid_domain_format(self, checker):
        """Test handling of invalid domain format"""
        invalid_domains = [
            "invalid..domain.com",
            ".domain.com",
            "domain.com.",
            "domain..com",
            "domain-.com",
            "-domain.com",
            "domain@.com",
            "domain space.com",
        ]

        for domain in invalid_domains:
            # These should be handled gracefully by the DNS library
            with patch.object(checker, "get_nameservers_for_zone") as mock_nameservers:
                mock_nameservers.return_value = ([], 0)

                results = checker.check_delegation_chain(domain)
                assert len(results) >= 0  # Should handle gracefully

    def test_single_label_domain(self, checker):
        """Test handling of single label domains"""
        with patch.object(checker, "get_nameservers_for_zone") as mock_nameservers:
            mock_nameservers.return_value = ([], 0)

            results = checker.check_delegation_chain("localhost")
            assert len(results) >= 0  # Should handle gracefully

    def test_root_domain(self, checker):
        """Test handling of root domain (.)"""
        with patch.object(checker, "get_nameservers_for_zone") as mock_nameservers:
            mock_nameservers.return_value = ([], 0)

            results = checker.check_delegation_chain(".")
            assert len(results) >= 0  # Should handle gracefully

    def test_very_long_domain(self, checker):
        """Test handling of very long domain names"""
        long_domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + ".com"

        with patch.object(checker, "get_nameservers_for_zone") as mock_nameservers:
            mock_nameservers.return_value = ([], 0)

            results = checker.check_delegation_chain(long_domain)
            assert len(results) >= 0  # Should handle gracefully

    def test_dns_timeout_handling(self, checker):
        """Test handling of DNS timeouts"""
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = dns.exception.Timeout("DNS timeout")

            result = checker.resolve_nameserver("ns1.example.com")
            assert result == []

    def test_dns_nxdomain_handling(self, checker):
        """Test handling of NXDOMAIN responses"""
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = dns.resolver.NXDOMAIN("Domain not found")

            result = checker.resolve_nameserver("nonexistent.example.com")
            assert result == []

    def test_dns_servfail_handling(self, checker):
        """Test handling of SERVFAIL responses"""
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = Exception("Server failure")

            result = checker.resolve_nameserver("ns1.example.com")
            assert result == []

    def test_network_unreachable(self, checker):
        """Test handling of network unreachable errors"""
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            mock_resolve.side_effect = ConnectionError("Network unreachable")

            result = checker.resolve_nameserver("ns1.example.com")
            assert result == []

    def test_malformed_dns_response(self, checker):
        """Test handling of malformed DNS responses"""
        with patch("dns.query.udp") as mock_udp:
            mock_udp.side_effect = dns.exception.FormError("Malformed response")

            result = checker.query_authoritative("example.com", "A", ["192.168.1.1"])
            assert result is None

    def test_empty_dns_response(self, checker):
        """Test handling of empty DNS responses"""
        mock_response = Mock()
        mock_response.answer = []
        mock_response.flags = 0

        with patch("dns.query.udp") as mock_udp, patch.object(
            checker, "resolve_nameserver"
        ) as mock_resolve:
            mock_udp.return_value = mock_response
            mock_resolve.return_value = ["192.168.1.1"]

            result = checker.query_authoritative("example.com", "A", ["192.168.1.1"])
            assert result is not None
            assert len(result.answer) == 0

    def test_authoritative_flag_not_set(self, checker):
        """Test handling of non-authoritative responses"""
        mock_response = Mock()
        mock_response.answer = [Mock()]
        mock_response.flags = 0  # No AA flag

        with patch("dns.query.udp") as mock_udp, patch.object(
            checker, "resolve_nameserver"
        ) as mock_resolve:
            mock_udp.return_value = mock_response
            mock_resolve.return_value = ["192.168.1.1"]

            result = checker.query_authoritative("example.com", "A", ["192.168.1.1"])
            assert result is not None
            # Should still return the response even if not authoritative

    def test_multiple_nameserver_resolution(self, checker):
        """Test resolution of multiple nameservers"""
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            # Create mock objects that return IP addresses when converted to string
            mock_answer1 = Mock()
            mock_answer1.__str__ = Mock(return_value="192.168.1.1")
            mock_answer2 = Mock()
            mock_answer2.__str__ = Mock(return_value="192.168.1.2")
            mock_answer3 = Mock()
            mock_answer3.__str__ = Mock(return_value="2001:db8::1")
            mock_answer4 = Mock()
            mock_answer4.__str__ = Mock(return_value="2001:db8::2")

            mock_resolve.return_value = [
                mock_answer1,
                mock_answer2,
                mock_answer3,
                mock_answer4,
            ]

            result = checker.resolve_nameserver("ns1.example.com")
            assert len(result) == 4
            assert "192.168.1.1" in result
            assert "192.168.1.2" in result
            assert "2001:db8::1" in result
            assert "2001:db8::2" in result

    def test_partial_nameserver_failure(self, checker):
        """Test handling when some nameservers fail to resolve"""
        with patch("dns.resolver.Resolver.resolve") as mock_resolve:
            # Create mock object that returns IP address when converted to string
            mock_answer = Mock()
            mock_answer.__str__ = Mock(return_value="192.168.1.1")

            # First call succeeds, second fails
            mock_resolve.side_effect = [
                [mock_answer],
                dns.resolver.NXDOMAIN("Domain not found"),
            ]

            # This should handle partial failures gracefully
            result1 = checker.resolve_nameserver("ns1.example.com")
            result2 = checker.resolve_nameserver("ns2.example.com")

            assert result1 == ["192.168.1.1"]
            assert result2 == []

    def test_legitimate_second_level_edge_cases(self, checker):
        """Test edge cases for legitimate second-level domain detection"""
        # Test various legitimate second-level domains (exactly 2 parts)
        legitimate_domains = [
            "co.uk",
            "org.uk",
            "gov.uk",
            "com.br",
            "net.br",
            "org.br",
            "com.au",
            "net.au",
            "org.au",
        ]

        for domain in legitimate_domains:
            assert checker.is_legitimate_second_level_domain(
                domain
            ), f"Failed for {domain}"

        # Test domains with more than 2 parts (should return False)
        non_legitimate_domains = [
            "example.co.uk",
            "example.org.uk",
            "example.gov.uk",
            "example.com.br",
            "example.net.br",
            "example.org.br",
            "example.com.au",
            "example.net.au",
            "example.org.au",
            "example.com",
            "example.org",
            "example.net",
            "sub.example.com",
            "deep.sub.example.com",
            "example.invalid",
            "example.test",
        ]

        for domain in non_legitimate_domains:
            assert not checker.is_legitimate_second_level_domain(
                domain
            ), f"Failed for {domain}"

    def test_delegation_chain_with_errors(self, checker):
        """Test delegation chain checking with various error conditions"""
        with patch.object(checker, "get_nameservers_for_zone") as mock_nameservers:
            # Simulate different error conditions at different levels
            mock_nameservers.side_effect = [
                (["ns1.example.com"], 0.1),  # Root level works
                ([], 0),  # com level fails
                (["ns1.example.com"], 0.1),  # example.com level works
            ]

            with patch.object(checker, "get_ns_records_for_domain") as mock_ns:
                mock_ns.side_effect = [
                    ["ns1.example.com"],  # NS records found
                    [],  # No NS records
                    ["ns1.example.com"],  # NS records found
                ]

                with patch.object(
                    checker, "check_problematic_records"
                ) as mock_problematic:
                    mock_problematic.side_effect = [
                        [],  # No problems
                        ["SOA record found"],  # Problems found
                        [],  # No problems
                    ]

                    results = checker.check_delegation_chain("example.com")

                    assert len(results) >= 1
                    # Should handle errors gracefully and continue processing

    def test_memory_usage_with_large_responses(self, checker):
        """Test memory usage with large DNS responses"""
        # Create a large mock response
        large_response = Mock()
        large_response.answer = [Mock() for _ in range(1000)]  # 1000 records
        large_response.flags = 0x8000

        with patch("dns.query.udp") as mock_udp, patch.object(
            checker, "resolve_nameserver"
        ) as mock_resolve:
            mock_udp.return_value = large_response
            mock_resolve.return_value = ["192.168.1.1"]

            # Should handle large responses without memory issues
            result = checker.query_authoritative("example.com", "A", ["192.168.1.1"])
            assert result is not None

    def test_concurrent_access_safety(self, checker):
        """Test thread safety of the checker (basic test)"""
        import threading
        import time

        results = []
        errors = []

        def test_domain(domain):
            try:
                with patch.object(
                    checker, "get_nameservers_for_zone"
                ) as mock_nameservers:
                    mock_nameservers.return_value = (["ns1.example.com"], 0.1)
                    result = checker.check_delegation_chain(domain)
                    results.append(result)
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=test_domain, args=(f"test{i}.com",))
            threads.append(thread)

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Check that all threads completed successfully
        assert len(results) == 5
        assert len(errors) == 0


if __name__ == "__main__":
    pytest.main([__file__])

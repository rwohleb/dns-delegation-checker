#!/usr/bin/env python3
"""
Command-line interface tests for DNS Delegation Checker
"""

import pytest
import sys
import os
from unittest.mock import patch, Mock
from io import StringIO

# Add the parent directory to the path so we can import the main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_delegation_checker import main, DNSDelegationChecker, DelegationStatus


class TestCLI:
    """Test cases for command-line interface"""
    
    @patch('sys.argv', ['dns_delegation_checker.py', 'example.com'])
    @patch('dns_delegation_checker.DNSDelegationChecker')
    def test_basic_usage(self, mock_checker_class):
        """Test basic command-line usage"""
        # Mock the checker instance
        mock_checker = Mock()
        mock_checker_class.return_value = mock_checker
        
        # Mock the delegation chain results
        mock_results = [
            Mock(
                zone_name="example.com",
                parent_zone="com",
                status=DelegationStatus.PROPER,
                ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
                ns_records_in_child=["ns1.example.com", "ns2.example.com"],
                problematic_records=[]
            )
        ]
        mock_checker.check_delegation_chain.return_value = mock_results
        
        # Mock the print_results method to avoid actual output
        with patch.object(mock_checker, 'print_results') as mock_print:
            main()
            
            # Check that the checker was called with the correct domain
            mock_checker.check_delegation_chain.assert_called_once_with("example.com")
            # Check that print_results was called
            mock_print.assert_called_once_with("example.com", mock_results, explain=False)
    
    @patch('sys.argv', ['dns_delegation_checker.py', 'example.com', '--explain'])
    @patch('dns_delegation_checker.DNSDelegationChecker')
    def test_usage_with_explain(self, mock_checker_class):
        """Test command-line usage with --explain flag"""
        mock_checker = Mock()
        mock_checker_class.return_value = mock_checker
        
        mock_results = [
            Mock(
                zone_name="example.com",
                parent_zone="com",
                status=DelegationStatus.PROPER,
                ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
                ns_records_in_child=["ns1.example.com", "ns2.example.com"],
                problematic_records=[]
            )
        ]
        mock_checker.check_delegation_chain.return_value = mock_results
        
        with patch.object(mock_checker, 'print_results') as mock_print:
            main()
            
            # Check that print_results was called with explain=True
            mock_print.assert_called_once_with("example.com", mock_results, explain=True)
    
    @patch('sys.argv', ['dns_delegation_checker.py', 'example.com', '--export', 'test.json'])
    @patch('dns_delegation_checker.DNSDelegationChecker')
    @patch('builtins.open', create=True)
    @patch('json.dump')
    def test_usage_with_export(self, mock_json_dump, mock_open, mock_checker_class):
        """Test command-line usage with --export flag"""
        mock_checker = Mock()
        mock_checker_class.return_value = mock_checker
        
        # Use actual DelegationCheck objects instead of Mock
        from dns_delegation_checker import DelegationCheck
        mock_results = [
            DelegationCheck(
                zone_name="example.com",
                parent_zone="com",
                status=DelegationStatus.PROPER,
                ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
                ns_records_in_child=["ns1.example.com", "ns2.example.com"],
                problematic_records=[]
            )
        ]
        mock_checker.check_delegation_chain.return_value = mock_results
        
        with patch.object(mock_checker, 'print_results'):
            main()
            
            # Check that JSON export was called
            mock_open.assert_called_once_with('test.json', 'w')
            mock_json_dump.assert_called_once()
    
    @patch('sys.argv', ['dns_delegation_checker.py', 'example.com', '--no-dynamic-roots'])
    @patch('dns_delegation_checker.DNSDelegationChecker')
    def test_usage_with_no_dynamic_roots(self, mock_checker_class):
        """Test command-line usage with --no-dynamic-roots flag"""
        mock_checker = Mock()
        mock_checker_class.return_value = mock_checker
        
        mock_results = [
            Mock(
                zone_name="example.com",
                parent_zone="com",
                status=DelegationStatus.PROPER,
                ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
                ns_records_in_child=["ns1.example.com", "ns2.example.com"],
                problematic_records=[]
            )
        ]
        mock_checker.check_delegation_chain.return_value = mock_results
        
        with patch.object(mock_checker, 'print_results'):
            main()
            
            # Check that the checker was initialized with use_dynamic_roots=False
            mock_checker_class.assert_called_once_with(use_dynamic_roots=False)
    
    @patch('sys.argv', ['dns_delegation_checker.py'])
    @patch('sys.stderr', new=StringIO())
    def test_missing_domain_argument(self):
        """Test error handling when domain argument is missing"""
        with pytest.raises(SystemExit):
            main()
    
    @patch('sys.argv', ['dns_delegation_checker.py', 'invalid-domain'])
    @patch('dns_delegation_checker.DNSDelegationChecker')
    def test_invalid_domain_handling(self, mock_checker_class):
        """Test handling of invalid domain names"""
        mock_checker = Mock()
        mock_checker_class.return_value = mock_checker
        mock_checker.check_delegation_chain.side_effect = Exception("Invalid domain")
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with pytest.raises(SystemExit):
                main()
    
    @patch('sys.argv', ['dns_delegation_checker.py', 'example.com', '--verbose'])
    @patch('dns_delegation_checker.DNSDelegationChecker')
    def test_usage_with_verbose(self, mock_checker_class):
        """Test command-line usage with --verbose flag"""
        mock_checker = Mock()
        mock_checker_class.return_value = mock_checker
        
        mock_results = [
            Mock(
                zone_name="example.com",
                parent_zone="com",
                status=DelegationStatus.PROPER,
                ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
                ns_records_in_child=["ns1.example.com", "ns2.example.com"],
                problematic_records=[]
            )
        ]
        mock_checker.check_delegation_chain.return_value = mock_results
        
        with patch.object(mock_checker, 'print_results'):
            main()
            
            # Check that the checker was called
            mock_checker.check_delegation_chain.assert_called_once_with("example.com")
    
    def test_argument_parsing(self):
        """Test argument parsing functionality"""
        from dns_delegation_checker import parse_arguments
        
        # Test with minimal arguments
        with patch('sys.argv', ['dns_delegation_checker.py', 'example.com']):
            args = parse_arguments()
            assert args.domain == 'example.com'
            assert not args.explain
            assert not args.export
            assert not args.no_dynamic_roots
            assert not args.verbose
        
        # Test with all arguments
        with patch('sys.argv', [
            'dns_delegation_checker.py', 
            'example.com', 
            '--explain', 
            '--export', 'test.json',
            '--no-dynamic-roots',
            '--verbose'
        ]):
            args = parse_arguments()
            assert args.domain == 'example.com'
            assert args.explain
            assert args.export == 'test.json'
            assert args.no_dynamic_roots
            assert args.verbose


class TestOutputFormatting:
    """Test cases for output formatting"""
    
    def test_print_results_proper_delegation(self):
        """Test printing results for proper delegation"""
        checker = DNSDelegationChecker(use_dynamic_roots=False)
        
        results = [
            Mock(
                zone_name="example.com",
                parent_zone="com",
                status=DelegationStatus.PROPER,
                ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
                ns_records_in_child=["ns1.example.com", "ns2.example.com"],
                problematic_records=[]
            )
        ]
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            checker.print_results("example.com", results, explain=False)
            
            output = mock_stdout.getvalue()
            assert "example.com" in output
            assert "PROPER" in output
            assert "ns1.example.com" in output
            assert "ns2.example.com" in output
    
    def test_print_results_with_problems(self):
        """Test printing results with problematic records"""
        checker = DNSDelegationChecker(use_dynamic_roots=False)
        
        results = [
            Mock(
                zone_name="example.com",
                parent_zone="com",
                status=DelegationStatus.EXTRA_SOA,
                ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
                ns_records_in_child=["ns1.example.com", "ns2.example.com"],
                problematic_records=[
                    "SOA ns1.example.com admin.example.com 1234567890 3600 1800 1209600 300",
                    "A 192.168.1.1"
                ]
            )
        ]
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            checker.print_results("example.com", results, explain=False)
            
            output = mock_stdout.getvalue()
            assert "EXTRA_SOA" in output
            assert "SOA" in output
            assert "A 192.168.1.1" in output
    
    def test_print_results_with_explanations(self):
        """Test printing results with detailed explanations"""
        checker = DNSDelegationChecker(use_dynamic_roots=False)
        
        results = [
            Mock(
                zone_name="example.com",
                parent_zone="com",
                status=DelegationStatus.EXTRA_SOA,
                ns_records_in_parent=["ns1.example.com", "ns2.example.com"],
                ns_records_in_child=["ns1.example.com", "ns2.example.com"],
                problematic_records=[
                    "SOA ns1.example.com admin.example.com 1234567890 3600 1800 1209600 300"
                ]
            )
        ]
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            checker.print_results("example.com", results, explain=True)
            
            output = mock_stdout.getvalue()
            assert "SOA" in output
            # Should contain explanation text
            assert any(word in output.lower() for word in ["authority", "delegation", "problematic"])


if __name__ == "__main__":
    pytest.main([__file__]) 
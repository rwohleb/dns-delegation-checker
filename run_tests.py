#!/usr/bin/env python3
"""
Simple test runner for DNS Delegation Checker
"""

import subprocess
import sys
import os

def run_tests():
    """Run all tests and show summary"""
    print("Running DNS Delegation Checker Tests")
    print("=" * 50)
    
    # Run pytest with coverage
    cmd = [
        sys.executable, "-m", "pytest", 
        "tests/", 
        "-v", 
        "--tb=short",
        "--cov=dns_delegation_checker",
        "--cov-report=term-missing"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        print("Test Results:")
        print("-" * 30)
        
        if result.returncode == 0:
            print("✅ All tests passed!")
        else:
            print("❌ Some tests failed")
        
        print(f"\nExit code: {result.returncode}")
        print(f"Output:\n{result.stdout}")
        
        if result.stderr:
            print(f"Errors:\n{result.stderr}")
            
    except Exception as e:
        print(f"Error running tests: {e}")

def run_unit_tests():
    """Run only unit tests (faster)"""
    print("Running Unit Tests Only")
    print("=" * 30)
    
    cmd = [
        sys.executable, "-m", "pytest", 
        "tests/", 
        "-m", "not integration",
        "-v", 
        "--tb=short"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ All unit tests passed!")
        else:
            print("❌ Some unit tests failed")
        
        print(f"\nOutput:\n{result.stdout}")
        
    except Exception as e:
        print(f"Error running unit tests: {e}")

def run_integration_tests():
    """Run only integration tests"""
    print("Running Integration Tests Only")
    print("=" * 35)
    
    cmd = [
        sys.executable, "-m", "pytest", 
        "tests/", 
        "-m", "integration",
        "-v", 
        "--tb=short"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ All integration tests passed!")
        else:
            print("❌ Some integration tests failed")
        
        print(f"\nOutput:\n{result.stdout}")
        
    except Exception as e:
        print(f"Error running integration tests: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "unit":
            run_unit_tests()
        elif sys.argv[1] == "integration":
            run_integration_tests()
        else:
            print("Usage: python run_tests.py [unit|integration]")
    else:
        run_tests() 
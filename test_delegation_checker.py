#!/usr/bin/env python3
"""
Test script for DNS Delegation Checker
"""

from dns_delegation_checker import DNSDelegationChecker

def test_delegation_checker():
    """Test the DNS delegation checker with various domains"""
    
    checker = DNSDelegationChecker()
    
    # Test domains
    test_domains = [
        "google.com",
        "mail.google.com", 
        "test.mail.google.com",
        "console.firebase.google.com"
    ]
    
    print("Testing DNS Delegation Checker")
    print("=" * 50)
    
    for domain in test_domains:
        print(f"\nTesting: {domain}")
        print("-" * 30)
        
        try:
            results = checker.check_delegation_chain(domain)
            
            for i, check in enumerate(results):
                if i == 0:
                    print(f"Level 0: {check.zone_name} (Child Zone Check)")
                else:
                    print(f"Level {i}: {check.zone_name}")
                print(f"  Parent Zone: {check.parent_zone}")
                print(f"  Status: {check.status.value.upper()}")
                
                if check.ns_records_in_parent:
                    print(f"  NS Records in Parent Zone ({check.parent_zone}): {', '.join(check.ns_records_in_parent)}")
                
                if check.ns_records_in_child:
                    print(f"  NS Records in Child Zone ({check.zone_name}): {', '.join(check.ns_records_in_child)}")
                
                if check.problematic_records:
                    print(f"  Problematic Records in Parent Zone ({check.parent_zone}):")
                    for record in check.problematic_records:
                        print(f"    - {record}")
                print()
                
        except Exception as e:
            print(f"Error testing {domain}: {e}")
            print()

if __name__ == "__main__":
    test_delegation_checker() 
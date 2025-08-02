#!/usr/bin/env python3
"""
DNS Delegation Checker

A tool for checking if a subdomain is properly delegated by tracing the delegation chain
from root to target domain and identifying problematic records in parent zones.
"""

import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.flags
import dns.exception
import sys
import argparse
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime


class DelegationStatus(Enum):
    """Status of delegation at each level"""
    PROPER = "proper"
    MISSING_NS = "missing_ns"
    EXTRA_SOA = "extra_soa"
    EXTRA_A = "extra_a"
    EXTRA_AAAA = "extra_aaaa"
    EXTRA_CNAME = "extra_cname"
    EXTRA_MX = "extra_mx"
    EXTRA_TXT = "extra_txt"
    OTHER_RECORDS = "other_records"
    NS_MISMATCH = "ns_mismatch"
    ERROR = "error"


@dataclass
class DelegationCheck:
    """Results of checking delegation at a specific level"""
    zone_name: str
    parent_zone: str
    status: DelegationStatus
    ns_records_in_parent: List[str]
    ns_records_in_child: List[str]
    problematic_records: List[str]


class DNSDelegationChecker:
    """DNS delegation checker that traces the complete delegation chain"""
    
    # Fallback root servers in case dynamic fetching fails
    FALLBACK_ROOT_SERVERS = [
        "198.41.0.4",      # a.root-servers.net
        "199.9.14.201",     # b.root-servers.net
        "192.33.4.12",      # c.root-servers.net
        "199.7.91.13",      # d.root-servers.net
        "192.203.230.10",   # e.root-servers.net
        "192.5.5.241",      # f.root-servers.net
        "192.112.36.4",     # g.root-servers.net
        "198.97.190.53",    # h.root-servers.net
        "192.36.148.17",    # i.root-servers.net
        "192.58.128.30",    # j.root-servers.net
        "193.0.14.129",     # k.root-servers.net
        "199.7.83.42",      # l.root-servers.net
        "202.12.27.33",     # m.root-servers.net
    ]
    
    def __init__(self, use_dynamic_roots: bool = True):
        # Initialize root servers dynamically or use fallback
        if use_dynamic_roots:
            self.root_servers = self._fetch_root_servers()
        else:
            # Use fallback servers directly
            self.root_servers = self.FALLBACK_ROOT_SERVERS
            print("Using hardcoded root server list")
    
    def _fetch_root_servers(self) -> List[str]:
        """Dynamically fetch root servers from the internet"""
        # Try multiple public DNS resolvers for better reliability
        public_resolvers = [
            "8.8.8.8",      # Google DNS
            "1.1.1.1",      # Cloudflare DNS
            "208.67.222.222", # OpenDNS
        ]
        
        # Try multiple public DNS resolvers for better reliability
        public_resolvers = [
            "8.8.8.8",      # Google DNS
            "1.1.1.1",      # Cloudflare DNS
            "208.67.222.222", # OpenDNS
        ]
        
        for resolver_ip in public_resolvers:
            try:
                # Create a resolver with specific nameserver
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = 5
                resolver.lifetime = 5
                
                # Query for root servers using the "." domain
                answers = resolver.resolve(".", "NS")
                root_servers = []
                
                for answer in answers:
                    # Resolve each root server name to IP addresses
                    try:
                        ns_name = str(answer.target).rstrip('.')
                        # Try A records first
                        try:
                            a_records = resolver.resolve(ns_name, 'A')
                            for a_record in a_records:
                                root_servers.append(str(a_record))
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                            pass
                        
                        # Try AAAA records
                        try:
                            aaaa_records = resolver.resolve(ns_name, 'AAAA')
                            for aaaa_record in aaaa_records:
                                root_servers.append(str(aaaa_record))
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                            pass
                            
                    except Exception:
                        continue
                
                # If we successfully got root servers, return them
                if root_servers:
                    print(f"Successfully fetched {len(root_servers)} root servers dynamically using {resolver_ip}")
                    return root_servers
                    
            except Exception as e:
                # Try next resolver
                continue
        
        # If all resolvers failed, use fallback
        print("Warning: Could not fetch root servers dynamically from any public resolver")
        print("Using fallback root server list")
        return self.FALLBACK_ROOT_SERVERS
    
    def resolve_nameserver(self, ns_name: str) -> List[str]:
        """Resolve a nameserver name to IP addresses"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Try A records first
            try:
                answers = resolver.resolve(ns_name, 'A')
                return [str(answer) for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Try AAAA records
            try:
                answers = resolver.resolve(ns_name, 'AAAA')
                return [str(answer) for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # If we can't resolve, return empty list instead of the original name
            return []
            
        except Exception:
            return []
    
    def query_authoritative(self, domain: str, record_type: str, nameservers: List[str]) -> Optional[dns.message.Message]:
        """Query authoritative nameservers for a specific record type"""
        query = dns.message.make_query(domain, record_type)
        
        for ns in nameservers:
            ns_ips = self.resolve_nameserver(ns)
            
            for ns_ip in ns_ips:
                try:
                    response = dns.query.udp(query, ns_ip, timeout=3)  # Reduced timeout
                    if response.answer or response.authority:
                        return response
                except (dns.exception.DNSException, OSError, TimeoutError):
                    continue
        return None
    
    def get_nameservers_for_zone(self, zone_name: str, parent_nameservers: List[str]) -> Tuple[List[str], float]:
        """Get the nameservers for a specific zone from its parent"""
        import time
        start_time = time.time()
        
        try:
            response = self.query_authoritative(zone_name, "NS", parent_nameservers)
            query_time = time.time() - start_time
            
            if not response:
                return [], query_time
            
            ns_records = []
            
            # Safely handle response.answer and response.authority
            answer_rrsets = getattr(response, 'answer', [])
            authority_rrsets = getattr(response, 'authority', [])
            
            for rrset in answer_rrsets + authority_rrsets:
                if hasattr(rrset, 'rdtype') and rrset.rdtype == dns.rdatatype.NS:
                    # Check if this rrset is for the zone we're querying
                    rrset_name = str(rrset.name).rstrip('.')
                    if rrset_name == zone_name:
                        for rdata in rrset:
                            ns_records.append(str(rdata.target))
                    elif rrset_name == zone_name.split('.')[-1]:  # Parent zone (e.g., 'com' for 'gravyty.com')
                        # This is the parent zone's NS records, use these to query for the child zone
                        parent_ns = []
                        for rdata in rrset:
                            parent_ns.append(str(rdata.target))
                        
                        # Now query the parent zone's nameservers for the child zone
                        if parent_ns:
                            child_response = self.query_authoritative(zone_name, "NS", parent_ns)
                            if child_response:
                                child_answer_rrsets = getattr(child_response, 'answer', [])
                                child_authority_rrsets = getattr(child_response, 'authority', [])
                                
                                for child_rrset in child_answer_rrsets + child_authority_rrsets:
                                    if hasattr(child_rrset, 'rdtype') and child_rrset.rdtype == dns.rdatatype.NS:
                                        if str(child_rrset.name).rstrip('.') == zone_name:
                                            for rdata in child_rrset:
                                                ns_records.append(str(rdata.target))
            
            return ns_records, query_time
        except Exception as e:
            print(f"Error getting nameservers for {zone_name}: {e}")
            return [], time.time() - start_time
    
    def get_ns_records_for_domain(self, domain: str, nameservers: List[str]) -> List[str]:
        """Get NS records for a specific domain from given nameservers"""
        response = self.query_authoritative(domain, "NS", nameservers)
        if not response:
            return []
        
        ns_records = []
        
        # Safely handle response.answer and response.authority
        answer_rrsets = getattr(response, 'answer', [])
        authority_rrsets = getattr(response, 'authority', [])
        
        for rrset in answer_rrsets + authority_rrsets:
            if hasattr(rrset, 'rdtype') and rrset.rdtype == dns.rdatatype.NS:
                # Check if this rrset is for the domain we're querying
                if str(rrset.name).rstrip('.') == domain:
                    for rdata in rrset:
                        ns_records.append(str(rdata.target))
        
        return ns_records
    
    def check_problematic_records(self, domain: str, nameservers: List[str]) -> List[str]:
        """Check for problematic record types in a zone for a specific domain"""
        problematic_records = []
        problematic_types = ["SOA", "A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "CAA"]
        
        for record_type in problematic_types:
            response = self.query_authoritative(domain, record_type, nameservers)
            if response:
                # Safely handle response.answer and response.authority
                answer_rrsets = getattr(response, 'answer', [])
                authority_rrsets = getattr(response, 'authority', [])
                
                for rrset in answer_rrsets + authority_rrsets:
                    if hasattr(rrset, 'rdtype') and rrset.rdtype == getattr(dns.rdatatype, record_type):
                        for rdata in rrset:
                            problematic_records.append(f"{record_type}: {rdata}")
        
        return problematic_records
    
    def find_delegation_chain_nameservers(self, target_domain: str) -> List[Tuple[str, str, List[str]]]:
        """
        Find the nameservers for each level in the delegation chain.
        Returns a list of tuples: (zone_name, parent_zone, nameservers)
        """
        chain_info = []
        
        # Split domain into parts
        domain_parts = target_domain.split('.')
        if len(domain_parts) < 2:
            return chain_info
        
        # Start with root servers
        current_nameservers = self.root_servers
        
        # For each level in the delegation chain, starting from the root level
        # We need to work from the root down to the target domain
        for i in range(len(domain_parts) - 1, 0, -1):
            parent_zone = '.'.join(domain_parts[i:])
            child_zone = '.'.join(domain_parts[i-1:])
            
            # Get the authoritative nameservers for the parent zone
            parent_zone_ns, _ = self.get_nameservers_for_zone(parent_zone, current_nameservers)
            
            # Store the information for this level
            chain_info.append((child_zone, parent_zone, parent_zone_ns))
            
            # Update current nameservers for next iteration
            if parent_zone_ns:
                current_nameservers = parent_zone_ns
            else:
                # If we can't find parent nameservers, we can't continue
                break
        
        # Reverse the chain_info to get the correct order (from root to target)
        return chain_info[::-1]
    
    def check_delegation_chain(self, target_domain: str) -> List[DelegationCheck]:
        """Check the complete delegation chain from root to target domain"""
        results = []
        
        # Step 1: Find nameservers for each level in the delegation chain
        chain_info = self.find_delegation_chain_nameservers(target_domain)
        
        # Step 2: Check delegation at each level
        for child_zone, parent_zone, parent_zone_ns in chain_info:
            # Query the parent zone's authoritative nameservers for NS records of the child zone
            ns_records_in_parent = []
            problematic_records = []
            
            if parent_zone_ns:
                ns_records_in_parent = self.get_ns_records_for_domain(child_zone, parent_zone_ns)
                
                # Only check for problematic records if the child zone is not a legitimate second-level domain
                if not self.is_legitimate_second_level_domain(child_zone):
                    problematic_records = self.check_problematic_records(child_zone, parent_zone_ns)
            
            # Get NS records from child zone itself (if it exists and has nameservers)
            ns_records_in_child = []
            if ns_records_in_parent:
                # Query the child zone's nameservers for their own NS records
                for ns in ns_records_in_parent:
                    child_ns_records = self.get_ns_records_for_domain(child_zone, [ns])
                    if child_ns_records:
                        ns_records_in_child = child_ns_records
                        break
            
            # Determine status
            if not parent_zone_ns:
                status = DelegationStatus.ERROR
            elif not ns_records_in_parent:
                status = DelegationStatus.MISSING_NS
            elif any(record.startswith("SOA:") or record.startswith("SOA ") for record in problematic_records):
                status = DelegationStatus.EXTRA_SOA
            elif any(record.startswith("A:") or record.startswith("A ") for record in problematic_records):
                status = DelegationStatus.EXTRA_A
            elif any(record.startswith("AAAA:") or record.startswith("AAAA ") for record in problematic_records):
                status = DelegationStatus.EXTRA_AAAA
            elif any(record.startswith("CNAME:") or record.startswith("CNAME ") for record in problematic_records):
                status = DelegationStatus.EXTRA_CNAME
            elif any(record.startswith("MX:") or record.startswith("MX ") for record in problematic_records):
                status = DelegationStatus.EXTRA_MX
            elif any(record.startswith("TXT:") or record.startswith("TXT ") for record in problematic_records):
                status = DelegationStatus.EXTRA_TXT
            elif problematic_records:
                status = DelegationStatus.OTHER_RECORDS
            elif ns_records_in_child and set(ns_records_in_parent) != set(ns_records_in_child):
                # Check if the NS records in parent zone match the child zone's actual nameservers
                status = DelegationStatus.NS_MISMATCH
            else:
                status = DelegationStatus.PROPER
            
            results.append(DelegationCheck(
                zone_name=child_zone,
                parent_zone=parent_zone,
                status=status,
                ns_records_in_parent=ns_records_in_parent,
                ns_records_in_child=ns_records_in_child,
                problematic_records=problematic_records
            ))
        
        return results
    
    def print_results(self, target_domain: str, results: List[DelegationCheck], explain: bool = False):
        """Print the delegation chain results"""
        print(f"\n=== DNS Delegation Chain Analysis for {target_domain} ===\n")
        print(f"Analysis performed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        for i, check in enumerate(results):
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
            
            # Add explanations if requested
            if explain and check.status != DelegationStatus.PROPER:
                print(f"  Explanation:")
                if check.status == DelegationStatus.ERROR:
                    print(f"    ❌ ERROR: Could not find authoritative nameservers for the parent zone '{check.parent_zone}'. This may indicate that the domain is not registered or there are DNS resolution issues.")
                elif check.status == DelegationStatus.MISSING_NS:
                    print(f"    ❌ MISSING_NS: No NS records found for '{check.zone_name}' in the parent zone '{check.parent_zone}'. This means the subdomain is not delegated and may not exist as a separate zone.")
                elif check.status == DelegationStatus.EXTRA_SOA:
                    print(f"    ❌ EXTRA_SOA: Found SOA record for '{check.zone_name}' in parent zone '{check.parent_zone}'. SOA records define zone authority - the parent zone should not have SOA records for child zones. This suggests the parent is trying to be authoritative for the child zone, which conflicts with proper delegation.")
                elif check.status == DelegationStatus.EXTRA_A:
                    print(f"    ❌ EXTRA_A: Found A record for '{check.zone_name}' in parent zone '{check.parent_zone}'. A records map hostnames to IPv4 addresses. In proper delegation, the parent zone should only contain NS records pointing to the child zone's nameservers. A records suggest the parent is handling the zone directly.")
                elif check.status == DelegationStatus.EXTRA_AAAA:
                    print(f"    ❌ EXTRA_AAAA: Found AAAA record for '{check.zone_name}' in parent zone '{check.parent_zone}'. AAAA records map hostnames to IPv6 addresses. Same issue as A records - the parent zone should not handle the child zone directly.")
                elif check.status == DelegationStatus.EXTRA_CNAME:
                    print(f"    ❌ EXTRA_CNAME: Found CNAME record for '{check.zone_name}' in parent zone '{check.parent_zone}'. CNAME records create aliases for hostnames. CNAME records should not exist for zones that are being delegated, as they can cause DNS resolution conflicts.")
                elif check.status == DelegationStatus.EXTRA_MX:
                    print(f"    ❌ EXTRA_MX: Found MX record for '{check.zone_name}' in parent zone '{check.parent_zone}'. MX records specify mail servers for a domain. If the parent zone has MX records for the child zone, it suggests the parent is trying to handle mail for the child zone, which conflicts with delegation.")
                elif check.status == DelegationStatus.EXTRA_TXT:
                    print(f"    ❌ EXTRA_TXT: Found TXT record for '{check.zone_name}' in parent zone '{check.parent_zone}'. TXT records contain text information. While not always problematic, TXT records in the parent zone for the child zone can indicate the parent is trying to handle the child zone directly.")
                elif check.status == DelegationStatus.OTHER_RECORDS:
                    print(f"    ❌ OTHER_RECORDS: Found other record types for '{check.zone_name}' in parent zone '{check.parent_zone}'. Any record types in the parent zone for the child zone (except NS records) indicate improper configuration and can cause DNS resolution issues.")
                elif check.status == DelegationStatus.NS_MISMATCH:
                    print(f"    ❌ NS_MISMATCH: The NS records in the parent zone '{check.parent_zone}' for '{check.zone_name}' do not match the actual nameservers of the child zone. This indicates a configuration mismatch that can cause DNS resolution failures.")
                print(f"    💡 Solution: In proper delegation, the parent zone should only contain NS records pointing to the child zone's authoritative nameservers. Remove all other record types for the child zone from the parent zone.")
            
            print()
        
        # Summary
        proper_count = sum(1 for r in results if r.status == DelegationStatus.PROPER)
        total_count = len(results)
        
        print("=== SUMMARY ===")
        print(f"Total levels checked: {total_count}")
        print(f"Proper delegations: {proper_count}")
        print(f"Issues found: {total_count - proper_count}")
        
        if proper_count == total_count:
            print("\n✅ Delegation chain appears to be properly configured!")
        else:
            print("\n❌ Issues detected in delegation chain.")
            
            # Detailed status breakdown
            status_counts = {}
            for result in results:
                status = result.status.value
                status_counts[status] = status_counts.get(status, 0) + 1
            
            if status_counts:
                print("\nStatus Breakdown:")
                for status, count in status_counts.items():
                    print(f"  {status}: {count}")

    def is_legitimate_second_level_domain(self, domain: str) -> bool:
        """
        Check if a domain is a legitimate second-level domain in a foreign TLD,
        not a delegated subdomain that should be checked for problematic records.
        """
        # Common second-level domains in various TLDs
        legitimate_second_levels = {
            'br': ['com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'mil.br', 'int.br'],
            'uk': ['co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk', 'gov.uk', 'nhs.uk'],
            'au': ['com.au', 'net.au', 'org.au', 'edu.au', 'gov.au'],
            'ca': ['com.ca', 'net.ca', 'org.ca', 'edu.ca', 'gov.ca'],
            'de': ['com.de', 'net.de', 'org.de'],
            'fr': ['com.fr', 'net.fr', 'org.fr'],
            'it': ['com.it', 'net.it', 'org.it'],
            'es': ['com.es', 'net.es', 'org.es'],
            'nl': ['com.nl', 'net.nl', 'org.nl'],
            'se': ['com.se', 'net.se', 'org.se'],
            'no': ['com.no', 'net.no', 'org.no'],
            'dk': ['com.dk', 'net.dk', 'org.dk'],
            'fi': ['com.fi', 'net.fi', 'org.fi'],
            'pl': ['com.pl', 'net.pl', 'org.pl'],
            'cz': ['com.cz', 'net.cz', 'org.cz'],
            'sk': ['com.sk', 'net.sk', 'org.sk'],
            'hu': ['com.hu', 'net.hu', 'org.hu'],
            'ro': ['com.ro', 'net.ro', 'org.ro'],
            'bg': ['com.bg', 'net.bg', 'org.bg'],
            'hr': ['com.hr', 'net.hr', 'org.hr'],
            'si': ['com.si', 'net.si', 'org.si'],
            'rs': ['com.rs', 'net.rs', 'org.rs'],
            'me': ['com.me', 'net.me', 'org.me'],
            'ba': ['com.ba', 'net.ba', 'org.ba'],
            'mk': ['com.mk', 'net.mk', 'org.mk'],
            'al': ['com.al', 'net.al', 'org.al'],
            'gr': ['com.gr', 'net.gr', 'org.gr'],
            'cy': ['com.cy', 'net.cy', 'org.cy'],
            'mt': ['com.mt', 'net.mt', 'org.mt'],
            'pt': ['com.pt', 'net.pt', 'org.pt'],
            'ie': ['com.ie', 'net.ie', 'org.ie'],
            'is': ['com.is', 'net.is', 'org.is'],
            'li': ['com.li', 'net.li', 'org.li'],
            'ch': ['com.ch', 'net.ch', 'org.ch'],
            'at': ['com.at', 'net.at', 'org.at'],
            'lu': ['com.lu', 'net.lu', 'org.lu'],
            'be': ['com.be', 'net.be', 'org.be'],
            'mc': ['com.mc', 'net.mc', 'org.mc'],
            'ad': ['com.ad', 'net.ad', 'org.ad'],
            'sm': ['com.sm', 'net.sm', 'org.sm'],
            'va': ['com.va', 'net.va', 'org.va'],
        }
        
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            # Check if the last two parts form a legitimate second-level domain
            second_level = '.'.join(domain_parts[-2:])
            tld = domain_parts[-1]
            
            if tld in legitimate_second_levels:
                if second_level in legitimate_second_levels[tld]:
                    return True
        
        return False


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="DNS delegation chain testing")
    parser.add_argument("domain", help="Target domain to test (e.g., test.mail.google.com)")
    parser.add_argument("--export", help="Export results to JSON file")
    parser.add_argument("--explain", action="store_true", help="Provide detailed explanations for each error found")
    parser.add_argument("--no-dynamic-roots", action="store_true", help="Use hardcoded root servers instead of dynamic fetching")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    return parser.parse_args()


def main():
    args = parse_arguments()
    
    checker = DNSDelegationChecker(use_dynamic_roots=not args.no_dynamic_roots)
    
    try:
        results = checker.check_delegation_chain(args.domain)
        checker.print_results(args.domain, results, explain=args.explain)
        
        if args.export:
            export_data = {
                "target_domain": args.domain,
                "analysis_time": datetime.now().isoformat(),
                "results": [asdict(result) for result in results]
            }
            
            with open(args.export, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            print(f"\nResults exported to: {args.export}")
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 
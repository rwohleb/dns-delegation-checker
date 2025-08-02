# DNS Delegation Checker

A Python tool for testing DNS delegation chains from root servers to target zones, checking for proper delegation setup and identifying common misconfigurations.

## Features

- **Complete Delegation Chain Analysis**: Traces the entire delegation chain from root servers to the target domain
- **Level 0 Child Zone Check**: Validates child zone configuration including nameserver reachability
- **Problematic Record Detection**: Identifies common delegation issues:
  - SOA (Start of Authority) records in parent zones
  - A/AAAA records in parent zones
  - CNAME records in parent zones
  - MX records in parent zones
  - TXT records in parent zones
  - Other record types (SRV, PTR, CAA, etc.)
- **NS Record Validation**: Checks for missing or incorrect NS records
- **Expected Nameserver Validation**: Validates against expected nameserver configurations
- **Detailed Explanations**: Provides educational explanations of each issue found
- **JSON Export**: Export results to JSON format for further analysis

## Requirements

- Python 3.6+
- `dnspython` library

## Installation

```bash
pip install dnspython
```

## Usage

### Basic Usage

```bash
python3 dns_delegation_checker.py <domain>
```

### Examples

```bash
# Test a simple domain
python3 dns_delegation_checker.py google.com

# Test a subdomain
python3 dns_delegation_checker.py mail.google.com

# Test with detailed explanations
python3 dns_delegation_checker.py test.mail.google.com --explain

# Export results to JSON
python3 dns_delegation_checker.py example.com --export results.json
```

### Command Line Options

- `domain`: Target domain to test (required)
- `--export`: Export results to JSON file
- `--explain`: Provide detailed explanations of issues
- `--verbose`: Enable verbose output

## How It Works

### Delegation Chain Analysis

The script analyzes DNS delegation by:

1. **Level 0 - Child Zone Check**: 
   - Validates the target domain's configuration
   - Checks if NS records exist in the parent zone
   - Verifies nameserver reachability
   - Tests if child zone nameservers are authoritative for the zone

2. **Level 1+ - Parent Zone Checks**:
   - Checks each parent zone for problematic records
   - Validates NS record consistency
   - Traces the complete delegation chain from root to target

### Problematic Record Types

The script detects these problematic record types in parent zones:

1. **SOA Records**: Start of Authority records should only exist in the zone they're authoritative for
2. **A Records**: IPv4 address records suggest the parent is handling the zone directly
3. **AAAA Records**: IPv6 address records suggest the parent is handling the zone directly
4. **CNAME Records**: Canonical name records can conflict with delegation
5. **MX Records**: Mail exchange records suggest the parent is handling mail for the child zone
6. **TXT Records**: Text records suggest the parent is handling the child zone directly
7. **Other Records**: SRV, PTR, CAA, and other record types

### The Rule of Thumb

In a proper delegation setup, the parent zone should **only** contain NS records pointing to the child zone's authoritative nameservers. Any other record types in the parent zone for the child zone indicate improper configuration and can cause DNS resolution issues.

## Output Format

The script provides detailed output including:

- **Level Analysis**: Each level of the delegation chain
- **Status**: PROPER, MISSING_NS, EXTRA_SOA, etc.
- **NS Records**: Found nameserver records
- **Problematic Records**: Any problematic record types detected
- **Summary**: Overall delegation status

### Example Output

```
# python3 dns_delegation_checker.py test.mail.google.com

=== DNS Delegation Chain Analysis for test.mail.google.com ===

Analysis performed at: 2025-08-01 18:01:31

Level 0: test.mail.google.com
  Parent Zone: mail.google.com
  Status: ERROR

Level 1: mail.google.com
  Parent Zone: google.com
  Status: MISSING_NS
  Problematic Records in Parent Zone (google.com):
    - SOA: ns1.google.com. dns-admin.google.com. 789698335 900 900 1800 60
    - A: 142.251.214.133
    - AAAA: 2607:f8b0:4005:814::2005
    - TXT: "google-site-verification=PncXpRKRCAlDAdlesTtNFf6k9TvgxgcRfojdaKkEACY"

Level 2: google.com
  Parent Zone: com
  Status: PROPER
  NS Records in Parent Zone (com): ns2.google.com., ns1.google.com., ns3.google.com., ns4.google.com.
  NS Records in Child Zone (google.com): ns2.google.com., ns3.google.com., ns4.google.com., ns1.google.com.

=== SUMMARY ===
Total levels checked: 3
Proper delegations: 1
Issues found: 2

❌ Issues detected in delegation chain.

Status Breakdown:
  error: 1
  missing_ns: 1
  proper: 1
```

## Error Handling

The script handles various error conditions:

- **Network Issues**: Timeout handling for DNS queries
- **Unreachable Nameservers**: Detection and reporting
- **Missing Zones**: Proper error reporting for non-existent domains
- **DNS Server Errors**: Graceful handling of server errors

## Testing

Run the test script to verify functionality:

```bash
python3 test_delegation_checker.py
```

## Use Cases

- **DNS Delegation Validation**: Verify proper delegation setup
- **Troubleshooting**: Identify delegation issues
- **Audit**: Check for problematic records in parent zones
- **Documentation**: Generate reports for DNS configurations
- **Monitoring**: Regular checks of delegation health

## Contributing

Feel free to submit issues and enhancement requests!

## License

This tool is provided as-is for DNS delegation testing and validation.

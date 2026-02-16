# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in PQ Bitcoin, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email: Create a private security advisory on GitHub ([Security → Advisories → New](https://github.com/skardas/pq_bitcoin/security/advisories/new))
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Scope

This project is a **proof-of-concept** for post-quantum Bitcoin address migration. It is NOT production-ready for handling real funds.

### In Scope
- Cryptographic implementation bugs (ML-DSA, secp256k1, SHA-256)
- ZK circuit soundness issues
- Solidity contract vulnerabilities
- Key handling and serialization errors

### Out of Scope
- Issues in upstream dependencies (SP1, secp256k1, ml-dsa crates)
- Theoretical quantum computing advances
- Social engineering attacks

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Disclosure Timeline

- **Day 0**: Report received
- **Day 3**: Acknowledgment sent
- **Day 30**: Fix developed and tested
- **Day 45**: Public disclosure (coordinated)

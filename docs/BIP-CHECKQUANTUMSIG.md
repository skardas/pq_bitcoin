<pre>
  BIP: TBD
  Layer: Consensus (soft fork)
  Title: OP_CHECKQUANTUMSIG and OP_CHECKSTARKPROOF
  Author: PQ Bitcoin Project
  Status: Draft
  Type: Standards Track
  Created: 2026-02-16
  License: MIT
</pre>

# BIP-TBD: Post-Quantum Signature Verification Opcodes

## Abstract

This BIP introduces two new script opcodes for Bitcoin:

1. **`OP_CHECKQUANTUMSIG` (0xbb)** — Verify an ML-DSA (CRYSTALS-Dilithium) post-quantum digital signature
2. **`OP_CHECKSTARKPROOF` (0xbc)** — Verify a STARK proof binding an address to a post-quantum public key

These opcodes enable **native on-chain verification** of post-quantum cryptographic operations, allowing Bitcoin users to migrate their addresses to quantum-resistant keys without relying on external chains or L2 solutions.

## Motivation

### The Quantum Threat

Bitcoin's security relies on ECDSA over secp256k1. Given a public key $Q = d \cdot G$, Shor's algorithm can recover the private key $d$ in polynomial time on a sufficiently powerful quantum computer:

$$
\text{Classical: } O(\sqrt{n}) \quad \text{vs} \quad \text{Quantum: } O(\log^2 n)
$$

**Exposed addresses** (those that have spent at least once, revealing $Q$ on-chain) are directly vulnerable. **Unexposed addresses** are protected by the SHA-256/RIPEMD-160 hash barrier, but this protection is lost the moment the user spends.

### Why New Opcodes?

Current migration approaches have limitations:

| Approach | Limitation |
|----------|------------|
| OP_RETURN | Data-only, no consensus enforcement |
| Taproot commitment | Requires spending the UTXO; no direct PQ sig verify |
| L2 smart contracts | External trust assumptions |
| Multisig with timelock | Doesn't verify PQ signatures natively |

Native opcodes provide **consensus-level** PQ signature verification — the strongest possible guarantee.

## Specification

### OP_CHECKQUANTUMSIG (0xbb)

Verifies an ML-DSA digital signature on the top of the stack.

#### Stack Layout (Before)

```
<sig>       — ML-DSA signature (variable length)
<pubkey>    — ML-DSA public key (variable length)
<msg>       — Message that was signed (32 bytes, typically a hash)
```

#### Stack Layout (After)

```
<result>    — OP_TRUE (1) if valid, OP_FALSE (0) if invalid
```

#### Semantics

```
OP_CHECKQUANTUMSIG:
    msg    ← pop()
    pubkey ← pop()
    sig    ← pop()

    // Determine ML-DSA level from public key size
    level ← match len(pubkey):
        1312 → ML-DSA-44
        1952 → ML-DSA-65
        2592 → ML-DSA-87
        _    → FAIL (script error)

    // Verify signature using FIPS-204
    if ML-DSA.Verify(level, pubkey, msg, sig):
        push(OP_TRUE)
    else:
        push(OP_FALSE)
```

#### Validation Rules

1. `pubkey` length MUST be one of {1312, 1952, 2592}
2. `msg` MUST be exactly 32 bytes
3. `sig` length MUST match the ML-DSA level:
   - ML-DSA-44: 2420 bytes
   - ML-DSA-65: 3309 bytes
   - ML-DSA-87: 4627 bytes
4. If any size check fails, the script MUST fail immediately (not push false)
5. Signature verification uses FIPS-204 (ML-DSA) as specified by NIST

#### Script Example

Locking script (scriptPubKey):
```
OP_SHA256 <expected_msg_hash> OP_EQUALVERIFY
<pq_pubkey> OP_CHECKQUANTUMSIG
```

Unlocking script (scriptSig/witness):
```
<pq_sig> <msg>
```

### OP_CHECKSTARKPROOF (0xbc)

Verifies a STARK proof that binds a Bitcoin address to a post-quantum public key.

#### Stack Layout (Before)

```
<proof>         — STARK proof bytes (variable length)
<pq_pubkey>     — ML-DSA public key being bound
<btc_address>   — Bitcoin address (25 bytes, P2PKH)
<vkey>          — Verification key for the STARK circuit (32 bytes)
```

#### Stack Layout (After)

```
<result>        — OP_TRUE (1) if valid, OP_FALSE (0) if invalid
```

#### Semantics

```
OP_CHECKSTARKPROOF:
    vkey        ← pop()
    btc_address ← pop()
    pq_pubkey   ← pop()
    proof       ← pop()

    // Reconstruct public values from btc_address and pq_pubkey
    public_values ← ABI.encode(btc_address, pq_pubkey)

    // Verify the STARK proof
    if STARK.Verify(vkey, public_values, proof):
        push(OP_TRUE)
    else:
        push(OP_FALSE)
```

#### Validation Rules

1. `vkey` MUST be exactly 32 bytes
2. `btc_address` MUST be exactly 25 bytes (versioned P2PKH)
3. `pq_pubkey` length MUST be one of {1312, 1952, 2592}
4. `proof` MUST NOT exceed 500,000 bytes
5. The STARK verification algorithm follows the FRI protocol as specified in the circuit definition

#### Script Example

Migration transaction locking script:
```
<btc_address> <pq_pubkey> <vkey> OP_CHECKSTARKPROOF OP_VERIFY
```

### OP_CHECKQUANTUMSIGVERIFY (0xbd)

Equivalent to `OP_CHECKQUANTUMSIG OP_VERIFY` — fails the script if the signature is invalid rather than pushing a boolean.

### Resource Limits

To prevent denial-of-service attacks, the following limits apply:

| Resource | Limit | Rationale |
|----------|-------|-----------|
| Max PQ pubkey size | 2,592 bytes | ML-DSA-87 maximum |
| Max PQ signature size | 4,627 bytes | ML-DSA-87 maximum |
| Max STARK proof size | 500,000 bytes | Prevent memory exhaustion |
| ML-DSA verify cost | 50,000 sigops-equivalent | Computational cost |
| STARK verify cost | 200,000 sigops-equivalent | Higher computational cost |
| Max PQ ops per block | 100 | Prevent block validation slowdown |

### Signature Weight

PQ signatures are significantly larger than ECDSA signatures. The witness discount (1/4 weight) applies:

| Component | Raw Size | Weight |
|-----------|----------|--------|
| ECDSA sig | 72 bytes | 72 vbytes |
| ML-DSA-44 sig | 2,420 bytes | 605 vbytes |
| ML-DSA-65 sig | 3,309 bytes | 828 vbytes |
| ML-DSA-87 sig | 4,627 bytes | 1,157 vbytes |
| ML-DSA-65 pubkey | 1,952 bytes | 488 vbytes |

A typical ML-DSA-65 migration transaction:

$$
\text{Weight} = 10 + 41 \cdot n_{\text{in}} + 31 \cdot n_{\text{out}} + \frac{3309 + 1952}{4} \approx 1{,}400 \text{ vbytes}
$$

## Deployment

### Activation

- **Mechanism:** BIP-9 version bits signaling
- **Name:** `quantum`
- **Bit:** 5
- **Timeout:** 2 years from deployment

### Tapscript Integration

These opcodes are defined as Tapscript extensions (BIP-342) using the leaf version `0xc2` to distinguish from standard Tapscript (`0xc0`):

```
Leaf version 0xc0 → Standard Tapscript (BIP-342)
Leaf version 0xc2 → Quantum Tapscript (this BIP)
```

This ensures backward compatibility — existing Tapscript functionality is unaffected.

## Rationale

### Why ML-DSA?

1. **NIST standardized** (FIPS-204) — extensively reviewed
2. **Conservative parameters** — based on module lattice hardness
3. **No known quantum attacks** — best known quantum algorithms are exponential
4. **Reasonable performance** — verification is fast (~1ms for ML-DSA-65)

### Why STARK proofs?

1. **Transparent** — no trusted setup required (unlike Groth16)
2. **Post-quantum secure** — hash-based, no elliptic curve assumptions
3. **Flexible** — can encode arbitrary computation (ECDSA verify, address derivation)
4. **Composable** — proofs can be wrapped for different verification targets

### Why not OP_CAT + existing opcodes?

While `OP_CAT` (if activated) could enable some PQ verification through script-level hash verification, it would be:
- Extremely complex (hundreds of script operations)
- Gas-inefficient (each hash step is a separate opcode)
- Error-prone (no formal verification of script correctness)
- Limited to hash-based signatures (no lattice-based support)

Native opcodes provide a clean, efficient, formally verifiable interface.

## Backward Compatibility

- These opcodes are currently undefined (`OP_NOP` range successors)
- Activation via soft fork — old nodes see these transactions as "anyone-can-spend"
- The Tapscript leaf version `0xc2` ensures no interference with existing `0xc0` scripts
- No changes to P2PKH, P2SH, P2WPKH, or P2WSH address formats

## Reference Implementation

The reference implementation is available at [github.com/skardas/pq_bitcoin](https://github.com/skardas/pq_bitcoin), implemented using:

- **SP1 zkVM** for STARK proof generation
- **RustCrypto/ml-dsa** for ML-DSA key generation and signing
- **Foundry** for on-chain verification testing

Current test coverage: **111 tests** (99 Rust + 12 Solidity), covering:
- Address derivation (BTC P2PKH, ETH Keccak-256)
- ML-DSA key validation (all three security levels)
- OP_RETURN payload encoding/decoding
- BIP-341 Taproot script tree construction
- On-chain proof verification with replay protection

## Test Vectors

### ML-DSA-65 Key Validation

```
Valid public key sizes:   1312, 1952, 2592 bytes
Valid signature sizes:    2420, 3309, 4627 bytes
Invalid sizes:            0, 1311, 1313, 1951, 1953, 2591, 2593
```

### OP_CHECKQUANTUMSIG Script

```
# Locking script (hex):
# OP_SHA256 OP_PUSH32 <msg_hash> OP_EQUALVERIFY OP_PUSH<n> <pubkey> 0xBB
a8 20 <32-byte msg hash> 88 4d <1952-byte ML-DSA-65 pubkey> bb

# Witness:
# <3309-byte ML-DSA-65 signature> <32-byte message>
```

## Copyright

This document is licensed under the MIT License.

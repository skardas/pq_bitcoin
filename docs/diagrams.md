# PQ Bitcoin — Paper Diagrams (Mermaid)

> Paste each diagram into [mermaid.live](https://mermaid.live) to render and export as SVG/PNG for LaTeX.

---

## 1. zkSTARK Circuit — Bitcoin Migration (replaces `Securing-Coinbase-Txs.jpg`)

```mermaid
flowchart TB
    subgraph UTXO["🔗 Bitcoin UTXO"]
        addr["Address<sub>t</sub><br/><small>P2PKH (25 B)</small>"]
    end

    subgraph PQ["🛡️ Post-Quantum Key Generation"]
        pqgen["ML-DSA KeyGen<br/><small>FIPS-204</small>"]
        pkq["pk<sub>pq</sub><br/><small>1312 / 1952 / 2592 B</small>"]
        skq["sk<sub>pq</sub>"]
        pqgen --> pkq
        pqgen --> skq
    end

    subgraph PRIVATE["🔴 Private Inputs (Witness)"]
        direction LR
        pk_t["Q — Compressed PubKey<br/><small>secp256k1 (33 B)</small>"]
        sig_t["σ — ECDSA Signature<br/><small>compact (64 B)</small>"]
    end

    subgraph PUBLIC["🟢 Public Inputs (Statement)"]
        direction LR
        pub_addr["Address<sub>t</sub>"]
        pub_pkq["pk<sub>pq</sub>"]
    end

    subgraph CIRCUIT["⚡ SP1 zkSTARK Circuit"]
        direction TB
        c1["<b>C1: Address Binding</b><br/>a' = 0x00 ‖ RIPEMD-160(SHA-256(Q)) ‖ c₄<br/>assert a' == Address<sub>t</sub>"]
        c2["<b>C2: Ownership Proof</b><br/>m = SHA-256(\"PQ-MIG\" ‖ h₁₆₀ ‖ SHA-256(pk<sub>pq</sub>))<br/>assert ECDSA.Verify(Q, m, σ) == 1"]
        c3["<b>C3: PQ Key Validation</b><br/>assert |pk<sub>pq</sub>| ∈ {1312, 1952, 2592}"]
        c1 --> c2 --> c3
    end

    subgraph OUTPUT["📤 Circuit Output"]
        proof["π<sub>STARK</sub><br/><small>STARK Proof</small>"]
        commit["Public Values<br/><small>ABI.encode(addr, pk<sub>pq</sub>)</small>"]
    end

    UTXO --> |"derives"| PRIVATE
    addr --> |"public"| PUBLIC
    pkq --> |"public"| PUBLIC
    pk_t --> |"private"| CIRCUIT
    sig_t --> |"private"| CIRCUIT
    pub_addr --> CIRCUIT
    pub_pkq --> CIRCUIT
    CIRCUIT --> proof
    CIRCUIT --> commit

    subgraph SIGN["✍️ PQ Signing"]
        pqsig["σ<sub>pq</sub> = ML-DSA.Sign(sk<sub>pq</sub>, addr ‖ pk<sub>pq</sub>)"]
    end

    skq --> SIGN
    commit --> SIGN

    subgraph TX["📦 Migration Transaction"]
        direction LR
        tx_proof["π<sub>STARK</sub>"]
        tx_pkq["pk<sub>pq</sub>"]
        tx_sig["σ<sub>pq</sub>"]
        tx_addr["Address<sub>t</sub>"]
    end

    proof --> TX
    pkq --> TX
    SIGN --> TX
    addr --> TX

    style PRIVATE fill:#fee,stroke:#c44,stroke-width:2px
    style PUBLIC fill:#efe,stroke:#4a4,stroke-width:2px
    style CIRCUIT fill:#e8f0fe,stroke:#4285f4,stroke-width:2px
    style OUTPUT fill:#fef9e7,stroke:#f0b429,stroke-width:2px
    style TX fill:#f3e8ff,stroke:#7c3aed,stroke-width:2px
    style PQ fill:#ecfdf5,stroke:#059669,stroke-width:2px
    style UTXO fill:#f9fafb,stroke:#6b7280,stroke-width:2px
    style SIGN fill:#fff7ed,stroke:#ea580c,stroke-width:2px
```

---

## 2. End-to-End Proof Pipeline (SP1 → STARK → SNARK → On-Chain)

```mermaid
flowchart LR
    subgraph S1["Stage 1: Key Generation"]
        ecdsa["secp256k1<br/>KeyGen"]
        mldsa["ML-DSA-65<br/>KeyGen"]
        sign["ECDSA.Sign<br/>(sk, migration_msg)"]
        ecdsa --> sign
    end

    subgraph S2["Stage 2: zkVM Execution"]
        stdin["SP1Stdin<br/><small>Q, addr, σ, pk<sub>pq</sub></small>"]
        risc["RISC-V<br/>Execution<br/><small>541K cycles</small>"]
        trace["Execution<br/>Trace"]
        stdin --> risc --> trace
    end

    subgraph S3["Stage 3: STARK Proof"]
        air["AIR<br/>Constraints"]
        fri["FRI<br/>Folding"]
        stark["π<sub>STARK</sub>"]
        trace --> air --> fri --> stark
    end

    subgraph S4["Stage 4: SNARK Wrapping"]
        recurse["SP1<br/>Recursion"]
        groth["Groth16<br/><small>~260 B</small>"]
        plonk["PLONK<br/><small>~800 B</small>"]
        stark --> recurse
        recurse --> groth
        recurse --> plonk
    end

    subgraph S5["Stage 5: On-Chain Verification"]
        gateway["SP1Verifier<br/>Gateway"]
        contract["PQBitcoin.sol<br/><small>verifyMigrationProof()</small>"]
        merkle["Merkle<br/>Registry<br/><small>depth 20</small>"]
        groth --> gateway
        plonk --> gateway
        gateway --> contract --> merkle
    end

    S1 --> S2

    style S1 fill:#ecfdf5,stroke:#059669
    style S2 fill:#eff6ff,stroke:#3b82f6
    style S3 fill:#fef3c7,stroke:#d97706
    style S4 fill:#fce7f3,stroke:#db2777
    style S5 fill:#f3e8ff,stroke:#7c3aed
```

---

## 3. On-Chain Verification — PQBitcoin.sol Architecture

```mermaid
flowchart TB
    subgraph CALLER["👤 Caller"]
        tx1["verifyMigrationProof<br/><small>(publicValues, proofBytes)</small>"]
        tx2["verifyDualSigMigration<br/><small>(publicValues, proofBytes, pqSig)</small>"]
    end

    subgraph VERIFY["🔐 SP1 Proof Verification"]
        sp1["ISP1Verifier.verifyProof<br/><small>(vkey, publicValues, proof)</small>"]
        decode["ABI.decode → (addr, pk<sub>pq</sub>)"]
        sp1 --> decode
    end

    subgraph VALIDATE["✅ Validation Layer"]
        pqval["_validatePQKeySize<br/><small>|pk| ∈ {1312, 1952, 2592}</small>"]
        replay["Replay Protection<br/><small>migrated[hash(addr)] == false</small>"]
        decode --> pqval --> replay
    end

    subgraph REGISTRY["📋 State Updates"]
        keyreg["pqKeyRegistry<br/><small>[hash(addr)] → hash(pk<sub>pq</sub>)</small>"]
        sigreg["pqSignatures<br/><small>[hash(addr)] → hash(σ<sub>pq</sub>)</small>"]
        merkle["Merkle Insert<br/><small>leaf = hash(addr ‖ hash(pk<sub>pq</sub>))</small>"]
        replay --> keyreg
        keyreg --> merkle
    end

    subgraph EVENTS["📡 Events"]
        evt1["AddressMigrated<br/><small>(addr, pk<sub>pq</sub>, leafIndex, root)</small>"]
        evt2["DualSigMigrated<br/><small>(addr, pk<sub>pq</sub>, sigHash, leafIndex, root)</small>"]
    end

    subgraph VIEWS["👁️ View Functions"]
        v1["getMerkleRoot()"]
        v2["getMigrationCount()"]
        v3["getPQKeyHash(addr)"]
        v4["isMigrated(addr)"]
    end

    subgraph ADMIN["🔑 Access Control (Ownable2Step)"]
        own["owner → pendingOwner → acceptOwnership()"]
        upd1["updateVerifier(addr)"]
        upd2["updateVKey(bytes32)"]
    end

    tx1 --> VERIFY
    tx2 --> VERIFY
    tx2 -.-> |"+ σ<sub>pq</sub> hash"| sigreg
    REGISTRY --> EVENTS
    merkle --> EVENTS

    style CALLER fill:#f9fafb,stroke:#6b7280,stroke-width:2px
    style VERIFY fill:#eff6ff,stroke:#3b82f6,stroke-width:2px
    style VALIDATE fill:#ecfdf5,stroke:#059669,stroke-width:2px
    style REGISTRY fill:#fef3c7,stroke:#d97706,stroke-width:2px
    style EVENTS fill:#f3e8ff,stroke:#7c3aed,stroke-width:2px
    style VIEWS fill:#f0fdf4,stroke:#22c55e
    style ADMIN fill:#fee2e2,stroke:#ef4444
```

---

## 4. Bitcoin Multi-Path Migration Strategy

```mermaid
flowchart TB
    user["👤 Bitcoin User<br/><small>Controls UTXO with (sk, Q)</small>"]

    subgraph TODAY["Available Today"]
        direction TB
        p1["<b>Path 1: OP_RETURN</b><br/><small>71-byte hash commitment<br/>PQMG ‖ SHA-256(pk<sub>pq</sub>) ‖ SHA-256(π)</small>"]
        p2["<b>Path 2: Taproot (BIP-341)</b><br/><small>PQ key hash in script tree<br/>Bech32m P2TR address</small>"]
        p3["<b>Path 3: Bitcoin L2</b><br/><small>PQBitcoin.sol on BOB/Citrea/Botanix<br/>Full smart contract registry</small>"]
    end

    subgraph FUTURE["Requires Soft Fork (BIP Draft)"]
        p4["<b>Path 4: Native Opcodes</b><br/><small>OP_CHECKQUANTUMSIG (0xbb)<br/>OP_CHECKSTARKPROOF (0xbc)<br/>Tapscript leaf version 0xc2</small>"]
    end

    user --> p1
    user --> p2
    user --> p3
    user --> p4

    subgraph INDEXER["🔍 Indexer Service"]
        idx["Axum REST API<br/><small>Scans PQMG OP_RETURN outputs<br/>GET /api/migrations<br/>GET /api/stats</small>"]
    end

    subgraph TAPROOT["🌳 Taproot Script Tree"]
        leaf0["Leaf 0: PQ Commitment<br/><small>OP_SHA256 &lt;pk_hash&gt;<br/>OP_EQUALVERIFY OP_TRUE</small>"]
        leaf1["Leaf 1: Timelock Fallback<br/><small>&lt;N&gt; OP_CSV<br/>OP_DROP OP_TRUE</small>"]
    end

    subgraph L2["⛓️ EVM Verification"]
        l2c["PQBitcoin.sol<br/><small>+ MerkleTree.sol<br/>+ SP1VerifierGateway</small>"]
    end

    p1 --> INDEXER
    p2 --> TAPROOT
    p3 --> L2

    style TODAY fill:#ecfdf5,stroke:#059669,stroke-width:2px
    style FUTURE fill:#fef3c7,stroke:#d97706,stroke-width:2px
    style INDEXER fill:#eff6ff,stroke:#3b82f6
    style TAPROOT fill:#f3e8ff,stroke:#7c3aed
    style L2 fill:#fce7f3,stroke:#db2777
```

---

## 5. Migration Scenarios — Exposed vs. Unexposed Keys

```mermaid
flowchart TB
    start["Bitcoin Address<br/>(P2PKH UTXO)"]
    
    decision{"Public Key<br/>Exposed?"}
    
    start --> decision

    subgraph EXPOSED["Scenario A: Key Exposed on-chain"]
        direction TB
        e1["Q visible → vulnerable to Shor's"]
        e2["Hybrid Dual-Signature Protocol"]
        e3["1. Sign pk<sub>pq</sub> with ECDSA (classical binding)"]
        e4["2. Sign migration msg with ML-DSA (PQ liveness)"]
        e5["3. Submit both to chain"]
        e6["4. Validators check ECDSA sig + ML-DSA hash"]
        e1 --> e2 --> e3 --> e4 --> e5 --> e6
    end

    subgraph UNEXPOSED["Scenario B: Key Hidden (hash-protected)"]
        direction TB
        u1["Q never revealed → hash barrier holds"]
        u2["Zero-Knowledge Migration via zkSTARK"]
        u3["1. Execute STARK circuit with Q as private input"]
        u4["2. Proof π attests: prover knows Q s.t. f(Q) = addr"]
        u5["3. Submit π + pk<sub>pq</sub> (Q never leaves device)"]
        u6["4. Miners verify π, create new UTXO locked to pk<sub>pq</sub>"]
        u1 --> u2 --> u3 --> u4 --> u5 --> u6
    end

    decision -->|"Yes<br/>(spent before)"| EXPOSED
    decision -->|"No<br/>(never spent)"| UNEXPOSED

    result_a["✅ New UTXO locked to pk<sub>pq</sub><br/><small>Classical key retired</small>"]
    result_b["✅ New UTXO locked to pk<sub>pq</sub><br/><small>Classical key never revealed</small>"]

    EXPOSED --> result_a
    UNEXPOSED --> result_b

    style EXPOSED fill:#fee2e2,stroke:#ef4444,stroke-width:2px
    style UNEXPOSED fill:#ecfdf5,stroke:#059669,stroke-width:2px
    style start fill:#f9fafb,stroke:#6b7280,stroke-width:2px
    style decision fill:#fef3c7,stroke:#d97706,stroke-width:2px
    style result_a fill:#f0fdf4,stroke:#22c55e
    style result_b fill:#f0fdf4,stroke:#22c55e
```

---

## 6. Ethereum Circuit — Keccak-256 Derivation Path

```mermaid
flowchart LR
    subgraph INPUTS["Inputs"]
        Qu["Q<sub>u</sub><br/><small>Uncompressed PubKey<br/>65 bytes (0x04 ‖ x ‖ y)</small>"]
        sig["σ<br/><small>ECDSA Signature<br/>64 bytes</small>"]
        eth_addr["a<sub>eth</sub><br/><small>ETH Address<br/>20 bytes</small>"]
        pkpq["pk<sub>pq</sub><br/><small>ML-DSA Key</small>"]
    end

    subgraph CIRCUIT["SP1 ETH Circuit"]
        strip["Strip 0x04 prefix<br/><small>Q<sub>raw</sub> = Q<sub>u</sub>[1:65]</small>"]
        keccak["Keccak-256<br/><small>(Q<sub>raw</sub>)</small>"]
        slice["Take bytes [12:32]<br/><small>→ a'<sub>eth</sub></small>"]
        assert1["<b>C1:</b> a'<sub>eth</sub> == a<sub>eth</sub>"]
        keccak_msg["Keccak-256<br/><small>(a<sub>eth</sub>)</small>"]
        ecdsa_v["<b>C2:</b> ECDSA.Verify<br/><small>(Q<sub>u</sub>, hash, σ)</small>"]
        pq_v["<b>C3:</b> |pk<sub>pq</sub>| ∈ {1312, 1952, 2592}"]

        strip --> keccak --> slice --> assert1
        eth_addr --> keccak_msg --> ecdsa_v
        assert1 --> pq_v
    end

    subgraph COMMIT["Output"]
        vals["Public Values<br/><small>ABI.encode(a<sub>eth</sub>, pk<sub>pq</sub>)</small>"]
    end

    Qu --> strip
    sig --> ecdsa_v
    pkpq --> pq_v
    pq_v --> vals

    style INPUTS fill:#fee2e2,stroke:#c44,stroke-width:2px
    style CIRCUIT fill:#e8f0fe,stroke:#4285f4,stroke-width:2px
    style COMMIT fill:#ecfdf5,stroke:#059669,stroke-width:2px
```

---

## Usage

1. Copy any diagram block (everything between ` ```mermaid ` and ` ``` `)
2. Paste into [mermaid.live](https://mermaid.live)
3. Export as **SVG** (vector, best for LaTeX) or **PNG**
4. Include in LaTeX:
   ```latex
   \includegraphics[width=0.85\textwidth]{imgs/diagram-name.pdf}
   ```
   (convert SVG → PDF via `inkscape` or `rsvg-convert` for best LaTeX quality)

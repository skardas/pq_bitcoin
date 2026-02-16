# PQBitcoin Contracts

On-chain verifier for SP1 zkSTARK proofs that bind Bitcoin/Ethereum addresses to post-quantum (ML-DSA) public keys.

## Contract

**`PQBitcoin.sol`** — Verifies SP1 proofs and maintains a migration registry.

| Function | Description |
|----------|-------------|
| `verifyMigrationProof()` | Verify proof + record migration (replay-protected) |
| `verifyMigrationProofView()` | Stateless verification (no state changes) |
| `isMigrated()` | Check if an address has already been migrated |

## Supported Networks

| Network | Type | Chain ID | Status |
|---------|------|----------|--------|
| Ethereum | L1 | 1 | Ready |
| Sepolia | L1 Testnet | 11155111 | Ready |
| **BOB** | Bitcoin L2 (OP Stack) | 60808 | Ready |
| **Citrea** | Bitcoin L2 (ZK Rollup) | 5115 | Ready |
| **Botanix** | Bitcoin L2 (EVM) | 3636 | Ready |

> **Note:** BOB, Citrea, and Botanix are EVM-compatible Bitcoin L2s. `PQBitcoin.sol` deploys with zero modifications.

## Quick Start

```bash
# 1. Install dependencies
forge install

# 2. Run tests (12 tests, 100% coverage)
make test

# 3. Copy and configure environment
cp .env.example .env
# Edit .env with your deployer key, SP1 verifier address, and program vkey

# 4. Deploy to a network
make deploy-sepolia         # Ethereum testnet
make deploy-bob-testnet     # BOB testnet
make deploy-citrea          # Citrea testnet
make deploy-botanix         # Botanix testnet

# 5. Deploy to mainnet
make deploy-ethereum        # Ethereum mainnet
make deploy-bob             # BOB mainnet

# 6. Dry-run all networks (no gas spent)
make dry-run-all
```

## Deployment

### Prerequisites

1. An SP1 verifier gateway contract must be deployed on the target chain
2. Generate the program verification key:
   ```bash
   cd ../script && cargo run --release --bin vkey
   ```
3. Set environment variables in `.env`

### Deploy Command

```bash
forge script script/Deploy.s.sol:DeployPQBitcoin \
  --rpc-url <RPC_URL> \
  --private-key <KEY> \
  --broadcast --verify
```

## Testing

```bash
make test       # Run all tests
make coverage   # Coverage report (100% lines/statements/branches/functions)
```

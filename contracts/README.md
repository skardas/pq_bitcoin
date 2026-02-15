# PQ Bitcoin — Smart Contracts

Solidity contracts for on-chain verification of PQ Bitcoin migration proofs.

## Contract: PQBitcoin.sol

Verifies SP1 proofs (Groth16 or PLONK) that a Bitcoin address has been migrated to a post-quantum public key.

### Functions

| Function | Description |
|----------|-------------|
| `verifyMigrationProof(publicValues, proof)` | Verify proof & record migration (replay-protected) |
| `verifyMigrationProofView(publicValues, proof)` | Verify proof without state changes |
| `isMigrated(btcAddress)` | Check if an address has been migrated |

### Events

```solidity
event AddressMigrated(bytes btcAddress, bytes pqPubkey);
```

## Testing

1. Generate fixtures (requires SP1):
   ```sh
   cd ../script
   cargo run --release --bin evm -- --system groth16
   ```

2. Run tests:
   ```sh
   forge test -vvv
   ```

## Deployment

```sh
forge create src/PQBitcoin.sol:PQBitcoin \
    --rpc-url $RPC_URL \
    --private-key $PRIVATE_KEY \
    --constructor-args $SP1_VERIFIER_ADDRESS $PROGRAM_VKEY
```

The `SP1_VERIFIER_ADDRESS` can be found in the [SP1 contracts documentation](https://docs.succinct.xyz/docs/onchain-verification/contract-addresses).

Retrieve your `PROGRAM_VKEY`:
```sh
cd ../script
cargo run --release --bin vkey
```

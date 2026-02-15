// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @notice The public values committed by the PQ Bitcoin zkSTARK circuit.
struct PublicValuesStruct {
    bytes btc_address;
    bytes pq_pubkey;
}

/// @title PQBitcoin
/// @notice Verifies SP1 proofs that bind a Bitcoin address to a post-quantum public key.
/// @dev The proof demonstrates that the prover knows the ECDSA private key corresponding to
///      btc_address and wishes to bind pq_pubkey as the quantum-resistant successor key.
contract PQBitcoin {
    /// @notice The address of the SP1 verifier contract (gateway or version-specific).
    address public verifier;

    /// @notice The verification key for the pq_bitcoin SP1 program.
    bytes32 public pqBitcoinProgramVKey;

    /// @notice Emitted when a BTC address is successfully migrated to a PQ public key.
    event AddressMigrated(bytes btcAddress, bytes pqPubkey);

    /// @notice Tracks which BTC addresses have already been migrated (prevents replay).
    mapping(bytes32 => bool) public migrated;

    constructor(address _verifier, bytes32 _pqBitcoinProgramVKey) {
        verifier = _verifier;
        pqBitcoinProgramVKey = _pqBitcoinProgramVKey;
    }

    /// @notice Verifies a migration proof and records the binding.
    /// @param _publicValues ABI-encoded PublicValuesStruct.
    /// @param _proofBytes   The SP1 proof bytes (Groth16 or PLONK).
    /// @return btcAddress The migrated Bitcoin address.
    /// @return pqPubkey   The bound post-quantum public key.
    function verifyMigrationProof(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) public returns (bytes memory btcAddress, bytes memory pqPubkey) {
        // Verify the SP1 proof on-chain.
        ISP1Verifier(verifier).verifyProof(pqBitcoinProgramVKey, _publicValues, _proofBytes);

        // Decode the public values.
        PublicValuesStruct memory publicValues = abi.decode(_publicValues, (PublicValuesStruct));
        btcAddress = publicValues.btc_address;
        pqPubkey = publicValues.pq_pubkey;

        // Prevent replay: each BTC address can only be migrated once.
        bytes32 addressHash = keccak256(btcAddress);
        require(!migrated[addressHash], "PQBitcoin: address already migrated");
        migrated[addressHash] = true;

        emit AddressMigrated(btcAddress, pqPubkey);
    }

    /// @notice View-only proof verification (no state changes, no replay protection).
    /// @param _publicValues ABI-encoded PublicValuesStruct.
    /// @param _proofBytes   The SP1 proof bytes.
    /// @return btcAddress The Bitcoin address from the proof.
    /// @return pqPubkey   The post-quantum public key from the proof.
    function verifyMigrationProofView(
        bytes calldata _publicValues,
        bytes calldata _proofBytes
    ) public view returns (bytes memory btcAddress, bytes memory pqPubkey) {
        ISP1Verifier(verifier).verifyProof(pqBitcoinProgramVKey, _publicValues, _proofBytes);

        PublicValuesStruct memory publicValues = abi.decode(_publicValues, (PublicValuesStruct));
        btcAddress = publicValues.btc_address;
        pqPubkey = publicValues.pq_pubkey;
    }

    /// @notice Check if a BTC address has already been migrated.
    /// @param _btcAddress The raw BTC address bytes.
    /// @return True if already migrated.
    function isMigrated(bytes calldata _btcAddress) external view returns (bool) {
        return migrated[keccak256(_btcAddress)];
    }
}

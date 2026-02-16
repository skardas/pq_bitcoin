// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {IncrementalMerkleTree} from "./MerkleTree.sol";

/// @notice The public values committed by the PQ Bitcoin zkSTARK circuit.
struct PublicValuesStruct {
    bytes btc_address;
    bytes pq_pubkey;
}

/// @title PQBitcoin
/// @notice Verifies SP1 proofs that bind a Bitcoin/Ethereum address to a post-quantum public key.
/// @dev The proof demonstrates that the prover knows the ECDSA private key corresponding to
///      btc_address and wishes to bind pq_pubkey as the quantum-resistant successor key.
///
///      Enhanced with:
///      - Ownable2Step access control for admin functions
///      - ML-DSA public key size validation (1312/1952/2592 bytes)
///      - Hybrid dual-signature migration (ECDSA proof + ML-DSA signature hash)
///      - Incremental Merkle tree for light-client-verifiable migration registry
contract PQBitcoin {
    using IncrementalMerkleTree for IncrementalMerkleTree.Tree;

    // ── Errors ──────────────────────────────────────────────────

    /// @notice Thrown when a non-owner calls an owner-only function.
    error Unauthorized();

    /// @notice Thrown when the PQ public key has an invalid size.
    /// @param actual The actual key length provided.
    error InvalidPQKeySize(uint256 actual);

    /// @notice Thrown when an address has already been migrated.
    error AlreadyMigrated();

    /// @notice Thrown when the pending owner is not the caller during acceptOwnership.
    error NotPendingOwner();

    // ── Events ──────────────────────────────────────────────────

    /// @notice Emitted when a BTC address is successfully migrated to a PQ public key.
    event AddressMigrated(
        bytes btcAddress,
        bytes pqPubkey,
        uint256 indexed leafIndex,
        bytes32 newMerkleRoot
    );

    /// @notice Emitted when a dual-sig migration (ECDSA proof + ML-DSA signature) is recorded.
    event DualSigMigrated(
        bytes btcAddress,
        bytes pqPubkey,
        bytes32 pqSignatureHash,
        uint256 indexed leafIndex,
        bytes32 newMerkleRoot
    );

    /// @notice Emitted when ownership transfer is initiated.
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when ownership is transferred.
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when the verifier address is updated.
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    /// @notice Emitted when the program verification key is updated.
    event VKeyUpdated(bytes32 indexed oldVKey, bytes32 indexed newVKey);

    // ── State ───────────────────────────────────────────────────

    /// @notice The contract owner.
    address public owner;

    /// @notice The pending owner (for two-step transfer).
    address public pendingOwner;

    /// @notice The address of the SP1 verifier contract (gateway or version-specific).
    address public verifier;

    /// @notice The verification key for the pq_bitcoin SP1 program.
    bytes32 public pqBitcoinProgramVKey;

    /// @notice Tracks which BTC addresses have already been migrated (prevents replay).
    mapping(bytes32 => bool) public migrated;

    /// @notice Maps migrated address hash → PQ public key hash (for lookups).
    mapping(bytes32 => bytes32) public pqKeyRegistry;

    /// @notice Maps migrated address hash → ML-DSA signature hash (dual-sig migrations only).
    mapping(bytes32 => bytes32) public pqSignatures;

    /// @notice The incremental Merkle tree tracking all migrations.
    IncrementalMerkleTree.Tree private _merkleTree;

    // ── Valid ML-DSA public key sizes ────────────────────────────

    uint256 private constant ML_DSA_44_PK_SIZE = 1312;
    uint256 private constant ML_DSA_65_PK_SIZE = 1952;
    uint256 private constant ML_DSA_87_PK_SIZE = 2592;

    // ── Modifiers ───────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ── Constructor ─────────────────────────────────────────────

    constructor(address _verifier, bytes32 _pqBitcoinProgramVKey) {
        owner = msg.sender;
        verifier = _verifier;
        pqBitcoinProgramVKey = _pqBitcoinProgramVKey;
        _merkleTree.init();

        emit OwnershipTransferred(address(0), msg.sender);
    }

    // ── Admin Functions ─────────────────────────────────────────

    /// @notice Update the SP1 verifier address. Only callable by the owner.
    /// @param _newVerifier The new verifier contract address.
    function updateVerifier(address _newVerifier) external onlyOwner {
        address old = verifier;
        verifier = _newVerifier;
        emit VerifierUpdated(old, _newVerifier);
    }

    /// @notice Update the SP1 program verification key. Only callable by the owner.
    /// @param _newVKey The new verification key.
    function updateVKey(bytes32 _newVKey) external onlyOwner {
        bytes32 old = pqBitcoinProgramVKey;
        pqBitcoinProgramVKey = _newVKey;
        emit VKeyUpdated(old, _newVKey);
    }

    /// @notice Initiate ownership transfer. The new owner must call acceptOwnership().
    /// @param _newOwner The address of the new owner.
    function transferOwnership(address _newOwner) external onlyOwner {
        pendingOwner = _newOwner;
        emit OwnershipTransferStarted(owner, _newOwner);
    }

    /// @notice Accept ownership transfer. Must be called by the pending owner.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        address old = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(old, msg.sender);
    }

    // ── Migration Functions ─────────────────────────────────────

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

        // Validate PQ key size.
        _validatePQKeySize(pqPubkey.length);

        // Prevent replay: each BTC address can only be migrated once.
        bytes32 addressHash = keccak256(btcAddress);
        if (migrated[addressHash]) revert AlreadyMigrated();
        migrated[addressHash] = true;

        // Store PQ key hash for lookups.
        bytes32 pqKeyHash = keccak256(pqPubkey);
        pqKeyRegistry[addressHash] = pqKeyHash;

        // Insert into Merkle tree.
        bytes32 leaf = keccak256(abi.encodePacked(btcAddress, pqKeyHash));
        uint256 leafIndex = _merkleTree.nextIndex;
        bytes32 newRoot = _merkleTree.insert(leaf);

        emit AddressMigrated(btcAddress, pqPubkey, leafIndex, newRoot);
    }

    /// @notice Verifies a dual-signature migration (ECDSA proof + ML-DSA signature).
    /// @dev The STARK proof verifies ECDSA ownership. The ML-DSA signature is hashed
    ///      and stored on-chain for independent off-chain verification.
    /// @param _publicValues ABI-encoded PublicValuesStruct.
    /// @param _proofBytes   The SP1 proof bytes.
    /// @param _pqSignature  The ML-DSA signature over the migration message.
    /// @return btcAddress The migrated Bitcoin address.
    /// @return pqPubkey   The bound post-quantum public key.
    function verifyDualSigMigration(
        bytes calldata _publicValues,
        bytes calldata _proofBytes,
        bytes calldata _pqSignature
    ) public returns (bytes memory btcAddress, bytes memory pqPubkey) {
        // Verify the SP1 proof on-chain.
        ISP1Verifier(verifier).verifyProof(pqBitcoinProgramVKey, _publicValues, _proofBytes);

        // Decode the public values.
        PublicValuesStruct memory publicValues = abi.decode(_publicValues, (PublicValuesStruct));
        btcAddress = publicValues.btc_address;
        pqPubkey = publicValues.pq_pubkey;

        // Validate PQ key size.
        _validatePQKeySize(pqPubkey.length);

        // Require non-empty PQ signature.
        require(_pqSignature.length > 0, "PQBitcoin: empty PQ signature");

        // Prevent replay.
        bytes32 addressHash = keccak256(btcAddress);
        if (migrated[addressHash]) revert AlreadyMigrated();
        migrated[addressHash] = true;

        // Store PQ key hash and signature hash.
        bytes32 pqKeyHash = keccak256(pqPubkey);
        bytes32 sigHash = keccak256(_pqSignature);
        pqKeyRegistry[addressHash] = pqKeyHash;
        pqSignatures[addressHash] = sigHash;

        // Insert into Merkle tree.
        bytes32 leaf = keccak256(abi.encodePacked(btcAddress, pqKeyHash));
        uint256 leafIndex = _merkleTree.nextIndex;
        bytes32 newRoot = _merkleTree.insert(leaf);

        emit DualSigMigrated(btcAddress, pqPubkey, sigHash, leafIndex, newRoot);
    }

    // ── View Functions ──────────────────────────────────────────

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

        // Validate PQ key size even in view mode.
        _validatePQKeySize(pqPubkey.length);
    }

    /// @notice Check if a BTC address has already been migrated.
    /// @param _btcAddress The raw BTC address bytes.
    /// @return True if already migrated.
    function isMigrated(bytes calldata _btcAddress) external view returns (bool) {
        return migrated[keccak256(_btcAddress)];
    }

    /// @notice Get the PQ key hash for a migrated address.
    /// @param _btcAddress The raw BTC address bytes.
    /// @return The keccak256 hash of the PQ public key, or bytes32(0) if not migrated.
    function getPQKeyHash(bytes calldata _btcAddress) external view returns (bytes32) {
        return pqKeyRegistry[keccak256(_btcAddress)];
    }

    /// @notice Get the PQ signature hash for a dual-sig migration.
    /// @param _btcAddress The raw BTC address bytes.
    /// @return The keccak256 hash of the ML-DSA signature, or bytes32(0) if not a dual-sig migration.
    function getPQSignatureHash(bytes calldata _btcAddress) external view returns (bytes32) {
        return pqSignatures[keccak256(_btcAddress)];
    }

    /// @notice Get the current Merkle root of the migration registry.
    /// @return The current Merkle root.
    function getMerkleRoot() external view returns (bytes32) {
        return _merkleTree.root;
    }

    /// @notice Get the total number of migrations recorded.
    /// @return The number of migrations.
    function getMigrationCount() external view returns (uint256) {
        return _merkleTree.nextIndex;
    }

    // ── Internal ────────────────────────────────────────────────

    /// @dev Validates that the PQ public key size matches ML-DSA-44, ML-DSA-65, or ML-DSA-87.
    function _validatePQKeySize(uint256 size) internal pure {
        if (size != ML_DSA_44_PK_SIZE && size != ML_DSA_65_PK_SIZE && size != ML_DSA_87_PK_SIZE) {
            revert InvalidPQKeySize(size);
        }
    }
}

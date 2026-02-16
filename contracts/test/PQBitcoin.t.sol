// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {PQBitcoin, PublicValuesStruct} from "../src/PQBitcoin.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

// ============================================================
//  Groth16 Tests (original + enhanced)
// ============================================================
contract PQBitcoinGroth16Test is Test {
    address verifier;
    PQBitcoin public pqBitcoin;
    bytes32 constant MOCK_VKEY = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

    // Sample BTC address (25 bytes, P2PKH)
    bytes constant SAMPLE_BTC_ADDRESS = hex"00abcdef1234567890abcdef1234567890abcdef1234aabbccdd";
    // Sample ML-DSA-65 PQ public key (1952 bytes, placeholder content)
    bytes samplePqPubkey;

    function setUp() public {
        verifier = address(new SP1VerifierGateway(address(1)));
        pqBitcoin = new PQBitcoin(verifier, MOCK_VKEY);

        // Create a 1952-byte mock PQ public key (ML-DSA-65 size)
        samplePqPubkey = new bytes(1952);
        for (uint i = 0; i < 1952; i++) {
            samplePqPubkey[i] = bytes1(uint8(i % 256));
        }
    }

    /// @dev Helper to ABI-encode PublicValuesStruct
    function _encodePublicValues(bytes memory btcAddr, bytes memory pqKey) internal pure returns (bytes memory) {
        return abi.encode(PublicValuesStruct(btcAddr, pqKey));
    }

    /// @dev Helper to mock the SP1 verifier
    function _mockVerifier() internal {
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );
    }

    function test_ValidMigrationProof() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"aabb";

        _mockVerifier();

        (bytes memory btcAddress, bytes memory pqPubkey) =
            pqBitcoin.verifyMigrationProof(publicValues, fakeProof);

        assertEq(keccak256(btcAddress), keccak256(SAMPLE_BTC_ADDRESS));
        assertEq(keccak256(pqPubkey), keccak256(samplePqPubkey));
    }

    function test_ViewOnlyVerification() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"aabb";

        _mockVerifier();

        (bytes memory btcAddress, bytes memory pqPubkey) =
            pqBitcoin.verifyMigrationProofView(publicValues, fakeProof);

        assertEq(keccak256(btcAddress), keccak256(SAMPLE_BTC_ADDRESS));
        assertEq(keccak256(pqPubkey), keccak256(samplePqPubkey));
    }

    function test_ReplayProtection() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"aabb";

        _mockVerifier();

        // First migration succeeds
        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);

        // Second migration with same address should revert
        vm.expectRevert(PQBitcoin.AlreadyMigrated.selector);
        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);
    }

    function test_IsMigrated() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"aabb";

        _mockVerifier();

        // Not migrated yet
        assertFalse(pqBitcoin.isMigrated(SAMPLE_BTC_ADDRESS));

        // Migrate
        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);

        // Now migrated
        assertTrue(pqBitcoin.isMigrated(SAMPLE_BTC_ADDRESS));
    }

    function test_EmitsAddressMigratedEvent() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"aabb";

        _mockVerifier();

        // Check that AddressMigrated event is emitted (with leafIndex and merkleRoot)
        vm.expectEmit(false, false, false, false);
        emit PQBitcoin.AddressMigrated(SAMPLE_BTC_ADDRESS, samplePqPubkey, 0, bytes32(0));

        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);
    }

    function testRevert_InvalidProof() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);

        // Do NOT mock the verifier — it will revert on invalid proof
        vm.expectRevert();

        bytes memory fakeProof = hex"deadbeef";
        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);
    }

    function test_DifferentAddressesCanMigrate() public {
        bytes memory fakeProof = hex"aabb";

        _mockVerifier();

        // First address
        bytes memory addr1 = hex"0011223344556677889900aabbccddeeff00112233aabbccdd";
        bytes memory publicValues1 = _encodePublicValues(addr1, samplePqPubkey);
        pqBitcoin.verifyMigrationProof(publicValues1, fakeProof);
        assertTrue(pqBitcoin.isMigrated(addr1));

        // Second address — different, should succeed
        bytes memory addr2 = hex"ff11223344556677889900aabbccddeeff00112233aabbccdd";
        bytes memory publicValues2 = _encodePublicValues(addr2, samplePqPubkey);
        pqBitcoin.verifyMigrationProof(publicValues2, fakeProof);
        assertTrue(pqBitcoin.isMigrated(addr2));
    }

    function test_ConstructorSetsStateCorrectly() public view {
        assertEq(pqBitcoin.verifier(), verifier);
        assertEq(pqBitcoin.pqBitcoinProgramVKey(), MOCK_VKEY);
        assertEq(pqBitcoin.owner(), address(this));
    }
}

// ============================================================
//  PLONK Tests
// ============================================================
contract PQBitcoinPlonkTest is Test {
    address verifier;
    PQBitcoin public pqBitcoin;
    bytes32 constant MOCK_VKEY = 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;

    bytes constant SAMPLE_BTC_ADDRESS = hex"00aabbccddeeff11223344556677889900aabbccdd00112233";
    bytes samplePqPubkey;

    function setUp() public {
        verifier = address(new SP1VerifierGateway(address(1)));
        pqBitcoin = new PQBitcoin(verifier, MOCK_VKEY);

        samplePqPubkey = new bytes(1952);
        for (uint i = 0; i < 1952; i++) {
            samplePqPubkey[i] = bytes1(uint8((i * 7) % 256));
        }
    }

    function _encodePublicValues(bytes memory btcAddr, bytes memory pqKey) internal pure returns (bytes memory) {
        return abi.encode(PublicValuesStruct(btcAddr, pqKey));
    }

    function _mockVerifier() internal {
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );
    }

    function test_ValidMigrationProof() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"1122";

        _mockVerifier();

        (bytes memory btcAddress, bytes memory pqPubkey) =
            pqBitcoin.verifyMigrationProof(publicValues, fakeProof);

        assertEq(keccak256(btcAddress), keccak256(SAMPLE_BTC_ADDRESS));
        assertEq(keccak256(pqPubkey), keccak256(samplePqPubkey));
    }

    function test_ViewOnlyVerification() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"1122";

        _mockVerifier();

        (bytes memory btcAddress, bytes memory pqPubkey) =
            pqBitcoin.verifyMigrationProofView(publicValues, fakeProof);

        assertEq(keccak256(btcAddress), keccak256(SAMPLE_BTC_ADDRESS));
        assertEq(keccak256(pqPubkey), keccak256(samplePqPubkey));
    }

    function test_ReplayProtection() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"1122";

        _mockVerifier();

        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);

        vm.expectRevert(PQBitcoin.AlreadyMigrated.selector);
        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);
    }

    function testRevert_InvalidProof() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);

        vm.expectRevert();
        bytes memory fakeProof = hex"deadbeef";
        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);
    }
}

// ============================================================
//  P0: Access Control Tests
// ============================================================
contract PQBitcoinAccessControlTest is Test {
    address verifier;
    PQBitcoin public pqBitcoin;
    bytes32 constant MOCK_VKEY = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {
        verifier = address(new SP1VerifierGateway(address(1)));
        pqBitcoin = new PQBitcoin(verifier, MOCK_VKEY);
    }

    function test_OwnerSetOnDeploy() public view {
        assertEq(pqBitcoin.owner(), address(this));
    }

    function test_UpdateVerifierAsOwner() public {
        address newVerifier = address(0x1234);
        pqBitcoin.updateVerifier(newVerifier);
        assertEq(pqBitcoin.verifier(), newVerifier);
    }

    function testRevert_UpdateVerifierAsNonOwner() public {
        vm.prank(alice);
        vm.expectRevert(PQBitcoin.Unauthorized.selector);
        pqBitcoin.updateVerifier(address(0x1234));
    }

    function test_UpdateVKeyAsOwner() public {
        bytes32 newVKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        pqBitcoin.updateVKey(newVKey);
        assertEq(pqBitcoin.pqBitcoinProgramVKey(), newVKey);
    }

    function testRevert_UpdateVKeyAsNonOwner() public {
        vm.prank(alice);
        vm.expectRevert(PQBitcoin.Unauthorized.selector);
        pqBitcoin.updateVKey(bytes32(0));
    }

    function test_TwoStepOwnershipTransfer() public {
        // Step 1: Current owner initiates transfer
        pqBitcoin.transferOwnership(alice);
        assertEq(pqBitcoin.pendingOwner(), alice);
        assertEq(pqBitcoin.owner(), address(this)); // still this

        // Step 2: Alice accepts
        vm.prank(alice);
        pqBitcoin.acceptOwnership();
        assertEq(pqBitcoin.owner(), alice);
        assertEq(pqBitcoin.pendingOwner(), address(0));
    }

    function testRevert_AcceptOwnershipByWrongAddress() public {
        pqBitcoin.transferOwnership(alice);

        vm.prank(bob);
        vm.expectRevert(PQBitcoin.NotPendingOwner.selector);
        pqBitcoin.acceptOwnership();
    }

    function testRevert_TransferOwnershipAsNonOwner() public {
        vm.prank(alice);
        vm.expectRevert(PQBitcoin.Unauthorized.selector);
        pqBitcoin.transferOwnership(bob);
    }

    function test_EmitsOwnershipEvents() public {
        vm.expectEmit(true, true, false, false);
        emit PQBitcoin.OwnershipTransferStarted(address(this), alice);
        pqBitcoin.transferOwnership(alice);

        vm.prank(alice);
        vm.expectEmit(true, true, false, false);
        emit PQBitcoin.OwnershipTransferred(address(this), alice);
        pqBitcoin.acceptOwnership();
    }

    function test_EmitsVerifierUpdatedEvent() public {
        address newVerifier = address(0x5678);
        vm.expectEmit(true, true, false, false);
        emit PQBitcoin.VerifierUpdated(verifier, newVerifier);
        pqBitcoin.updateVerifier(newVerifier);
    }

    function test_EmitsVKeyUpdatedEvent() public {
        bytes32 newVKey = 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd;
        vm.expectEmit(true, true, false, false);
        emit PQBitcoin.VKeyUpdated(MOCK_VKEY, newVKey);
        pqBitcoin.updateVKey(newVKey);
    }
}

// ============================================================
//  P0: PQ Key Size Validation Tests
// ============================================================
contract PQBitcoinKeyValidationTest is Test {
    address verifier;
    PQBitcoin public pqBitcoin;
    bytes32 constant MOCK_VKEY = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

    bytes constant SAMPLE_BTC_ADDRESS = hex"00abcdef1234567890abcdef1234567890abcdef1234aabbccdd";

    function setUp() public {
        verifier = address(new SP1VerifierGateway(address(1)));
        pqBitcoin = new PQBitcoin(verifier, MOCK_VKEY);
    }

    function _mockVerifier() internal {
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );
    }

    function test_AcceptsMLDSA44Key() public {
        bytes memory pqKey44 = new bytes(1312);
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, pqKey44));
        _mockVerifier();

        pqBitcoin.verifyMigrationProof(publicValues, hex"aabb");
        assertTrue(pqBitcoin.isMigrated(SAMPLE_BTC_ADDRESS));
    }

    function test_AcceptsMLDSA65Key() public {
        bytes memory pqKey65 = new bytes(1952);
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, pqKey65));
        _mockVerifier();

        pqBitcoin.verifyMigrationProof(publicValues, hex"aabb");
        assertTrue(pqBitcoin.isMigrated(SAMPLE_BTC_ADDRESS));
    }

    function test_AcceptsMLDSA87Key() public {
        bytes memory pqKey87 = new bytes(2592);
        bytes memory addr = hex"ff11223344556677889900aabbccddeeff00112233aabbccdd";
        bytes memory publicValues = abi.encode(PublicValuesStruct(addr, pqKey87));
        _mockVerifier();

        pqBitcoin.verifyMigrationProof(publicValues, hex"aabb");
        assertTrue(pqBitcoin.isMigrated(addr));
    }

    function testRevert_InvalidKeySize_TooSmall() public {
        bytes memory badKey = new bytes(100);
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, badKey));
        _mockVerifier();

        vm.expectRevert(abi.encodeWithSelector(PQBitcoin.InvalidPQKeySize.selector, 100));
        pqBitcoin.verifyMigrationProof(publicValues, hex"aabb");
    }

    function testRevert_InvalidKeySize_BetweenLevels() public {
        bytes memory badKey = new bytes(1500); // between 1312 and 1952
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, badKey));
        _mockVerifier();

        vm.expectRevert(abi.encodeWithSelector(PQBitcoin.InvalidPQKeySize.selector, 1500));
        pqBitcoin.verifyMigrationProof(publicValues, hex"aabb");
    }

    function testRevert_InvalidKeySize_Empty() public {
        bytes memory badKey = new bytes(0);
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, badKey));
        _mockVerifier();

        vm.expectRevert(abi.encodeWithSelector(PQBitcoin.InvalidPQKeySize.selector, 0));
        pqBitcoin.verifyMigrationProof(publicValues, hex"aabb");
    }

    function testRevert_InvalidKeySize_OffByOne() public {
        bytes memory badKey = new bytes(1953); // ML-DSA-65 + 1
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, badKey));
        _mockVerifier();

        vm.expectRevert(abi.encodeWithSelector(PQBitcoin.InvalidPQKeySize.selector, 1953));
        pqBitcoin.verifyMigrationProof(publicValues, hex"aabb");
    }

    function testRevert_InvalidKeySize_InViewMode() public {
        bytes memory badKey = new bytes(500);
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, badKey));
        _mockVerifier();

        vm.expectRevert(abi.encodeWithSelector(PQBitcoin.InvalidPQKeySize.selector, 500));
        pqBitcoin.verifyMigrationProofView(publicValues, hex"aabb");
    }
}

// ============================================================
//  P2: Dual-Signature Migration Tests
// ============================================================
contract PQBitcoinDualSigTest is Test {
    address verifier;
    PQBitcoin public pqBitcoin;
    bytes32 constant MOCK_VKEY = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

    bytes constant SAMPLE_BTC_ADDRESS = hex"00abcdef1234567890abcdef1234567890abcdef1234aabbccdd";
    bytes samplePqPubkey;
    bytes samplePqSignature;

    function setUp() public {
        verifier = address(new SP1VerifierGateway(address(1)));
        pqBitcoin = new PQBitcoin(verifier, MOCK_VKEY);

        samplePqPubkey = new bytes(1952);
        for (uint i = 0; i < 1952; i++) {
            samplePqPubkey[i] = bytes1(uint8(i % 256));
        }

        // Mock ML-DSA-65 signature (3309 bytes)
        samplePqSignature = new bytes(3309);
        for (uint i = 0; i < 3309; i++) {
            samplePqSignature[i] = bytes1(uint8((i * 13) % 256));
        }
    }

    function _mockVerifier() internal {
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );
    }

    function test_DualSigMigration() public {
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, samplePqPubkey));
        _mockVerifier();

        pqBitcoin.verifyDualSigMigration(publicValues, hex"aabb", samplePqSignature);

        // Check migration recorded
        assertTrue(pqBitcoin.isMigrated(SAMPLE_BTC_ADDRESS));

        // Check PQ key hash stored
        bytes32 expectedKeyHash = keccak256(samplePqPubkey);
        assertEq(pqBitcoin.getPQKeyHash(SAMPLE_BTC_ADDRESS), expectedKeyHash);

        // Check PQ signature hash stored
        bytes32 expectedSigHash = keccak256(samplePqSignature);
        assertEq(pqBitcoin.getPQSignatureHash(SAMPLE_BTC_ADDRESS), expectedSigHash);
    }

    function test_DualSigEmitsEvent() public {
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, samplePqPubkey));
        _mockVerifier();

        vm.expectEmit(false, false, false, false);
        emit PQBitcoin.DualSigMigrated(SAMPLE_BTC_ADDRESS, samplePqPubkey, bytes32(0), 0, bytes32(0));

        pqBitcoin.verifyDualSigMigration(publicValues, hex"aabb", samplePqSignature);
    }

    function test_DualSigReplayProtection() public {
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, samplePqPubkey));
        _mockVerifier();

        pqBitcoin.verifyDualSigMigration(publicValues, hex"aabb", samplePqSignature);

        vm.expectRevert(PQBitcoin.AlreadyMigrated.selector);
        pqBitcoin.verifyDualSigMigration(publicValues, hex"aabb", samplePqSignature);
    }

    function testRevert_DualSigEmptySignature() public {
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, samplePqPubkey));
        _mockVerifier();

        vm.expectRevert("PQBitcoin: empty PQ signature");
        pqBitcoin.verifyDualSigMigration(publicValues, hex"aabb", hex"");
    }

    function testRevert_DualSigInvalidKeySize() public {
        bytes memory badKey = new bytes(1000);
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, badKey));
        _mockVerifier();

        vm.expectRevert(abi.encodeWithSelector(PQBitcoin.InvalidPQKeySize.selector, 1000));
        pqBitcoin.verifyDualSigMigration(publicValues, hex"aabb", samplePqSignature);
    }

    function test_RegularMigrationHasNoSignatureHash() public {
        bytes memory publicValues = abi.encode(PublicValuesStruct(SAMPLE_BTC_ADDRESS, samplePqPubkey));
        _mockVerifier();

        // Regular migration (not dual-sig)
        pqBitcoin.verifyMigrationProof(publicValues, hex"aabb");

        // Signature hash should be zero
        assertEq(pqBitcoin.getPQSignatureHash(SAMPLE_BTC_ADDRESS), bytes32(0));

        // But PQ key hash should be set
        assertEq(pqBitcoin.getPQKeyHash(SAMPLE_BTC_ADDRESS), keccak256(samplePqPubkey));
    }
}

// ============================================================
//  P2: Merkle Tree Registry Tests
// ============================================================
contract PQBitcoinMerkleTreeTest is Test {
    address verifier;
    PQBitcoin public pqBitcoin;
    bytes32 constant MOCK_VKEY = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

    bytes samplePqPubkey;

    function setUp() public {
        verifier = address(new SP1VerifierGateway(address(1)));
        pqBitcoin = new PQBitcoin(verifier, MOCK_VKEY);

        samplePqPubkey = new bytes(1952);
        for (uint i = 0; i < 1952; i++) {
            samplePqPubkey[i] = bytes1(uint8(i % 256));
        }
    }

    function _mockVerifier() internal {
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );
    }

    function test_InitialMerkleState() public view {
        assertEq(pqBitcoin.getMigrationCount(), 0);
        // Root should be non-zero (initialized with zero hashes)
        assertTrue(pqBitcoin.getMerkleRoot() != bytes32(0));
    }

    function test_MerkleRootChangesAfterMigration() public {
        bytes32 rootBefore = pqBitcoin.getMerkleRoot();

        bytes memory addr = hex"00abcdef1234567890abcdef1234567890abcdef1234aabbccdd";
        bytes memory publicValues = abi.encode(PublicValuesStruct(addr, samplePqPubkey));
        _mockVerifier();
        pqBitcoin.verifyMigrationProof(publicValues, hex"aabb");

        bytes32 rootAfter = pqBitcoin.getMerkleRoot();
        assertTrue(rootBefore != rootAfter);
        assertEq(pqBitcoin.getMigrationCount(), 1);
    }

    function test_MultipleMigrationsUpdateTree() public {
        _mockVerifier();

        bytes32 prevRoot = pqBitcoin.getMerkleRoot();

        for (uint256 i = 0; i < 5; i++) {
            bytes memory addr = abi.encodePacked(bytes1(uint8(i)), hex"abcdef1234567890abcdef1234567890abcdef1234aabbcc");
            bytes memory publicValues = abi.encode(PublicValuesStruct(addr, samplePqPubkey));
            pqBitcoin.verifyMigrationProof(publicValues, hex"aabb");

            bytes32 currentRoot = pqBitcoin.getMerkleRoot();
            assertTrue(currentRoot != prevRoot);
            prevRoot = currentRoot;
        }

        assertEq(pqBitcoin.getMigrationCount(), 5);
    }

    function test_DualSigAlsoUpdatesTree() public {
        bytes memory addr = hex"00abcdef1234567890abcdef1234567890abcdef1234aabbccdd";
        bytes memory publicValues = abi.encode(PublicValuesStruct(addr, samplePqPubkey));
        bytes memory sig = hex"aabbccdd";

        _mockVerifier();

        bytes32 rootBefore = pqBitcoin.getMerkleRoot();
        pqBitcoin.verifyDualSigMigration(publicValues, hex"aabb", sig);
        bytes32 rootAfter = pqBitcoin.getMerkleRoot();

        assertTrue(rootBefore != rootAfter);
        assertEq(pqBitcoin.getMigrationCount(), 1);
    }

    function test_LeafIndexInEvent() public {
        _mockVerifier();

        // First migration should have leafIndex 0
        bytes memory addr1 = hex"0011223344556677889900aabbccddeeff00112233aabbccdd";
        bytes memory pv1 = abi.encode(PublicValuesStruct(addr1, samplePqPubkey));

        vm.expectEmit(true, false, false, false);
        emit PQBitcoin.AddressMigrated(addr1, samplePqPubkey, 0, bytes32(0));
        pqBitcoin.verifyMigrationProof(pv1, hex"aabb");

        // Second migration should have leafIndex 1
        bytes memory addr2 = hex"ff11223344556677889900aabbccddeeff00112233aabbccdd";
        bytes memory pv2 = abi.encode(PublicValuesStruct(addr2, samplePqPubkey));

        vm.expectEmit(true, false, false, false);
        emit PQBitcoin.AddressMigrated(addr2, samplePqPubkey, 1, bytes32(0));
        pqBitcoin.verifyMigrationProof(pv2, hex"aabb");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {PQBitcoin, PublicValuesStruct} from "../src/PQBitcoin.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

// ============================================================
//  Groth16 Tests
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

    function test_ValidMigrationProof() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"aabb";

        // Mock the SP1 verifier to accept any proof
        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );

        (bytes memory btcAddress, bytes memory pqPubkey) =
            pqBitcoin.verifyMigrationProof(publicValues, fakeProof);

        assertEq(keccak256(btcAddress), keccak256(SAMPLE_BTC_ADDRESS));
        assertEq(keccak256(pqPubkey), keccak256(samplePqPubkey));
    }

    function test_ViewOnlyVerification() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"aabb";

        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );

        (bytes memory btcAddress, bytes memory pqPubkey) =
            pqBitcoin.verifyMigrationProofView(publicValues, fakeProof);

        assertEq(keccak256(btcAddress), keccak256(SAMPLE_BTC_ADDRESS));
        assertEq(keccak256(pqPubkey), keccak256(samplePqPubkey));
    }

    function test_ReplayProtection() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"aabb";

        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );

        // First migration succeeds
        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);

        // Second migration with same address should revert
        vm.expectRevert("PQBitcoin: address already migrated");
        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);
    }

    function test_IsMigrated() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"aabb";

        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );

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

        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );

        vm.expectEmit(false, false, false, true);
        emit PQBitcoin.AddressMigrated(SAMPLE_BTC_ADDRESS, samplePqPubkey);

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

        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );

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

    function test_ValidMigrationProof() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"1122";

        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );

        (bytes memory btcAddress, bytes memory pqPubkey) =
            pqBitcoin.verifyMigrationProof(publicValues, fakeProof);

        assertEq(keccak256(btcAddress), keccak256(SAMPLE_BTC_ADDRESS));
        assertEq(keccak256(pqPubkey), keccak256(samplePqPubkey));
    }

    function test_ViewOnlyVerification() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"1122";

        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );

        (bytes memory btcAddress, bytes memory pqPubkey) =
            pqBitcoin.verifyMigrationProofView(publicValues, fakeProof);

        assertEq(keccak256(btcAddress), keccak256(SAMPLE_BTC_ADDRESS));
        assertEq(keccak256(pqPubkey), keccak256(samplePqPubkey));
    }

    function test_ReplayProtection() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);
        bytes memory fakeProof = hex"1122";

        vm.mockCall(
            verifier,
            abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector),
            abi.encode()
        );

        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);

        vm.expectRevert("PQBitcoin: address already migrated");
        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);
    }

    function testRevert_InvalidProof() public {
        bytes memory publicValues = _encodePublicValues(SAMPLE_BTC_ADDRESS, samplePqPubkey);

        vm.expectRevert();
        bytes memory fakeProof = hex"deadbeef";
        pqBitcoin.verifyMigrationProof(publicValues, fakeProof);
    }
}

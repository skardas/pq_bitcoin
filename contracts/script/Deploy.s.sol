// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {PQBitcoin} from "../src/PQBitcoin.sol";

/// @title Deploy PQBitcoin
/// @notice Foundry deployment script for PQBitcoin contract.
///         Works on Ethereum mainnet/testnet, and Bitcoin L2s (BOB, Citrea, etc.).
///
/// Usage:
///   forge script script/Deploy.s.sol:DeployPQBitcoin \
///     --rpc-url $RPC_URL \
///     --private-key $DEPLOYER_PRIVATE_KEY \
///     --broadcast --verify
///
/// Environment variables:
///   SP1_VERIFIER    - Address of the SP1 verifier gateway contract
///   PROGRAM_VKEY    - SP1 program verification key (bytes32)
contract DeployPQBitcoin is Script {
    function run() external {
        // ── Load configuration ─────────────────────────────────
        address verifier = vm.envAddress("SP1_VERIFIER");
        bytes32 programVKey = vm.envBytes32("PROGRAM_VKEY");

        console.log("=== PQBitcoin Deployment ===");
        console.log("Chain ID:     ", block.chainid);
        console.log("Deployer:     ", msg.sender);
        console.log("SP1 Verifier: ", verifier);
        console.log("Program VKey: ");
        console.logBytes32(programVKey);

        // ── Deploy ─────────────────────────────────────────────
        vm.startBroadcast();
        PQBitcoin pqBitcoin = new PQBitcoin(verifier, programVKey);
        vm.stopBroadcast();

        console.log("PQBitcoin deployed at:", address(pqBitcoin));
        console.log("");
        console.log("=== Verification ===");
        console.log("Verifier set: ", pqBitcoin.verifier());
        console.logBytes32(pqBitcoin.pqBitcoinProgramVKey());
    }
}

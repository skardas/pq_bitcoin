# ── PQBitcoin Contract Deployment ────────────────────────────────
#
# Load environment: cp .env.example .env && fill in values
# All commands assume you are in the contracts/ directory.

-include .env

# ── Deploy to specific networks ─────────────────────────────────

deploy-sepolia:
	forge script script/Deploy.s.sol:DeployPQBitcoin \
		--rpc-url $(SEPOLIA_RPC_URL) \
		--private-key $(DEPLOYER_PRIVATE_KEY) \
		--broadcast --verify \
		--etherscan-api-key $(ETHERSCAN_API_KEY)

deploy-ethereum:
	forge script script/Deploy.s.sol:DeployPQBitcoin \
		--rpc-url $(ETHEREUM_RPC_URL) \
		--private-key $(DEPLOYER_PRIVATE_KEY) \
		--broadcast --verify \
		--etherscan-api-key $(ETHERSCAN_API_KEY)

deploy-bob:
	forge script script/Deploy.s.sol:DeployPQBitcoin \
		--rpc-url $(BOB_RPC_URL) \
		--private-key $(DEPLOYER_PRIVATE_KEY) \
		--broadcast

deploy-bob-testnet:
	forge script script/Deploy.s.sol:DeployPQBitcoin \
		--rpc-url $(BOB_SEPOLIA_RPC_URL) \
		--private-key $(DEPLOYER_PRIVATE_KEY) \
		--broadcast

deploy-citrea:
	forge script script/Deploy.s.sol:DeployPQBitcoin \
		--rpc-url $(CITREA_TESTNET_RPC_URL) \
		--private-key $(DEPLOYER_PRIVATE_KEY) \
		--broadcast

deploy-botanix:
	forge script script/Deploy.s.sol:DeployPQBitcoin \
		--rpc-url $(BOTANIX_RPC_URL) \
		--private-key $(DEPLOYER_PRIVATE_KEY) \
		--broadcast

# ── Testing ─────────────────────────────────────────────────────

test:
	forge test -vvv

coverage:
	forge coverage

# ── Utilities ───────────────────────────────────────────────────

build:
	forge build

clean:
	forge clean

# ── All networks (dry-run, no broadcast) ────────────────────────

dry-run-all:
	@echo "=== Sepolia ==="
	forge script script/Deploy.s.sol:DeployPQBitcoin --rpc-url $(SEPOLIA_RPC_URL)
	@echo "=== BOB ==="
	forge script script/Deploy.s.sol:DeployPQBitcoin --rpc-url $(BOB_RPC_URL)
	@echo "=== Citrea ==="
	forge script script/Deploy.s.sol:DeployPQBitcoin --rpc-url $(CITREA_TESTNET_RPC_URL)

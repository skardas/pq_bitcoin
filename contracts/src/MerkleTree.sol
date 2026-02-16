// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IncrementalMerkleTree
/// @notice Append-only Merkle tree for tracking migrations.
/// @dev Depth 20 → supports up to 1,048,576 leaves.
///      Uses Keccak-256 and pre-computed zero hashes for empty subtrees.
///      Gas cost: ~60K per insert (20 hash operations).
library IncrementalMerkleTree {
    uint256 internal constant DEPTH = 20;
    uint256 internal constant MAX_LEAVES = 1 << DEPTH; // 1,048,576

    struct Tree {
        /// @dev Number of inserted leaves.
        uint256 nextIndex;
        /// @dev The "filled subtrees" — one per level. filledSubtrees[i] holds the
        ///      most recently completed subtree hash at depth i.
        bytes32[DEPTH] filledSubtrees;
        /// @dev Current Merkle root.
        bytes32 root;
    }

    // ── Pre-computed zero hashes ────────────────────────────────
    // zeros[0] = keccak256(abi.encodePacked(bytes32(0)))
    // zeros[i] = keccak256(abi.encodePacked(zeros[i-1], zeros[i-1]))
    // These represent the hash of an empty subtree at each level.

    /// @notice Returns the zero hash for a given depth level.
    function zeros(uint256 level) internal pure returns (bytes32) {
        // Pre-computed zero hashes for depth 0..19
        if (level == 0) return 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563;
        if (level == 1) return 0x633dc4d7da7256660a892f8f1604a44b5432649cc8ec5cb3ced4c4e6ac94dd1d;
        if (level == 2) return 0x890740a8eb06ce9be422cb8da5cdafc2b58c0a5e24036c578de2a433c828ff7d;
        if (level == 3) return 0x3b8ec09e026fdc305365dfc94e189a81b38c7597b3d941c279f042e8206e0bd8;
        if (level == 4) return 0xecd50eee38e386bd62be9bedb990706951b65fe053bd9d8a521af753d139e2da;
        if (level == 5) return 0xdefff6d330bb5403f63b14f33b578274160de3a50df4efecf0e0db73bcdd3da5;
        if (level == 6) return 0x617bdd11f7c0a11f49db22f629387a12da7596f9d1704d7465177c63d88ec7d7;
        if (level == 7) return 0x292c23a9aa1d8bea7e2435e555a4a60e379a5a35f3f452bae60121073fb6eead;
        if (level == 8) return 0xe1cea92ed99acdcb045a6726b2f87107e8a61620a232cf4d7d5b5766b3952e10;
        if (level == 9) return 0x7ad66c0a68c72cb89e4fb4303c7a5a3c30bce953c01c81e5a77e0ed7f182edf5;
        if (level == 10) return 0x47c59da22fc156bd59f66e6baa7204013bc38c65a03dbae290ef730278654113;
        if (level == 11) return 0x4c61856f26f9a77cad22bb1cb6d32a4a7485b1c2e6e9cc8bde4fe0f6912e7ec5;
        if (level == 12) return 0x7a4f4d81b827338f94f21fe97e3e646036e56f22a1f4e0e64bbc563c5e932dc4;
        if (level == 13) return 0x7c67c5e22247e208489f92f0d87e1e19d3e6ab877e18fd09be5bff45c0ef0fac;
        if (level == 14) return 0xbec81e21ae0b1bbf89ac42e22cdf9d68edec7c7900806d1b32c0d70ae32a85c4;
        if (level == 15) return 0x2559dd7e041f1c64ceff23b0c3ce1e07a4c0fcd84f20977886c0fefe4f3dc99c;
        if (level == 16) return 0x16fdb2940765042832a15838a15c490d8c5c0e8cec67d76a8b70f3ea20f12ad0;
        if (level == 17) return 0x20c4e05dcd5e14f4af46028ca10e0db32aa258aff31bea7a43b457f5fd2f0715;
        if (level == 18) return 0x1fcb5cc05d32abe6cdcaa13f45f2d77f2a9a81cc49caef7e449e0d23afb64bcc;
        if (level == 19) return 0x091bab8a6ce3ce781a8b84a1e4b7ce1c2b6b30f08ddaa56ac4b6f61c39ae0d05;
        revert("IncrementalMerkleTree: level out of bounds");
    }

    /// @notice Initialize the tree with zeros root.
    function init(Tree storage self) internal {
        // Compute the root of an all-zeros tree
        bytes32 currentHash = zeros(0);
        for (uint256 i = 0; i < DEPTH; i++) {
            self.filledSubtrees[i] = zeros(i);
            currentHash = keccak256(abi.encodePacked(currentHash, zeros(i)));
        }
        self.root = currentHash;
    }

    /// @notice Insert a leaf into the tree and return the new root.
    /// @param leaf The leaf hash to insert.
    /// @return newRoot The updated Merkle root.
    function insert(Tree storage self, bytes32 leaf) internal returns (bytes32 newRoot) {
        require(self.nextIndex < MAX_LEAVES, "IncrementalMerkleTree: tree is full");

        uint256 currentIndex = self.nextIndex;
        bytes32 currentHash = leaf;

        for (uint256 i = 0; i < DEPTH; i++) {
            if (currentIndex % 2 == 0) {
                // Left child: pair with zero
                self.filledSubtrees[i] = currentHash;
                currentHash = keccak256(abi.encodePacked(currentHash, zeros(i)));
            } else {
                // Right child: pair with stored left sibling
                currentHash = keccak256(abi.encodePacked(self.filledSubtrees[i], currentHash));
            }
            currentIndex /= 2;
        }

        self.root = currentHash;
        self.nextIndex++;
        return currentHash;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SchnorrVerifier {
    // secp256k1 prime field
    uint256 constant PRIME     = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 constant GENERATOR = 2;

    /**
     * Verifies a Schnorr-style signature in F_p using the modexp precompile (0x05).
     * NOTE: Function is `view` due to precompile call.
     */
    function verifySignature(
        uint256 pubKey,
        uint256 r,
        uint256 s,
        bytes32 messageHash
    ) public view returns (bool) {
        // ---- Input sanity checks ----
        if (pubKey == 0 || pubKey >= PRIME) return false;
        if (r == 0 || r >= PRIME)          return false;
        if (s == 0 || s >= (PRIME - 1))    return false;

        // h = keccak256(r || messageHash) mod p
        uint256 h = uint256(keccak256(abi.encodePacked(r, messageHash))) % PRIME;

        // Check: g^s ?= r * pubKey^h  (mod p)
        uint256 left  = modExpPrecompile(GENERATOR, s, PRIME);
        uint256 right = mulmod(r, modExpPrecompile(pubKey, h, PRIME), PRIME);
        return left == right;
    }

    /// @dev Calls the EIP-198 modexp precompile at address 0x05.
    function modExpPrecompile(uint256 base, uint256 exp, uint256 mod) internal view returns (uint256 result) {
        // Precompile expects: baseLen|expLen|modLen|base|exp|mod, each length as 32-byte big-endian.
        bytes memory input = abi.encode(
            uint256(32), uint256(32), uint256(32),
            base, exp, mod
        );
        bytes memory output = new bytes(32);
        bool success;
        assembly {
            success := staticcall(gas(), 0x05, add(input, 32), mload(input), add(output, 32), 32)
        }
        require(success, "modexp failed");
        result = abi.decode(output, (uint256));
    }
}

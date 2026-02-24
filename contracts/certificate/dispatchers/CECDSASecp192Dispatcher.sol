// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {AbstractCDispatcher} from "./abstract/AbstractCDispatcher.sol";

import {Bytes2Poseidon} from "../../utils/Bytes2Poseidon.sol";

/**
 * @notice Certificate dispatcher for secp192r1 ECDSA keys.
 *
 * secp192r1 keys are 48 bytes (24-byte X + 24-byte Y).
 * Standard hash512 requires 64 bytes, so we pad each coordinate
 * to 32 bytes (big-endian, zero-padded on the left) before hashing.
 *
 * This ensures the on-chain hash matches:
 *   Poseidon(X mod 2^248, Y mod 2^248) = Poseidon(X, Y)
 * which is the same as the Noir circuit's extract_pk_hash.
 */
contract CECDSASecp192Dispatcher is AbstractCDispatcher {
    using Bytes2Poseidon for bytes;

    function __CECDSASecp192Dispatcher_init(
        address signer_,
        uint256 keyByteLength_,
        bytes calldata keyCheckPrefix_
    ) external initializer {
        __AbstractCDispatcher_init(signer_, keyByteLength_, keyCheckPrefix_);
    }

    function getCertificateKey(
        bytes memory certificatePublicKey_
    ) external pure override returns (uint256 keyHash_) {
        uint256 coordSize = certificatePublicKey_.length / 2;

        // Pad each coordinate to 32 bytes (big-endian, right-aligned)
        bytes memory padded = new bytes(64);

        // Copy X coordinate to padded[32-coordSize : 32]
        for (uint256 i = 0; i < coordSize; i++) {
            padded[32 - coordSize + i] = certificatePublicKey_[i];
        }

        // Copy Y coordinate to padded[64-coordSize : 64]
        for (uint256 i = 0; i < coordSize; i++) {
            padded[64 - coordSize + i] = certificatePublicKey_[coordSize + i];
        }

        return padded.hash512();
    }
}

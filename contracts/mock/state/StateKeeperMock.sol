// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {DynamicSet} from "@solarity/solidity-lib/libs/data-structures/DynamicSet.sol";

import {StateKeeper} from "../../state/StateKeeper.sol";

contract StateKeeperMock is StateKeeper {
    using DynamicSet for DynamicSet.StringSet;

    function mockAddRegistrations(string[] memory keys_, address[] memory values_) external {
        for (uint256 i = 0; i < keys_.length; i++) {
            require(_registrationKeys.add(keys_[i]), "StateKeeperMock: duplicate registration");
            _registrations[keys_[i]] = values_[i];
            _registrationExists[values_[i]] = true;
        }
    }

    function mockChangeICAOMasterTreeRoot(bytes32 newRoot_) external {
        icaoMasterTreeMerkleRoot = newRoot_;
    }

    function mockPassportData(bytes32 passportKey_, bytes32 mockSessionKey_) external {
        _passportInfos[passportKey_].activeSessionCount++;
        _passportSessions[passportKey_].push(mockSessionKey_);
    }

    function mockSessionData(bytes32 sessionKey_, bytes32 mockPassportKey_) external {
        _sessionInfos[sessionKey_].activePassport = mockPassportKey_;
        _sessionInfos[sessionKey_].issueTimestamp = uint64(block.timestamp);
    }

    function mockClearPassport(bytes32 passportKey_, bytes32 sigHash_) external {
        bytes32[] memory sessions = _passportSessions[passportKey_];
        for (uint256 i = 0; i < sessions.length; i++) {
            _sessionInfos[sessions[i]].activePassport = bytes32(0);
            _sessionInfos[sessions[i]].issueTimestamp = 0;
        }

        delete _passportSessions[passportKey_];
        _passportInfos[passportKey_].activeSessionCount = 0;
        usedSignatures[sigHash_] = false;
    }

    function _authorizeUpgrade(address) internal pure virtual override {}
}

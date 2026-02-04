// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {KYCRegistry} from "../../sdk/KYCRegistry.sol";

contract KYCRegistryMock is KYCRegistry {
    function mockClearKYC(address user_, bytes32 passportKey_) external {
        zkKycData[user_][passportKey_].passportKey = bytes32(0);
        zkKycData[user_][passportKey_].minExpirationDate = 0;
        zkKycData[user_][passportKey_].verifiedAt = 0;

        passportKeyToAddress[passportKey_] = address(0);

        bytes32[] storage passports = userPassports[user_];
        for (uint256 i = 0; i < passports.length; i++) {
            if (passports[i] == passportKey_) {
                passports[i] = passports[passports.length - 1];
                passports.pop();
                break;
            }
        }
    }

    function mockClearAllKYC(address user_) external {
        bytes32[] memory passports = userPassports[user_];
        for (uint256 i = 0; i < passports.length; i++) {
            bytes32 passportKey = passports[i];
            zkKycData[user_][passportKey].passportKey = bytes32(0);
            zkKycData[user_][passportKey].minExpirationDate = 0;
            zkKycData[user_][passportKey].verifiedAt = 0;
            passportKeyToAddress[passportKey] = address(0);
        }

        delete userPassports[user_];
    }

    function _authorizeUpgrade(address) internal override {}
}

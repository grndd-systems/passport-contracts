// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {PoseidonUnit1L, PoseidonUnit2L, PoseidonUnit3L} from "../libraries/Poseidon.sol";

import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {TypeCaster} from "@solarity/solidity-lib/libs/utils/TypeCaster.sol";
import {AMultiOwnable} from "@solarity/solidity-lib/access/AMultiOwnable.sol";

import {DynamicSet} from "@solarity/solidity-lib/libs/data-structures/DynamicSet.sol";

import {PoseidonSMT} from "./PoseidonSMT.sol";

contract StateKeeper is Initializable, AMultiOwnable, UUPSUpgradeable {
    using TypeCaster for address;
    using DynamicSet for DynamicSet.StringSet;

    bytes32 public constant REVOKED = keccak256("REVOKED");
    bytes32 public constant USED = keccak256("USED");

    enum MethodId {
        None,
        ChangeICAOMasterTreeRoot,
        AddRegistrations,
        RemoveRegistrations
    }

    struct CertificateInfo {
        uint64 expirationTimestamp;
    }

    struct PassportInfo {
        uint64 activeSessionCount; // Number of active sessions bound to this passport
    }

    /**
     * @notice Session information for a persistent session key
     * @dev A session key is a long-lived cryptographic key generated on a user's device
     *      for passport Active Authentication. Unlike traditional temporary session keys,
     *      these persist indefinitely until explicitly revoked by the user.
     *      Each device generates its own unique session key, allowing users to:
     *      - Have multiple active devices simultaneously
     *      - Revoke specific devices without affecting others
     *      - Sign out from all other devices while keeping current one active
     */
    struct SessionInfo {
        bytes32 activePassport; // Associated passport key (or REVOKED constant if revoked)
        uint64 issueTimestamp; // When this session was created
    }

    // Previously, _owners (type: struct EnumerableSet.AddressSet) from the old AMultiOwnable
    bytes32[2] private _deprecated;

    PoseidonSMT public certificatesSmt;

    bytes32 public icaoMasterTreeMerkleRoot;

    mapping(bytes32 => bool) public usedSignatures;

    mapping(bytes32 => CertificateInfo) internal _certificateInfos;

    mapping(bytes32 => PassportInfo) internal _passportInfos;
    mapping(bytes32 => SessionInfo) internal _sessionInfos;

    /// @notice Mapping from passportKey to array of session keys (supports multiple sessions per passport)
    mapping(bytes32 => bytes32[]) internal _passportSessions;

    DynamicSet.StringSet internal _registrationKeys;
    mapping(string => address) internal _registrations;
    mapping(address => bool) internal _registrationExists;

    event CertificateAdded(bytes32 certificateKey, uint256 expirationTimestamp);
    event CertificateRemoved(bytes32 certificateKey);
    event BondAdded(bytes32 passportKey, bytes32 sessionKey);
    event BondRevoked(bytes32 passportKey, bytes32 sessionKey);
    event BondSessionReissued(bytes32 passportKey, bytes32 sessionKey);

    modifier onlyRegistration() {
        _onlyRegistration();
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function __StateKeeper_init(
        address initialOwner_,
        address certificatesSmt_,
        bytes32 icaoMasterTreeMerkleRoot_
    ) external initializer {
        __AMultiOwnable_init();

        certificatesSmt = PoseidonSMT(certificatesSmt_);

        icaoMasterTreeMerkleRoot = icaoMasterTreeMerkleRoot_;

        addOwners(initialOwner_.asSingletonArray());
    }

    function __StateKeeper_init_v2() external reinitializer(2) {
        __AMultiOwnable_init();
    }

    /**
     * @notice Adds passport's certificate
     */
    function addCertificate(
        bytes32 certificateKey_,
        uint256 expirationTimestamp_
    ) external virtual onlyRegistration {
        require(
            expirationTimestamp_ + 5 * 365 days > block.timestamp,
            "StateKeeper: certificate is expired"
        );

        _certificateInfos[certificateKey_].expirationTimestamp = uint64(expirationTimestamp_);

        certificatesSmt.add(certificateKey_, certificateKey_);

        emit CertificateAdded(certificateKey_, expirationTimestamp_);
    }

    /**
     * @notice Removes passport's certificate
     */
    function removeCertificate(bytes32 certificateKey_) external virtual onlyRegistration {
        CertificateInfo storage _info = _certificateInfos[certificateKey_];

        require(
            _info.expirationTimestamp > 0 && _info.expirationTimestamp < block.timestamp,
            "StateKeeper: certificate is not expired"
        );

        delete _certificateInfos[certificateKey_];

        certificatesSmt.remove(certificateKey_);

        emit CertificateRemoved(certificateKey_);
    }

    /**
     * @notice Adds new session bond to a passport (supports multiple sessions per passport)
     * @dev Creates a persistent session key binding that remains active until explicitly revoked.
     *      Session keys are long-lived credentials (not temporary) that allow users to authenticate
     *      from specific devices. Users must explicitly call revoke functions to terminate sessions.
     * @param passportKey_ The passport public key hash
     * @param passportHash_ The passport hash (for passports without AA)
     * @param sessionKey_ The persistent session key generated on user's device
     */
    function addBond(
        bytes32 passportKey_,
        bytes32 passportHash_,
        bytes32 sessionKey_
    ) external virtual onlyRegistration {
        if (passportKey_ == bytes32(0)) {
            (passportHash_, passportKey_) = (passportKey_, passportHash_);
        }

        PassportInfo storage _passportInfo = _passportInfos[passportKey_];
        SessionInfo storage _sessionInfo = _sessionInfos[sessionKey_];

        // Session key can only be used once - even if revoked, it cannot be reused
        require(_sessionInfo.activePassport == bytes32(0), "StateKeeper: session already used");

        // Add session to passport's session array
        _passportSessions[passportKey_].push(sessionKey_);

        // Update counter
        _passportInfo.activeSessionCount++;

        // Set session info
        _sessionInfo.activePassport = passportKey_;
        _sessionInfo.issueTimestamp = uint64(block.timestamp);

        emit BondAdded(passportKey_, sessionKey_);
    }

    /**
     * @notice Revokes a specific session bond and removes it from the passport's session array
     */
    function revokeBond(
        bytes32 passportKey_,
        bytes32 sessionKey_
    ) external virtual onlyRegistration {
        _revokeSingleBond(passportKey_, sessionKey_);
    }

    /**
     * @notice Revokes multiple session bonds (batch operation)
     * @param passportKey_ The passport key
     * @param sessionKeys_ Array of session keys to revoke
     */
    function revokeBonds(
        bytes32 passportKey_,
        bytes32[] calldata sessionKeys_
    ) external virtual onlyRegistration {
        require(sessionKeys_.length > 0, "StateKeeper: empty session array");

        for (uint256 i = 0; i < sessionKeys_.length; i++) {
            _revokeSingleBond(passportKey_, sessionKeys_[i]);
        }
    }

    /**
     * @notice Revokes all sessions except one (useful for "sign out on all other devices")
     * @param passportKey_ The passport key
     * @param keepSessionKey_ The session to keep active
     */
    function revokeBondsExcept(
        bytes32 passportKey_,
        bytes32 keepSessionKey_
    ) external virtual onlyRegistration {
        PassportInfo storage _passportInfo = _passportInfos[passportKey_];
        SessionInfo storage _keepSessionInfo = _sessionInfos[keepSessionKey_];

        require(
            _keepSessionInfo.activePassport == passportKey_,
            "StateKeeper: keepSession not bound to this passport"
        );

        bytes32[] memory sessions = _passportSessions[passportKey_];

        // Revoke all sessions except the one to keep
        for (uint256 i = 0; i < sessions.length; i++) {
            if (sessions[i] != keepSessionKey_) {
                _revokeSingleBond(passportKey_, sessions[i]);
            }
        }
    }

    /**
     * @notice Revokes all session bonds for a passport
     * @param passportKey_ The passport key
     */
    function revokeAllBonds(bytes32 passportKey_) external virtual onlyRegistration {
        bytes32[] memory sessions = _passportSessions[passportKey_];

        for (uint256 i = 0; i < sessions.length; i++) {
            _revokeSingleBond(passportKey_, sessions[i]);
        }
    }

    /**
     * @notice Internal function to revoke a single session bond
     */
    function _revokeSingleBond(bytes32 passportKey_, bytes32 sessionKey_) internal {
        PassportInfo storage _passportInfo = _passportInfos[passportKey_];
        SessionInfo storage _sessionInfo = _sessionInfos[sessionKey_];

        require(
            _sessionInfo.activePassport == passportKey_,
            "StateKeeper: session not bound to this passport"
        );
        require(_passportInfo.activeSessionCount > 0, "StateKeeper: no active sessions");

        // Mark session as revoked
        _sessionInfo.activePassport = REVOKED;

        // Remove session from passport's array
        bytes32[] storage sessions = _passportSessions[passportKey_];
        for (uint256 i = 0; i < sessions.length; i++) {
            if (sessions[i] == sessionKey_) {
                // Move last element to this position and pop
                sessions[i] = sessions[sessions.length - 1];
                sessions.pop();
                _passportInfo.activeSessionCount--;
                break;
            }
        }

        emit BondRevoked(passportKey_, sessionKey_);
    }

    /**
     * @notice Stores used signatures throughout the registrations
     */
    function useSignature(bytes32 sigHash_) external virtual onlyRegistration {
        require(!usedSignatures[sigHash_], "StateKeeper: signature used");

        usedSignatures[sigHash_] = true;
    }

    /**
     * @notice Change ICAO tree Merkle root to a new one via Rarimo TSS.
     * @param newRoot_ the new ICAO root
     */
    function changeICAOMasterTreeRoot(bytes32 newRoot_) external virtual onlyOwner {
        icaoMasterTreeMerkleRoot = newRoot_;
    }

    /**
     * @notice Add or Remove registrations via Rarimo TSS
     * @param methodId_ the method id (AddRegistrations or RemoveRegistrations)
     * @param data_ An ABI encoded arrays of string keys addresses to add or remove
     */
    function updateRegistrationSet(
        MethodId methodId_,
        bytes calldata data_
    ) external virtual onlyOwner {
        if (methodId_ == MethodId.AddRegistrations) {
            (string[] memory keys_, address[] memory values_) = abi.decode(
                data_,
                (string[], address[])
            );

            for (uint256 i = 0; i < keys_.length; i++) {
                require(_registrationKeys.add(keys_[i]), "StateKeeper: duplicate registration");
                _registrations[keys_[i]] = values_[i];
                _registrationExists[values_[i]] = true;
            }
        } else if (methodId_ == MethodId.RemoveRegistrations) {
            string[] memory keys_ = abi.decode(data_, (string[]));

            for (uint256 i = 0; i < keys_.length; i++) {
                delete _registrationExists[_registrations[keys_[i]]];
                delete _registrations[keys_[i]];
                _registrationKeys.remove(keys_[i]);
            }
        } else {
            revert("StateKeeper: Invalid method");
        }
    }

    /**
     * @notice Get info about the registered X509 certificate
     * @param certificateKey_ the hash of a certificate public key
     * @return the certificate info
     */
    function getCertificateInfo(
        bytes32 certificateKey_
    ) external view virtual returns (CertificateInfo memory) {
        return _certificateInfos[certificateKey_];
    }

    /**
     * @notice Get info about the registered passport
     * @param passportKey_ the hash of a passport public key
     * @return passportInfo_ the passport info
     */
    function getPassportInfo(
        bytes32 passportKey_
    ) external view virtual returns (PassportInfo memory passportInfo_) {
        passportInfo_ = _passportInfos[passportKey_];
    }

    /**
     * @notice Get all session keys bound to a passport
     * @param passportKey_ the hash of a passport public key
     * @return sessionKeys_ array of session keys
     */
    function getPassportSessions(
        bytes32 passportKey_
    ) external view virtual returns (bytes32[] memory sessionKeys_) {
        return _passportSessions[passportKey_];
    }

    /**
     * @notice Get detailed info about all sessions bound to a passport
     * @param passportKey_ the hash of a passport public key
     * @return sessionKeys_ array of session keys
     * @return sessionInfos_ array of session info structs
     */
    function getPassportSessionsInfo(
        bytes32 passportKey_
    )
        external
        view
        virtual
        returns (bytes32[] memory sessionKeys_, SessionInfo[] memory sessionInfos_)
    {
        sessionKeys_ = _passportSessions[passportKey_];
        sessionInfos_ = new SessionInfo[](sessionKeys_.length);

        for (uint256 i = 0; i < sessionKeys_.length; i++) {
            sessionInfos_[i] = _sessionInfos[sessionKeys_[i]];
        }
    }

    /**
     * @notice Get info about a specific session
     * @param sessionKey_ the session key
     * @return sessionInfo_ the session info
     */
    function getSessionInfo(
        bytes32 sessionKey_
    ) external view virtual returns (SessionInfo memory sessionInfo_) {
        return _sessionInfos[sessionKey_];
    }

    /**
     * @notice Check if a passport is fully revoked (all sessions revoked)
     * @param passportKey_ the hash of a passport public key
     * @return isFullyRevoked_ true if all sessions are revoked
     */
    function isPassportFullyRevoked(
        bytes32 passportKey_
    ) external view virtual returns (bool isFullyRevoked_) {
        // Passport is fully revoked if it has no active sessions and no sessions in the array
        return
            _passportInfos[passportKey_].activeSessionCount == 0 &&
            _passportSessions[passportKey_].length == 0;
    }

    /**
     * @notice Lists all the registrations with their keys
     */
    function getRegistrations()
        external
        view
        virtual
        returns (string[] memory keys_, address[] memory values_)
    {
        keys_ = _registrationKeys.values();
        values_ = new address[](keys_.length);

        for (uint256 i = 0; i < keys_.length; i++) {
            values_[i] = _registrations[keys_[i]];
        }
    }

    /**
     * @notice Get the registration address by its key
     */
    function getRegistrationByKey(string memory key_) external view virtual returns (address) {
        return _registrations[key_];
    }

    /**
     * @notice Checks whether the passed address is a registration
     */
    function isRegistration(address registration_) external view virtual returns (bool) {
        return _registrationExists[registration_];
    }

    function _onlyRegistration() internal view {
        require(_registrationExists[msg.sender], "StateKeeper: not a registration");
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address) internal virtual override onlyOwner {}

    function implementation() external view returns (address) {
        return ERC1967Utils.getImplementation();
    }
}

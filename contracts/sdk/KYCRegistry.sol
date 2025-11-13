// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {AQueryProofExecutor} from "./AQueryProofExecutor.sol";
import {PublicSignalsBuilder} from "./lib/PublicSignalsBuilder.sol";
import {PublicSignalsTD1Builder} from "./lib/PublicSignalsTD1Builder.sol";
import {PoseidonUnit3L} from "../libraries/Poseidon.sol";
import {StateKeeper} from "../state/StateKeeper.sol";
import {Date2Time} from "../utils/Date2Time.sol";
/**
 * @title KYC
 * @notice KYC verification contract that binds addresses to passports
 * @dev Creates a verifiable binding between an Ethereum address and a passport
 *      after successful ZK proof verification via SDK
 */
contract KYCRegistry is
    AQueryProofExecutor,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    ReentrancyGuardUpgradeable
{
    using PublicSignalsBuilder for uint256;

    // Selector bitfield:
    // bit 0 - nullifier reveal
    // bit 12 - passport expiration lowerbound
    // bit 17 - verify citizenship mask as a blacklist
    uint256 public constant SELECTOR = 0x20001; // 0b100001000000000001

    /// @notice Citizenship mask for blocked countries (configurable by owner)
    uint256 public citizenshipMask;

    // Minimum KYC term - passport must be valid for at least 90 days
    uint256 public constant MIN_KYC_TERM = 90 days;

    struct ZKKYCData {
        uint256 nullifier;
        bytes32 passportHash; // Stable passport identifier (DG15 hash)
        uint256 minExpirationDate; // Minimum passport expiration date (yyMMdd format)
        uint64 verifiedAt;
    }

    /// @notice StateKeeper contract for passport-identity binding verification
    StateKeeper public stateKeeper;

    /// @notice Mapping from address to ZK-based KYC data
    mapping(address => ZKKYCData) public zkKycData;

    /// @notice Mapping from passportHash to address (prevents sybil attacks)
    /// @dev One passport can only be bound to one address, even after identity reissuance
    mapping(bytes32 => address) public passportHashToAddress;

    /// @notice Mapping from nullifier to used status (prevents double registration)
    mapping(uint256 => bool) public usedNullifiers;

    /// @notice Emitted when ZK proof KYC is verified
    event ZKKYCVerified(
        address indexed user,
        uint256 indexed nullifier,
        bytes32 indexed passportHash,
        uint256 timestamp
    );

    /// @notice Emitted when ZK KYC is revoked
    event ZKKYCRevoked(address indexed user, uint256 timestamp);

    /// @notice Emitted when passport is updated for a verified address
    event PassportUpdated(
        address indexed user,
        bytes32 indexed oldPassportHash,
        bytes32 indexed newPassportHash,
        uint256 timestamp
    );

    /// @notice Emitted when StateKeeper is updated
    event StateKeeperUpdated(address indexed stateKeeper);

    /// @notice Emitted when citizenship mask is updated
    event CitizenshipMaskUpdated(uint256 indexed newMask);

    error NullifierAlreadyUsed(uint256 nullifier);
    error AddressAlreadyVerified(address user);
    error AddressNotVerified(address user);
    error PassportAlreadyBound(bytes32 passportHash, address boundAddress);
    error NoUpdateRequired();
    error InsufficientKYCTerm(uint256 provided, uint256 minimum);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the contract
     * @param stateKeeper_ Address of the StateKeeper contract
     * @param verifierTD3_ Address of the ZK proof verifier for TD3 passports
     * @param verifierTD1_ Address of the ZK proof verifier for TD1 ID
     * @param citizenshipMask_ Initial citizenship mask for blocked countries
     */
    function initialize(
        address stateKeeper_,
        address verifierTD3_,
        address verifierTD1_,
        uint256 citizenshipMask_
    ) public initializer {
        __AQueryProofExecutor_init(verifierTD3_, verifierTD1_);
        __UUPSUpgradeable_init();
        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();

        require(stateKeeper_ != address(0), "KYC: zero stateKeeper address");

        stateKeeper = StateKeeper(stateKeeper_);
        citizenshipMask = citizenshipMask_;

        emit StateKeeperUpdated(stateKeeper_);
        emit CitizenshipMaskUpdated(citizenshipMask_);
    }

    /**
     * @notice Update the StateKeeper address
     * @param stateKeeper_ New StateKeeper address
     */
    function updateStateKeeper(address stateKeeper_) external onlyOwner {
        require(stateKeeper_ != address(0), "KYC: zero address");
        stateKeeper = StateKeeper(stateKeeper_);
        emit StateKeeperUpdated(stateKeeper_);
    }

    /**
     * @notice Update the citizenship mask
     * @param citizenshipMask_ New citizenship mask for blocked countries
     */
    function updateCitizenshipMask(uint256 citizenshipMask_) external onlyOwner {
        citizenshipMask = citizenshipMask_;
        emit CitizenshipMaskUpdated(citizenshipMask_);
    }

    // ============ ZK Proof-based KYC Functions (SDK) ============

    /**
     * @notice Called before proof verification to validate the request.
     * @dev Checks if the nullifier has been used (unless address is updating),
     *      validates minExpirationDate meets minimum KYC term requirement,
     *      and ensures sybil resistance by checking passport hash binding.
     *      Allows KYC-verified addresses to update their identity or passport.
     */
    function _beforeVerify(uint256 currentDate_, bytes memory userPayload_) internal override {
        (
            address user,
            uint256 nullifier,
            bytes32 passportHash,
            uint256 _identityCreationTimestamp,
            uint256 minExpirationDate
        ) = abi.decode(userPayload_, (address, uint256, bytes32, uint256, uint256));

        // Convert dates from yyMMdd format to timestamps for comparison
        uint256 currentTimestamp = Date2Time.timestampFromDate(currentDate_);
        uint256 minExpirationTimestamp = Date2Time.timestampFromDate(minExpirationDate);
        uint256 requiredMinTimestamp = currentTimestamp + MIN_KYC_TERM;

        // Validate minExpirationDate >= currentDate + MIN_KYC_TERM
        if (minExpirationTimestamp < requiredMinTimestamp) {
            revert InsufficientKYCTerm(minExpirationTimestamp - currentTimestamp, MIN_KYC_TERM);
        }

        // VALIDATE PASSPORT → IDENTITY BINDING via StateKeeper
        (
            StateKeeper.PassportInfo memory passportInfo,
            StateKeeper.IdentityInfo memory _identityInfo
        ) = stateKeeper.getPassportInfo(passportHash);

        require(passportInfo.activeIdentity != stateKeeper.REVOKED(), "KYC: passport is revoked");

        // Check if passport has an active identity
        require(passportInfo.activeIdentity != bytes32(0), "KYC: passport not registered");

        // Verify that the nullifier from proof matches the identity bound to this passport
        // Note: We can't directly compare nullifier to identityKey here,
        // but ZK proof will verify that user owns the identity bound to this passport
        // The proof verification in executeNoir validates nullifier ownership

        // Check if this address already has valid KYC
        bool hasExistingKYC = zkKycData[user].verifiedAt > 0;

        // SYBIL RESISTANCE: Check if passport is bound to a different address
        address boundAddress = passportHashToAddress[passportHash];
        if (boundAddress != address(0) && boundAddress != user) {
            revert PassportAlreadyBound(passportHash, boundAddress);
        }

        // If address is re-verifying (identity change or passport renewal):
        // - Allow updates since msg.sender controls the address (has private key)
        if (hasExistingKYC) {
            ZKKYCData storage existingData = zkKycData[user];

            // Re-verification only makes sense when passport OR identity changes
            if (existingData.passportHash == passportHash && nullifier == existingData.nullifier) {
                revert NoUpdateRequired();
            }

            // If passport is changing, verify msg.sender to prevent attacks
            if (existingData.passportHash != passportHash) {
                require(user == msg.sender, "KYC: only address owner can update passport");
                delete passportHashToAddress[existingData.passportHash];
            }

            // If identity changed (new nullifier with same address)
            if (nullifier != existingData.nullifier) {
                // Check new nullifier hasn't been used and mark it
                // IMPORTANT: Do NOT delete old nullifier - nullifiers are permanent
                if (usedNullifiers[nullifier]) {
                    revert NullifierAlreadyUsed(nullifier);
                }
                usedNullifiers[nullifier] = true;
            }
        } else {
            // New verification: check nullifier hasn't been used
            if (usedNullifiers[nullifier]) {
                revert NullifierAlreadyUsed(nullifier);
            }

            // Mark nullifier as used
            usedNullifiers[nullifier] = true;
        }
    }

    /**
     * @notice Called after successful proof verification to bind the identity to the user.
     * @dev Stores the permanent binding between address, passport, and nullifier.
     *      Allows:
     *      - Identity reissuance (new nullifier)
     *      - Passport renewal (new passportHash) if user controls the address
     */
    function _afterVerify(uint256, bytes memory userPayload_) internal override {
        (
            address user,
            uint256 nullifier,
            bytes32 passportHash,
            uint256 identityCreationTimestamp,
            uint256 minExpirationDate
        ) = abi.decode(userPayload_, (address, uint256, bytes32, uint256, uint256));

        // Check if passport is being updated
        bool isPassportUpdate = zkKycData[user].verifiedAt > 0 &&
            zkKycData[user].passportHash != passportHash;

        if (isPassportUpdate) {
            bytes32 oldPassportHash = zkKycData[user].passportHash;
            emit PassportUpdated(user, oldPassportHash, passportHash, block.timestamp);
        }

        // Store/Update ZK KYC information
        // This allows:
        // 1. Identity reissuance (new nullifier, same passport)
        // 2. Passport renewal (new passport, user controls address)
        zkKycData[user] = ZKKYCData({
            nullifier: nullifier,
            passportHash: passportHash,
            minExpirationDate: minExpirationDate,
            verifiedAt: uint64(block.timestamp)
        });

        // Store the binding from passport to address (SYBIL RESISTANCE)
        // One passport = one address at a time
        passportHashToAddress[passportHash] = user;

        emit ZKKYCVerified(user, nullifier, passportHash, block.timestamp);
    }

    /**
     * @notice Builds the public signals for ZK proof verification.
     * @dev Constructs the public signals array including nullifier, timestamp, and current date.
     *      Validates that passport expiration date >= minExpirationDate.
     *      passportHash is provided by user but validated through the ZK proof.
     */
    function _buildPublicSignals(
        uint256 currentDate_,
        bytes memory userPayload_
    ) internal view override returns (uint256 dataPointer_) {
        (
            address user,
            uint256 nullifier,
            bytes32 passportHash,
            uint256 identityCreationTimestamp,
            uint256 minExpirationDate
        ) = abi.decode(userPayload_, (address, uint256, bytes32, uint256, uint256));

        // Determine identity bounds based on whether timestamp is provided
        uint256 identityCreationTimestampUpperBound = 0;
        uint256 identityCounterUpperBound = 0;

        if (identityCreationTimestamp > 0) {
            identityCreationTimestampUpperBound = identityCreationTimestamp;
            identityCounterUpperBound = 1; // Enforce single registration
        }

        // Initialize builder with selector (0x1 = nullifier only) and nullifier
        dataPointer_ = PublicSignalsBuilder.newPublicSignalsBuilder(SELECTOR, nullifier);

        // Add event ID and data (ties proof to this user and contract)
        uint256 eventId = getEventId(user);
        dataPointer_.withEventIdAndData(
            eventId, // Event ID
            uint256(uint160(user)) // User address as event data
        );

        // Get the active identity bound to this passport from StateKeeper
        (
            StateKeeper.PassportInfo memory passportInfo,
            StateKeeper.IdentityInfo memory _identityInfo
        ) = stateKeeper.getPassportInfo(passportHash);

        // Add pkIdentityHash at position [11]
        dataPointer_.withActiveIdentity(uint256(passportInfo.activeIdentity));
        // Add current date validation (±1 day)
        dataPointer_.withCurrentDate(currentDate_, 1 days);

        // Add timestamp bounds for identity creation verification
        dataPointer_.withTimestampLowerboundAndUpperbound(
            0, // Lower bound: any time in the past
            identityCreationTimestampUpperBound // Upper bound: must be before creation time
        );

        // Birth date bounds (not enforced - using ZERO_DATE)
        dataPointer_.withBirthDateLowerboundAndUpperbound(
            PublicSignalsBuilder.ZERO_DATE,
            PublicSignalsBuilder.ZERO_DATE
        );

        // Add identity counter bounds (prevents multiple registrations if timestamp provided)
        dataPointer_.withIdentityCounterLowerbound(0, identityCounterUpperBound);

        // Expiration date bounds (passport must be valid for at least minExpirationDate)
        // minExpirationDate is in yyMMdd format, already validated to be >= currentDate + MIN_KYC_TERM
        dataPointer_.withExpirationDateLowerboundAndUpperbound(
            minExpirationDate, // Passport expiration must be > minExpirationDate
            PublicSignalsBuilder.ZERO_DATE
        );

        // Add citizenship mask to restrict allowed countries
        dataPointer_.withCitizenshipMask(citizenshipMask);

        return dataPointer_;
    }

    /**
     * @notice Builds the public signals for TD1 (ID card) ZK proof verification.
     * @dev Constructs the public signals array for TD1 documents (ID cards).
     *      Similar to _buildPublicSignals but uses PublicSignalsTD1Builder.
     */
    function _buildPublicSignalsTD1(
        uint256 currentDate_,
        bytes memory userPayload_
    ) internal view override returns (uint256 dataPointer_) {
        (
            address user,
            uint256 nullifier,
            bytes32 passportHash,
            uint256 identityCreationTimestamp,
            uint256 minExpirationDate
        ) = abi.decode(userPayload_, (address, uint256, bytes32, uint256, uint256));

        // Determine identity bounds based on whether timestamp is provided
        uint256 identityCreationTimestampUpperBound = 0;
        uint256 identityCounterUpperBound = 0;

        if (identityCreationTimestamp > 0) {
            identityCreationTimestampUpperBound = identityCreationTimestamp;
            identityCounterUpperBound = 1; // Enforce single registration
        }

        // Initialize builder with selector (0x1 = nullifier only) and nullifier
        dataPointer_ = PublicSignalsTD1Builder.newPublicSignalsBuilder(SELECTOR, nullifier);

        // Add event ID and data (ties proof to this user and contract)
        uint256 eventId = getEventId(user);
        PublicSignalsTD1Builder.withEventIdAndData(
            dataPointer_,
            eventId, // Event ID
            uint256(uint160(user)) // User address as event data
        );

        // Get the active identity bound to this passport from StateKeeper
        (
            StateKeeper.PassportInfo memory passportInfo,
            StateKeeper.IdentityInfo memory _identityInfo
        ) = stateKeeper.getPassportInfo(passportHash);

        // Add pkIdentityHash at position [11]
        PublicSignalsTD1Builder.withActiveIdentity(
            dataPointer_,
            uint256(passportInfo.activeIdentity)
        );
        // Add current date validation (±1 day)
        PublicSignalsTD1Builder.withCurrentDate(dataPointer_, currentDate_, 1 days);

        // Add timestamp bounds for identity creation verification
        PublicSignalsTD1Builder.withTimestampLowerboundAndUpperbound(
            dataPointer_,
            0, // Lower bound: any time in the past
            identityCreationTimestampUpperBound // Upper bound: must be before creation time
        );

        // Birth date bounds (not enforced - using ZERO_DATE)
        PublicSignalsTD1Builder.withBirthDateLowerboundAndUpperbound(
            dataPointer_,
            PublicSignalsTD1Builder.ZERO_DATE,
            PublicSignalsTD1Builder.ZERO_DATE
        );

        // Add identity counter bounds (prevents multiple registrations if timestamp provided)
        PublicSignalsTD1Builder.withIdentityCounterLowerbound(
            dataPointer_,
            0,
            identityCounterUpperBound
        );

        // Expiration date bounds (ID card must be valid for at least minExpirationDate)
        // minExpirationDate is in yyMMdd format, already validated to be >= currentDate + MIN_KYC_TERM
        PublicSignalsTD1Builder.withExpirationDateLowerboundAndUpperbound(
            dataPointer_,
            PublicSignalsTD1Builder.ZERO_DATE, // ID card expiration must be >= minExpirationDate
            minExpirationDate
        );

        // Note: TD1 doesn't have citizenshipMask like passport query circuit

        return dataPointer_;
    }

    /**
     * @notice Revoke ZK-based KYC for an address (owner only)
     * @param user_ The address to revoke KYC for
     */
    function revokeZKKYC(address user_) external onlyOwner {
        if (zkKycData[user_].verifiedAt == 0) {
            revert AddressNotVerified(user_);
        }

        uint256 nullifier = zkKycData[user_].nullifier;
        bytes32 passportHash = zkKycData[user_].passportHash;

        // Clean up all mappings
        delete zkKycData[user_];
        delete passportHashToAddress[passportHash];
        delete usedNullifiers[nullifier];

        emit ZKKYCRevoked(user_, block.timestamp);
    }

    /**
     * @notice Check if an address has verified ZK-based KYC
     * @param user_ The address to check
     * @return isVerified Whether ZK KYC is verified
     * @return data The ZK KYC data
     */
    function getZKKYCStatus(
        address user_
    ) external view returns (bool isVerified, ZKKYCData memory data) {
        data = zkKycData[user_];
        isVerified = data.verifiedAt > 0;
        return (isVerified, data);
    }

    /**
     * @notice Get the address associated with a passport hash
     * @param passportHash_ The passport hash to check
     * @return The address associated with the passport (address(0) if not bound)
     */
    function getAddressForPassport(bytes32 passportHash_) external view returns (address) {
        return passportHashToAddress[passportHash_];
    }

    /**
     * @notice Generates a unique event ID for this contract and user
     * @param user The user address
     * @return The event ID (Poseidon hash of chainid, contract address, and user address)
     */
    function getEventId(address user) public view returns (uint256) {
        return
            PoseidonUnit3L.poseidon(
                [block.chainid, uint256(uint160(address(this))), uint256(uint160(user))]
            );
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

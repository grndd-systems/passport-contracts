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
    // bit 12 - passport expiration lowerbound
    // bit 17 - verify citizenship mask as a blacklist
    uint256 public constant SELECTOR = 0x20000; // 0b100000000000000000

    /// @notice Citizenship mask for blocked countries (configurable by owner)
    uint256 public citizenshipMask;

    // Minimum KYC term - passport must be valid for at least 90 days
    uint256 public constant MIN_KYC_TERM = 90 days;

    struct ZKKYCData {
        bytes32 passportHash; // Stable passport identifier (DG15 hash)
        uint256 minExpirationDate; // Minimum passport expiration date (yyMMdd format)
        uint64 verifiedAt;
    }

    /// @notice StateKeeper contract for passport-identity binding verification
    StateKeeper public stateKeeper;

    /// @notice Mapping from address to passportHash to ZK-based KYC data (supports multiple passports per address)
    mapping(address => mapping(bytes32 => ZKKYCData)) public zkKycData;

    /// @notice Mapping from address to array of passport hashes (for iteration)
    mapping(address => bytes32[]) public userPassports;

    /// @notice Mapping from passportHash to address (prevents sybil attacks)
    /// @dev One passport can only be bound to one address
    mapping(bytes32 => address) public passportHashToAddress;

    /// @notice Emitted when ZK proof KYC is verified
    event ZKKYCVerified(address indexed user, bytes32 indexed passportHash, uint256 timestamp);

    /// @notice Emitted when ZK KYC is revoked for a specific passport
    event ZKKYCRevoked(address indexed user, bytes32 indexed passportHash, uint256 timestamp);

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

    error AddressAlreadyVerified(address user);
    error AddressNotVerified(address user);
    error PassportAlreadyBound(bytes32 passportHash, address boundAddress);
    error PassportAlreadyAddedToAddress(bytes32 passportHash, address user);
    error PassportNotFound(bytes32 passportHash, address user);
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
     * @dev Validates minExpirationDate meets minimum KYC term requirement,
     *      and ensures sybil resistance by checking passport hash binding.
     *      Allows addresses to have multiple passports and update existing ones.
     */
    function _beforeVerify(
        uint256 currentDate_,
        bytes memory userPayload_
    ) internal view override {
        (address user, bytes32 sessionKey, bytes32 passportHash, uint256 minExpirationDate) = abi
            .decode(userPayload_, (address, bytes32, bytes32, uint256));

        // Convert dates from yyMMdd format to timestamps for comparison
        uint256 currentTimestamp = Date2Time.timestampFromDate(currentDate_);
        uint256 minExpirationTimestamp = Date2Time.timestampFromDate(minExpirationDate);
        uint256 requiredMinTimestamp = currentTimestamp + MIN_KYC_TERM;

        // Validate minExpirationDate >= currentDate + MIN_KYC_TERM
        if (minExpirationTimestamp < requiredMinTimestamp) {
            revert InsufficientKYCTerm(minExpirationTimestamp - currentTimestamp, MIN_KYC_TERM);
        }

        // VALIDATE PASSPORT → SESSION BINDING via StateKeeper
        StateKeeper.PassportInfo memory passportInfo = stateKeeper.getPassportInfo(passportHash);

        // Check if passport has at least one active session
        require(
            passportInfo.activeSessionCount > 0,
            "KYC: passport not registered or all sessions revoked"
        );

        // Verify that the provided session key is bound to this passport
        StateKeeper.SessionInfo memory sessionInfo = stateKeeper.getSessionInfo(sessionKey);
        require(
            sessionInfo.activePassport == passportHash,
            "KYC: session not bound to this passport"
        );

        // ZK proof will verify that user owns this session
        // The proof verification validates session ownership through Active Authentication

        // SYBIL RESISTANCE: Check if passport is bound to a different address
        address boundAddress = passportHashToAddress[passportHash];
        if (boundAddress != address(0) && boundAddress != user) {
            revert PassportAlreadyBound(passportHash, boundAddress);
        }

        // Verify msg.sender to prevent others from adding passports to this address
        require(user == msg.sender, "KYC: only address owner can add or update passport");
    }

    /**
     * @notice Called after successful proof verification to bind the passport to the user.
     * @dev Stores the permanent binding between address and passport.
     *      Allows adding multiple passports to the same address.
     */
    function _afterVerify(uint256, bytes memory userPayload_) internal override {
        (address user, bytes32 _sessionKey, bytes32 passportHash, uint256 minExpirationDate) = abi
            .decode(userPayload_, (address, bytes32, bytes32, uint256));

        // Check if this passport is new for this user
        bool isNewPassport = zkKycData[user][passportHash].verifiedAt == 0;

        if (isNewPassport) {
            // Adding a new passport to this address
            userPassports[user].push(passportHash);
        } else {
            // Updating existing passport data (e.g., new expiration date)
            emit PassportUpdated(user, passportHash, passportHash, block.timestamp);
        }

        // Store/Update ZK KYC information for this specific passport
        zkKycData[user][passportHash] = ZKKYCData({
            passportHash: passportHash,
            minExpirationDate: minExpirationDate,
            verifiedAt: uint64(block.timestamp)
        });

        // Store the binding from passport to address (SYBIL RESISTANCE)
        // One passport = one address at a time
        passportHashToAddress[passportHash] = user;

        emit ZKKYCVerified(user, passportHash, block.timestamp);
    }

    /**
     * @notice Builds the public signals for ZK proof verification.
     * @dev Constructs the public signals array for proof validation.
     *      Validates that passport expiration date >= minExpirationDate.
     *      passportHash is provided by user but validated through the ZK proof.
     */
    function _buildPublicSignals(
        uint256 currentDate_,
        bytes memory userPayload_
    ) internal view override returns (uint256 dataPointer_) {
        (address user, bytes32 sessionKey, bytes32 _passportHash, uint256 minExpirationDate) = abi
            .decode(userPayload_, (address, bytes32, bytes32, uint256));

        // Initialize builder with selector
        dataPointer_ = PublicSignalsBuilder.newPublicSignalsBuilder(SELECTOR, 0);

        // Add event ID and data (ties proof to this user and contract)
        uint256 eventId = getEventId(user);
        dataPointer_.withEventIdAndData(
            eventId, // Event ID
            uint256(uint160(user)) // User address as event data
        );

        // Add session key at position [11]
        dataPointer_.withActiveSession(uint256(sessionKey));
        // Add current date validation (±1 day)
        dataPointer_.withCurrentDate(currentDate_, 1 days);

        // Add timestamp bounds (not enforced - any time)
        dataPointer_.withTimestampLowerboundAndUpperbound(0, 0);

        // Birth date bounds (not enforced - using ZERO_DATE)
        dataPointer_.withBirthDateLowerboundAndUpperbound(
            PublicSignalsBuilder.ZERO_DATE,
            PublicSignalsBuilder.ZERO_DATE
        );

        // Identity counter bounds (not enforced)
        dataPointer_.withIdentityCounterLowerbound(0, 0);

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
        (address user, bytes32 sessionKey, bytes32 _passportHash, uint256 minExpirationDate) = abi
            .decode(userPayload_, (address, bytes32, bytes32, uint256));

        // Initialize builder with selector
        dataPointer_ = PublicSignalsTD1Builder.newPublicSignalsBuilder(SELECTOR, 0);

        // Add event ID and data (ties proof to this user and contract)
        uint256 eventId = getEventId(user);
        PublicSignalsTD1Builder.withEventIdAndData(
            dataPointer_,
            eventId, // Event ID
            uint256(uint160(user)) // User address as event data
        );

        // Add session key at position [11]
        PublicSignalsTD1Builder.withActiveSession(dataPointer_, uint256(sessionKey));
        // Add current date validation (±1 day)
        PublicSignalsTD1Builder.withCurrentDate(dataPointer_, currentDate_, 1 days);

        // Add timestamp bounds (not enforced - any time)
        PublicSignalsTD1Builder.withTimestampLowerboundAndUpperbound(dataPointer_, 0, 0);

        // Birth date bounds (not enforced - using ZERO_DATE)
        PublicSignalsTD1Builder.withBirthDateLowerboundAndUpperbound(
            dataPointer_,
            PublicSignalsTD1Builder.ZERO_DATE,
            PublicSignalsTD1Builder.ZERO_DATE
        );

        // Identity counter bounds (not enforced)
        PublicSignalsTD1Builder.withIdentityCounterLowerbound(dataPointer_, 0, 0);

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
     * @notice Revoke ZK-based KYC for a specific passport
     * @dev Can be called by either the contract owner or the address owner (user)
     * @param user_ The address to revoke KYC for
     * @param passportHash_ The passport hash to revoke
     */
    function revokeZKKYC(address user_, bytes32 passportHash_) external {
        // Allow both contract owner and the user themselves to revoke
        require(
            msg.sender == owner() || msg.sender == user_,
            "KYC: only owner or address owner can revoke"
        );

        if (zkKycData[user_][passportHash_].verifiedAt == 0) {
            revert PassportNotFound(passportHash_, user_);
        }

        // Clean up all mappings
        delete zkKycData[user_][passportHash_];
        delete passportHashToAddress[passportHash_];

        // Remove from userPassports array
        bytes32[] storage passports = userPassports[user_];
        for (uint256 i = 0; i < passports.length; i++) {
            if (passports[i] == passportHash_) {
                // Move last element to this position and pop
                passports[i] = passports[passports.length - 1];
                passports.pop();
                break;
            }
        }

        emit ZKKYCRevoked(user_, passportHash_, block.timestamp);
    }

    /**
     * @notice Check if an address has verified ZK-based KYC for a specific passport
     * @param user_ The address to check
     * @param passportHash_ The passport hash to check
     * @return isVerified Whether ZK KYC is verified for this passport
     * @return data The ZK KYC data for this passport
     */
    function getZKKYCStatus(
        address user_,
        bytes32 passportHash_
    ) external view returns (bool isVerified, ZKKYCData memory data) {
        data = zkKycData[user_][passportHash_];
        isVerified = data.verifiedAt > 0;
        return (isVerified, data);
    }

    /**
     * @notice Get all passport hashes for a user
     * @param user_ The address to check
     * @return passportHashes Array of passport hashes associated with this address
     */
    function getUserPassports(address user_) external view returns (bytes32[] memory) {
        return userPassports[user_];
    }

    /**
     * @notice Get all ZK KYC data for a user (all passports)
     * @param user_ The address to check
     * @return passportHashes Array of passport hashes
     * @return kycDataArray Array of ZK KYC data for each passport
     */
    function getAllZKKYCData(
        address user_
    ) external view returns (bytes32[] memory passportHashes, ZKKYCData[] memory kycDataArray) {
        passportHashes = userPassports[user_];
        kycDataArray = new ZKKYCData[](passportHashes.length);

        for (uint256 i = 0; i < passportHashes.length; i++) {
            kycDataArray[i] = zkKycData[user_][passportHashes[i]];
        }

        return (passportHashes, kycDataArray);
    }

    /**
     * @notice Check if a user has any verified passport
     * @param user_ The address to check
     * @return hasKYC Whether the user has at least one verified passport
     */
    function hasAnyVerifiedKYC(address user_) external view returns (bool) {
        return userPassports[user_].length > 0;
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

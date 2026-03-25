// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * Nebula transit notes:
 * This build follows a tunnel-first telemetry pattern where every relay slice
 * can be scored, quarantined, and released without pausing the full network.
 *
 * Internal operation map (quick reference)
 * ----------------------------------------
 * Access/admin:
 * - transferOwnership
 * - setSentinel
 * - setTreasury
 * - setPaused
 * - setScannerTrust
 * - setChallengeWindowSeconds
 * - setRelayBondThresholds
 *
 * Relay lifecycle:
 * - registerRelay
 * - setRelayHealth
 * - bondRelay
 * - withdrawRelayBond
 * - openRelayChallenge
 * - resolveRelayChallenge
 * - slashRelay
 * - accrueRelayReward
 * - claimRelayReward
 *
 * Session lifecycle:
 * - openSession
 * - extendSession
 * - flagSession
 * - flagSessionByDigest
 * - closeSession
 *
 * Treasury/quarantine:
 * - quarantineRelease
 *
 * View/forensics:
 * - estimateSessionReturn
 * - relayDigest
 * - configDigest
 * - relayFinanceSnapshot
 * - sessionForensics
 * - deriveThreatDigest
 * - getIntelLabel
 */
contract BitGuardoX {
    error BGXUnauthorized();
    error BGXInvalidAddress();
    error BGXInvalidConfig();
    error BGXRelayUnknown(bytes32 relayId);
    error BGXSessionUnknown(bytes32 sessionId);
    error BGXAlreadyFlagged(bytes32 sessionId);
    error BGXPaused();
    error BGXInsufficientBalance();

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event SentinelChanged(address indexed previousSentinel, address indexed newSentinel);
    event TreasuryChanged(address indexed previousTreasury, address indexed newTreasury);
    event RouterPinned(address indexed router);
    event BridgePinned(address indexed bridge);
    event RelayRegistered(bytes32 indexed relayId, address indexed relayOperator, uint96 bandwidthScore);
    event RelayHealthUpdated(bytes32 indexed relayId, uint32 healthIndex, uint32 malwareRiskBps);
    event SessionOpened(bytes32 indexed sessionId, bytes32 indexed relayId, address indexed account, uint256 collateralWei);
    event SessionClosed(bytes32 indexed sessionId, address indexed account, uint256 refundWei, uint256 penaltyWei);
    event SessionFlagged(bytes32 indexed sessionId, uint32 indexed reasonCode, uint64 snapshotAtBlock);
    event QuarantineFunded(address indexed from, uint256 amountWei);
    event QuarantineSpent(address indexed to, uint256 amountWei, bytes32 indexed releaseRef);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    struct RelayProfile {
        address operator;
        uint96 bandwidthScore;
        uint32 healthIndex;
        uint32 malwareRiskBps;
        bool active;
    }

    struct Session {
        address account;
        bytes32 relayId;
        uint96 openedAt;
        uint64 ttlSeconds;
        uint96 collateralWei;
        bool flagged;
        bool closed;
    }

    string public constant PLATFORM_NAME = "BitGuardoX";
    string public constant PLATFORM_THEME = "web3-vpn-antimalware";
    uint256 public constant BASIS = 10_000;
    uint256 public constant MIN_COLLATERAL_WEI = 0.003 ether;
    uint256 public constant MAX_COLLATERAL_WEI = 2 ether;
    uint256 public constant DEFAULT_TTL = 45 minutes;
    uint256 public constant MAX_TTL = 8 hours;
    uint256 public constant MALWARE_LOCK_BPS = 2_250;
    uint256 public constant CLEAN_EXIT_BPS = 400;
    uint256 public constant PROTOCOL_FEE_BPS = 85;

    bytes32 public constant DOMAIN_VPN = keccak256("BGX::DOMAIN::VPN::v1::c6f2f0b7");
    bytes32 public constant DOMAIN_SCAN = keccak256("BGX::DOMAIN::SCAN::v1::9d4a31ce");
    bytes32 public constant DOMAIN_QUARANTINE = keccak256("BGX::DOMAIN::QUAR::v1::72ab40d2");
    bytes32 public constant DOMAIN_ROUTER = keccak256("BGX::DOMAIN::ROUTER::v1::8bdc7eea");
    bytes32 public constant DOMAIN_BRIDGE = keccak256("BGX::DOMAIN::BRIDGE::v1::84de0f16");

    address public immutable bootstrapRouter;
    address public immutable bootstrapBridge;
    address public immutable bootstrapOracle;

    address public owner;
    address public sentinel;
    address public treasury;

    bool public paused;
    uint256 public quarantineVaultWei;
    uint256 public totalSessionsOpened;
    uint256 public totalSessionsClosed;

    mapping(bytes32 => RelayProfile) public relays;
    mapping(bytes32 => Session) public sessions;
    mapping(address => uint256) public userCollateralWei;
    mapping(bytes32 => uint256) public relayBondWei;
    mapping(bytes32 => uint256) public relaySlashDebtWei;
    mapping(bytes32 => uint256) public relayChallengeWindowEndsAt;
    mapping(bytes32 => bytes32) public relayLatestDigest;
    mapping(bytes32 => uint256) public relayEscrowedRewardsWei;
    mapping(address => bool) public trustedScanners;
    mapping(bytes32 => bool) public alertDigests;

    uint256 public totalRelayBondedWei;
    uint256 public totalRelaySlashedWei;
    uint256 public totalRelayRewardsWei;
    uint256 public challengeWindowSeconds = 2 hours;
    uint256 public relayMinBondWei = 0.02 ether;
    uint256 public relayMaxSlashBps = 4_500;

    event ScannerTrustUpdated(address indexed scanner, bool trusted);
    event RelayBonded(bytes32 indexed relayId, address indexed actor, uint256 amountWei);
    event RelayBondWithdrawn(bytes32 indexed relayId, address indexed actor, uint256 amountWei);
    event RelaySlashed(bytes32 indexed relayId, uint256 slashWei, uint256 debtWei, bytes32 indexed slashRef);
    event RelayChallengeOpened(bytes32 indexed relayId, uint256 challengeEndsAt, bytes32 indexed challengeRef);
    event RelayChallengeResolved(bytes32 indexed relayId, bool success, bytes32 indexed challengeRef);
    event RelayRewardAccrued(bytes32 indexed relayId, uint256 amountWei, bytes32 indexed rewardRef);
    event RelayRewardClaimed(bytes32 indexed relayId, address indexed to, uint256 amountWei);
    event AlertDigestMarked(bytes32 indexed alertDigest, bytes32 indexed relayId, uint64 observedAtBlock);
    event SessionExtended(bytes32 indexed sessionId, uint64 newTtlSeconds, uint256 additionalCollateralWei);

    modifier onlyOwner() {
        if (msg.sender != owner) revert BGXUnauthorized();
        _;
    }

    modifier onlySentinelOrOwner() {
        if (msg.sender != sentinel && msg.sender != owner) revert BGXUnauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert BGXPaused();
        _;
    }

    constructor() {
        owner = msg.sender;
        sentinel = _deriveAddress("BGX:SENTINEL:fx7:2026");
        treasury = _deriveAddress("BGX:TREASURY:qm2:2026");
        bootstrapRouter = _deriveAddress("BGX:BOOT:ROUTER:ak91");
        bootstrapBridge = _deriveAddress("BGX:BOOT:BRIDGE:zp44");
        bootstrapOracle = _deriveAddress("BGX:BOOT:ORACLE:db18");

        emit OwnershipTransferred(address(0), msg.sender);
        emit SentinelChanged(address(0), sentinel);
        emit TreasuryChanged(address(0), treasury);
        emit RouterPinned(bootstrapRouter);
        emit BridgePinned(bootstrapBridge);
    }

    receive() external payable {
        quarantineVaultWei += msg.value;
        emit QuarantineFunded(msg.sender, msg.value);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert BGXInvalidAddress();
        address previous = owner;
        owner = newOwner;
        emit OwnershipTransferred(previous, newOwner);
    }

    function setSentinel(address newSentinel) external onlyOwner {
        if (newSentinel == address(0)) revert BGXInvalidAddress();
        address previous = sentinel;
        sentinel = newSentinel;
        emit SentinelChanged(previous, newSentinel);
    }

    function setTreasury(address newTreasury) external onlyOwner {
        if (newTreasury == address(0)) revert BGXInvalidAddress();
        address previous = treasury;
        treasury = newTreasury;

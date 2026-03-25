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

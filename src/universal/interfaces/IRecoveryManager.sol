// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {GuardianStorage, GuardianStatus} from "../libraries/EnumerableGuardianMap.sol";

interface IRecoveryManager {
    /*//////////////////////////////////////////////////////////////////////////
                                TYPE DELARATIONS
    //////////////////////////////////////////////////////////////////////////*/

    // struct ValidatorConfig {
    //     uint256 validationId;
    //     uint256 maxSigLen;
    //     uint256

    // }

    /**
     * A struct representing the values required for recovery configuration
     * Config should be maintained over subsequent recovery attempts unless explicitly modified
     */
    struct RecoveryConfig {
        uint256 delay; // the time from when recovery is started until the recovery request can be
        // executed
        uint256 expiry; // the time from when recovery is started until the recovery request becomes
        // invalid. The recovery expiry encourages the timely execution of successful recovery
        // attempts, and reduces the risk of unauthorized access through stale or outdated
        // requests.
    }

    /**
     * A struct representing the values required for a recovery request
     * The request state should be maintained over a single recovery attempts unless
     * explicitly modified. It should be deleted after a recovery attempt has been processed
     */
    struct RecoveryRequest {
        uint256 executeAfter; // the timestamp from which the recovery request can be executed
        uint256 executeBefore; // the timestamp from which the recovery request becomes invalid
        uint256 currentWeight; // total weight of all guardian approvals for the recovery request
        bytes32 calldataHash; // the keccak256 hash of the calldata used to execute the
        mapping(bytes32 => bool) usedNullifiers;
        // recovery attempt
    }

    /**
     * A struct representing the values required for guardian configuration
     * Config should be maintained over subsequent recovery attempts unless explicitly modified
     */
    struct GuardianConfig {
        uint256 guardianCount;
        uint256 totalWeight;
        uint256 threshold;
        bool initialized;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                    EVENTS
    //////////////////////////////////////////////////////////////////////////*/

    event RecoveryConfigured(address indexed account, uint256 guardianCount);
    event RecoveryConfigUpdated(
        address indexed account,
        uint256 delay,
        uint256 expiry
    );
    event GuardianAccepted(address indexed account, address indexed guardian);
    event RecoveryProcessed(
        address indexed account,
        uint256 executeAfter,
        uint256 executeBefore
    );
    event RecoveryCompleted(address indexed account);
    event RecoveryCancelled(address indexed account);
    event RecoveryDeInitialized(address indexed account);

    /*//////////////////////////////////////////////////////////////////////////
                                    ERRORS
    //////////////////////////////////////////////////////////////////////////*/

    error InitializerNotDeployer();
    error InvalidRecoveryModule();
    error RecoveryInProcess();
    error SetupAlreadyCalled();
    error AccountNotConfigured();
    error RecoveryModuleNotAuthorized();
    error DelayMoreThanExpiry();
    error RecoveryWindowTooShort();
    error InvalidTemplateIndex();
    error InvalidGuardianStatus(
        GuardianStatus guardianStatus,
        GuardianStatus expectedGuardianStatus
    );
    error InvalidAccountAddress();
    error NoRecoveryConfigured();
    error NotEnoughApprovals();
    error DelayNotPassed();
    error RecoveryRequestExpired();
    error InvalidCalldataHash();
    error NotRecoveryModule();
    error InvalidSignal();
    error DuplicatedNullifier();
    error InvalidProof();
    error NullifierAlreadyUsed();
    error InvalidNewOnwerAddress();
    error InvalidValidatorType();
    error InvalidSignature();
    error InvalidValidatorAddress();

    /*//////////////////////////////////////////////////////////////////////////
                                    FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    function getRecoveryConfig(
        address account
    ) external view returns (RecoveryConfig memory);

    // function getRecoveryRequest(
    //     address account
    // ) external view returns (RecoveryRequest memory);
    function getRecoveryRequest(
        address account
    ) external view returns (uint, uint, uint, bytes32);

    function configureRecovery(
        address[] memory guardians,
        uint256[] memory weights,
        uint256 threshold,
        uint256 delay,
        uint256 expiry
    ) external;

    function updateRecoveryConfig(
        RecoveryConfig calldata recoveryConfig
    ) external;

    function deInitRecoveryFromModule(address account) external;

    function cancelRecovery() external;

    /*//////////////////////////////////////////////////////////////////////////
                                GUARDIAN LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    function getGuardianConfig(
        address account
    ) external view returns (GuardianConfig memory);

    function getGuardian(
        address account,
        address guardian
    ) external view returns (GuardianStorage memory);

    function addGuardian(address guardian, uint256 weight) external;

    function removeGuardian(address guardian) external;

    function changeThreshold(uint256 threshold) external;
}

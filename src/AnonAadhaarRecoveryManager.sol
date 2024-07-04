// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import {IAnonAadhaar} from "@anon-aadhaar/contracts/interfaces/IAnonAadhaar.sol";
import {IAnonAadhaarRecoveryManager} from "./interfaces/IAnonAadhaarRecoveryManager.sol";
import {IAnonAadhaarRecoveryModule} from "./interfaces/IAnonAadhaarRecoveryModule.sol";
import {EnumerableGuardianMap, GuardianStorage, GuardianStatus} from "./libraries/EnumerableGuardianMap.sol";
import {GuardianUtils} from "./libraries/GuardianUtils.sol";

/**
 * @title AnonAadhaarRecoveryManager
 * @notice Provides a mechanism for account recovery using email guardians
 * @dev The underlying EmailAccountRecovery contract provides some base logic for deploying
 * guardian contracts and handling email verification.
 *
 * This contract defines a default implementation for email-based recovery. It is designed to
 * provide the core logic for email based account recovery that can be used across different account
 * implementations.
 *
 * AnonAadhaarRecoveryManager relies on a dedicated recovery module to execute a recovery attempt. This
 * (AnonAadhaarRecoveryManager) contract defines "what a valid recovery attempt is for an account", and
 * the recovery module defines “how that recovery attempt is executed on the account”.
 */
contract AnonAadhaarRecoveryManager is
    Initializable,
    IAnonAadhaarRecoveryManager
{
    using GuardianUtils for mapping(address => GuardianConfig);
    using GuardianUtils for mapping(address => EnumerableGuardianMap.UintToGuardianMap);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CONSTANTS & STORAGE                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * Minimum required time window between when a recovery attempt becomes valid and when it
     * becomes invalid
     */
    uint256 public constant MINIMUM_RECOVERY_WINDOW = 2 days;

    /**
     * The recovery module that is responsible for recovering an account
     */
    address public anonAadhaarRecoveryModule;

    /**
     * Deployer address stored to prevent frontrunning at initialization
     */
    address private deployer;

    /**
     * AnonAadhaarAddr address
     */
    address public anonAadhaarAddr;

    /**
     * Relayer address
     */
    address public relayerAddr;

    /**
     * Account address to recovery config
     */
    mapping(address account => RecoveryConfig recoveryConfig)
        internal recoveryConfigs;

    /**
     * Account address to recovery request
     */
    mapping(address account => RecoveryRequest recoveryRequest)
        internal recoveryRequests;

    /**
     * Account to guardian config
     */
    mapping(address account => GuardianConfig guardianConfig)
        internal guardianConfigs;

    /**
     * Account address to guardian address to guardian storage
     */
    mapping(address account => EnumerableGuardianMap.UintToGuardianMap guardian)
        internal guardiansStorage;

    constructor(address _anonAadhaar, address _relayerAddr) {
        anonAadhaarAddr = _anonAadhaar;
        relayerAddr = _relayerAddr;
        deployer = msg.sender;
    }

    function initialize(
        address _anonAadhaarRecoveryModule
    ) external initializer {
        if (msg.sender != deployer) {
            revert InitializerNotDeployer();
        }
        if (_anonAadhaarRecoveryModule == address(0)) {
            revert InvalidRecoveryModule();
        }
        anonAadhaarRecoveryModule = _anonAadhaarRecoveryModule;
    }

    /**
     * @notice Modifier to check recovery status. Reverts if recovery is in process for the account
     */
    modifier onlyWhenNotRecovering() {
        if (recoveryRequests[msg.sender].currentWeight > 0) {
            revert RecoveryInProcess();
        }
        _;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*       RECOVERY CONFIG, REQUEST AND TEMPLATE GETTERS        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Retrieves the recovery configuration for a given account
     * @param account The address of the account for which the recovery configuration is being
     * retrieved
     * @return RecoveryConfig The recovery configuration for the specified account
     */
    function getRecoveryConfig(
        address account
    ) external view returns (RecoveryConfig memory) {
        return recoveryConfigs[account];
    }

    /**
     * @notice Retrieves the recovery request details for a given account
     * @param account The address of the account for which the recovery request details are being
     * retrieved
     * @return RecoveryRequest The recovery request details for the specified account
     */
    // function getRecoveryRequest(
    //     address account
    // ) external view returns (RecoveryRequest memory) {
    //     return recoveryRequests[account];
    // }
    function getRecoveryRequest(
        address account
    ) external view returns (uint, uint, uint, bytes32) {
        RecoveryRequest storage request = recoveryRequests[account];
        return (
            request.executeAfter,
            request.executeBefore,
            request.currentWeight,
            request.calldataHash
        );
    }

    function getIsNullifiedInRecoveryRequest(
        address account,
        bytes32 nullifier
    ) external view returns (bool) {
        return recoveryRequests[account].usedNullifiers[nullifier];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     CONFIGURE RECOVERY                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Configures recovery for the caller's account. This is the first core function
     * that must be called during the end-to-end recovery flow
     * @dev Can only be called once for configuration. Sets up the guardians, deploys a router
     * contract, and validates config parameters, ensuring that no recovery is in process
     * @param guardians An array of guardian addresses
     * @param weights An array of weights corresponding to each guardian
     * @param threshold The threshold weight required for recovery
     * @param delay The delay period before recovery can be executed
     * @param expiry The expiry time after which the recovery attempt is invalid
     */
    function configureRecovery(
        uint[] memory guardians,
        uint256[] memory weights,
        uint256 threshold,
        uint256 delay,
        uint256 expiry
    ) external {
        address account = msg.sender;

        // Threshold can only be 0 at initialization.
        // Check ensures that setup function can only be called once.
        if (guardianConfigs[account].threshold > 0) {
            revert SetupAlreadyCalled();
        }

        setupGuardians(account, guardians, weights, threshold);

        if (
            !IAnonAadhaarRecoveryModule(anonAadhaarRecoveryModule)
                .isAuthorizedToRecover(account)
        ) {
            revert RecoveryModuleNotAuthorized();
        }

        RecoveryConfig memory recoveryConfig = RecoveryConfig(delay, expiry);
        updateRecoveryConfig(recoveryConfig);

        emit RecoveryConfigured(account, guardians.length);
    }

    /**
     * @notice Updates and validates the recovery configuration for the caller's account
     * @dev Validates and sets the new recovery configuration for the caller's account, ensuring
     * that no
     * recovery is in process. Reverts if the recovery module address is invalid, if the
     * delay is greater than the expiry, or if the recovery window is too short
     * @param recoveryConfig The new recovery configuration to be set for the caller's account
     */
    function updateRecoveryConfig(
        RecoveryConfig memory recoveryConfig
    ) public onlyWhenNotRecovering {
        address account = msg.sender;

        if (!guardianConfigs[account].initialized) {
            revert AccountNotConfigured();
        }
        if (recoveryConfig.delay > recoveryConfig.expiry) {
            revert DelayMoreThanExpiry();
        }
        if (
            recoveryConfig.expiry - recoveryConfig.delay <
            MINIMUM_RECOVERY_WINDOW
        ) {
            revert RecoveryWindowTooShort();
        }

        recoveryConfigs[account] = recoveryConfig;

        emit RecoveryConfigUpdated(
            account,
            recoveryConfig.delay,
            recoveryConfig.expiry
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     HANDLE ACCEPTANCE                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Accepts a guardian for the specified account. This is the second core function
     * that must be called during the end-to-end recovery flow
     * @dev Called once per guardian added. Although this adds an extra step to recovery, this
     * acceptance
     * flow is an important security feature to ensure that no typos are made when adding a guardian
     * and that the guardian explicitly consents to the role. Called as part of handleAcceptance
     * in EmailAccountRecovery
     * @param guardian The address of the guardian to be accepted
     */
    function handleAcceptance(
        address account,
        uint guardian,
        bytes memory proofData
    ) external {
        if (recoveryRequests[account].currentWeight > 0) {
            revert RecoveryInProcess();
        }

        if (
            !IAnonAadhaarRecoveryModule(anonAadhaarRecoveryModule)
                .isAuthorizedToRecover(account)
        ) {
            revert RecoveryModuleNotAuthorized();
        }

        // This check ensures GuardianStatus is correct and also implicitly that the
        // account in anonAadhaar is a valid account
        GuardianStorage memory guardianStorage = getGuardian(account, guardian);
        if (guardianStorage.status != GuardianStatus.REQUESTED) {
            revert InvalidGuardianStatus(
                guardianStorage.status,
                GuardianStatus.REQUESTED
            );
        }

        if (!verifyProofData(guardian, proofData)) {
            revert InvalidProof();
        }

        guardiansStorage.updateGuardianStatus(
            account,
            guardian,
            GuardianStatus.ACCEPTED
        );

        emit GuardianAccepted(account, guardian);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      HANDLE RECOVERY                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Processes a recovery request for a given account. This is the third core function
     * that must be called during the end-to-end recovery flow
     * @dev Reverts if the guardian address is invalid, if the template index is not zero, or if the
     * guardian status is not accepted
     * @param guardian The address of the guardian initiating the recovery
     */
    function handleRecovery(
        address account,
        uint guardian,
        bytes memory proofData,
        bytes32 calldataHash  // TODO: how to get bytes32 calldataHash...?
    ) external {

        if (
            !IAnonAadhaarRecoveryModule(anonAadhaarRecoveryModule)
                .isAuthorizedToRecover(account)
        ) {
            revert RecoveryModuleNotAuthorized();
        }

        if (!verifyProofData(guardian, proofData)) {
            revert InvalidProof();
        }

        // This check ensures GuardianStatus is correct and also implicitly that the
        // account in anonAadhaar is a valid account
        GuardianStorage memory guardianStorage = getGuardian(account, guardian);
        if (guardianStorage.status != GuardianStatus.ACCEPTED) {
            revert InvalidGuardianStatus(
                guardianStorage.status,
                GuardianStatus.ACCEPTED
            );
        }

        RecoveryRequest storage recoveryRequest = recoveryRequests[account];

        bytes32 nullifier = keccak256(abi.encodePacked(proofData));
        if (recoveryRequest.usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed();
        }
        
        recoveryRequest.currentWeight += guardianStorage.weight;

        uint256 threshold = guardianConfigs[account].threshold;
        if (recoveryRequest.currentWeight >= threshold) {
            uint256 executeAfter = block.timestamp +
                recoveryConfigs[account].delay;
            uint256 executeBefore = block.timestamp +
                recoveryConfigs[account].expiry;

            recoveryRequest.executeAfter = executeAfter;
            recoveryRequest.executeBefore = executeBefore;
            recoveryRequest.calldataHash = calldataHash;

            emit RecoveryProcessed(account, executeAfter, executeBefore);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     COMPLETE RECOVERY                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Completes the recovery process for a given account. This is the forth and final
     * core function that must be called during the end-to-end recovery flow. Can be called by
     * anyone.
     * @dev Validates the recovery request by checking the total weight, that the delay has passed,
     * and the request has not expired. Triggers the recovery module to perform the recovery. The
     * recovery module trusts that this contract has validated the recovery attempt. Deletes the
     * recovery
     * request but recovery config state is maintained so future recovery requests can be made
     * without having to reconfigure everything
     * @param account The address of the account for which the recovery is being completed
     */
    function completeRecovery(
        address account,
        bytes memory recoveryCalldata
    ) public {
        if (account == address(0)) {
            revert InvalidAccountAddress();
        }
        RecoveryRequest storage recoveryRequest = recoveryRequests[account];

        uint256 threshold = guardianConfigs[account].threshold;
        if (threshold == 0) {
            revert NoRecoveryConfigured();
        }

        if (recoveryRequest.currentWeight < threshold) {
            revert NotEnoughApprovals();
        }

        if (block.timestamp < recoveryRequest.executeAfter) {
            revert DelayNotPassed();
        }

        if (block.timestamp >= recoveryRequest.executeBefore) {
            revert RecoveryRequestExpired();
        }

        bytes32 calldataHash = keccak256(recoveryCalldata);
        if (calldataHash != recoveryRequest.calldataHash) {
            revert InvalidCalldataHash();
        }

        delete recoveryRequests[account];

        IAnonAadhaarRecoveryModule(anonAadhaarRecoveryModule).recover(
            account,
            recoveryCalldata
        );

        emit RecoveryCompleted(account);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     VERIFY PROOF                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function verifyProofData(
        uint guardian,
        bytes memory proofData
    ) internal returns (bool) {
        (
            uint256 nullifierSeed,
            uint256 timestamp,
            uint256 signal,
            uint[4] memory revealArray,
            uint[8] memory groth16Proof
        ) = abi.decode(proofData, (uint, uint, uint, uint[4], uint[8]));

        // TODO: check proof nullifier

        if (
            !IAnonAadhaar(anonAadhaarAddr).verifyAnonAadhaarProof(
                nullifierSeed,
                guardian,
                timestamp,
                signal,
                revealArray,
                groth16Proof
            )
        ) {
            return false;
        } else {
            // TODO: store proof nullifier
            return true;
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CANCEL/DE-INIT LOGIC                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Cancels the recovery request for the caller's account
     * @dev Deletes the current recovery request associated with the caller's account
     */
    function cancelRecovery() external virtual {
        delete recoveryRequests[msg.sender];
        emit RecoveryCancelled(msg.sender);
    }

    /**
     * @notice Removes all state related to an account. Must be called from a configured recovery
     * module
     * @dev In order to prevent unexpected behaviour when reinstalling account modules, the module
     * should be deinitialized. This should include remove state accociated with an account.
     * @param account The account to delete state for
     */
    function deInitRecoveryFromModule(address account) external {
        if (anonAadhaarRecoveryModule != msg.sender) {
            revert NotRecoveryModule();
        }

        if (recoveryRequests[account].currentWeight > 0) {
            revert RecoveryInProcess();
        }

        delete recoveryConfigs[account];
        delete recoveryRequests[account];

        guardiansStorage.removeAllGuardians(account);
        delete guardianConfigs[account];

        emit RecoveryDeInitialized(account);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       GUARDIAN LOGIC                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function getGuardianConfig(
        address account
    ) external view returns (GuardianConfig memory) {
        return guardianConfigs[account];
    }

    function getGuardian(
        address account,
        uint guardian
    ) public view returns (GuardianStorage memory) {
        return guardiansStorage.getGuardianStorage(account, guardian);
    }

    function setupGuardians(
        address account,
        uint[] memory guardians,
        uint256[] memory weights,
        uint256 threshold
    ) internal {
        guardianConfigs.setupGuardians(
            guardiansStorage,
            account,
            guardians,
            weights,
            threshold
        );
    }

    // why this is external...?
    function addGuardian(
        uint guardian,
        uint256 weight
    ) external onlyWhenNotRecovering {
        guardiansStorage.addGuardian(
            guardianConfigs,
            msg.sender,
            guardian,
            weight
        );
    }

    function removeGuardian(uint guardian) external onlyWhenNotRecovering {
        guardiansStorage.removeGuardian(guardianConfigs, msg.sender, guardian);
    }

    function changeThreshold(uint256 threshold) external onlyWhenNotRecovering {
        guardianConfigs.changeThreshold(msg.sender, threshold);
    }
}

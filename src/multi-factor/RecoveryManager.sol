// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import {IRecoveryManager} from "./interfaces/IRecoveryManager.sol";
import {IRecoveryModule} from "./interfaces/IRecoveryModule.sol";
import {IRecoveryValidator, IRecoveryValidatorConstants} from "./interfaces/IRecoveryValidator.sol";
import {EnumerableGuardianMap, GuardianStorage, GuardianStatus, ValidatorType} from "./libraries/EnumerableGuardianMap.sol";
import {GuardianUtils} from "./libraries/GuardianUtils.sol";

/// signature

// 0: module type
// mb 1: guardian len
//

contract RecoveryManager is Initializable, IRecoveryManager {
    using GuardianUtils for mapping(address => GuardianConfig);
    using GuardianUtils for mapping(address => EnumerableGuardianMap.AddressToGuardianMap);
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x1626ba7e;

    // bytes32 internal EIP1271_MAGICVALUE =

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
    address public recoveryModule;

    /**
     * Deployer address stored to prevent frontrunning at initialization
     */
    address private deployer;

    /**
     * RecoveryValidator type to validator address
     */

    mapping(uint8 => address) internal validators; // validatorType => validator
    // TODO: have getter method for this
    // TODO: may need reverse one address => type
    // TODO; need validator length

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
    mapping(address account => EnumerableGuardianMap.AddressToGuardianMap guardian)
        internal guardiansStorage;

    constructor(address[] memory _validators) {
        deployer = msg.sender;

        for (uint8 i = 0; i < _validators.length; i++) {
            if (_validators[i] == address(0)) {
                revert InvalidValidatorAddress();
            }
            validators[i] = _validators[i];
        }
    }

    function initialize(address _recoveryModule) external initializer {
        if (msg.sender != deployer) {
            revert InitializerNotDeployer();
        }
        if (_recoveryModule == address(0)) {
            revert InvalidRecoveryModule();
        }
        recoveryModule = _recoveryModule;
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
        address[] memory guardians,
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

        if (!IRecoveryModule(recoveryModule).isAuthorizedToRecover(account)) {
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
        address guardian,
        bytes memory signature
    ) external {
        if (recoveryRequests[account].currentWeight > 0) {
            revert RecoveryInProcess();
        }

        if (!IRecoveryModule(recoveryModule).isAuthorizedToRecover(account)) {
            revert RecoveryModuleNotAuthorized();
        }

        // This check ensures GuardianStatus is correct and also implicitly that the
        // account in  is a valid account
        GuardianStorage memory guardianStorage = getGuardian(account, guardian);
        if (guardianStorage.status != GuardianStatus.REQUESTED) {
            revert InvalidGuardianStatus(
                guardianStorage.status,
                GuardianStatus.REQUESTED
            );
        }

        if (!validateGuardianSignature(signature)) {
            revert InvalidSignature();
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
        address guardian,
        bytes32 calldataHash,
        bytes memory signature
    ) external {
        if (!IRecoveryModule(recoveryModule).isAuthorizedToRecover(account)) {
            revert RecoveryModuleNotAuthorized();
        }

        if (!validateGuardianSignature(signature)) {
            revert InvalidSignature();
        }

        // This check ensures GuardianStatus is correct and also implicitly that the
        // account in  is a valid account
        GuardianStorage memory guardianStorage = getGuardian(account, guardian);
        if (guardianStorage.status != GuardianStatus.ACCEPTED) {
            revert InvalidGuardianStatus(
                guardianStorage.status,
                GuardianStatus.ACCEPTED
            );
        }

        RecoveryRequest storage recoveryRequest = recoveryRequests[account];

        // Check if the same proof has been already used to vote for this recovery
        // If not, nullifiy it in usedNullifiers mapping.
        bytes32 nullifier = keccak256(abi.encodePacked(signature));
        if (recoveryRequest.usedNullifiers[nullifier]) {
            revert NullifierAlreadyUsed();
        } else {
            recoveryRequest.usedNullifiers[nullifier] = true;
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

        IRecoveryModule(recoveryModule).recover(account, recoveryCalldata);

        emit RecoveryCompleted(account);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     VERIFY PROOF                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function validateGuardianSignature(
        bytes memory signature
    ) internal returns (bool) {
        (uint8 validatorType, bytes memory validationData) = abi.decode(
            signature,
            (uint8, bytes)
        );

        // TODO: conditional call to validator depending on validatorType
        bytes4 validaionResult;
        if (validatorType == uint8(ValidatorType.K256)) {
            (bytes32 message, bytes memory signature) = abi.decode(
                validationData,
                (bytes32, bytes)
            );
            validaionResult = IRecoveryValidator(validators[validatorType])
                .isValidSignature(message, signature);
        } else if (validatorType == uint8(ValidatorType.AADHAAR)) {
            (bytes32 calldataHash, bytes memory signature) = abi.decode(
                validationData,
                (bytes32, bytes)
            );

            validaionResult = IRecoveryValidator(validators[validatorType])
                .isValidSignature(calldataHash, signature);
        } else if (validatorType == uint8(ValidatorType.P256)) {
            validaionResult = IRecoveryValidator(validators[validatorType])
                .isValidSignature(bytes32(0), validationData);
        } else {
            revert InvalidValidatorType();
        }

        // return validaionResult == IRecoveryValidator.EIP1271_MAGIC_VALUE;
        return validaionResult == EIP1271_MAGIC_VALUE;
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
        if (recoveryModule != msg.sender) {
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
        address guardian
    ) public view returns (GuardianStorage memory) {
        return guardiansStorage.getGuardianStorage(account, guardian);
    }

    function setupGuardians(
        address account,
        address[] memory guardians,
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
        address guardian,
        uint256 weight
    ) external onlyWhenNotRecovering {
        guardiansStorage.addGuardian(
            guardianConfigs,
            msg.sender,
            guardian,
            weight
        );
    }

    function removeGuardian(address guardian) external onlyWhenNotRecovering {
        guardiansStorage.removeGuardian(guardianConfigs, msg.sender, guardian);
    }

    function changeThreshold(uint256 threshold) external onlyWhenNotRecovering {
        guardianConfigs.changeThreshold(msg.sender, threshold);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       Validator LOGIC                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // add validator
    // remove validator
    // query validator by type
    // query type by validator
}

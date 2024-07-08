// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ERC7579ExecutorBase} from "@rhinestone/modulekit/src/Modules.sol";
import {IERC7579Account} from "erc7579/interfaces/IERC7579Account.sol";
import {IModule} from "erc7579/interfaces/IERC7579Module.sol";
import {IRecoveryModule} from "../interfaces/IRecoveryModule.sol";
import {IRecoveryManager} from "../interfaces/IRecoveryManager.sol";

/**
 * @title RecoveryModule
 * @notice This contract provides a simple mechanism for recovering account validators by
 * permissioning certain functions to be called on validators. It facilitates recovery by
 * integration with a trusted email recovery manager. The module defines how a recovery request is
 * executed on a validator, while the trusted recovery manager defines what a valid
 * recovery request is
 */
contract RecoveryModule is ERC7579ExecutorBase, IRecoveryModule {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CONSTANTS & STORAGE                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * Trusted email recovery manager contract that handles recovery requests
     */
    address public immutable recoveryManager;

    address public immutable validator;

    bytes4 public immutable selector;

    /**
     * Account address to authorized validator
     */
    mapping(address account => bool isAuthorized) internal authorized;

    event RecoveryExecuted();

    error InvalidSelector(bytes4 selector);
    error InvalidOnInstallData();
    error InvalidValidator(address validator);
    error NotTrustedRecoveryManager();
    error RecoveryNotAuthorizedForAccount();

    constructor(
        address _recoveryManager,
        address _validator,
        bytes4 _selector
    ) {
        if (
            _selector == IModule.onUninstall.selector ||
            _selector == IModule.onInstall.selector
        ) {
            revert InvalidSelector(_selector);
        }

        recoveryManager = _recoveryManager;
        validator = _validator;
        selector = _selector;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          CONFIG                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * Initializes the module with the threshold and guardians
     * @dev data is encoded as follows: abi.encode(validator, isInstalledContext, initialSelector,
     * guardians, weights, threshold, delay, expiry)
     *
     * @param data encoded data for recovery configuration
     */
    function onInstall(bytes calldata data) external {
        if (data.length == 0) revert InvalidOnInstallData();
        (
            bytes memory isInstalledContext,
            address[] memory guardians,
            uint256[] memory weights,
            uint256 threshold,
            uint256 delay,
            uint256 expiry
        ) = abi.decode(
                data,
                (bytes, address[], uint256[], uint256, uint256, uint256)
            );

        if (
            !IERC7579Account(msg.sender).isModuleInstalled(
                TYPE_VALIDATOR,
                validator,
                isInstalledContext
            )
        ) {
            revert InvalidValidator(validator);
        }
        authorized[msg.sender] = true;

        _execute({
            to: recoveryManager,
            value: 0,
            data: abi.encodeCall(
                IRecoveryManager.configureRecovery,
                (guardians, weights, threshold, delay, expiry)
            )
        });
    }

    /**
     * Handles the uninstallation of the module and clears the recovery configuration
     * @dev the data parameter is not used
     */
    function onUninstall(bytes calldata /* data */) external {
        authorized[msg.sender] = false;
        IRecoveryManager(recoveryManager).deInitRecoveryFromModule(msg.sender);
    }

    /**
     * Check if the module is initialized
     * @param smartAccount The smart account to check
     * @return true if the module is initialized, false otherwise
     */
    function isInitialized(address smartAccount) external view returns (bool) {
        return
            IRecoveryManager(recoveryManager)
                .getGuardianConfig(smartAccount)
                .threshold != 0;
    }

    function isAuthorizedToRecover(
        address smartAccount
    ) external view returns (bool) {
        return authorized[smartAccount];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        MODULE LOGIC                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Executes recovery on a validator. Must be called by the trusted recovery manager
     * @param account The account to execute recovery for
     * @param recoveryCalldata The recovery calldata that should be executed on the validator
     * being recovered
     */
    function recover(
        address account,
        bytes calldata recoveryCalldata
    ) external {
        if (msg.sender != recoveryManager) {
            revert NotTrustedRecoveryManager();
        }

        if (!authorized[account]) {
            revert RecoveryNotAuthorizedForAccount();
        }

        bytes4 calldataSelector = bytes4(recoveryCalldata[:4]);
        if (calldataSelector != selector) {
            revert InvalidSelector(calldataSelector);
        }

        _execute({
            account: account,
            to: validator,
            value: 0,
            data: recoveryCalldata
        });

        emit RecoveryExecuted();
    }

    /**
     * @notice Returns the address of the trusted recovery manager.
     * @return address The address of the email recovery manager.
     */
    function getTrustedRecoveryManager() external view returns (address) {
        return recoveryManager;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         METADATA                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * Returns the name of the module
     * @return name of the module
     */
    function name() external pure returns (string memory) {
        return "Universal.RecoveryModule";
    }

    /**
     * Returns the version of the module
     * @return version of the module
     */
    function version() external pure returns (string memory) {
        return "0.0.1";
    }

    /**
     * Returns the type of the module
     * @param typeID type of the module
     * @return true if the type is a module type, false otherwise
     */
    function isModuleType(uint256 typeID) external pure returns (bool) {
        return typeID == TYPE_EXECUTOR;
    }
}

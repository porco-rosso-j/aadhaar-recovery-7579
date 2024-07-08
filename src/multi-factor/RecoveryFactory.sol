// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {RecoveryManager} from "./RecoveryManager.sol";
import {RecoveryModule} from "./modules/RecoveryModule.sol";

contract RecoveryFactory {
    address[] public recoveryValidators;

    event RecoveryModuleDeployed(
        address RecoveryModule,
        address recoveryManager
    );

    constructor(address[] memory _recoveryValidators) {
        recoveryValidators = _recoveryValidators;
    }

    function deployRecoveryModule(
        bytes32 recoveryManagerSalt,
        bytes32 recoveryModuleSalt,
        address validator,
        bytes4 functionSelector
    ) external returns (address, address) {
        // Deploy recovery manager
        address recoveryManager = address(
            new RecoveryManager{salt: recoveryManagerSalt}(recoveryValidators)
        );

        // Deploy recovery module
        address recoveryModule = address(
            new RecoveryModule{salt: recoveryModuleSalt}(
                recoveryManager,
                validator,
                functionSelector
            )
        );

        // Initialize recovery manager with module address
        RecoveryManager(recoveryManager).initialize(recoveryModule);
        emit RecoveryModuleDeployed(recoveryModule, recoveryManager);

        return (recoveryModule, recoveryManager);
    }
}

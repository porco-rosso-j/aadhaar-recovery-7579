// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {AnonAadhaarRecoveryManager} from "./AnonAadhaarRecoveryManager.sol";
import {AnonAadhaarRecoveryModule} from "./modules/AnonAadhaarRecoveryModule.sol";

contract AnonAadhaarRecoveryFactory {
    address public immutable anonAadhaar;
    address public immutable verifier;

    event AnonAadhaarRecoveryModuleDeployed(
        address anonAadhaarRecoveryModule,
        address anonAadhaarRecoveryManager
    );

    constructor(address _anonAadhaar, address _verifier) {
        anonAadhaar = _anonAadhaar;
        verifier = _verifier;
    }

    function deployAnonAadhaarRecoveryModule(
        bytes32 recoveryManagerSalt,
        bytes32 recoveryModuleSalt,
        address validator,
        bytes4 functionSelector
    ) external returns (address, address) {
        // Deploy recovery manager
        address anonAadhaarRecoveryManager = address(
            new AnonAadhaarRecoveryManager{salt: recoveryManagerSalt}(
                anonAadhaar,
                verifier
            )
        );

        // Deploy recovery module
        address anonAadhaarRecoveryModule = address(
            new AnonAadhaarRecoveryModule{salt: recoveryModuleSalt}(
                anonAadhaarRecoveryManager,
                validator,
                functionSelector
            )
        );

        // Initialize recovery manager with module address
        AnonAadhaarRecoveryManager(anonAadhaarRecoveryManager).initialize(
            anonAadhaarRecoveryModule
        );
        emit AnonAadhaarRecoveryModuleDeployed(
            anonAadhaarRecoveryModule,
            anonAadhaarRecoveryManager
        );

        return (anonAadhaarRecoveryModule, anonAadhaarRecoveryManager);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {AnonAadhaarRecoveryManager} from "./AnonAadhaarRecoveryManager.sol";
import {AnonAadhaarRecoveryModule} from "./modules/AnonAadhaarRecoveryModule.sol";

contract AnonAadhaarRecoveryFactory {
    function deployAll(
        bytes32 recoveryManagerSalt,
        bytes32 recoveryModuleSalt,
        address anonAadhaar,
        address relayer,
        address validator,
        bytes4 functionSelector
    ) external returns (address, address) {
        // Deploy recovery manager
        AnonAadhaarRecoveryManager anonAadhaarRecoveryManager = new AnonAadhaarRecoveryManager{
                salt: recoveryManagerSalt
            }(anonAadhaar, relayer);
        address anonAadhaarRecoveryManagerAddress = address(
            anonAadhaarRecoveryManager
        );

        // Deploy recovery module
        AnonAadhaarRecoveryModule anonAadhaarRecoveryModule = new AnonAadhaarRecoveryModule{
                salt: recoveryModuleSalt
            }(anonAadhaarRecoveryManagerAddress, validator, functionSelector);
        address anonAadhaarRecoveryModuleAddress = address(
            anonAadhaarRecoveryModule
        );

        // Initialize recovery manager with module address
        anonAadhaarRecoveryManager.initialize(anonAadhaarRecoveryModuleAddress);

        return (
            anonAadhaarRecoveryManagerAddress,
            anonAadhaarRecoveryModuleAddress
        );
    }
}

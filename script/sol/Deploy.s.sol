// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {console2} from "forge-std/console2.sol";
import {Script} from "forge-std/Script.sol";

import {RecoveryFactory} from "src/multi-factor/RecoveryFactory.sol";
import {RecoveryManager} from "src/multi-factor/RecoveryManager.sol";
import {OwnableValidator} from "src/test/OwnableValidator.sol";
import {EcdsaValidator} from "src/multi-factor/validators/EcdsaValidator.sol";
import {AnonAadhaarValidator} from "src/multi-factor/validators/AnonAadhaarValidator.sol";

contract DeployAccount is Script {
    address deployerAddress = vm.envAddress("ADDRESS");
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
    address anonAadhaar = 0x03A36a3f2002190aC03bB64dD881ff2e208DF7ee;

    RecoveryFactory recoveryFactory;

    function run() external {
        vm.startBroadcast(deployerPrivateKey);

        address ownableValidator = address(new OwnableValidator());
        address ecdsaRecoveryValidator = address(new EcdsaValidator());
        address anonAadhaarRecoveryValidator = address(
            new AnonAadhaarValidator(anonAadhaar)
        );

        address[] memory validators = new address[](2);
        validators[0] = ecdsaRecoveryValidator;
        validators[1] = anonAadhaarRecoveryValidator;

        recoveryFactory = new RecoveryFactory(validators);

        bytes32 recoveryManagerSalt = bytes32(uint256(0));
        bytes32 recoveryModuleSalt = bytes32(uint256(0));

        (
            address recoveryModuleAddress,
            address recoveryManagerAddress
        ) = recoveryFactory.deployRecoveryModule(
                recoveryManagerSalt,
                recoveryModuleSalt,
                ownableValidator,
                bytes4(keccak256(bytes("changeOwner(address)")))
            );

        console2.logAddress(address(recoveryFactory));
        console2.logAddress(address(recoveryManagerAddress));
        console2.logAddress(address(recoveryModuleAddress));

        vm.stopBroadcast();
    }
}

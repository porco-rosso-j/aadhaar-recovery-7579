// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {console2} from "forge-std/console2.sol";
import {ModuleKitHelpers, ModuleKitUserOp} from "modulekit/ModuleKit.sol";
import {MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR} from "modulekit/external/ERC7579.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {AnonAadhaarRecoveryFactory} from "src/AnonAadhaarRecoveryFactory.sol";
import {AnonAadhaarRecoveryManager} from "src/AnonAadhaarRecoveryManager.sol";
import {OwnableValidator} from "src/test/OwnableValidator.sol";
import {IntegrationBase} from "../IntegrationBase.t.sol";

abstract contract OwnableValidatorRecovery_AnonAadhaarRecoveryModule_Base is
    IntegrationBase
{
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using Strings for uint256;
    using Strings for address;

    AnonAadhaarRecoveryFactory anonAadhaarRecoveryFactory;
    AnonAadhaarRecoveryManager anonAadhaarRecoveryManager;

    address anonAadhaarRecoveryManagerAddress;
    address recoveryModuleAddress;
    address validatorAddress;

    OwnableValidator validator;
    bytes isInstalledContext;
    bytes4 functionSelector;

    bytes recoveryCalldata;
    bytes32 calldataHash;
    uint256 nullifierCount;

    function setUp() public virtual override {
        super.setUp();

        // Deploy validator to be recovered
        validator = new OwnableValidator();
        validatorAddress = address(validator);
        isInstalledContext = bytes("0");
        functionSelector = bytes4(keccak256(bytes("changeOwner(address)")));

        anonAadhaarRecoveryFactory = new AnonAadhaarRecoveryFactory(
            address(anonAadhaar),
            address(verifier)
        );

        // Deploy AnonAadhaarRecoveryManager & AnonAadhaarRecoveryModule
        bytes32 recoveryManagerSalt = bytes32(uint256(0));
        bytes32 recoveryModuleSalt = bytes32(uint256(0));
        (
            recoveryModuleAddress,
            anonAadhaarRecoveryManagerAddress
        ) = anonAadhaarRecoveryFactory.deployAnonAadhaarRecoveryModule(
            recoveryManagerSalt,
            recoveryModuleSalt,
            validatorAddress,
            functionSelector
        );

        anonAadhaarRecoveryManager = AnonAadhaarRecoveryManager(
            anonAadhaarRecoveryManagerAddress
        );

        recoveryCalldata = abi.encodeWithSelector(functionSelector, newOwner);
        calldataHash = keccak256(recoveryCalldata);

        bytes memory recoveryModuleInstallData = abi.encode(
            isInstalledContext,
            guardians,
            guardianWeights,
            threshold,
            delay,
            expiry
        );

        // Install modules for account 1
        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: validatorAddress,
            data: abi.encode(owner)
        });

        instance.installModule({
            moduleTypeId: MODULE_TYPE_EXECUTOR,
            module: recoveryModuleAddress,
            data: recoveryModuleInstallData
        });
    }

    function acceptGuardian(
        address account,
        uint guardian,
        bytes memory proofData
    ) public {
        anonAadhaarRecoveryManager.handleAcceptance(
            account,
            guardian,
            proofData
        );
    }

    function handleRecovery(
        address account,
        uint guardian,
        bytes32 calldataHash,
        bytes memory proofData
    ) public {
        anonAadhaarRecoveryManager.handleRecovery(
            account,
            guardian,
            calldataHash,
            proofData
        );
    }
}

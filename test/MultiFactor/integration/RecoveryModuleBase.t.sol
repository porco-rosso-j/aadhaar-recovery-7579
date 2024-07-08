// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {console2} from "forge-std/console2.sol";
import {ModuleKitHelpers, ModuleKitUserOp} from "modulekit/ModuleKit.sol";
import {MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR} from "modulekit/external/ERC7579.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {RecoveryFactory} from "src/multi-factor/RecoveryFactory.sol";
import {RecoveryManager} from "src/multi-factor/RecoveryManager.sol";
import {EcdsaValidator} from "src/multi-factor/validators/EcdsaValidator.sol";
import {AnonAadhaarValidator} from "src/multi-factor/validators/AnonAadhaarValidator.sol";
import {OwnableValidator} from "src/test/OwnableValidator.sol";

import {IntegrationBase} from "../IntegrationBase.t.sol";

abstract contract OwnableValidatorRecovery_RecoveryModule_Base is
    IntegrationBase
{
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using Strings for uint256;
    using Strings for address;

    RecoveryFactory recoveryFactory;
    RecoveryManager recoveryManager;

    address recoveryManagerAddress;
    address recoveryModuleAddress;

    // recovery validators, not 7579
    address ecdsaRecoveryValidatorAddress;
    address anonAadhaarRecoveryValidatorAddress;

    EcdsaValidator ecdsaRecoveryValidator;
    AnonAadhaarValidator anonAadhaarRecoveryValidator;

    // default validator for account
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

        ecdsaRecoveryValidator = new EcdsaValidator();
        anonAadhaarRecoveryValidator = new AnonAadhaarValidator(
            address(anonAadhaar)
        );

        ecdsaRecoveryValidatorAddress = address(ecdsaRecoveryValidator);
        anonAadhaarRecoveryValidatorAddress = address(
            anonAadhaarRecoveryValidator
        );

        isInstalledContext = bytes("0");
        functionSelector = bytes4(keccak256(bytes("changeOwner(address)")));

        address[] memory validators = new address[](2);
        validators[0] = ecdsaRecoveryValidatorAddress;
        validators[1] = anonAadhaarRecoveryValidatorAddress;

        recoveryFactory = new RecoveryFactory(validators);

        // Deploy RecoveryManager & RecoveryModule
        bytes32 recoveryManagerSalt = bytes32(uint256(0));
        bytes32 recoveryModuleSalt = bytes32(uint256(0));

        (recoveryModuleAddress, recoveryManagerAddress) = recoveryFactory
            .deployRecoveryModule(
                recoveryManagerSalt,
                recoveryModuleSalt,
                validatorAddress,
                functionSelector
            );

        recoveryManager = RecoveryManager(recoveryManagerAddress);

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
        address guardian,
        bytes memory sigData
    ) public {
        recoveryManager.handleAcceptance(account, guardian, sigData);
    }

    function handleRecovery(
        address account,
        address guardian,
        bytes32 calldataHash,
        bytes memory sigData
    ) public {
        recoveryManager.handleRecovery(
            account,
            guardian,
            calldataHash,
            sigData
        );
    }
}

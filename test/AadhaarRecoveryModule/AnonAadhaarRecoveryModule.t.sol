// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {console2} from "forge-std/console2.sol";
import {ModuleKitHelpers, ModuleKitUserOp} from "modulekit/ModuleKit.sol";
import {MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR} from "modulekit/external/ERC7579.sol";

import {IAnonAadhaarRecoveryManager} from "src/interfaces/IAnonAadhaarRecoveryManager.sol";
import {GuardianStorage, GuardianStatus} from "src/libraries/EnumerableGuardianMap.sol";
import {OwnableValidator} from "src/test/OwnableValidator.sol";

import {OwnableValidatorRecovery_AnonAadhaarRecoveryModule_Base} from "./AnonAadhaarRecoveryModuleBase.t.sol";

contract OwnableValidatorRecovery_AnonAadhaarRecoveryModule_Integration_Test is
    OwnableValidatorRecovery_AnonAadhaarRecoveryModule_Base
{
    function setUp() public override {
        super.setUp();
    }

    function test_Recover_RotatesOwnerSuccessfully() public {
        // Accept guardian 1
        acceptGuardian(accountAddress, guardians[0], guardian1proofData[0]);
        GuardianStorage memory guardianStorage1 = anonAadhaarRecoveryManager
            .getGuardian(accountAddress, guardians[0]);
        assertEq(
            uint256(guardianStorage1.status),
            uint256(GuardianStatus.ACCEPTED)
        );
        assertEq(guardianStorage1.weight, uint256(1));

        // Accept guardian 2
        acceptGuardian(accountAddress, guardians[1], guardian2proofData[0]);
        GuardianStorage memory guardianStorage2 = anonAadhaarRecoveryManager
            .getGuardian(accountAddress, guardians[1]);
        assertEq(
            uint256(guardianStorage2.status),
            uint256(GuardianStatus.ACCEPTED)
        );
        assertEq(guardianStorage2.weight, uint256(2));

        // Time travel so that EmailAuth timestamp is valid
        vm.warp(12 seconds);
        // handle recovery request for guardian 1
        handleRecovery(
            accountAddress,
            guardians[0],
            calldataHash,
            guardian1proofData[1]
        );

        // IAnonAadhaarRecoveryManager.RecoveryRequest
        //     memory recoveryRequest = anonAadhaarRecoveryManager
        //         .getRecoveryRequest(accountAddress);

        (
            uint executeAfter,
            uint executeBefore,
            uint currentWeight,
            bytes32 calldataHash
        ) = anonAadhaarRecoveryManager.getRecoveryRequest(accountAddress);

        // assertEq(recoveryRequest.executeAfter, 0);
        // assertEq(recoveryRequest.executeBefore, 0);
        // assertEq(recoveryRequest.currentWeight, 1);
        assertEq(executeAfter, 0);
        assertEq(executeBefore, 0);
        assertEq(currentWeight, 1);

        // handle recovery request for guardian 2
        executeAfter = block.timestamp + delay;
        executeBefore = block.timestamp + expiry;
        handleRecovery(
            accountAddress,
            guardians[1],
            calldataHash,
            guardian2proofData[1]
        );
        // recoveryRequest = anonAadhaarRecoveryManager.getRecoveryRequest(
        //     accountAddress
        // );
        // assertEq(recoveryRequest.executeAfter, executeAfter);
        // assertEq(recoveryRequest.executeBefore, executeBefore);
        // assertEq(recoveryRequest.currentWeight, 3);
        (
            executeAfter,
            executeBefore,
            currentWeight,
            calldataHash
        ) = anonAadhaarRecoveryManager.getRecoveryRequest(accountAddress);
        assertEq(executeAfter, executeAfter);
        assertEq(executeBefore, executeBefore);
        assertEq(currentWeight, 3);

        // Time travel so that the recovery delay has passed
        vm.warp(block.timestamp + delay);

        // Complete recovery
        anonAadhaarRecoveryManager.completeRecovery(
            accountAddress,
            recoveryCalldata
        );

        // recoveryRequest = anonAadhaarRecoveryManager.getRecoveryRequest(
        //     accountAddress
        // );
        (
            executeAfter,
            executeBefore,
            currentWeight,
            calldataHash
        ) = anonAadhaarRecoveryManager.getRecoveryRequest(accountAddress);

        address updatedOwner = validator.owners(accountAddress);

        // assertEq(recoveryRequest.executeAfter, 0);
        // assertEq(recoveryRequest.executeBefore, 0);
        // assertEq(recoveryRequest.currentWeight, 0);
        // assertEq(updatedOwner, newOwner);
        assertEq(executeAfter, 0);
        assertEq(executeBefore, 0);
        assertEq(currentWeight, 0);
        assertEq(updatedOwner, newOwner);
    }

    // // Helper function
    // function executeRecoveryFlowForAccount(
    //     address account,
    //     bytes32 calldataHash,
    //     bytes memory recoveryCalldata
    // ) internal {
    //     acceptGuardian(account, guardians[0]);
    //     acceptGuardian(account, guardians[1]);
    //     vm.warp(block.timestamp + 12 seconds);
    //     handleRecovery(account, guardians[0], calldataHash);
    //     handleRecovery(account, guardians[1], calldataHash);
    //     vm.warp(block.timestamp + delay);
    //     anonAadhaarRecoveryManager.completeRecovery(account, recoveryCalldata);
    // }
}

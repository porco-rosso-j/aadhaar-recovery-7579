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

        // Accept guardian 3
        acceptGuardian(accountAddress, guardians[2], guardian3proofData[0]);
        GuardianStorage memory guardianStorage3 = anonAadhaarRecoveryManager
            .getGuardian(accountAddress, guardians[2]);
        assertEq(
            uint256(guardianStorage3.status),
            uint256(GuardianStatus.ACCEPTED)
        );
        assertEq(guardianStorage3.weight, uint256(1));

        // handle recovery request for guardian 1
        handleRecovery(
            accountAddress,
            guardians[0],
            bytes32(0),
            guardian1proofData[1]
        );

        (
            uint executeAfter,
            uint executeBefore,
            uint currentWeight,
            bytes32 _calldataHash
        ) = anonAadhaarRecoveryManager.getRecoveryRequest(accountAddress);

        assertEq(executeAfter, 0);
        assertEq(executeBefore, 0);
        assertEq(currentWeight, 1);

        // handle recovery request for guardian 2
        handleRecovery(
            accountAddress,
            guardians[1],
            bytes32(0),
            guardian2proofData[1]
        );

        (
            executeAfter,
            executeBefore,
            currentWeight,
            _calldataHash
        ) = anonAadhaarRecoveryManager.getRecoveryRequest(accountAddress);
        assertEq(executeAfter, 0);
        assertEq(executeBefore, 0);
        assertEq(currentWeight, 3);

        uint _executeAfter = block.timestamp + delay;
        uint _executeBefore = block.timestamp + expiry;

        // handle recovery request for guardian 3
        handleRecovery(
            accountAddress,
            guardians[2],
            calldataHash,
            guardian3proofData[1]
        );

        (
            executeAfter,
            executeBefore,
            currentWeight,
            _calldataHash
        ) = anonAadhaarRecoveryManager.getRecoveryRequest(accountAddress);
        assertEq(executeAfter, _executeAfter);
        assertEq(executeBefore, _executeBefore);
        assertEq(currentWeight, 4);

        // Time travel so that the recovery delay has passed
        vm.warp(block.timestamp + delay);

        // Complete recovery
        anonAadhaarRecoveryManager.completeRecovery(
            accountAddress,
            recoveryCalldata
        );

        (
            executeAfter,
            executeBefore,
            currentWeight,
            _calldataHash
        ) = anonAadhaarRecoveryManager.getRecoveryRequest(accountAddress);

        address updatedOwner = validator.owners(accountAddress);

        assertEq(executeAfter, 0);
        assertEq(executeBefore, 0);
        assertEq(currentWeight, 0);
        assertEq(updatedOwner, newOwner);
    }
}

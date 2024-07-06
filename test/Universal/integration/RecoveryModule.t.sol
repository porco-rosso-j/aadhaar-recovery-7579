// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {console2} from "forge-std/console2.sol";
import {ModuleKitHelpers, ModuleKitUserOp} from "modulekit/ModuleKit.sol";
import {MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR} from "modulekit/external/ERC7579.sol";

import {IRecoveryManager} from "src/universal/interfaces/IRecoveryManager.sol";
import {GuardianStorage, GuardianStatus} from "src/universal/libraries/EnumerableGuardianMap.sol";
import {OwnableValidator} from "src/test/OwnableValidator.sol";

import {OwnableValidatorRecovery_RecoveryModule_Base} from "./RecoveryModuleBase.t.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";


// 3 guardians where 1st and 2nd guardins use ecrecover and and the 3rd uses anon aadhaar zkp

contract OwnableValidatorRecovery_AnonAadhaarRecoveryModule_Integration_Test is
    OwnableValidatorRecovery_RecoveryModule_Base
{
    function setUp() public override {
        super.setUp();
    }

    function constructEcdsaSignatureParam(
        address guardian,
        uint guardianPrivateKey
    ) internal returns (bytes memory) {
        vm.warp(block.timestamp + 1);
        bytes32 testMsgHash = keccak256(abi.encodePacked(block.timestamp));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            guardianPrivateKey,
            ECDSA.toEthSignedMessageHash(testMsgHash)
        );
        bytes memory inner_sig = abi.encode(guardian, v, r, s);
        bytes memory validationData = abi.encode(testMsgHash, inner_sig);
        return abi.encode(0, validationData); // valiudation type
    }

    function constructAadhaarSignatureParam(
        bool isAccept
    ) internal returns (bytes memory) {
        bytes memory validationData = abi.encode(
            isAccept ? bytes32(0) : calldataHash,
            guardianSigData[isAccept ? 0 : 1]
        );
        return abi.encode(1, validationData);
    }

    function test_UniversalRecover_RotatesOwnerSuccessfully() public {
        // Accept guardian 1
        bytes memory acceptSignature1 = constructEcdsaSignatureParam(
            guardians[0],
            guardianPrivatekeys[0]
        );
        acceptGuardian(accountAddress, guardians[0], acceptSignature1);
        GuardianStorage memory guardianStorage1 = recoveryManager.getGuardian(
            accountAddress,
            guardians[0]
        );

        assertEq(
            uint256(guardianStorage1.status),
            uint256(GuardianStatus.ACCEPTED)
        );
        assertEq(guardianStorage1.weight, uint256(1));

        // Accept guardian 2
        bytes memory acceptSignature2 = constructEcdsaSignatureParam(
            guardians[1],
            guardianPrivatekeys[1]
        );
        acceptGuardian(accountAddress, guardians[1], acceptSignature2);
        GuardianStorage memory guardianStorage2 = recoveryManager.getGuardian(
            accountAddress,
            guardians[1]
        );
        assertEq(
            uint256(guardianStorage2.status),
            uint256(GuardianStatus.ACCEPTED)
        );
        assertEq(guardianStorage2.weight, uint256(2));

        // Accept guardian 3
        bytes memory acceptSignature3 = constructAadhaarSignatureParam(true);
        acceptGuardian(accountAddress, guardians[2], acceptSignature3);
        GuardianStorage memory guardianStorage3 = recoveryManager.getGuardian(
            accountAddress,
            guardians[2]
        );
        assertEq(
            uint256(guardianStorage3.status),
            uint256(GuardianStatus.ACCEPTED)
        );
        assertEq(guardianStorage3.weight, uint256(1));

        // handle recovery request for guardian 1
        bytes memory processSignature1 = constructEcdsaSignatureParam(
            guardians[0],
            guardianPrivatekeys[0]
        );

        handleRecovery(
            accountAddress,
            guardians[0],
            bytes32(0),
            processSignature1
        );

        (
            uint executeAfter,
            uint executeBefore,
            uint currentWeight,
            bytes32 _calldataHash
        ) = recoveryManager.getRecoveryRequest(accountAddress);

        assertEq(executeAfter, 0);
        assertEq(executeBefore, 0);
        assertEq(currentWeight, 1);

        // handle recovery request for guardian 2
        bytes memory processSignature2 = constructEcdsaSignatureParam(
            guardians[0],
            guardianPrivatekeys[0]
        );

        handleRecovery(
            accountAddress,
            guardians[1],
            bytes32(0),
            processSignature2
        );

        (
            executeAfter,
            executeBefore,
            currentWeight,
            _calldataHash
        ) = recoveryManager.getRecoveryRequest(accountAddress);
        assertEq(executeAfter, 0);
        assertEq(executeBefore, 0);
        assertEq(currentWeight, 3);

        uint _executeAfter = block.timestamp + delay;
        uint _executeBefore = block.timestamp + expiry;

        // handle recovery request for guardian 3
        bytes memory processSignature3 = constructAadhaarSignatureParam(false);

        handleRecovery(
            accountAddress,
            guardians[2],
            calldataHash,
            processSignature3
        );

        (
            executeAfter,
            executeBefore,
            currentWeight,
            _calldataHash
        ) = recoveryManager.getRecoveryRequest(accountAddress);
        assertEq(executeAfter, _executeAfter);
        assertEq(executeBefore, _executeBefore);
        assertEq(currentWeight, 4);

        // Time travel so that the recovery delay has passed
        vm.warp(block.timestamp + delay);

        // Complete recovery
        recoveryManager.completeRecovery(accountAddress, recoveryCalldata);

        (
            executeAfter,
            executeBefore,
            currentWeight,
            _calldataHash
        ) = recoveryManager.getRecoveryRequest(accountAddress);

        address updatedOwner = validator.owners(accountAddress);

        assertEq(executeAfter, 0);
        assertEq(executeBefore, 0);
        assertEq(currentWeight, 0);
        assertEq(updatedOwner, newOwner);
    }
}

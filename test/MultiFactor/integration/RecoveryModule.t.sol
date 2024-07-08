// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {console2} from "forge-std/console2.sol";
import {ModuleKitHelpers, ModuleKitUserOp} from "modulekit/ModuleKit.sol";
import {MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR} from "modulekit/external/ERC7579.sol";

import {IRecoveryManager} from "src/multi-factor/interfaces/IRecoveryManager.sol";
import {GuardianStorage, GuardianStatus} from "src/multi-factor/libraries/EnumerableGuardianMap.sol";
import {OwnableValidator} from "src/test/OwnableValidator.sol";

import {OwnableValidatorRecovery_RecoveryModule_Base} from "./RecoveryModuleBase.t.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

// 3 guardians where 1st and 2nd guardins use ecrecover and and the 3rd uses anon aadhaar zkp

contract OwnableValidatorRecovery_UniversalRecoveryModule_Integration_Test is
    OwnableValidatorRecovery_RecoveryModule_Base
{
    function setUp() public override {
        console2.log("");
        console2.log(
            unicode"/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*/"
        );
        console2.log(
            "                    Running Recovery Test                   "
        );
        console2.log(
            unicode"/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/"
        );
        console2.log("");

        super.setUp();

        console2.log(" ---- -Account Settings ------ ");
        console2.log("");
        console2.log("    AccountAddress:", accountAddress);
        console2.log("    Current Owner:", owner);
        console2.log("    New Owner:", newOwner);
        console2.log("");
        console2.log("");

        console2.log(" ---- Recovery Configuration ----- ");
        console2.log("");
        console2.log(" - Guardians ");
        console2.log("");
        console2.log("  - Guardian 1 - ");
        console2.log("    Address:", guardians[0]);
        console2.log("    Voting power:", guardianWeights[0]);
        console2.log("    Validation Method:", "ECDSA");
        console2.log("");
        console2.log("  - Guardian 2 - ");
        console2.log("    Address:", guardians[1]);
        console2.log("    Voting power:", guardianWeights[1]);
        console2.log("    Validation Method:", "ECDSA");
        console2.log("");
        console2.log("  - Guardian 3 - ");
        console2.log("    Address:", guardians[2]);
        console2.log("    Voting power:", guardianWeights[2]);
        console2.log("    Validation Method:", "AnonAadhaar");
        console2.log("");
        console2.log(" - Threshold :", threshold);
        console2.log(" - Delay :", delay);
        console2.log(" - Expiry :", expiry);
        console2.log("");
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
        console2.log(" ////////////////////////////// ");
        console2.log("          Acceptance Phase      ");
        console2.log(" ////////////////////////////// ");
        console2.log("");
        console2.log(" Guardian 1 Accepting Request...");
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
        console2.log(
            " Acceptance by Guardian 1 has been succsssfully performed"
        );
        console2.log(" Current Approval Count: ", (guardianStorage1.weight));
        console2.log("");

        // Accept guardian 2
        console2.log(" Guardian 2 Accepting Request...");
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
        assertEq(guardianStorage2.weight, uint256(1));
        console2.log(
            " Acceptance by Guardian 2 has been succsssfully performed"
        );
        console2.log(" Current Approval Count: ", (guardianStorage2.weight));
        console2.log("");

        // Accept guardian 3
        console2.log(" Guardian 3 Accepting Request...");
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

        console2.log(
            " Acceptance by Guardian 3 has been succsssfully performed"
        );
        console2.log(" Current Approval Count: ", (guardianStorage3.weight));
        console2.log("");

        console2.log(
            unicode" |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||| "
        );
        console2.log(
            unicode"           ||||||||||||||||||||||||||||||||||||||||||||||| "
        );
        console2.log(unicode"                        |||||||||||||||||||||| ");
        console2.log("");
        console2.log("                            Opps! Key Lost!          ");
        console2.log("");
        console2.log(unicode"                        |||||||||||||||||||||| ");
        console2.log(
            unicode"           ||||||||||||||||||||||||||||||||||||||||||||||| "
        );
        console2.log(
            unicode" |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||| "
        );

        console2.log("");

        console2.log(" ////////////////////////////// ");
        console2.log("          Process Phase         ");
        console2.log(" ////////////////////////////// ");
        console2.log("");

        // handle recovery request for guardian 1
        console2.log(" Guardian 1 Processing Recovery...");
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
        console2.log(
            " Recovery Request has been succsssfully approved by Guardian 1"
        );
        console2.log(" Current Approval Count: ", currentWeight);
        console2.log("");

        // handle recovery request for guardian 2
        console2.log(" Guardian 2 Processing Recovery...");
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
        assertEq(currentWeight, 2);
        console2.log(
            " Recovery Request has been succsssfully approved by Guardian 2"
        );
        console2.log(" Current Approval Count: ", currentWeight);
        console2.log("");

        uint _executeAfter = block.timestamp + delay;
        uint _executeBefore = block.timestamp + expiry;

        // handle recovery request for guardian 3
        console2.log(" Guardian 3 Processing Recovery...");

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
        assertEq(currentWeight, 3);
        console2.log(
            " Recovery Request has been succsssfully approved by Guardian 3"
        );
        console2.log(" Current Approval Count: ", currentWeight);
        console2.log("");

        // Time travel so that the recovery delay has passed
        vm.warp(block.timestamp + delay);

        console2.log(" ////////////////////////////// ");
        console2.log("         Complete Phase         ");
        console2.log(" ////////////////////////////// ");
        console2.log("");

        // Complete recovery
        console2.log(" Performing recovery completion...");
        recoveryManager.completeRecovery(accountAddress, recoveryCalldata);

        (
            executeAfter,
            executeBefore,
            currentWeight,
            _calldataHash
        ) = recoveryManager.getRecoveryRequest(accountAddress);

        address updatedOwner = validator.owners(accountAddress);
        console2.log(" Current Approval Count: ", currentWeight);
        console2.log(" Updated New Owner: ", updatedOwner);

        assertEq(executeAfter, 0);
        assertEq(executeBefore, 0);
        assertEq(currentWeight, 0);
        assertEq(updatedOwner, newOwner);
    }
}

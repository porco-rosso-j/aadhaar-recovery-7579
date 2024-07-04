// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {RhinestoneModuleKit, AccountInstance} from "modulekit/ModuleKit.sol";

import {Verifier as AnonAaadhaarVerifier} from "@anon-aadhaar/contracts/src/Verifier.sol";
import {AnonAadhaar} from "@anon-aadhaar/contracts/src/AnonAadhaar.sol";
import {Inputs} from "./Inputs.sol";

abstract contract IntegrationBase is RhinestoneModuleKit, Test, Inputs {
    // ZK Email contracts and variables
    address anonAadhaarDeployer = vm.addr(1);
    AnonAadhaar anonAadhaar;
    AnonAaadhaarVerifier verifier;

    // account and owners
    AccountInstance instance;
    address accountAddress;
    address owner;
    address newOwner;

    // recovery config
    uint256[] guardians;
    uint256[] guardianWeights;
    uint256 totalWeight;
    uint256 delay;
    uint256 expiry;
    uint256 threshold;
    uint256 templateIdx;

    // Account salts
    bytes32 accountSalt;

    string selector = "12345";
    uint anonAadhaaTestPubKeyHash =
        15134874015316324267425466444584014077184337590635665158241104437045239495873;

    function setUp() public virtual {
        console2.logUint(0);
        init();

        console2.logUint(1);

        // Create ZK Email contracts
        vm.startPrank(anonAadhaarDeployer);
        verifier = new AnonAaadhaarVerifier();
        anonAadhaar = new AnonAadhaar(
            address(verifier),
            anonAadhaaTestPubKeyHash
        );
        vm.stopPrank();

        console2.logUint(2);

        // create owners
        owner = vm.createWallet("owner").addr;
        newOwner = vm.createWallet("newOwner").addr;
        // Deploy and fund the accounts
        instance = makeAccountInstance("account");
        accountAddress = instance.account;
        vm.deal(address(instance.account), 10 ether);

        accountSalt = keccak256(abi.encode("account salt"));

        console2.logUint(3);

        // Compute guardian addresses
        guardians = new uint256[](3);
        // guardians[0] = guardianHash1;
        // guardians[1] = guardianHash2;
        // guardians[2] = guardianHash3;
        // guardians = new uint256[](1);
        guardians[0] = guardianHash1;
        guardians[1] = guardianHash2;
        guardians[2] = guardianHash3;

        // Set recovery config variables
        guardianWeights = new uint256[](3);
        // guardianWeights = new uint256[](1);
        guardianWeights[0] = 1;
        guardianWeights[1] = 2;
        guardianWeights[2] = 1;

        totalWeight = 4;
        delay = 1 seconds;
        expiry = 2 weeks;

        threshold = 4;
    }
}

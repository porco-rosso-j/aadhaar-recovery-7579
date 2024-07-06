// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";

import {RhinestoneModuleKit, AccountInstance} from "modulekit/ModuleKit.sol";

import {Verifier as AnonAaadhaarVerifier} from "@anon-aadhaar/contracts/src/Verifier.sol";
import {AnonAadhaar} from "@anon-aadhaar/contracts/src/AnonAadhaar.sol";
import {Inputs} from "./Inputs.sol";

abstract contract IntegrationBase is RhinestoneModuleKit, Test, Inputs {
    // ZK Email contracts and variables
    address deployer = vm.addr(1);
    AnonAadhaar anonAadhaar;
    AnonAaadhaarVerifier verifier;

    // account and owners
    AccountInstance instance;
    address accountAddress;
    address owner;
    address newOwner;

    // recovery config
    address[] guardians;
    uint256[] guardianWeights;
    uint256 totalWeight;
    uint256 delay;
    uint256 expiry;
    uint256 threshold;
    uint256 templateIdx;

    // for ecdsa sign
    uint[] guardianPrivatekeys;
    bytes32 testMsgHash;

    // Account salts
    bytes32 accountSalt;

    string selector = "12345";
    uint anonAadhaarTestPubKeyHash =
        15134874015316324267425466444584014077184337590635665158241104437045239495873;

    function setUp() public virtual {
        init();

        // Create ZK Email contracts
        vm.startPrank(deployer);
        verifier = new AnonAaadhaarVerifier();
        anonAadhaar = new AnonAadhaar(
            address(verifier),
            anonAadhaarTestPubKeyHash
        );

        vm.stopPrank();

        // create owners
        owner = vm.createWallet("owner").addr;
        newOwner = vm.createWallet("newOwner").addr;
        // Deploy and fund the accounts
        instance = makeAccountInstance("account");
        accountAddress = instance.account;
        vm.deal(address(instance.account), 10 ether);

        accountSalt = keccak256(abi.encode("account salt"));

        testMsgHash = keccak256(abi.encodePacked("Test message"));

        // Vm.Wallet memory guardianWallet1 = vm.createWallet(
        //     uint256(keccak256(bytes("guardian1")))
        // );

        Vm.Wallet memory guardianWallet1 = vm.createWallet(
            uint256(keccak256(bytes("guardian1")))
        );
        Vm.Wallet memory guardianWallet2 = vm.createWallet(
            uint256(keccak256(bytes("guardian2")))
        );
        Vm.Wallet memory guardianWallet3 = vm.createWallet(
            uint256(keccak256(bytes("guardian3")))
        );

        // Compute guardian addresses
        guardians = new address[](3);
        guardians[0] = guardianWallet1.addr;
        guardians[1] = guardianWallet2.addr;
        guardians[2] = guardianWallet3.addr;

        guardianPrivatekeys = new uint[](3);
        guardianPrivatekeys[0] = guardianWallet1.privateKey;
        guardianPrivatekeys[1] = guardianWallet2.privateKey;
        guardianPrivatekeys[2] = guardianWallet3.privateKey;

        // Set recovery config variables
        guardianWeights = new uint[](3);
        guardianWeights[0] = 1;
        guardianWeights[1] = 2;
        guardianWeights[2] = 1;

        totalWeight = 4;
        delay = 1 seconds;
        expiry = 2 weeks;

        threshold = 4;
    }
}

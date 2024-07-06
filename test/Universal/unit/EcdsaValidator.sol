// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "src/universal/validators/EcdsaValidator.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

contract EcdsaValidatorTest is Test {
    EcdsaValidator validator;

    function setUp() public {
        validator = new EcdsaValidator();
    }

    function testIsValidSignature() public {
        Vm.Wallet memory wallet = vm.createWallet(
            uint256(keccak256(bytes("1")))
        );

        uint256 privateKey = wallet.privateKey;
        address signer = wallet.addr;

        // Create a hash to sign
        bytes32 hash = keccak256(abi.encodePacked("Test message"));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            ECDSA.toEthSignedMessageHash(hash)
        );

        bytes memory signature = abi.encode(signer, v, r, s);
        // Call the isValidSignature function
        bytes4 magicValue = validator.isValidSignature(hash, signature);

        // Check the result
        assertEq(magicValue, bytes4(0x1626ba7e));
    }
}

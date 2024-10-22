// // SPDX-License-Identifier: GPL-3.0
// pragma solidity ^0.8.20;

// import {DKIMRegistry} from "@zk-email/contracts/DKIMRegistry.sol";
// import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
// import {IRecoveryValidator} from "../interfaces/IRecoveryValidator.sol";
// import {Groth16Verifier} from "ether-email-auth/packages/contracts/src/utils/Groth16Verifier.sol";

// contract EmailValidator is Initializable, UUPSUpgradeable, IRecoveryValidator {
//     DKIMRegistry public immutable dkimRegistry;
//     Groth16Verifier public immutable verifier;
//     bytes32 public senderCommitment;

//     constructor(DKIMRegistry registry, Groth16Verifier _verifier) {
//         dkimRegistry = registry;
//         verifier = _verifier;
//         _disableInitializers();
//     }

//     function initialize(bytes32 _senderCommitment) public initializer {
//         senderCommitment = _senderCommitment;
//     }

//     function getEmailApproverInfo()
//         external
//         view
//         returns (DKIMRegistry, Groth16Verifier, bytes32)
//     {
//         return (dkimRegistry, verifier, senderCommitment);
//     }

//     function _isValidProof(
//         uint256[8] memory proof,
//         bytes32 pubkeyHash,
//         bytes32 senderDomainHash,
//         bytes32 approvedHash
//     ) internal view returns (bool) {
//         // 1. Verify DKIM key
//         // Note: this currently is not compitable with the current DKIMRegistry
//         require(
//             dkimRegistry.isDKIMPublicKeyHashValid(senderDomainHash, pubkeyHash),
//             "invalid dkim signature"
//         );

//         uint256[6] memory signals;
//         signals[0] = uint256(pubkeyHash);
//         signals[1] = uint256(senderDomainHash);
//         signals[2] = uint256(senderCommitment);
//         signals[3] = uint256(uint160(address(this)));
//         // split bytes32 hash into two parts
//         signals[4] = uint256(approvedHash) >> 128;
//         signals[5] = uint256(approvedHash) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
//         // Verify Dkim proof
//         return
//             verifier.verifyProof(
//                 [proof[0], proof[1]],
//                 [[proof[2], proof[3]], [proof[4], proof[5]]],
//                 [proof[6], proof[7]],
//                 signals
//             );
//     }

//     function isValidSignature(
//         bytes32 hash,
//         bytes memory signature
//     ) external view returns (bytes4 magicValue) {
//         // decode signature
//         (
//             uint256[8] memory proof,
//             bytes32 pubkeyHash,
//             bytes32 senderDomainHash
//         ) = abi.decode(signature, (uint256[8], bytes32, bytes32));
//         return
//             _isValidProof(proof, pubkeyHash, senderDomainHash, hash)
//                 ? EIP1271_MAGIC_VALUE
//                 : EIP1271_INVALID_ID;
//     }

//     function _authorizeUpgrade(
//         address newImplementation
//     ) internal virtual override {
//         revert("disable upgradeable");
//         // solhint-disable-previous-line no-empty-blocks
//     }
// }

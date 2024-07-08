import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IRecoveryValidator} from "../interfaces/IRecoveryValidator.sol";
import {IAnonAadhaar} from "@anon-aadhaar/contracts/interfaces/IAnonAadhaar.sol";

contract AnonAadhaarValidator is
    Initializable,
    UUPSUpgradeable,
    IRecoveryValidator
{
    address public anonAadhaarAddr;

    constructor(address _anonAadhaarAddr) {
        anonAadhaarAddr = _anonAadhaarAddr;
        _disableInitializers();
    }

    function isValidSignature(
        bytes32 hash, // recovery calldata ?
        bytes calldata signature
    ) external view override returns (bytes4 magicValue) {

        // decode signature
        (
            uint256 nullifierSeed,
            uint256 nullifier,
            uint256 timestamp,
            uint[4] memory revealArray,
            uint[8] memory groth16Proof
        ) = abi.decode(signature, (uint, uint, uint, uint[4], uint[8]));

        uint256 uintCalldataHash = uint256(hash);

        return
            _verifyProofData(
                nullifierSeed,
                nullifier,
                timestamp,
                uintCalldataHash,
                revealArray,
                groth16Proof
            )
                ? EIP1271_MAGIC_VALUE
                : EIP1271_INVALID_ID;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     VERIFY PROOF                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _verifyProofData(
        uint256 nullifierSeed,
        uint256 nullifier,
        uint256 timestamp,
        uint256 signal,
        uint[4] memory revealArray,
        uint[8] memory groth16Proof
    ) internal view returns (bool) {
        if (
            !IAnonAadhaar(anonAadhaarAddr).verifyAnonAadhaarProof(
                nullifierSeed,
                nullifier,
                timestamp,
                signal, // recovery calldata bound to proof
                revealArray,
                groth16Proof
            )
        ) {
            return false;
        } else {
            return true;
        }
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal virtual override {
        revert("disable upgradeable");
        // solhint-disable-previous-line no-empty-blocks
    }
}

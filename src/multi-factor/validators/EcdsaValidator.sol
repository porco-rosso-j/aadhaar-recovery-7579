import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IRecoveryValidator} from "../interfaces/IRecoveryValidator.sol";
import {SignatureDecoder} from "../libraries/SignatureDecoder.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

// signature lenght == 20 + 64 (address + ecdsa signature)

contract EcdsaValidator is
    Initializable,
    UUPSUpgradeable,
    IRecoveryValidator,
    SignatureDecoder
{
    function isValidSignature(
        bytes32 hash, // recovery calldata ?
        bytes memory signature
    ) external view override returns (bytes4 magicValue) {
        (address guardianAddress, uint8 v, bytes32 r, bytes32 s) = abi.decode(
            signature,
            (address, uint8, bytes32, bytes32)
        );

        address recoveredAddress = ecrecover(
            ECDSA.toEthSignedMessageHash(hash),
            v,
            r,
            s
        );

        return
            recoveredAddress == guardianAddress
                ? EIP1271_MAGIC_VALUE
                : EIP1271_INVALID_ID;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal virtual override {
        revert("disable upgradeable");
        // solhint-disable-previous-line no-empty-blocks
    }
}
